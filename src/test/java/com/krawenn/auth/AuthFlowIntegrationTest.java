package com.krawenn.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.jayway.jsonpath.JsonPath;
import java.util.UUID;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

/**
 * Exercises the real thing: Flyway migrations on a real PostgreSQL, the security filter
 * chain, RS256 signing and refresh-token rotation.
 *
 * <p>The behaviours asserted here — rotation, reuse detection, role enforcement — cannot
 * be proven by unit tests, because they only exist once persistence and the filter chain
 * are involved.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Testcontainers
class AuthFlowIntegrationTest {

    @Container
    @ServiceConnection
    private static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16-alpine");

    private static final String PASSWORD = "correct-horse-battery-staple";

    @Autowired
    private MockMvc mockMvc;

    @Test
    @DisplayName("Register, log in and reach a protected endpoint")
    void registerLoginAndCallProtectedEndpoint() throws Exception {
        String username = uniqueUsername();
        register(username, username + "@example.test");

        String tokens = login(username);
        String accessToken = JsonPath.read(tokens, "$.accessToken");

        assertThat((String) JsonPath.read(tokens, "$.tokenType")).isEqualTo("Bearer");
        assertThat((Integer) JsonPath.read(tokens, "$.expiresIn")).isPositive();

        mockMvc.perform(get("/api/auth/me").header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value(username))
                .andExpect(jsonPath("$.role").value("USER"))
                // A password field must never appear in any representation of an account.
                .andExpect(jsonPath("$.passwordHash").doesNotExist());
    }

    @Test
    @DisplayName("A protected endpoint without a token answers 401 in the standard error shape")
    void missingTokenIsRejected() throws Exception {
        mockMvc.perform(get("/api/auth/me"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("UNAUTHENTICATED"))
                .andExpect(jsonPath("$.path").value("/api/auth/me"));
    }

    @Test
    @DisplayName("Refresh rotates the token, and replaying the old one kills every session")
    void refreshRotatesAndDetectsReuse() throws Exception {
        String username = uniqueUsername();
        register(username, username + "@example.test");

        String firstRefresh = JsonPath.read(login(username), "$.refreshToken");
        String rotated = refresh(firstRefresh);
        String secondRefresh = JsonPath.read(rotated, "$.refreshToken");

        assertThat(secondRefresh).isNotEqualTo(firstRefresh);

        // Replaying the consumed token is treated as theft.
        mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(refreshBody(firstRefresh)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("INVALID_REFRESH_TOKEN"));

        // ...which also invalidates the token the legitimate client is holding.
        mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(refreshBody(secondRefresh)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("INVALID_REFRESH_TOKEN"));
    }

    @Test
    @DisplayName("Logout revokes the session and is silent about unknown tokens")
    void logoutRevokesTheSession() throws Exception {
        String username = uniqueUsername();
        register(username, username + "@example.test");
        String refreshToken = JsonPath.read(login(username), "$.refreshToken");

        mockMvc.perform(post("/api/auth/logout")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(refreshBody(refreshToken)))
                .andExpect(status().isNoContent());

        mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(refreshBody(refreshToken)))
                .andExpect(status().isUnauthorized());

        // An unknown token must not reveal that it is unknown.
        mockMvc.perform(post("/api/auth/logout")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(refreshBody("never-issued")))
                .andExpect(status().isNoContent());
    }

    @Test
    @DisplayName("Logging in twice leaves both sessions usable")
    void multipleDevicesStaySignedIn() throws Exception {
        String username = uniqueUsername();
        register(username, username + "@example.test");

        String firstDevice = JsonPath.read(login(username), "$.refreshToken");
        String secondDevice = JsonPath.read(login(username), "$.refreshToken");

        refresh(firstDevice);
        refresh(secondDevice);
    }

    @Test
    @DisplayName("JWKS publishes the public key and nothing else")
    void jwksExposesOnlyPublicKeyMaterial() throws Exception {
        String jwks = mockMvc.perform(get("/.well-known/jwks.json"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.keys[0].kty").value("RSA"))
                .andExpect(jsonPath("$.keys[0].kid").isNotEmpty())
                // "d" is the private exponent; its presence would leak the signing key.
                .andExpect(jsonPath("$.keys[0].d").doesNotExist())
                .andReturn()
                .getResponse()
                .getContentAsString();

        assertThat(jwks).doesNotContain("PRIVATE");
    }

    @Test
    @DisplayName("A USER may not reach the admin endpoint")
    void adminEndpointRequiresAdminRole() throws Exception {
        String username = uniqueUsername();
        register(username, username + "@example.test");
        String accessToken = JsonPath.read(login(username), "$.accessToken");

        mockMvc.perform(patch("/api/admin/users/{id}/role", UUID.randomUUID())
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"role\":\"ADMIN\"}"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("FORBIDDEN"));
    }

    @Test
    @DisplayName("The bootstrap email registers as ADMIN and can promote another account")
    void bootstrapAdminCanAssignRoles() throws Exception {
        String adminName = uniqueUsername();
        // Matches auth.registration.bootstrap-admin-emails in application-test.yml.
        register(adminName, "admin@example.test").andExpect(jsonPath("$.role").value("ADMIN"));
        String adminToken = JsonPath.read(login(adminName), "$.accessToken");

        String targetName = uniqueUsername();
        String targetId = JsonPath.read(
                register(targetName, targetName + "@example.test")
                        .andReturn()
                        .getResponse()
                        .getContentAsString(),
                "$.id");

        mockMvc.perform(patch("/api/admin/users/{id}/role", targetId)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + adminToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"role\":\"ADMIN\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.role").value("ADMIN"));
    }

    @Test
    @DisplayName("A second registration with the same username is refused")
    void duplicateRegistrationIsRefused() throws Exception {
        String username = uniqueUsername();
        register(username, username + "@example.test");

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(registerBody(username, "other-" + username + "@example.test")))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.code").value("USER_ALREADY_EXISTS"));
    }

    @Test
    @DisplayName("Validation reports the field but never echoes the value")
    void validationDoesNotEchoTheRejectedValue() throws Exception {
        String weakPassword = "short";

        String body = mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(registerBody(uniqueUsername(), "weak@example.test", weakPassword)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("VALIDATION_FAILED"))
                .andExpect(jsonPath("$.fieldErrors[0].field").value("password"))
                .andReturn()
                .getResponse()
                .getContentAsString();

        assertThat(body).doesNotContain(weakPassword);
    }

    @Test
    @DisplayName("Wrong credentials give the same answer as an unknown account")
    void failedLoginIsIndistinguishable() throws Exception {
        String username = uniqueUsername();
        register(username, username + "@example.test");

        String wrongPassword = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(loginBody(username, "wrong-password-entirely")))
                .andExpect(status().isUnauthorized())
                .andReturn()
                .getResponse()
                .getContentAsString();

        String unknownUser = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(loginBody(uniqueUsername(), PASSWORD)))
                .andExpect(status().isUnauthorized())
                .andReturn()
                .getResponse()
                .getContentAsString();

        assertThat(JsonPath.<String>read(wrongPassword, "$.message"))
                .isEqualTo(JsonPath.read(unknownUser, "$.message"));
        assertThat(JsonPath.<String>read(wrongPassword, "$.code")).isEqualTo(JsonPath.read(unknownUser, "$.code"));
    }

    private static String uniqueUsername() {
        return "user-" + UUID.randomUUID().toString().substring(0, 8);
    }

    private ResultActions register(String username, String email) throws Exception {
        return mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(registerBody(username, email)))
                .andExpect(status().isCreated());
    }

    private String login(String username) throws Exception {
        return mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(loginBody(username, PASSWORD)))
                .andExpect(status().isOk())
                .andReturn()
                .getResponse()
                .getContentAsString();
    }

    private String refresh(String refreshToken) throws Exception {
        return mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(refreshBody(refreshToken)))
                .andExpect(status().isOk())
                .andReturn()
                .getResponse()
                .getContentAsString();
    }

    private static String registerBody(String username, String email) {
        return registerBody(username, email, PASSWORD);
    }

    private static String registerBody(String username, String email, String password) {
        return """
                {"username":"%s","email":"%s","password":"%s"}""".formatted(username, email, password);
    }

    private static String loginBody(String username, String password) {
        return """
                {"username":"%s","password":"%s"}""".formatted(username, password);
    }

    private static String refreshBody(String refreshToken) {
        return """
                {"refreshToken":"%s"}""".formatted(refreshToken);
    }
}
