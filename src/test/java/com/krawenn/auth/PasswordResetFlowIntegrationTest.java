package com.krawenn.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.after;
import static org.mockito.Mockito.timeout;
import static org.mockito.Mockito.verify;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.jayway.jsonpath.JsonPath;
import com.krawenn.auth.password.PasswordResetMailer;
import com.krawenn.auth.password.PasswordResetTokens;
import java.util.UUID;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

/**
 * Forgetting, resetting and changing a password, against a real PostgreSQL and the real filter chain.
 *
 * <p>The mailer is the one thing replaced, and it is replaced to be <em>read</em>: the test takes the link it was
 * given exactly as a person would take it from their inbox. What these prove — that a reset really signs other devices
 * out, that a spent link stays spent, that the two unauthenticated endpoints are reachable and the third is not — only
 * exists once persistence and security are both in play.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Testcontainers
class PasswordResetFlowIntegrationTest {

    @Container
    @ServiceConnection
    private static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16-alpine");

    private static final String PASSWORD = "correct-horse-battery-staple";
    private static final String NEW_PASSWORD = "an-entirely-new-passphrase";

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private PasswordResetMailer mailer;

    @Test
    @DisplayName("A forgotten password is reset from the emailed link, and every old session ends")
    void forgottenPasswordIsResetFromTheLink() throws Exception {
        String username = uniqueUsername();
        String email = username + "@example.test";
        register(username, email);
        String oldRefresh = JsonPath.read(login(username, PASSWORD), "$.refreshToken");

        requestReset(email);
        String token = tokenFromMailedLink();

        mockMvc.perform(post("/api/auth/password/reset")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(resetBody(token, NEW_PASSWORD)))
                .andExpect(status().isNoContent());

        login(username, NEW_PASSWORD);
        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(loginBody(username, PASSWORD)))
                .andExpect(status().isUnauthorized());

        // The session that existed before the reset is gone: the reset locked out whoever held it.
        mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"refreshToken\":\"%s\"}".formatted(oldRefresh)))
                .andExpect(status().isUnauthorized());

        // And the link cannot be spent twice.
        mockMvc.perform(post("/api/auth/password/reset")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(resetBody(token, "yet-another-passphrase")))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("INVALID_RESET_TOKEN"));
    }

    @Test
    @DisplayName("An address with no account gets the same 202 and nothing is sent")
    void unknownAddressLooksTheSame() throws Exception {
        requestReset("nobody-" + UUID.randomUUID() + "@example.test");

        verify(mailer, after(500).never()).send(any());
    }

    @Test
    @DisplayName("Asking twice inside the cooldown sends one email")
    void cooldownSendsOneEmail() throws Exception {
        String username = uniqueUsername();
        String email = username + "@example.test";
        register(username, email);

        requestReset(email);
        requestReset(email);

        verify(mailer, timeout(5000).times(1)).send(any());
        verify(mailer, after(500).times(1)).send(any());
    }

    @Test
    @DisplayName("Changing a password keeps the caller signed in and signs every other session out")
    void changeKeepsTheCallerAndEndsTheRest() throws Exception {
        String username = uniqueUsername();
        register(username, username + "@example.test");
        String thisDevice = login(username, PASSWORD);
        String otherDeviceRefresh = JsonPath.read(login(username, PASSWORD), "$.refreshToken");

        String answer = mockMvc.perform(post("/api/auth/password/change")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + JsonPath.read(thisDevice, "$.accessToken"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(changeBody(PASSWORD, NEW_PASSWORD)))
                .andExpect(status().isOk())
                .andReturn()
                .getResponse()
                .getContentAsString();

        mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"refreshToken\":\"%s\"}".formatted(otherDeviceRefresh)))
                .andExpect(status().isUnauthorized());

        mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"refreshToken\":\"%s\"}"
                                .formatted((String) JsonPath.read(answer, "$.refreshToken"))))
                .andExpect(status().isOk());

        login(username, NEW_PASSWORD);
    }

    @Test
    @DisplayName("A wrong current password is a 400, not a 401 a client would answer by refreshing")
    void wrongCurrentPasswordIsBadRequest() throws Exception {
        String username = uniqueUsername();
        register(username, username + "@example.test");
        String accessToken = JsonPath.read(login(username, PASSWORD), "$.accessToken");

        mockMvc.perform(post("/api/auth/password/change")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(changeBody("not-the-password-at-all", NEW_PASSWORD)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("INVALID_CURRENT_PASSWORD"));
    }

    @Test
    @DisplayName("Changing a password needs a token; forgetting one does not")
    void changeRequiresAToken() throws Exception {
        mockMvc.perform(post("/api/auth/password/change")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(changeBody(PASSWORD, NEW_PASSWORD)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("UNAUTHENTICATED"));
    }

    @Test
    @DisplayName("A new password is held to the registration rules")
    void weakNewPasswordIsRejected() throws Exception {
        mockMvc.perform(post("/api/auth/password/reset")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(resetBody("any-token", "short")))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("VALIDATION_FAILED"));
    }

    private String tokenFromMailedLink() {
        ArgumentCaptor<PasswordResetTokens.IssuedReset> sent =
                ArgumentCaptor.forClass(PasswordResetTokens.IssuedReset.class);
        // Delivery runs on another thread, which is the point of it.
        verify(mailer, timeout(5000)).send(sent.capture());
        String link = sent.getValue().link();
        assertThat(link).startsWith("https://client.test/reset-password?token=");
        return link.substring(link.indexOf("token=") + "token=".length());
    }

    private static String uniqueUsername() {
        return "user-" + UUID.randomUUID().toString().substring(0, 8);
    }

    private void register(String username, String email) throws Exception {
        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"username":"%s","email":"%s","password":"%s"}""".formatted(username, email, PASSWORD)))
                .andExpect(status().isCreated());
    }

    private String login(String username, String password) throws Exception {
        return mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(loginBody(username, password)))
                .andExpect(status().isOk())
                .andReturn()
                .getResponse()
                .getContentAsString();
    }

    private void requestReset(String email) throws Exception {
        mockMvc.perform(post("/api/auth/password/forgot")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"%s\"}".formatted(email)))
                .andExpect(status().isAccepted());
    }

    private static String loginBody(String username, String password) {
        return """
                {"username":"%s","password":"%s"}""".formatted(username, password);
    }

    private static String resetBody(String token, String newPassword) {
        return """
                {"token":"%s","newPassword":"%s"}""".formatted(token, newPassword);
    }

    private static String changeBody(String currentPassword, String newPassword) {
        return """
                {"currentPassword":"%s","newPassword":"%s"}""".formatted(currentPassword, newPassword);
    }
}
