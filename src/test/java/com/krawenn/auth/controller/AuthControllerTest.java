package com.krawenn.auth.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.krawenn.auth.dto.AuthRequest;
import com.krawenn.auth.dto.AuthResponse;
import com.krawenn.auth.dto.RefreshRequest;
import com.krawenn.auth.exception.InvalidCredentialsException;
import com.krawenn.auth.exception.UserAlreadyExistsException;
import com.krawenn.auth.exception.UserNotFoundException;
import com.krawenn.auth.service.AuthService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.beans.factory.annotation.Autowired;

import static org.mockito.ArgumentMatchers.any;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(AuthController.class)
@AutoConfigureMockMvc(addFilters = false)
@TestPropertySource(properties = "spring.config.import=optional:configserver:")
@Import(AuthControllerTest.MockAuthServiceConfig.class)
class AuthControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private AuthService authService;

    @Autowired
    private ObjectMapper objectMapper;

    @TestConfiguration
    static class MockAuthServiceConfig {
        @Bean
        public AuthService authService() {
            return Mockito.mock(AuthService.class);
        }
    }

    @Test
    @DisplayName("Register should return 200 OK")
    void register_shouldReturnOk() throws Exception {
        AuthRequest request = new AuthRequest();
        request.setUsername("testuser");
        request.setEmail("test@example.com");
        request.setPassword("password123");

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk());
    }

    @Test
    @DisplayName("Register should return 409 Conflict if user already exists")
    void register_shouldReturnConflictIfUserExists() throws Exception {
        AuthRequest request = new AuthRequest();
        request.setUsername("testuser");
        request.setEmail("test@example.com");
        request.setPassword("password123");

        Mockito.doThrow(new UserAlreadyExistsException()).when(authService).register(any(AuthRequest.class));

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isConflict())
                .andExpect(content().string("User already exists"));
    }

    @Test
    @DisplayName("Login should return AuthResponse")
    void login_shouldReturnAuthResponse() throws Exception {
        AuthRequest request = new AuthRequest();
        request.setUsername("testuser");
        request.setEmail("test@example.com");
        request.setPassword("password123");

        AuthResponse response = new AuthResponse("jwt-token", "refresh-token", "USER");
        Mockito.when(authService.login(any(AuthRequest.class))).thenReturn(response);

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").value("jwt-token"))
                .andExpect(jsonPath("$.refreshToken").value("refresh-token"))
                .andExpect(jsonPath("$.role").value("USER"));
    }

    @Test
    @DisplayName("Login should return 401 Unauthorized for invalid credentials")
    void login_shouldReturnUnauthorizedForInvalidCredentials() throws Exception {
        AuthRequest request = new AuthRequest();
        request.setUsername("testuser");
        request.setEmail("test@example.com");
        request.setPassword("wrongpassword");

        Mockito.when(authService.login(any(AuthRequest.class)))
                .thenThrow(new InvalidCredentialsException());

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized())
                .andExpect(content().string("Invalid credentials"));
    }

    @Test
    @DisplayName("Login should return 404 Not Found for missing user")
    void login_shouldReturnNotFoundForMissingUser() throws Exception {
        AuthRequest request = new AuthRequest();
        request.setUsername("nouser");
        request.setEmail("nouser@example.com");
        request.setPassword("password123");

        Mockito.when(authService.login(any(AuthRequest.class)))
                .thenThrow(new UserNotFoundException());

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isNotFound())
                .andExpect(content().string("User not found"));
    }

    @Test
    @DisplayName("Refresh should return new AuthResponse")
    void refresh_shouldReturnAuthResponse() throws Exception {
        RefreshRequest request = new RefreshRequest();
        request.setRefreshToken("refresh-token");

        AuthResponse response = new AuthResponse("new-jwt-token", "refresh-token", "USER");
        Mockito.when(authService.refreshToken(any(RefreshRequest.class))).thenReturn(response);

        mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").value("new-jwt-token"))
                .andExpect(jsonPath("$.refreshToken").value("refresh-token"))
                .andExpect(jsonPath("$.role").value("USER"));
    }

    @Test
    @DisplayName("Refresh should return 401 Unauthorized for invalid refresh token")
    void refresh_shouldReturnUnauthorizedForInvalidToken() throws Exception {
        RefreshRequest request = new RefreshRequest();
        request.setRefreshToken("invalid-token");

        Mockito.when(authService.refreshToken(any(RefreshRequest.class)))
                .thenThrow(new InvalidCredentialsException());

        mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized())
                .andExpect(content().string("Invalid credentials"));
    }

    @Test
    @DisplayName("Register should return 400 Bad Request for validation errors")
    void register_shouldReturnBadRequestForValidationErrors() throws Exception {
        AuthRequest request = new AuthRequest(); // empty

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.username").exists())
                .andExpect(jsonPath("$.email").exists())
                .andExpect(jsonPath("$.password").exists());
    }

    @Test
    @DisplayName("Login should return 400 Bad Request for validation errors")
    void login_shouldReturnBadRequestForValidationErrors() throws Exception {
        AuthRequest request = new AuthRequest(); // empty

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.username").exists())
                .andExpect(jsonPath("$.email").exists())
                .andExpect(jsonPath("$.password").exists());
    }

    @Test
    @DisplayName("Refresh should return 400 Bad Request for validation errors")
    void refresh_shouldReturnBadRequestForValidationErrors() throws Exception {
        RefreshRequest request = new RefreshRequest(); // missing token

        mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.refreshToken").exists());
    }
}