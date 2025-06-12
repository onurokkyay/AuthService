package com.krawenn.auth.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.krawenn.auth.config.MockAuthServiceTestConfig;
import com.krawenn.auth.dto.AuthRequest;
import com.krawenn.auth.dto.AuthResponse;
import com.krawenn.auth.dto.RefreshRequest;
import com.krawenn.auth.exception.InvalidCredentialsException;
import com.krawenn.auth.exception.UserAlreadyExistsException;
import com.krawenn.auth.exception.UserNotFoundException;
import com.krawenn.auth.service.AuthService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
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
@Import(MockAuthServiceTestConfig.class)
class AuthControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private AuthService authService;

    @Autowired
    private ObjectMapper objectMapper;

    private AuthRequest validAuthRequest;
    private RefreshRequest validRefreshRequest;
    private AuthResponse validAuthResponse;

    @BeforeEach
    void setUp() {
        // Setup valid auth request
        validAuthRequest = new AuthRequest();
        validAuthRequest.setUsername("testuser");
        validAuthRequest.setEmail("test@example.com");
        validAuthRequest.setPassword("password123");

        // Setup valid refresh request
        validRefreshRequest = new RefreshRequest();
        validRefreshRequest.setRefreshToken("refresh-token");

        // Setup valid auth response
        validAuthResponse = new AuthResponse("jwt-token", "refresh-token", "USER");
    }

    @Test
    @DisplayName("Register should return 200 OK")
    void register_shouldReturnOk() throws Exception {
        Mockito.doNothing().when(authService).register(any(AuthRequest.class));

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(validAuthRequest)))
                .andExpect(status().isOk());
    }

    @Test
    @DisplayName("Register should return 409 Conflict if user already exists")
    void register_shouldReturnConflictIfUserExists() throws Exception {
        Mockito.doThrow(new UserAlreadyExistsException()).when(authService).register(any(AuthRequest.class));

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(validAuthRequest)))
                .andExpect(status().isConflict())
                .andExpect(content().string("User already exists"));
    }

    @Test
    @DisplayName("Login should return AuthResponse")
    void login_shouldReturnAuthResponse() throws Exception {
        Mockito.when(authService.login(any(AuthRequest.class))).thenReturn(validAuthResponse);

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(validAuthRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").value("jwt-token"))
                .andExpect(jsonPath("$.refreshToken").value("refresh-token"))
                .andExpect(jsonPath("$.role").value("USER"));
    }

    @Test
    @DisplayName("Login should return 401 Unauthorized for invalid credentials")
    void login_shouldReturnUnauthorizedForInvalidCredentials() throws Exception {
        Mockito.when(authService.login(any(AuthRequest.class)))
                .thenThrow(new InvalidCredentialsException());

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(validAuthRequest)))
                .andExpect(status().isUnauthorized())
                .andExpect(content().string("Invalid credentials"));
    }

    @Test
    @DisplayName("Login should return 404 Not Found for missing user")
    void login_shouldReturnNotFoundForMissingUser() throws Exception {
        Mockito.when(authService.login(any(AuthRequest.class)))
                .thenThrow(new UserNotFoundException());

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(validAuthRequest)))
                .andExpect(status().isNotFound())
                .andExpect(content().string("User not found"));
    }

    @Test
    @DisplayName("Refresh should return new AuthResponse")
    void refresh_shouldReturnAuthResponse() throws Exception {
        Mockito.when(authService.refreshToken(any(RefreshRequest.class))).thenReturn(validAuthResponse);

        mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(validRefreshRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").value("jwt-token"))
                .andExpect(jsonPath("$.refreshToken").value("refresh-token"))
                .andExpect(jsonPath("$.role").value("USER"));
    }

    @Test
    @DisplayName("Refresh should return 401 Unauthorized for invalid refresh token")
    void refresh_shouldReturnUnauthorizedForInvalidToken() throws Exception {
        Mockito.when(authService.refreshToken(any(RefreshRequest.class)))
                .thenThrow(new InvalidCredentialsException());

        mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(validRefreshRequest)))
                .andExpect(status().isUnauthorized())
                .andExpect(content().string("Invalid credentials"));
    }

    @Test
    @DisplayName("Register should return 400 Bad Request for validation errors")
    void register_shouldReturnBadRequestForValidationErrors() throws Exception {
        AuthRequest invalidRequest = new AuthRequest(); // empty request

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(invalidRequest)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.username").exists())
                .andExpect(jsonPath("$.email").exists())
                .andExpect(jsonPath("$.password").exists());
    }

    @Test
    @DisplayName("Login should return 400 Bad Request for validation errors")
    void login_shouldReturnBadRequestForValidationErrors() throws Exception {
        AuthRequest invalidRequest = new AuthRequest(); // empty request

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(invalidRequest)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.username").exists())
                .andExpect(jsonPath("$.email").exists())
                .andExpect(jsonPath("$.password").exists());
    }

    @Test
    @DisplayName("Refresh should return 400 Bad Request for validation errors")
    void refresh_shouldReturnBadRequestForValidationErrors() throws Exception {
        RefreshRequest invalidRequest = new RefreshRequest(); // missing token

        mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(invalidRequest)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.refreshToken").exists());
    }
}