package com.krawenn.auth.service;

import com.krawenn.auth.dto.AuthRequest;
import com.krawenn.auth.dto.AuthResponse;
import com.krawenn.auth.dto.RefreshRequest;
import com.krawenn.auth.exception.InvalidCredentialsException;
import com.krawenn.auth.exception.UserAlreadyExistsException;
import com.krawenn.auth.exception.UserNotFoundException;
import com.krawenn.auth.model.RefreshToken;
import com.krawenn.auth.model.User;
import com.krawenn.auth.repository.RefreshTokenRepository;
import com.krawenn.auth.repository.UserRepository;
import com.krawenn.auth.security.JwtUtil;
import com.krawenn.auth.service.impl.AuthServiceImpl;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.Instant;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private RefreshTokenRepository refreshTokenRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private JwtUtil jwtUtil;

    @InjectMocks
    private AuthServiceImpl authService;

    private AuthRequest validAuthRequest;
    private User validUser;
    private RefreshToken validRefreshToken;

    @BeforeEach
    void setUp() {
        validAuthRequest = new AuthRequest();
        validAuthRequest.setUsername("testuser");
        validAuthRequest.setEmail("test@example.com");
        validAuthRequest.setPassword("password123");

        validUser = new User();
        validUser.setId("user123");
        validUser.setUsername("testuser");
        validUser.setEmail("test@example.com");
        validUser.setPassword("encodedPassword");
        validUser.setRole("USER");

        validRefreshToken = new RefreshToken();
        validRefreshToken.setId("token123");
        validRefreshToken.setUserId("user123");
        validRefreshToken.setToken("refresh-token");
        validRefreshToken.setExpiryDate(Instant.now().plusSeconds(3600));
    }

    @Test
    @DisplayName("Register should create new user successfully")
    void register_shouldCreateNewUser() {
        when(userRepository.findByUsername(validAuthRequest.getUsername())).thenReturn(Optional.empty());
        when(userRepository.findByEmail(validAuthRequest.getEmail())).thenReturn(Optional.empty());
        when(passwordEncoder.encode(validAuthRequest.getPassword())).thenReturn("encodedPassword");

        assertDoesNotThrow(() -> authService.register(validAuthRequest));

        verify(userRepository).save(any(User.class));
    }

    @Test
    @DisplayName("Register should throw UserAlreadyExistsException when username exists")
    void register_shouldThrowExceptionWhenUsernameExists() {
        when(userRepository.findByUsername(validAuthRequest.getUsername()))
                .thenReturn(Optional.of(validUser));

        assertThrows(UserAlreadyExistsException.class, () -> authService.register(validAuthRequest));
        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    @DisplayName("Register should throw UserAlreadyExistsException when email exists")
    void register_shouldThrowExceptionWhenEmailExists() {
        when(userRepository.findByUsername(validAuthRequest.getUsername())).thenReturn(Optional.empty());
        when(userRepository.findByEmail(validAuthRequest.getEmail()))
                .thenReturn(Optional.of(validUser));

        assertThrows(UserAlreadyExistsException.class, () -> authService.register(validAuthRequest));
        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    @DisplayName("Login should return AuthResponse with tokens")
    void login_shouldReturnAuthResponse() {
        when(userRepository.findByUsername(validAuthRequest.getUsername()))
                .thenReturn(Optional.of(validUser));
        when(passwordEncoder.matches(validAuthRequest.getPassword(), validUser.getPassword()))
                .thenReturn(true);
        when(jwtUtil.generateToken(validUser.getUsername(), validUser.getRole()))
                .thenReturn("jwt-token");

        AuthResponse response = authService.login(validAuthRequest);

        assertNotNull(response);
        assertEquals("jwt-token", response.getToken());
        assertNotNull(response.getRefreshToken());
        assertEquals("USER", response.getRole());
        verify(refreshTokenRepository).deleteByUserId(validUser.getId());
        verify(refreshTokenRepository).save(any(RefreshToken.class));
    }

    @Test
    @DisplayName("Login should throw UserNotFoundException when user not found")
    void login_shouldThrowExceptionWhenUserNotFound() {
        when(userRepository.findByUsername(validAuthRequest.getUsername()))
                .thenReturn(Optional.empty());

        assertThrows(UserNotFoundException.class, () -> authService.login(validAuthRequest));
        verify(refreshTokenRepository, never()).save(any(RefreshToken.class));
    }

    @Test
    @DisplayName("Login should throw InvalidCredentialsException when password is wrong")
    void login_shouldThrowExceptionWhenPasswordWrong() {
        when(userRepository.findByUsername(validAuthRequest.getUsername()))
                .thenReturn(Optional.of(validUser));
        when(passwordEncoder.matches(validAuthRequest.getPassword(), validUser.getPassword()))
                .thenReturn(false);

        assertThrows(InvalidCredentialsException.class, () -> authService.login(validAuthRequest));
        verify(refreshTokenRepository, never()).save(any(RefreshToken.class));
    }

    @Test
    @DisplayName("Refresh token should return new AuthResponse")
    void refreshToken_shouldReturnNewAuthResponse() {
        RefreshRequest request = new RefreshRequest();
        request.setRefreshToken("refresh-token");

        when(refreshTokenRepository.findByToken(request.getRefreshToken()))
                .thenReturn(Optional.of(validRefreshToken));
        when(userRepository.findById(validRefreshToken.getUserId()))
                .thenReturn(Optional.of(validUser));
        when(jwtUtil.generateToken(validUser.getUsername(), validUser.getRole()))
                .thenReturn("new-jwt-token");

        AuthResponse response = authService.refreshToken(request);

        assertNotNull(response);
        assertEquals("new-jwt-token", response.getToken());
        assertEquals("refresh-token", response.getRefreshToken());
        assertEquals("USER", response.getRole());
    }

    @Test
    @DisplayName("Refresh token should throw InvalidCredentialsException when token not found")
    void refreshToken_shouldThrowExceptionWhenTokenNotFound() {
        RefreshRequest request = new RefreshRequest();
        request.setRefreshToken("invalid-token");

        when(refreshTokenRepository.findByToken(request.getRefreshToken()))
                .thenReturn(Optional.empty());

        assertThrows(InvalidCredentialsException.class, () -> authService.refreshToken(request));
    }

    @Test
    @DisplayName("Refresh token should throw InvalidCredentialsException when token expired")
    void refreshToken_shouldThrowExceptionWhenTokenExpired() {
        RefreshRequest request = new RefreshRequest();
        request.setRefreshToken("expired-token");

        validRefreshToken.setExpiryDate(Instant.now().minusSeconds(3600));
        when(refreshTokenRepository.findByToken(request.getRefreshToken()))
                .thenReturn(Optional.of(validRefreshToken));

        assertThrows(InvalidCredentialsException.class, () -> authService.refreshToken(request));
        verify(refreshTokenRepository).delete(validRefreshToken);
    }

    @Test
    @DisplayName("Refresh token should throw UserNotFoundException when user not found")
    void refreshToken_shouldThrowExceptionWhenUserNotFound() {
        RefreshRequest request = new RefreshRequest();
        request.setRefreshToken("refresh-token");

        when(refreshTokenRepository.findByToken(request.getRefreshToken()))
                .thenReturn(Optional.of(validRefreshToken));
        when(userRepository.findById(validRefreshToken.getUserId()))
                .thenReturn(Optional.empty());

        assertThrows(UserNotFoundException.class, () -> authService.refreshToken(request));
    }
} 