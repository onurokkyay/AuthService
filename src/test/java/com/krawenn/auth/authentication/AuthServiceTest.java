package com.krawenn.auth.authentication;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.krawenn.auth.TestAuthProperties;
import com.krawenn.auth.api.dto.LoginRequest;
import com.krawenn.auth.api.dto.RegisterRequest;
import com.krawenn.auth.api.dto.TokenResponse;
import com.krawenn.auth.error.InvalidCredentialsException;
import com.krawenn.auth.error.UserAlreadyExistsException;
import com.krawenn.auth.token.AccessToken;
import com.krawenn.auth.token.AccessTokenService;
import com.krawenn.auth.token.RefreshTokenService;
import com.krawenn.auth.user.Role;
import com.krawenn.auth.user.User;
import com.krawenn.auth.user.UserRepository;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Locale;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.security.crypto.password.PasswordEncoder;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class AuthServiceTest {

    private static final Instant NOW = Instant.parse("2026-01-01T12:00:00Z");
    private static final String RAW_PASSWORD = "correct-horse-battery";
    private static final String STORED_HASH = "$2a$12$stored";

    @Mock
    private UserRepository userRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private AccessTokenService accessTokenService;

    @Mock
    private RefreshTokenService refreshTokenService;

    private AuthService authService;

    @BeforeEach
    void setUp() {
        authService = new AuthService(
                userRepository,
                passwordEncoder,
                accessTokenService,
                refreshTokenService,
                TestAuthProperties.create(),
                Clock.fixed(NOW, ZoneOffset.UTC));

        when(userRepository.save(any(User.class))).thenAnswer(invocation -> invocation.getArgument(0));
        when(accessTokenService.issue(any(User.class))).thenReturn(new AccessToken("access-token", 900));
        when(refreshTokenService.issue(any(User.class))).thenReturn("refresh-token");
    }

    private User existingUser() {
        return new User("testuser", "test@example.test", STORED_HASH, Role.USER);
    }

    private RegisterRequest registerRequest(String email) {
        return new RegisterRequest("testuser", email, RAW_PASSWORD);
    }

    @Test
    @DisplayName("Registration stores an encoded password and the USER role")
    void registrationCreatesUser() {
        when(passwordEncoder.encode(RAW_PASSWORD)).thenReturn(STORED_HASH);

        User created = authService.register(registerRequest("test@example.test"));

        ArgumentCaptor<User> saved = ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(saved.capture());
        assertThat(saved.getValue().getPasswordHash()).isEqualTo(STORED_HASH);
        assertThat(saved.getValue().getPasswordHash()).isNotEqualTo(RAW_PASSWORD);
        assertThat(created.getRole()).isEqualTo(Role.USER);
    }

    @Test
    @DisplayName("A reserved username reads as taken, whatever its case")
    void reservedUsernameReadsAsTaken() {
        assertThatExceptionOfType(UserAlreadyExistsException.class)
                .isThrownBy(() -> authService.register(new RegisterRequest("Admin", "a@example.test", RAW_PASSWORD)));
        verify(userRepository, never()).save(any());
    }

    @Test
    @DisplayName("A name the configuration reserves reads as taken too")
    void configuredReservedUsernameReadsAsTaken() {
        assertThatExceptionOfType(UserAlreadyExistsException.class)
                .isThrownBy(() -> authService.register(new RegisterRequest("ACME", "b@example.test", RAW_PASSWORD)));
    }

    @Test
    @DisplayName("An email on the bootstrap list registers as ADMIN")
    void bootstrapEmailBecomesAdmin() {
        User created = authService.register(registerRequest(TestAuthProperties.BOOTSTRAP_ADMIN_EMAIL));

        assertThat(created.getRole()).isEqualTo(Role.ADMIN);
    }

    @Test
    @DisplayName("The bootstrap list is matched case-insensitively")
    void bootstrapEmailIgnoresCase() {
        User created = authService.register(
                registerRequest(TestAuthProperties.BOOTSTRAP_ADMIN_EMAIL.toUpperCase(Locale.ROOT)));

        assertThat(created.getRole()).isEqualTo(Role.ADMIN);
    }

    @Test
    @DisplayName("A taken username is refused")
    void duplicateUsernameIsRefused() {
        when(userRepository.existsByUsernameIgnoreCase("testuser")).thenReturn(true);

        assertThatExceptionOfType(UserAlreadyExistsException.class)
                .isThrownBy(() -> authService.register(registerRequest("test@example.test")));
        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    @DisplayName("A taken email is refused")
    void duplicateEmailIsRefused() {
        when(userRepository.existsByEmailIgnoreCase("test@example.test")).thenReturn(true);

        assertThatExceptionOfType(UserAlreadyExistsException.class)
                .isThrownBy(() -> authService.register(registerRequest("test@example.test")));
        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    @DisplayName("Login returns a token pair and clears the failure counter")
    void loginSucceeds() {
        User user = existingUser();
        user.registerFailedLogin(NOW, TestAuthProperties.MAX_FAILED_ATTEMPTS, TestAuthProperties.LOCK_DURATION);
        when(userRepository.findByUsernameIgnoreCase("testuser")).thenReturn(Optional.of(user));
        when(passwordEncoder.matches(RAW_PASSWORD, STORED_HASH)).thenReturn(true);

        TokenResponse response = authService.login(new LoginRequest("testuser", RAW_PASSWORD));

        assertThat(response.accessToken()).isEqualTo("access-token");
        assertThat(response.refreshToken()).isEqualTo("refresh-token");
        assertThat(response.tokenType()).isEqualTo("Bearer");
        assertThat(response.expiresIn()).isEqualTo(900);
        assertThat(user.getFailedLoginAttempts()).isZero();
    }

    @Test
    @DisplayName("An unknown username still costs a password hash, so timing does not reveal it")
    void unknownUsernameIsTimingEqualized() {
        when(userRepository.findByUsernameIgnoreCase("nobody")).thenReturn(Optional.empty());

        assertThatExceptionOfType(InvalidCredentialsException.class)
                .isThrownBy(() -> authService.login(new LoginRequest("nobody", RAW_PASSWORD)));

        verify(passwordEncoder).encode(anyString());
        verify(refreshTokenService, never()).issue(any(User.class));
    }

    @Test
    @DisplayName("A wrong password counts towards the lockout")
    void wrongPasswordIncrementsCounter() {
        User user = existingUser();
        when(userRepository.findByUsernameIgnoreCase("testuser")).thenReturn(Optional.of(user));
        when(passwordEncoder.matches(anyString(), anyString())).thenReturn(false);

        assertThatExceptionOfType(InvalidCredentialsException.class)
                .isThrownBy(() -> authService.login(new LoginRequest("testuser", "wrong")));

        assertThat(user.getFailedLoginAttempts()).isEqualTo(1);
        verify(accessTokenService, never()).issue(any(User.class));
    }

    @Test
    @DisplayName("Enough wrong passwords lock the account")
    void repeatedFailuresLockTheAccount() {
        User user = existingUser();
        when(userRepository.findByUsernameIgnoreCase("testuser")).thenReturn(Optional.of(user));
        when(passwordEncoder.matches(anyString(), anyString())).thenReturn(false);

        for (int attempt = 0; attempt < TestAuthProperties.MAX_FAILED_ATTEMPTS; attempt++) {
            assertThatExceptionOfType(InvalidCredentialsException.class)
                    .isThrownBy(() -> authService.login(new LoginRequest("testuser", "wrong")));
        }

        assertThat(user.isLocked(NOW)).isTrue();
    }

    @Test
    @DisplayName("A locked account is refused without checking the password")
    void lockedAccountIsRefusedEarly() {
        User user = existingUser();
        for (int attempt = 0; attempt < TestAuthProperties.MAX_FAILED_ATTEMPTS; attempt++) {
            user.registerFailedLogin(NOW, TestAuthProperties.MAX_FAILED_ATTEMPTS, TestAuthProperties.LOCK_DURATION);
        }
        when(userRepository.findByUsernameIgnoreCase("testuser")).thenReturn(Optional.of(user));

        assertThatExceptionOfType(InvalidCredentialsException.class)
                .isThrownBy(() -> authService.login(new LoginRequest("testuser", RAW_PASSWORD)));

        verify(passwordEncoder, never()).matches(anyString(), anyString());
    }

    @Test
    @DisplayName("A disabled account cannot log in even with the right password")
    void disabledAccountIsRefused() {
        User user = existingUser();
        user.disable();
        when(userRepository.findByUsernameIgnoreCase("testuser")).thenReturn(Optional.of(user));
        when(passwordEncoder.matches(anyString(), anyString())).thenReturn(true);

        assertThatExceptionOfType(InvalidCredentialsException.class)
                .isThrownBy(() -> authService.login(new LoginRequest("testuser", RAW_PASSWORD)));

        verify(accessTokenService, never()).issue(any(User.class));
    }

    @Test
    @DisplayName("Refresh rotates the token and issues a new access token")
    void refreshRotates() {
        User user = existingUser();
        when(refreshTokenService.rotate("old-refresh"))
                .thenReturn(new RefreshTokenService.Rotation(user, "new-refresh"));

        TokenResponse response = authService.refresh("old-refresh");

        assertThat(response.refreshToken()).isEqualTo("new-refresh");
        assertThat(response.accessToken()).isEqualTo("access-token");
        verify(accessTokenService).issue(user);
    }

    @Test
    @DisplayName("Logout revokes the presented refresh token")
    void logoutRevokes() {
        authService.logout("some-refresh");

        verify(refreshTokenService).revoke("some-refresh");
    }
}
