package com.krawenn.auth.password;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.krawenn.auth.TestAuthProperties;
import com.krawenn.auth.api.dto.TokenResponse;
import com.krawenn.auth.error.InvalidCurrentPasswordException;
import com.krawenn.auth.error.InvalidResetCodeException;
import com.krawenn.auth.error.InvalidResetTokenException;
import com.krawenn.auth.token.AccessToken;
import com.krawenn.auth.token.AccessTokenService;
import com.krawenn.auth.token.OpaqueTokens;
import com.krawenn.auth.token.RefreshTokenRepository;
import com.krawenn.auth.token.RefreshTokenService;
import com.krawenn.auth.user.TestUsers;
import com.krawenn.auth.user.User;
import com.krawenn.auth.user.UserRepository;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.core.task.TaskExecutor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class PasswordServiceTest {

    private static final Instant NOW = Instant.parse("2026-01-01T12:00:00Z");
    private static final UUID USER_ID = UUID.fromString("01900000-0000-7000-8000-000000000001");
    private static final String NEW_PASSWORD = "a-brand-new-password";
    private static final String EMAIL = "test@example.test";

    @Mock
    private PasswordResetTokens resetTokens;

    @Mock
    private PasswordResetTokenRepository resetTokenRepository;

    @Mock
    private PasswordResetMailer mailer;

    @Mock
    private UserRepository userRepository;

    @Mock
    private RefreshTokenRepository refreshTokenRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private AccessTokenService accessTokenService;

    @Mock
    private RefreshTokenService refreshTokenService;

    private PasswordService passwordService;
    private User user;

    @BeforeEach
    void setUp() {
        // Runs delivery on the calling thread, so a test can see what was sent without waiting.
        TaskExecutor sameThread = Runnable::run;
        passwordService = new PasswordService(
                resetTokens,
                resetTokenRepository,
                mailer,
                sameThread,
                userRepository,
                refreshTokenRepository,
                passwordEncoder,
                accessTokenService,
                refreshTokenService,
                TestAuthProperties.create(),
                Clock.fixed(NOW, ZoneOffset.UTC));

        user = TestUsers.withId(USER_ID);
        when(passwordEncoder.encode(NEW_PASSWORD)).thenReturn("$2a$12$new-hash");
    }

    private PasswordResetToken tokenExpiringAt(Instant expiresAt) {
        return new PasswordResetToken(user, "digest", "code-hash", expiresAt);
    }

    @Test
    @DisplayName("A right code is exchanged for a fresh reset token, and works only once")
    void rightCodeIsExchangedOnce() {
        PasswordResetToken request = tokenExpiringAt(NOW.plusSeconds(600));
        when(userRepository.findByEmailIgnoreCase(EMAIL)).thenReturn(Optional.of(user));
        when(resetTokenRepository.findUsableOf(USER_ID, NOW)).thenReturn(Optional.of(request));
        when(passwordEncoder.matches("123456", "code-hash")).thenReturn(true);

        String resetToken = passwordService.exchangeCode(EMAIL, "123456");

        assertThat(ReflectionTestUtils.getField(request, "tokenHash")).isEqualTo(OpaqueTokens.hash(resetToken));
        assertThatExceptionOfType(InvalidResetCodeException.class)
                .isThrownBy(() -> passwordService.exchangeCode(EMAIL, "123456"));
    }

    @Test
    @DisplayName("Wrong codes count, and the last one allowed retires the request")
    void wrongCodesRetireTheRequest() {
        PasswordResetToken request = tokenExpiringAt(NOW.plusSeconds(600));
        when(userRepository.findByEmailIgnoreCase(EMAIL)).thenReturn(Optional.of(user));
        when(resetTokenRepository.findUsableOf(USER_ID, NOW)).thenReturn(Optional.of(request));
        when(passwordEncoder.matches(anyString(), anyString())).thenReturn(false);

        for (int attempt = 1; attempt <= TestAuthProperties.RESET_MAX_CODE_ATTEMPTS; attempt++) {
            assertThat(request.isUsable(NOW)).isTrue();
            assertThatExceptionOfType(InvalidResetCodeException.class)
                    .isThrownBy(() -> passwordService.exchangeCode(EMAIL, "000000"));
        }

        assertThat(request.getFailedCodeAttempts()).isEqualTo(TestAuthProperties.RESET_MAX_CODE_ATTEMPTS);
        assertThat(request.isUsable(NOW)).isFalse();
    }

    @Test
    @DisplayName("An address with no open request gets the same refusal after the same BCrypt work")
    void noOpenRequestLooksLikeAWrongCode() {
        when(userRepository.findByEmailIgnoreCase("nobody@example.test")).thenReturn(Optional.empty());

        assertThatExceptionOfType(InvalidResetCodeException.class)
                .isThrownBy(() -> passwordService.exchangeCode("nobody@example.test", "123456"));
        verify(passwordEncoder).encode("000000");
    }

    @Test
    @DisplayName("A reset link is mailed only when a token was actually issued")
    void mailIsSentOnlyForAnIssuedToken() {
        PasswordResetTokens.IssuedReset reset = new PasswordResetTokens.IssuedReset(
                USER_ID, "test@example.test", "testuser", "https://client.test/reset-password?token=abc", "123456");
        when(resetTokens.issue("test@example.test")).thenReturn(Optional.of(reset));

        passwordService.requestReset("test@example.test");

        verify(mailer).send(reset);
    }

    @Test
    @DisplayName("An address with no account is sent nothing, and the caller cannot tell")
    void unknownAddressSendsNothing() {
        when(resetTokens.issue(anyString())).thenReturn(Optional.empty());

        passwordService.requestReset("nobody@example.test");

        verify(mailer, never()).send(any());
    }

    @Test
    @DisplayName("A valid link sets the password and signs the account out everywhere")
    void validLinkResetsAndRevokesSessions() {
        when(resetTokenRepository.findByTokenHash(anyString()))
                .thenReturn(Optional.of(tokenExpiringAt(NOW.plusSeconds(600))));

        passwordService.resetPassword("raw-token", NEW_PASSWORD);

        assertThat(user.getPasswordHash()).isEqualTo("$2a$12$new-hash");
        verify(refreshTokenRepository).deleteAllOf(USER_ID);
        // Spends the presented link and retires any other one still sitting in the inbox.
        verify(resetTokenRepository).invalidateAllOf(USER_ID, NOW);
    }

    @Test
    @DisplayName("A reset lifts a lockout, or it would look as though it had not worked")
    void resetUnlocksTheAccount() {
        for (int attempt = 0; attempt < TestAuthProperties.MAX_FAILED_ATTEMPTS; attempt++) {
            user.registerFailedLogin(NOW, TestAuthProperties.MAX_FAILED_ATTEMPTS, TestAuthProperties.LOCK_DURATION);
        }
        assertThat(user.isLocked(NOW)).isTrue();
        when(resetTokenRepository.findByTokenHash(anyString()))
                .thenReturn(Optional.of(tokenExpiringAt(NOW.plusSeconds(600))));

        passwordService.resetPassword("raw-token", NEW_PASSWORD);

        assertThat(user.isLocked(NOW)).isFalse();
    }

    @Test
    @DisplayName("An expired link is refused and changes nothing")
    void expiredLinkIsRefused() {
        when(resetTokenRepository.findByTokenHash(anyString()))
                .thenReturn(Optional.of(tokenExpiringAt(NOW.minusSeconds(1))));

        assertThatExceptionOfType(InvalidResetTokenException.class)
                .isThrownBy(() -> passwordService.resetPassword("raw-token", NEW_PASSWORD));
        verify(passwordEncoder, never()).encode(anyString());
        verify(refreshTokenRepository, never()).deleteAllOf(any());
    }

    @Test
    @DisplayName("A link that was already used is refused, with the same answer as an unknown one")
    void spentLinkIsRefused() {
        PasswordResetToken spent = tokenExpiringAt(NOW.plusSeconds(600));
        ReflectionTestUtils.setField(spent, "usedAt", NOW.minusSeconds(30));
        when(resetTokenRepository.findByTokenHash(anyString())).thenReturn(Optional.of(spent));

        assertThatExceptionOfType(InvalidResetTokenException.class)
                .isThrownBy(() -> passwordService.resetPassword("raw-token", NEW_PASSWORD));
        verify(passwordEncoder, never()).encode(anyString());
    }

    @Test
    @DisplayName("An unknown link is refused")
    void unknownLinkIsRefused() {
        when(resetTokenRepository.findByTokenHash(anyString())).thenReturn(Optional.empty());

        assertThatExceptionOfType(InvalidResetTokenException.class)
                .isThrownBy(() -> passwordService.resetPassword("never-issued", NEW_PASSWORD));
    }

    @Test
    @DisplayName("Changing a password ends the other sessions before issuing the caller's new pair")
    void changeKeepsTheCallerSignedIn() {
        when(userRepository.findById(USER_ID)).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("current-password", TestUsers.PASSWORD_HASH))
                .thenReturn(true);
        when(accessTokenService.issue(user)).thenReturn(new AccessToken("access-token", 900));
        when(refreshTokenService.issue(user)).thenReturn("refresh-token");

        TokenResponse tokens = passwordService.changePassword(USER_ID, "current-password", NEW_PASSWORD);

        assertThat(tokens.accessToken()).isEqualTo("access-token");
        assertThat(tokens.refreshToken()).isEqualTo("refresh-token");
        assertThat(user.getPasswordHash()).isEqualTo("$2a$12$new-hash");
        // In this order or not at all: deleting after issuing would sign out the very session
        // this call just handed back.
        InOrder order = inOrder(refreshTokenRepository, refreshTokenService);
        order.verify(refreshTokenRepository).deleteAllOf(USER_ID);
        order.verify(refreshTokenService).issue(user);
    }

    @Test
    @DisplayName("A wrong current password counts towards the lockout")
    void wrongCurrentPasswordCountsAsAFailure() {
        when(userRepository.findById(USER_ID)).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("wrong-password", TestUsers.PASSWORD_HASH)).thenReturn(false);

        assertThatExceptionOfType(InvalidCurrentPasswordException.class)
                .isThrownBy(() -> passwordService.changePassword(USER_ID, "wrong-password", NEW_PASSWORD));

        assertThat(user.getFailedLoginAttempts()).isEqualTo(1);
        verify(passwordEncoder, never()).encode(anyString());
        verify(refreshTokenRepository, never()).deleteAllOf(any());
    }

    @Test
    @DisplayName("A locked account cannot change its password, and the lock is not even tested against")
    void lockedAccountCannotChange() {
        for (int attempt = 0; attempt < TestAuthProperties.MAX_FAILED_ATTEMPTS; attempt++) {
            user.registerFailedLogin(NOW, TestAuthProperties.MAX_FAILED_ATTEMPTS, TestAuthProperties.LOCK_DURATION);
        }
        when(userRepository.findById(USER_ID)).thenReturn(Optional.of(user));

        assertThatExceptionOfType(InvalidCurrentPasswordException.class)
                .isThrownBy(() -> passwordService.changePassword(USER_ID, "current-password", NEW_PASSWORD));

        verify(passwordEncoder, never()).matches(anyString(), anyString());
    }
}
