package com.krawenn.auth.password;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.krawenn.auth.TestAuthProperties;
import com.krawenn.auth.token.OpaqueTokens;
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
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class PasswordResetTokensTest {

    private static final Instant NOW = Instant.parse("2026-01-01T12:00:00Z");
    private static final UUID USER_ID = UUID.fromString("01900000-0000-7000-8000-000000000002");
    private static final String EMAIL = "test@example.test";

    @Mock
    private UserRepository userRepository;

    @Mock
    private PasswordResetTokenRepository tokenRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    private PasswordResetTokens resetTokens;
    private User user;

    @BeforeEach
    void setUp() {
        resetTokens = new PasswordResetTokens(
                userRepository,
                tokenRepository,
                passwordEncoder,
                TestAuthProperties.create(),
                Clock.fixed(NOW, ZoneOffset.UTC));
        user = TestUsers.withId(USER_ID);
        when(userRepository.findByEmailIgnoreCase(EMAIL)).thenReturn(Optional.of(user));
        when(tokenRepository.findLatestIssuedAt(USER_ID)).thenReturn(Optional.empty());
        when(passwordEncoder.encode(anyString())).thenAnswer(call -> "bcrypt:" + call.getArgument(0));
    }

    @Test
    @DisplayName("An address with no account issues nothing, but costs the same BCrypt work as one that has")
    void unknownAddressIssuesNothing() {
        when(userRepository.findByEmailIgnoreCase("nobody@example.test")).thenReturn(Optional.empty());

        assertThat(resetTokens.issue("nobody@example.test")).isEmpty();
        verify(tokenRepository, never()).save(any());
        verify(passwordEncoder).encode(anyString());
    }

    @Test
    @DisplayName("The code is six digits and only its BCrypt hash is stored")
    void codeIsSixDigitsAndStoredHashed() {
        PasswordResetTokens.IssuedReset reset = resetTokens.issue(EMAIL).orElseThrow();

        ArgumentCaptor<PasswordResetToken> stored = ArgumentCaptor.forClass(PasswordResetToken.class);
        verify(tokenRepository).save(stored.capture());

        assertThat(reset.code()).matches("\\d{6}");
        assertThat(ReflectionTestUtils.getField(stored.getValue(), "codeHash")).isEqualTo("bcrypt:" + reset.code());
    }

    @Test
    @DisplayName("A disabled account issues nothing")
    void disabledAccountIssuesNothing() {
        user.disable();

        assertThat(resetTokens.issue(EMAIL)).isEmpty();
        verify(tokenRepository, never()).save(any());
    }

    @Test
    @DisplayName("A second request inside the cooldown issues nothing, so the endpoint cannot flood an inbox")
    void requestInsideCooldownIssuesNothing() {
        when(tokenRepository.findLatestIssuedAt(USER_ID)).thenReturn(Optional.of(NOW.minusSeconds(10)));

        assertThat(resetTokens.issue(EMAIL)).isEmpty();
        verify(tokenRepository, never()).save(any());
    }

    @Test
    @DisplayName("After the cooldown a new link retires the previous one before it is stored")
    void newLinkRetiresThePreviousOne() {
        when(tokenRepository.findLatestIssuedAt(USER_ID))
                .thenReturn(Optional.of(
                        NOW.minus(TestAuthProperties.RESET_REQUEST_COOLDOWN).minusSeconds(1)));

        assertThat(resetTokens.issue(EMAIL)).isPresent();

        InOrder order = inOrder(tokenRepository);
        order.verify(tokenRepository).invalidateAllOf(USER_ID, NOW);
        order.verify(tokenRepository).save(any(PasswordResetToken.class));
    }

    @Test
    @DisplayName("The link carries the raw token and only its digest is stored")
    void onlyTheDigestIsStored() {
        PasswordResetTokens.IssuedReset reset = resetTokens.issue(EMAIL).orElseThrow();

        ArgumentCaptor<PasswordResetToken> stored = ArgumentCaptor.forClass(PasswordResetToken.class);
        verify(tokenRepository).save(stored.capture());

        String rawToken = reset.link().substring(reset.link().indexOf("token=") + "token=".length());
        assertThat(reset.link()).startsWith("https://client.test/reset-password?token=");
        assertThat(ReflectionTestUtils.getField(stored.getValue(), "tokenHash"))
                .isEqualTo(OpaqueTokens.hash(rawToken))
                .isNotEqualTo(rawToken);
        assertThat(stored.getValue().getExpiresAt()).isEqualTo(NOW.plus(TestAuthProperties.RESET_TOKEN_TTL));
    }

    @Test
    @DisplayName("Printing what was issued never prints the link or the code")
    void issuedResetDoesNotPrintTheLink() {
        PasswordResetTokens.IssuedReset reset = resetTokens.issue(EMAIL).orElseThrow();

        assertThat(reset.toString())
                .doesNotContain(reset.link())
                .doesNotContain(reset.code())
                .doesNotContain("token=")
                .doesNotContain(EMAIL);
    }
}
