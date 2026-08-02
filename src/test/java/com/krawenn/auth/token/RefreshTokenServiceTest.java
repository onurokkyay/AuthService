package com.krawenn.auth.token;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.krawenn.auth.TestAuthProperties;
import com.krawenn.auth.error.InvalidRefreshTokenException;
import com.krawenn.auth.user.TestUsers;
import com.krawenn.auth.user.User;
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
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class RefreshTokenServiceTest {

    private static final Instant NOW = Instant.parse("2026-01-01T12:00:00Z");

    @Mock
    private RefreshTokenRepository refreshTokenRepository;

    private RefreshTokenService refreshTokenService;
    private User user;

    @BeforeEach
    void setUp() {
        refreshTokenService = new RefreshTokenService(
                refreshTokenRepository, TestAuthProperties.create(), Clock.fixed(NOW, ZoneOffset.UTC));
        user = TestUsers.withId(UUID.randomUUID());
    }

    @Test
    @DisplayName("The issued token is random and only its digest is stored")
    void issueStoresOnlyTheDigest() {
        String issued = refreshTokenService.issue(user);

        ArgumentCaptor<RefreshToken> saved = ArgumentCaptor.forClass(RefreshToken.class);
        verify(refreshTokenRepository).save(saved.capture());
        assertThat(issued).isNotBlank();
        // The stored row must not contain the token itself in any field.
        assertThat(saved.getValue().toString()).doesNotContain(issued);
        assertThat(saved.getValue().getExpiresAt()).isEqualTo(NOW.plus(TestAuthProperties.REFRESH_TOKEN_TTL));
    }

    @Test
    @DisplayName("Two issued tokens are never the same")
    void issuedTokensAreUnique() {
        assertThat(refreshTokenService.issue(user)).isNotEqualTo(refreshTokenService.issue(user));
    }

    @Test
    @DisplayName("An unknown token is rejected")
    void unknownTokenIsRejected() {
        when(refreshTokenRepository.findByTokenHash(any())).thenReturn(Optional.empty());

        assertThatExceptionOfType(InvalidRefreshTokenException.class)
                .isThrownBy(() -> refreshTokenService.rotate("nonsense"));
    }

    @Test
    @DisplayName("Rotation revokes the presented token and issues a replacement")
    void rotationRevokesAndReplaces() {
        RefreshToken stored = new RefreshToken(user, "hash", NOW.plusSeconds(3600));
        when(refreshTokenRepository.findByTokenHash(any())).thenReturn(Optional.of(stored));

        RefreshTokenService.Rotation rotation = refreshTokenService.rotate("presented");

        assertThat(stored.isRevoked()).isTrue();
        assertThat(stored.getRevokedAt()).isEqualTo(NOW);
        assertThat(rotation.user()).isSameAs(user);
        assertThat(rotation.refreshToken()).isNotBlank();
        verify(refreshTokenRepository).save(any(RefreshToken.class));
    }

    @Test
    @DisplayName("An expired token is rejected without issuing anything")
    void expiredTokenIsRejected() {
        RefreshToken stored = new RefreshToken(user, "hash", NOW.minusSeconds(1));
        when(refreshTokenRepository.findByTokenHash(any())).thenReturn(Optional.of(stored));

        assertThatExceptionOfType(InvalidRefreshTokenException.class)
                .isThrownBy(() -> refreshTokenService.rotate("presented"));
        verify(refreshTokenRepository, never()).save(any(RefreshToken.class));
    }

    @Test
    @DisplayName("Replaying a rotated token revokes every session of that account")
    void reuseRevokesAllSessions() {
        RefreshToken stored = new RefreshToken(user, "hash", NOW.plusSeconds(3600));
        stored.revoke(NOW.minusSeconds(60));
        when(refreshTokenRepository.findByTokenHash(any())).thenReturn(Optional.of(stored));

        assertThatExceptionOfType(InvalidRefreshTokenException.class)
                .isThrownBy(() -> refreshTokenService.rotate("presented"));

        verify(refreshTokenRepository).revokeAllActiveOf(eq(user.getId()), eq(NOW));
        verify(refreshTokenRepository, never()).save(any(RefreshToken.class));
    }

    @Test
    @DisplayName("Logout revokes the presented token")
    void revokeMarksTheToken() {
        RefreshToken stored = new RefreshToken(user, "hash", NOW.plusSeconds(3600));
        when(refreshTokenRepository.findByTokenHash(any())).thenReturn(Optional.of(stored));

        refreshTokenService.revoke("presented");

        assertThat(stored.getRevokedAt()).isEqualTo(NOW);
    }

    @Test
    @DisplayName("Logout with an unknown token succeeds silently")
    void revokeIsSilentForUnknownTokens() {
        when(refreshTokenRepository.findByTokenHash(any())).thenReturn(Optional.empty());

        refreshTokenService.revoke("nonsense");
    }

    @Test
    @DisplayName("The same token always maps to the same lookup digest")
    void lookupIsDeterministic() {
        when(refreshTokenRepository.findByTokenHash(any())).thenReturn(Optional.empty());

        assertThatExceptionOfType(InvalidRefreshTokenException.class)
                .isThrownBy(() -> refreshTokenService.rotate("same-token"));
        assertThatExceptionOfType(InvalidRefreshTokenException.class)
                .isThrownBy(() -> refreshTokenService.rotate("same-token"));

        ArgumentCaptor<String> hashes = ArgumentCaptor.forClass(String.class);
        verify(refreshTokenRepository, times(2)).findByTokenHash(hashes.capture());
        assertThat(hashes.getAllValues().get(0)).isEqualTo(hashes.getAllValues().get(1));
        // The lookup key is a digest, never the token itself.
        assertThat(hashes.getAllValues().get(0)).isNotEqualTo("same-token");
    }
}
