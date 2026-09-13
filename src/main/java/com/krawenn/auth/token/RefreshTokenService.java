package com.krawenn.auth.token;

import com.krawenn.auth.config.AuthProperties;
import com.krawenn.auth.error.InvalidRefreshTokenException;
import com.krawenn.auth.user.User;
import java.time.Clock;
import java.time.Instant;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Issues, rotates and revokes refresh tokens.
 *
 * <p>Three properties matter here and each is load-bearing:
 *
 * <ul>
 *   <li><b>Opaque and hashed.</b> The token is random bytes, and only its SHA-256 digest
 *       is stored ({@link OpaqueTokens}). A database dump therefore does not hand out sessions.
 *   <li><b>Rotated on every use.</b> A refresh consumes the presented token and returns a
 *       new one, so a stolen token is useful only until the legitimate client refreshes.
 *   <li><b>Reuse is treated as theft.</b> Presenting an already-rotated token revokes
 *       every session of that account, because either the attacker or the victim is
 *       replaying and there is no way to tell which.
 * </ul>
 *
 * <p>Login does not revoke existing tokens: several devices may hold valid sessions at
 * the same time.
 */
@Service
public class RefreshTokenService {

    private static final Logger log = LoggerFactory.getLogger(RefreshTokenService.class);

    private final RefreshTokenRepository refreshTokenRepository;
    private final AuthProperties properties;
    private final Clock clock;

    public RefreshTokenService(RefreshTokenRepository refreshTokenRepository, AuthProperties properties, Clock clock) {
        this.refreshTokenRepository = refreshTokenRepository;
        this.properties = properties;
        this.clock = clock;
    }

    /** @return the raw token; it is never readable again after this call */
    @Transactional
    public String issue(User user) {
        String rawToken = OpaqueTokens.generate();
        Instant expiresAt = Instant.now(clock).plus(properties.refreshToken().ttl());
        refreshTokenRepository.save(new RefreshToken(user, OpaqueTokens.hash(rawToken), expiresAt));
        return rawToken;
    }

    /**
     * Consumes the presented token and issues a replacement for the same account.
     *
     * <p>{@code noRollbackFor} is essential rather than cosmetic: the reuse path revokes
     * every session and <em>then</em> fails the request. With the default rollback rules
     * the revocation would be undone by the very exception that reports it, leaving the
     * stolen sessions alive.
     */
    @Transactional(noRollbackFor = InvalidRefreshTokenException.class)
    public Rotation rotate(String rawToken) {
        RefreshToken stored = refreshTokenRepository
                .findByTokenHash(OpaqueTokens.hash(rawToken))
                .orElseThrow(InvalidRefreshTokenException::new);
        Instant now = Instant.now(clock);

        if (stored.isRevoked()) {
            int revoked =
                    refreshTokenRepository.revokeAllActiveOf(stored.getUser().getId(), now);
            log.warn(
                    "Refresh token reuse detected for user {}; revoked {} active session(s)",
                    stored.getUser().getId(),
                    revoked);
            throw new InvalidRefreshTokenException();
        }
        if (stored.isExpired(now)) {
            throw new InvalidRefreshTokenException();
        }

        stored.revoke(now);
        User user = stored.getUser();
        return new Rotation(user, issue(user));
    }

    /**
     * Logout. An unknown token is silently accepted: reporting that it was unknown would
     * turn this endpoint into an oracle for guessing valid tokens.
     */
    @Transactional
    public void revoke(String rawToken) {
        refreshTokenRepository
                .findByTokenHash(OpaqueTokens.hash(rawToken))
                .ifPresent(token -> token.revoke(Instant.now(clock)));
    }

    /** Deletes tokens that expired and can therefore no longer evidence reuse. */
    @Transactional
    public int deleteExpired() {
        return refreshTokenRepository.deleteExpiredBefore(Instant.now(clock));
    }

    /** The account the rotated token belongs to, and its replacement token. */
    public record Rotation(User user, String refreshToken) {}
}
