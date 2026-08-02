package com.krawenn.auth.token;

import com.krawenn.auth.persistence.AbstractEntity;
import com.krawenn.auth.user.User;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import java.time.Instant;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

/**
 * A refresh token issued to one account.
 *
 * <p>Only the SHA-256 hash of the token is stored, so a database dump does not hand out
 * sessions. There is deliberately no getter for the hash: nothing outside this package
 * needs it, and not exposing it keeps it out of logs and serialized responses.
 *
 * <p>Rotated and logged-out tokens are revoked rather than deleted. Keeping the row
 * until it expires is what makes replay of an old token distinguishable from a random
 * unknown token.
 */
@Entity
@Table(name = "refresh_token")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class RefreshToken extends AbstractEntity {

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id", nullable = false, updatable = false)
    private User user;

    @Getter(AccessLevel.NONE)
    @Column(name = "token_hash", nullable = false, updatable = false)
    private String tokenHash;

    @Column(name = "expires_at", nullable = false, updatable = false)
    private Instant expiresAt;

    @Column(name = "revoked_at")
    private Instant revokedAt;

    public RefreshToken(User user, String tokenHash, Instant expiresAt) {
        this.user = user;
        this.tokenHash = tokenHash;
        this.expiresAt = expiresAt;
    }

    /** Idempotent: the first revocation wins, so the original time is not overwritten. */
    public void revoke(Instant now) {
        if (this.revokedAt == null) {
            this.revokedAt = now;
        }
    }

    public boolean isRevoked() {
        return revokedAt != null;
    }

    public boolean isExpired(Instant now) {
        return !expiresAt.isAfter(now);
    }

    public boolean isActive(Instant now) {
        return !isRevoked() && !isExpired(now);
    }
}
