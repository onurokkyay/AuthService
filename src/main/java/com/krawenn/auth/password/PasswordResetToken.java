package com.krawenn.auth.password;

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
 * A single-use link to set a new password.
 *
 * <p>Only the digest is stored and there is no getter for it, for the reasons {@code RefreshToken} gives: nothing
 * outside this package needs it, and not exposing it keeps it out of logs and serialized responses.
 *
 * <p>A spent token is kept rather than deleted until it expires. Deleting it on use would make a replayed link look
 * like a mistyped one, and the two deserve the same answer only because this service chooses to give it — not because
 * the row happened to be gone.
 */
@Entity
@Table(name = "password_reset_token")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class PasswordResetToken extends AbstractEntity {

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id", nullable = false, updatable = false)
    private User user;

    @Getter(AccessLevel.NONE)
    @Column(name = "token_hash", nullable = false, updatable = false)
    private String tokenHash;

    @Column(name = "expires_at", nullable = false, updatable = false)
    private Instant expiresAt;

    @Column(name = "used_at")
    private Instant usedAt;

    public PasswordResetToken(User user, String tokenHash, Instant expiresAt) {
        this.user = user;
        this.tokenHash = tokenHash;
        this.expiresAt = expiresAt;
    }

    /** Neither spent nor expired. */
    public boolean isUsable(Instant now) {
        return usedAt == null && expiresAt.isAfter(now);
    }
}
