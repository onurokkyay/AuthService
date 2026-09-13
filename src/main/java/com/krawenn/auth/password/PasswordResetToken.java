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
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * One request to set a new password, reachable two ways: the link in the email, or the code beside it.
 *
 * <p>Only digests are stored and there is no getter for either, for the reasons {@code RefreshToken} gives: nothing
 * outside this package needs them, and not exposing them keeps them out of logs and serialized responses.
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

    /** Replaced once, when the code is exchanged: the link and the code then lead to the same new token. */
    @Getter(AccessLevel.NONE)
    @Column(name = "token_hash", nullable = false)
    private String tokenHash;

    /** BCrypt of the code; null once it has been exchanged. */
    @Getter(AccessLevel.NONE)
    @Column(name = "code_hash")
    private String codeHash;

    @Column(name = "failed_code_attempts", nullable = false)
    private int failedCodeAttempts;

    @Column(name = "expires_at", nullable = false, updatable = false)
    private Instant expiresAt;

    @Column(name = "used_at")
    private Instant usedAt;

    public PasswordResetToken(User user, String tokenHash, String codeHash, Instant expiresAt) {
        this.user = user;
        this.tokenHash = tokenHash;
        this.codeHash = codeHash;
        this.expiresAt = expiresAt;
    }

    /** Neither spent nor expired. */
    public boolean isUsable(Instant now) {
        return usedAt == null && expiresAt.isAfter(now);
    }

    /** False for a code already exchanged, which is what makes a code single-use. */
    boolean codeMatches(String code, PasswordEncoder encoder) {
        return codeHash != null && encoder.matches(code, codeHash);
    }

    /**
     * Counts a wrong code, and retires the whole request — link included — once there have been too many.
     *
     * <p>The link goes too because the two are one request: a code under attack is a request somebody else is trying to
     * complete, and the owner can simply ask again.
     *
     * @return whether this attempt retired the request
     */
    boolean registerFailedCodeAttempt(Instant now, int maxAttempts) {
        failedCodeAttempts++;
        if (failedCodeAttempts >= maxAttempts && usedAt == null) {
            usedAt = now;
            return true;
        }
        return false;
    }

    /** Spends the code for a fresh token; the link from the email stops working, since the code has done its job. */
    void exchangeCodeFor(String newTokenHash) {
        this.tokenHash = newTokenHash;
        this.codeHash = null;
    }
}
