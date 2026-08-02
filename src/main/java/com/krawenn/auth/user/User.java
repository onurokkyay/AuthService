package com.krawenn.auth.user;

import com.krawenn.auth.persistence.AbstractEntity;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Table;
import java.time.Duration;
import java.time.Instant;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

/**
 * An account. Table {@code app_user}, because {@code user} is reserved in PostgreSQL.
 *
 * <p>There are no setters: every transition is a named method, so the reason for a
 * change is visible at the call site and invalid states cannot be assembled field by
 * field. Nothing here is domain-specific — a consuming service stores its own profile
 * data against {@link #getId()}.
 */
@Entity
@Table(name = "app_user")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class User extends AbstractEntity {

    @Column(nullable = false)
    private String username;

    @Column(nullable = false)
    private String email;

    @Column(name = "password_hash", nullable = false)
    private String passwordHash;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private Role role;

    @Column(nullable = false)
    private boolean enabled;

    @Column(name = "failed_login_attempts", nullable = false)
    private int failedLoginAttempts;

    @Column(name = "locked_until")
    private Instant lockedUntil;

    public User(String username, String email, String passwordHash, Role role) {
        this.username = username;
        this.email = email;
        this.passwordHash = passwordHash;
        this.role = role;
        this.enabled = true;
        this.failedLoginAttempts = 0;
    }

    public void changePassword(String newPasswordHash) {
        this.passwordHash = newPasswordHash;
    }

    public void assignRole(Role newRole) {
        this.role = newRole;
    }

    public void disable() {
        this.enabled = false;
    }

    public void enable() {
        this.enabled = true;
    }

    public boolean isLocked(Instant now) {
        return lockedUntil != null && lockedUntil.isAfter(now);
    }

    /**
     * Counts a failed password attempt and locks the account once the threshold is hit.
     *
     * <p>The counter resets together with the lock: after the lock expires the account
     * gets a fresh set of attempts rather than being re-locked by a single mistake.
     */
    public void registerFailedLogin(Instant now, int maxAttempts, Duration lockDuration) {
        this.failedLoginAttempts++;
        if (this.failedLoginAttempts >= maxAttempts) {
            this.lockedUntil = now.plus(lockDuration);
            this.failedLoginAttempts = 0;
        }
    }

    public void registerSuccessfulLogin() {
        this.failedLoginAttempts = 0;
        this.lockedUntil = null;
    }
}
