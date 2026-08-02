package com.krawenn.auth.user;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.time.Instant;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class UserTest {

    private static final Instant NOW = Instant.parse("2026-01-01T12:00:00Z");
    private static final Duration LOCK = Duration.ofMinutes(15);
    private static final int MAX_ATTEMPTS = 3;

    private User newUser() {
        return new User("testuser", "test@example.test", "hash", Role.USER);
    }

    @Test
    @DisplayName("A new account is enabled and unlocked")
    void newAccountIsUsable() {
        User user = newUser();

        assertThat(user.isEnabled()).isTrue();
        assertThat(user.isLocked(NOW)).isFalse();
        assertThat(user.getFailedLoginAttempts()).isZero();
    }

    @Test
    @DisplayName("Failures below the threshold count but do not lock")
    void failuresBelowThresholdDoNotLock() {
        User user = newUser();

        user.registerFailedLogin(NOW, MAX_ATTEMPTS, LOCK);
        user.registerFailedLogin(NOW, MAX_ATTEMPTS, LOCK);

        assertThat(user.getFailedLoginAttempts()).isEqualTo(2);
        assertThat(user.isLocked(NOW)).isFalse();
    }

    @Test
    @DisplayName("Reaching the threshold locks the account for the configured duration")
    void thresholdLocksAccount() {
        User user = newUser();

        for (int attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
            user.registerFailedLogin(NOW, MAX_ATTEMPTS, LOCK);
        }

        assertThat(user.isLocked(NOW)).isTrue();
        assertThat(user.isLocked(NOW.plus(LOCK))).isFalse();
        // Counter resets with the lock, so one mistake after it expires does not re-lock.
        assertThat(user.getFailedLoginAttempts()).isZero();
    }

    @Test
    @DisplayName("A successful login clears both the counter and the lock")
    void successClearsLockState() {
        User user = newUser();
        for (int attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
            user.registerFailedLogin(NOW, MAX_ATTEMPTS, LOCK);
        }

        user.registerSuccessfulLogin();

        assertThat(user.isLocked(NOW)).isFalse();
        assertThat(user.getFailedLoginAttempts()).isZero();
    }

    @Test
    @DisplayName("Role and password change through named methods")
    void statefulChangesAreExplicit() {
        User user = newUser();

        user.assignRole(Role.ADMIN);
        user.changePassword("new-hash");
        user.disable();

        assertThat(user.getRole()).isEqualTo(Role.ADMIN);
        assertThat(user.getPasswordHash()).isEqualTo("new-hash");
        assertThat(user.isEnabled()).isFalse();
    }
}
