package com.krawenn.auth.password;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * Deletes expired password reset tokens.
 *
 * <p>Spent tokens are kept until they expire rather than deleted on use, so without this the table would grow for as
 * long as anyone keeps forgetting a password.
 */
@Component
public class PasswordResetCleanupTask {

    private static final Logger log = LoggerFactory.getLogger(PasswordResetCleanupTask.class);

    private final PasswordResetTokens resetTokens;

    public PasswordResetCleanupTask(PasswordResetTokens resetTokens) {
        this.resetTokens = resetTokens;
    }

    @Scheduled(cron = "${auth.password-reset.cleanup-cron}")
    public void deleteExpiredTokens() {
        int deleted = resetTokens.deleteExpired();
        if (deleted > 0) {
            log.info("Deleted {} expired password reset token(s)", deleted);
        }
    }
}
