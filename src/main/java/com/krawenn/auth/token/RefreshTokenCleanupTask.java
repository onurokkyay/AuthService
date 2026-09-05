package com.krawenn.auth.token;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * Deletes expired refresh tokens.
 *
 * <p>Without this the table grows for the lifetime of the deployment: rotation revokes
 * rows but keeps them, and logout does the same.
 */
@Component
public class RefreshTokenCleanupTask {

    private static final Logger log = LoggerFactory.getLogger(RefreshTokenCleanupTask.class);

    private final RefreshTokenService refreshTokenService;

    public RefreshTokenCleanupTask(RefreshTokenService refreshTokenService) {
        this.refreshTokenService = refreshTokenService;
    }

    @Scheduled(cron = "${auth.refresh-token.cleanup-cron}")
    public void deleteExpiredTokens() {
        int deleted = refreshTokenService.deleteExpired();
        if (deleted > 0) {
            log.info("Deleted {} expired refresh token(s)", deleted);
        }
    }
}
