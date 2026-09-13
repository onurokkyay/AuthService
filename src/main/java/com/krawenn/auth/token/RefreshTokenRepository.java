package com.krawenn.auth.token;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, UUID> {

    /** Fetches the owner eagerly: every caller needs it, and lazy loading here is an N+1. */
    @Query("select t from RefreshToken t join fetch t.user where t.tokenHash = :tokenHash")
    Optional<RefreshToken> findByTokenHash(@Param("tokenHash") String tokenHash);

    /** Reuse detection: one replayed token invalidates every session of that account. */
    @Modifying
    @Query("update RefreshToken t set t.revokedAt = :now where t.user.id = :userId and t.revokedAt is null")
    int revokeAllActiveOf(@Param("userId") UUID userId, @Param("now") Instant now);

    /**
     * Ends every session of an account without leaving evidence of them behind, for a password change or reset.
     *
     * <p>Deleted rather than revoked, and the difference is what the other devices do next. A revoked token presented
     * later reads as a replayed one, and reuse detection would then revoke the session the password change had just
     * issued: change the password on one device, and the next background refresh on another signs you out of the first.
     * Deleted, the stale token is simply unknown and gets a plain {@code 401}. Nothing is lost -- every session of the
     * account has ended, so there is none left for these rows to protect.
     */
    @Modifying
    @Query("delete from RefreshToken t where t.user.id = :userId")
    int deleteAllOf(@Param("userId") UUID userId);

    /** Expired rows can no longer prove reuse, so they are safe to delete. */
    @Modifying
    @Query("delete from RefreshToken t where t.expiresAt < :cutoff")
    int deleteExpiredBefore(@Param("cutoff") Instant cutoff);
}
