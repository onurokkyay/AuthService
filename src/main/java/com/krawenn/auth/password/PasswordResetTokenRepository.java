package com.krawenn.auth.password;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface PasswordResetTokenRepository extends JpaRepository<PasswordResetToken, UUID> {

    /** Fetches the owner eagerly: a reset always changes the account the token belongs to. */
    @Query("select t from PasswordResetToken t join fetch t.user where t.tokenHash = :tokenHash")
    Optional<PasswordResetToken> findByTokenHash(@Param("tokenHash") String tokenHash);

    /** When this account was last sent a link, for the cooldown between requests. */
    @Query("select max(t.createdAt) from PasswordResetToken t where t.user.id = :userId")
    Optional<Instant> findLatestIssuedAt(@Param("userId") UUID userId);

    /** Retires every unspent link of one account: a newer request, a completed reset, or a changed password. */
    @Modifying
    @Query("update PasswordResetToken t set t.usedAt = :now where t.user.id = :userId and t.usedAt is null")
    int invalidateAllOf(@Param("userId") UUID userId, @Param("now") Instant now);

    /** An expired token can no longer be used or replayed, so its row has nothing left to prove. */
    @Modifying
    @Query("delete from PasswordResetToken t where t.expiresAt < :cutoff")
    int deleteExpiredBefore(@Param("cutoff") Instant cutoff);
}
