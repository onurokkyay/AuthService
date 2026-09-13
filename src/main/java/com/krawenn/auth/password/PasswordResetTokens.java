package com.krawenn.auth.password;

import com.krawenn.auth.config.AuthProperties;
import com.krawenn.auth.token.OpaqueTokens;
import com.krawenn.auth.user.User;
import com.krawenn.auth.user.UserRepository;
import java.time.Clock;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Issues password reset tokens, and deletes the ones that can no longer be used.
 *
 * <p>A bean of its own for one reason: the email must go out only after the token it carries has been committed.
 * Issuing here, in a transaction that ends when this method returns, means that by the time {@link PasswordService}
 * hands the message to the mailer the row exists. A link that could arrive before its token was committed would be a
 * link that sometimes does not work.
 */
@Service
public class PasswordResetTokens {

    private static final Logger log = LoggerFactory.getLogger(PasswordResetTokens.class);

    private final UserRepository userRepository;
    private final PasswordResetTokenRepository tokenRepository;
    private final AuthProperties properties;
    private final Clock clock;

    public PasswordResetTokens(
            UserRepository userRepository,
            PasswordResetTokenRepository tokenRepository,
            AuthProperties properties,
            Clock clock) {
        this.userRepository = userRepository;
        this.tokenRepository = tokenRepository;
        this.properties = properties;
        this.clock = clock;
    }

    /**
     * Issues a reset token for the account with this email, when there is one that may have it.
     *
     * <p>Says nothing about why nothing was issued. An unknown address, a disabled account and a second request inside
     * the cooldown all end the same way for the caller — anything else would turn the endpoint into a way of finding
     * out which addresses have accounts.
     *
     * <p>The cooldown is what stops the endpoint being used to fill somebody's inbox. Asking again after it retires the
     * previous link, so only the newest email in an inbox ever works.
     *
     * @return what the mailer needs, or empty when no email should be sent
     */
    @Transactional
    public Optional<IssuedReset> issue(String email) {
        Optional<User> found = userRepository.findByEmailIgnoreCase(email);
        if (found.isEmpty()) {
            // Neither the address nor a hint of it: this line is written for every miss.
            log.info("Password reset requested for an address with no account");
            return Optional.empty();
        }

        User user = found.get();
        if (!user.isEnabled()) {
            log.warn("Password reset requested for disabled user {}; nothing sent", user.getId());
            return Optional.empty();
        }

        Instant now = Instant.now(clock);
        Optional<Instant> lastIssued = tokenRepository.findLatestIssuedAt(user.getId());
        if (lastIssued.isPresent()
                && lastIssued
                        .get()
                        .plus(properties.passwordReset().requestCooldown())
                        .isAfter(now)) {
            log.info("Password reset for user {} ignored: requested again inside the cooldown", user.getId());
            return Optional.empty();
        }

        tokenRepository.invalidateAllOf(user.getId(), now);
        String rawToken = OpaqueTokens.generate();
        tokenRepository.save(new PasswordResetToken(
                user,
                OpaqueTokens.hash(rawToken),
                now.plus(properties.passwordReset().tokenTtl())));
        log.info("Issued a password reset token for user {}", user.getId());

        String link = properties.passwordReset().linkTemplate().replace("{token}", rawToken);
        return Optional.of(new IssuedReset(user.getId(), user.getEmail(), user.getUsername(), link));
    }

    /** Deletes tokens that expired and can therefore no longer be used. */
    @Transactional
    public int deleteExpired() {
        return tokenRepository.deleteExpiredBefore(Instant.now(clock));
    }

    /**
     * What delivering one reset takes.
     *
     * @param link carries the raw token, which makes it a credential; {@link #toString()} leaves it out so that logging
     *     this record by accident cannot put a working reset link into a log file
     */
    public record IssuedReset(UUID userId, String email, String username, String link) {

        @Override
        public String toString() {
            return "IssuedReset[userId=" + userId + "]";
        }
    }
}
