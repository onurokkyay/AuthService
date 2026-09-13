package com.krawenn.auth.password;

import com.krawenn.auth.api.dto.TokenResponse;
import com.krawenn.auth.config.AuthProperties;
import com.krawenn.auth.error.InvalidCurrentPasswordException;
import com.krawenn.auth.error.InvalidResetCodeException;
import com.krawenn.auth.error.InvalidResetTokenException;
import com.krawenn.auth.error.UserNotFoundException;
import com.krawenn.auth.token.AccessToken;
import com.krawenn.auth.token.AccessTokenService;
import com.krawenn.auth.token.OpaqueTokens;
import com.krawenn.auth.token.RefreshTokenRepository;
import com.krawenn.auth.token.RefreshTokenService;
import com.krawenn.auth.user.User;
import com.krawenn.auth.user.UserRepository;
import java.time.Clock;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.core.task.TaskExecutor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/** Everything that changes a password: forgetting it, resetting it from a link, and changing it while signed in. */
@Service
public class PasswordService {

    private static final Logger log = LoggerFactory.getLogger(PasswordService.class);

    /** Hashed when there is no request to check a code against, so that a miss costs what a check does. */
    private static final String TIMING_EQUALIZER_CODE = "000000";

    private final PasswordResetTokens resetTokens;
    private final PasswordResetTokenRepository resetTokenRepository;
    private final PasswordResetMailer mailer;
    private final TaskExecutor mailExecutor;
    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final AccessTokenService accessTokenService;
    private final RefreshTokenService refreshTokenService;
    private final AuthProperties properties;
    private final Clock clock;

    public PasswordService(
            PasswordResetTokens resetTokens,
            PasswordResetTokenRepository resetTokenRepository,
            PasswordResetMailer mailer,
            @Qualifier("applicationTaskExecutor") TaskExecutor mailExecutor,
            UserRepository userRepository,
            RefreshTokenRepository refreshTokenRepository,
            PasswordEncoder passwordEncoder,
            AccessTokenService accessTokenService,
            RefreshTokenService refreshTokenService,
            AuthProperties properties,
            Clock clock) {
        this.resetTokens = resetTokens;
        this.resetTokenRepository = resetTokenRepository;
        this.mailer = mailer;
        this.mailExecutor = mailExecutor;
        this.userRepository = userRepository;
        this.refreshTokenRepository = refreshTokenRepository;
        this.passwordEncoder = passwordEncoder;
        this.accessTokenService = accessTokenService;
        this.refreshTokenService = refreshTokenService;
        this.properties = properties;
        this.clock = clock;
    }

    /**
     * Starts a reset. Always returns normally, whether or not an email goes out.
     *
     * <p><b>Deliberately not {@code @Transactional}.</b> {@link PasswordResetTokens#issue} commits the token before
     * returning, which is what makes it safe to email: an outer transaction here would hold that commit back until
     * after the message had been handed off.
     *
     * <p><b>Delivery runs on another thread</b>, and the reason is timing rather than throughput. Sending mail takes
     * hundreds of milliseconds, and a request that is that much slower exactly when the address has an account would
     * answer, through the clock, the question the uniform response exists to leave unanswered.
     */
    public void requestReset(String email) {
        resetTokens.issue(email).ifPresent(reset -> mailExecutor.execute(() -> mailer.send(reset)));
    }

    /**
     * Exchanges the code from a reset email for a reset token, for a client that cannot open the link.
     *
     * <p>The token answered here is spent through {@link #resetPassword} like the one in the link, which keeps a single
     * way of actually setting the password. Exchanging also spends the code and retires the link: one request, one
     * reset.
     *
     * <p><b>Six digits can be guessed; this is where guessing is made slow.</b> Every wrong code counts against the
     * request, and at {@code max-code-attempts} the request is retired, link included. With the cooldown between
     * requests, that caps an attacker at a handful of guesses a minute out of a million, each one mailing the owner.
     *
     * <p>A wrong code, an expired or retired request, and an address with no account all get the same answer, and the
     * miss does the BCrypt work a real check would, so neither the body nor the clock tells them apart.
     *
     * @throws InvalidResetCodeException for every way the code fails to unlock a reset
     */
    @Transactional(noRollbackFor = InvalidResetCodeException.class)
    public String exchangeCode(String email, String code) {
        Instant now = Instant.now(clock);
        Optional<PasswordResetToken> usable = userRepository
                .findByEmailIgnoreCase(email)
                .filter(User::isEnabled)
                .flatMap(user -> resetTokenRepository.findUsableOf(user.getId(), now));
        if (usable.isEmpty()) {
            passwordEncoder.encode(TIMING_EQUALIZER_CODE);
            log.info("Password reset code presented for an address with no open request");
            throw new InvalidResetCodeException();
        }

        PasswordResetToken token = usable.get();
        UUID userId = token.getUser().getId();
        if (!token.codeMatches(code, passwordEncoder)) {
            boolean retired = token.registerFailedCodeAttempt(
                    now, properties.passwordReset().maxCodeAttempts());
            log.warn(
                    "Wrong password reset code for user {} (attempt {}){}",
                    userId,
                    token.getFailedCodeAttempts(),
                    retired ? "; request retired" : "");
            throw new InvalidResetCodeException();
        }

        String rawToken = OpaqueTokens.generate();
        token.exchangeCodeFor(OpaqueTokens.hash(rawToken));
        log.info("Exchanged a password reset code for user {}", userId);
        return rawToken;
    }

    /**
     * Sets a new password from a reset link and signs the account out everywhere.
     *
     * <p>Every session goes, because the usual reason for resetting a password is that somebody else may know it; a
     * reset that left their session running would not have locked them out of anything.
     *
     * <p>It also lifts a lockout. An account locked by failed guesses is exactly the one whose owner reaches for this,
     * and a reset that left the lock in place would look, for fifteen minutes, as though it had not worked.
     *
     * @throws InvalidResetTokenException when the token is unknown, expired or already used — one answer for all three,
     *     so that a replayed link reveals nothing a mistyped one would not
     */
    @Transactional
    public void resetPassword(String rawToken, String newPassword) {
        Instant now = Instant.now(clock);
        PasswordResetToken token = resetTokenRepository
                .findByTokenHash(OpaqueTokens.hash(rawToken))
                .filter(candidate -> candidate.isUsable(now))
                .orElseThrow(InvalidResetTokenException::new);

        User user = token.getUser();
        user.changePassword(passwordEncoder.encode(newPassword));
        user.unlock();
        // Spends this token and retires any other link still sitting in the inbox.
        resetTokenRepository.invalidateAllOf(user.getId(), now);
        int ended = refreshTokenRepository.deleteAllOf(user.getId());

        log.info("Password reset for user {}; ended {} session token(s)", user.getId(), ended);
    }

    /**
     * Changes the password of a signed-in account, keeping the caller signed in and nobody else.
     *
     * <p>Every other session ends for the reason a reset ends them. The caller gets a fresh token pair in the
     * answer, so that changing a password does not also sign out the person who just changed it.
     *
     * <p><b>A wrong current password counts towards the lockout like a failed login.</b> An access token is all it takes
     * to reach this endpoint, and without the count a stolen one would be an unlimited oracle for guessing the password
     * behind it. {@code noRollbackFor} keeps the count, for the reason {@code AuthService#login} gives.
     *
     * @throws InvalidCurrentPasswordException when the current password is wrong or the account is locked
     */
    @Transactional(noRollbackFor = InvalidCurrentPasswordException.class)
    public TokenResponse changePassword(UUID userId, String currentPassword, String newPassword) {
        Instant now = Instant.now(clock);
        User user = userRepository.findById(userId).orElseThrow(() -> new UserNotFoundException(userId));

        if (user.isLocked(now)) {
            log.warn("Password change rejected for user {}: account is locked", userId);
            throw new InvalidCurrentPasswordException();
        }
        if (!passwordEncoder.matches(currentPassword, user.getPasswordHash())) {
            user.registerFailedLogin(
                    now,
                    properties.login().maxFailedAttempts(),
                    properties.login().lockDuration());
            log.warn("Password change rejected for user {}: wrong current password", userId);
            throw new InvalidCurrentPasswordException();
        }

        user.changePassword(passwordEncoder.encode(newPassword));
        user.unlock();
        resetTokenRepository.invalidateAllOf(userId, now);
        // Deleted, not revoked: see RefreshTokenRepository#deleteAllOf for why this keeps the caller signed in.
        int ended = refreshTokenRepository.deleteAllOf(userId);
        log.info("Password changed for user {}; ended {} other session token(s)", userId, ended);

        AccessToken accessToken = accessTokenService.issue(user);
        String refreshToken = refreshTokenService.issue(user);
        return TokenResponse.bearer(accessToken.value(), refreshToken, accessToken.expiresInSeconds());
    }
}
