package com.krawenn.auth.authentication;

import com.krawenn.auth.api.dto.LoginRequest;
import com.krawenn.auth.api.dto.RegisterRequest;
import com.krawenn.auth.api.dto.TokenResponse;
import com.krawenn.auth.config.AuthProperties;
import com.krawenn.auth.error.InvalidCredentialsException;
import com.krawenn.auth.error.UserAlreadyExistsException;
import com.krawenn.auth.token.AccessToken;
import com.krawenn.auth.token.AccessTokenService;
import com.krawenn.auth.token.RefreshTokenService;
import com.krawenn.auth.user.ReservedUsernames;
import com.krawenn.auth.user.Role;
import com.krawenn.auth.user.User;
import com.krawenn.auth.user.UserRepository;
import java.time.Clock;
import java.time.Instant;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/** Registration and the session lifecycle: login, refresh and logout. */
@Service
public class AuthService {

    private static final Logger log = LoggerFactory.getLogger(AuthService.class);

    /**
     * Hashed when the username is unknown so that a failed login costs the same whether
     * or not the account exists. Without this, response timing would undo the uniform
     * error message that keeps accounts unenumerable.
     */
    private static final String TIMING_EQUALIZER_PASSWORD = "not-a-real-password";

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AccessTokenService accessTokenService;
    private final RefreshTokenService refreshTokenService;
    private final AuthProperties properties;
    private final Clock clock;

    public AuthService(
            UserRepository userRepository,
            PasswordEncoder passwordEncoder,
            AccessTokenService accessTokenService,
            RefreshTokenService refreshTokenService,
            AuthProperties properties,
            Clock clock) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.accessTokenService = accessTokenService;
        this.refreshTokenService = refreshTokenService;
        this.properties = properties;
        this.clock = clock;
    }

    @Transactional
    public User register(RegisterRequest request) {
        if (ReservedUsernames.isReserved(request.username())
                || userRepository.existsByUsernameIgnoreCase(request.username())
                || userRepository.existsByEmailIgnoreCase(request.email())) {
            // Same response for all three, so registration cannot be used to test which
            // usernames or emails are taken. A reserved name simply reads as taken.
            throw new UserAlreadyExistsException();
        }

        Role role = resolveInitialRole(request.email());
        User user = userRepository.save(
                new User(request.username(), request.email(), passwordEncoder.encode(request.password()), role));

        log.info("Registered user {} with role {}", user.getId(), role);
        return user;
    }

    /**
     * {@code noRollbackFor} is required: a wrong password increments the failure counter
     * and then fails the request. Under the default rules the exception would roll back
     * the increment, and the account could never actually lock.
     */
    @Transactional(noRollbackFor = InvalidCredentialsException.class)
    public TokenResponse login(LoginRequest request) {
        Instant now = Instant.now(clock);
        Optional<User> found = userRepository.findByUsernameIgnoreCase(request.username());

        if (found.isEmpty()) {
            passwordEncoder.encode(TIMING_EQUALIZER_PASSWORD);
            log.warn("Login failed for unknown username");
            throw new InvalidCredentialsException();
        }

        User user = found.get();
        if (user.isLocked(now)) {
            log.warn("Login rejected for user {}: account is locked", user.getId());
            throw new InvalidCredentialsException();
        }
        if (!user.isEnabled()) {
            log.warn("Login rejected for user {}: account is disabled", user.getId());
            throw new InvalidCredentialsException();
        }
        if (!passwordEncoder.matches(request.password(), user.getPasswordHash())) {
            user.registerFailedLogin(
                    now,
                    properties.login().maxFailedAttempts(),
                    properties.login().lockDuration());
            if (user.isLocked(now)) {
                log.warn(
                        "Locked user {} after {} failed attempts",
                        user.getId(),
                        properties.login().maxFailedAttempts());
            } else {
                log.warn("Login failed for user {}: wrong password", user.getId());
            }
            throw new InvalidCredentialsException();
        }

        user.registerSuccessfulLogin();
        log.info("Login succeeded for user {}", user.getId());
        return issueTokens(user);
    }

    /**
     * Deliberately <em>not</em> {@code @Transactional}.
     *
     * <p>{@link RefreshTokenService#rotate} owns the transaction because its reuse path
     * must commit the revocation of every session while still failing the request. An
     * outer transaction here would join it and apply its own rollback rules, silently
     * undoing that revocation — the exact failure the integration test reproduces.
     * Signing the access token needs no database access, so there is nothing to wrap.
     */
    public TokenResponse refresh(String refreshToken) {
        RefreshTokenService.Rotation rotation = refreshTokenService.rotate(refreshToken);
        AccessToken accessToken = accessTokenService.issue(rotation.user());
        return TokenResponse.bearer(accessToken.value(), rotation.refreshToken(), accessToken.expiresInSeconds());
    }

    /** Transaction boundary lives in {@link RefreshTokenService#revoke}. */
    public void logout(String refreshToken) {
        refreshTokenService.revoke(refreshToken);
    }

    /**
     * The bootstrap list is the only way a first administrator can exist; every later
     * change goes through the admin endpoint.
     */
    private Role resolveInitialRole(String email) {
        boolean bootstrapAdmin = properties.registration().bootstrapAdminEmails().stream()
                .anyMatch(candidate -> candidate.equalsIgnoreCase(email));
        return bootstrapAdmin ? Role.ADMIN : Role.USER;
    }

    private TokenResponse issueTokens(User user) {
        AccessToken accessToken = accessTokenService.issue(user);
        String refreshToken = refreshTokenService.issue(user);
        return TokenResponse.bearer(accessToken.value(), refreshToken, accessToken.expiresInSeconds());
    }
}
