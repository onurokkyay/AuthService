package com.krawenn.auth.account;

import com.krawenn.auth.config.AuthProperties;
import com.krawenn.auth.error.AccountDeletionIncompleteException;
import com.krawenn.auth.error.InvalidCurrentPasswordException;
import com.krawenn.auth.error.UserNotFoundException;
import com.krawenn.auth.user.User;
import com.krawenn.auth.user.UserRepository;
import java.net.URI;
import java.net.http.HttpClient;
import java.time.Clock;
import java.time.Instant;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

/**
 * Closes an account, after every application that holds data about it has deleted that data.
 *
 * <p>Three steps, in this order and never in one transaction, because the middle one is HTTP:
 * <ol>
 *   <li>The password is checked, counting towards the lockout like a login, so a stolen access token
 *       alone cannot delete anybody.
 *   <li>Each application in {@code auth.account-deletion.notify-urls} is sent a {@code DELETE} carrying
 *       the person's own access token. It sees the same caller it always sees; there is no
 *       service-to-service secret to keep.
 *   <li>Only when every one answered 2xx is the account deleted here, with its refresh and reset tokens.
 * </ol>
 *
 * <p>A failure in the middle leaves the account open and says so. Closing it anyway would leave the
 * other application's data with no owner who could ever sign in to delete it. Each application's own
 * deletion is idempotent, so trying again is safe.
 */
@Service
public class AccountDeletion {

    private static final Logger log = LoggerFactory.getLogger(AccountDeletion.class);

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthProperties properties;
    private final TransactionTemplate transactions;
    private final RestClient http;
    private final Clock clock;

    @Autowired
    public AccountDeletion(
            UserRepository userRepository,
            PasswordEncoder passwordEncoder,
            AuthProperties properties,
            PlatformTransactionManager transactionManager,
            Clock clock) {
        this(userRepository, passwordEncoder, properties, transactionManager, clock, client(properties));
    }

    AccountDeletion(
            UserRepository userRepository,
            PasswordEncoder passwordEncoder,
            AuthProperties properties,
            PlatformTransactionManager transactionManager,
            Clock clock,
            RestClient http) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.properties = properties;
        this.transactions = new TransactionTemplate(transactionManager);
        this.http = http;
        this.clock = clock;
    }

    /**
     * @param accessToken the caller's own, passed on to each application as its proof of who is asking
     * @throws InvalidCurrentPasswordException when the password is wrong or the account is locked
     * @throws AccountDeletionIncompleteException when an application did not confirm; nothing was closed
     */
    public void delete(UUID userId, String password, String accessToken) {
        verifyPassword(userId, password);
        for (URI application : properties.accountDeletion().notifyUrls()) {
            notify(application, accessToken);
        }
        transactions.executeWithoutResult(status -> userRepository.deleteById(userId));
        log.info("Account {} closed", userId);
    }

    /** Its own transaction, committed even when the password is wrong, so the failure still counts. */
    private void verifyPassword(UUID userId, String password) {
        boolean matched = Boolean.TRUE.equals(transactions.execute(status -> {
            Instant now = Instant.now(clock);
            User user = userRepository.findById(userId).orElseThrow(() -> new UserNotFoundException(userId));
            if (user.isLocked(now)) {
                log.warn("Account deletion rejected for user {}: account is locked", userId);
                return false;
            }
            if (!passwordEncoder.matches(password, user.getPasswordHash())) {
                user.registerFailedLogin(
                        now,
                        properties.login().maxFailedAttempts(),
                        properties.login().lockDuration());
                log.warn("Account deletion rejected for user {}: wrong password", userId);
                return false;
            }
            return true;
        }));
        if (!matched) {
            throw new InvalidCurrentPasswordException();
        }
    }

    private void notify(URI application, String accessToken) {
        try {
            http.delete()
                    .uri(application)
                    .headers(headers -> headers.setBearerAuth(accessToken))
                    .retrieve()
                    .toBodilessEntity();
        } catch (RestClientException ex) {
            // The address and the failure, never the token.
            log.warn(
                    "Account deletion stopped: {} did not confirm deleting its data ({})",
                    application,
                    ex.getMessage());
            throw new AccountDeletionIncompleteException();
        }
    }

    private static RestClient client(AuthProperties properties) {
        JdkClientHttpRequestFactory requestFactory = new JdkClientHttpRequestFactory(HttpClient.newBuilder()
                .connectTimeout(properties.accountDeletion().timeout())
                .build());
        requestFactory.setReadTimeout(properties.accountDeletion().timeout());
        return RestClient.builder().requestFactory(requestFactory).build();
    }
}
