package com.krawenn.auth.config;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Positive;
import java.time.Duration;
import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.core.io.Resource;
import org.springframework.validation.annotation.Validated;

/**
 * Every knob this service has, validated at startup.
 *
 * <p>Binding failures surface as a refusal to start rather than as a runtime surprise on
 * the first request, which is the only acceptable behaviour for security settings.
 */
@Validated
@ConfigurationProperties(prefix = "auth")
public record AuthProperties(
        @Valid @NotNull Jwt jwt,
        @Valid @NotNull RefreshToken refreshToken,
        @Valid @NotNull Login login,
        @Valid @NotNull Registration registration,
        @Valid @NotNull Cors cors,
        @Valid @NotNull PasswordReset passwordReset) {

    /**
     * Access token settings.
     *
     * @param issuer the {@code iss} claim, also verified on incoming tokens
     * @param audience the {@code aud} claim, also verified on incoming tokens
     * @param accessTokenTtl short by design; revocation happens through the refresh token
     * @param privateKey PKCS#8 PEM signing key, or {@code null} to generate a throwaway
     *     development key pair at startup
     * @param publicKey X.509 PEM verification key, paired with {@code privateKey}
     */
    public record Jwt(
            @NotBlank String issuer,
            @NotBlank String audience,
            @NotNull Duration accessTokenTtl,
            Resource privateKey,
            Resource publicKey) {}

    /**
     * @param ttl lifetime of a newly issued refresh token; rotation does not extend it
     * @param cleanupCron when expired rows are deleted
     */
    public record RefreshToken(
            @NotNull Duration ttl, @NotBlank String cleanupCron) {}

    /**
     * Brute-force protection.
     *
     * @param maxFailedAttempts consecutive failures before the account is locked
     * @param lockDuration how long the lock lasts
     */
    public record Login(
            @Positive int maxFailedAttempts, @NotNull Duration lockDuration) {}

    /**
     * @param bootstrapAdminEmails accounts registering with one of these emails become
     *     {@code ADMIN}. This is how the first administrator comes into existence;
     *     afterwards roles are managed through the admin endpoint.
     * @param reservedUsernames names no account may take beyond the built-in generic ones — a consumer's own
     *     name, for instance; refused exactly like a taken name
     */
    public record Registration(
            @NotNull List<String> bootstrapAdminEmails,
            @NotNull List<String> reservedUsernames) {}

    /**
     * @param allowedOrigins empty by default — a browser client must be named explicitly
     */
    public record Cors(
            @NotNull List<String> allowedOrigins, @NotNull List<String> allowedMethods) {}

    /**
     * Password reset by email.
     *
     * @param tokenTtl how long an emailed link works; short, because the link is a credential
     *     for as long as it lives
     * @param requestCooldown how long an account waits before another link is sent — what
     *     keeps the endpoint from being used to fill somebody's inbox
     * @param maxCodeAttempts wrong codes before the request is retired, link included. Six
     *     digits are guessable; this, together with the cooldown, is what makes guessing slow.
     * @param linkTemplate where the emailed link points, with {@code {token}} where the token
     *     goes. A page of the consuming application, which posts the token back here.
     * @param cleanupCron when expired tokens are deleted
     * @param mail delivery settings
     */
    public record PasswordReset(
            @NotNull Duration tokenTtl,
            @NotNull Duration requestCooldown,
            @Positive int maxCodeAttempts,

            @NotBlank @Pattern(regexp = ".*\\{token}.*", message = "must contain {token}")
            String linkTemplate,

            @NotBlank String cleanupCron,
            @Valid @NotNull Mail mail) {

        /**
         * Everything a recipient reads is configured here, so that no consuming application's
         * name has to reach the source tree.
         *
         * @param enabled off by default: a deployment without a mail server must still start,
         *     and the mailer says in the log each time a reset was asked for and not sent
         * @param from sender address
         * @param productName substituted for {@code {product}}
         * @param subject may use {@code {product}}
         * @param bodyTemplate must contain {@code {link}}; may use {@code {code}},
         *     {@code {product}}, {@code {username}} and {@code {minutes}}
         */
        public record Mail(
                boolean enabled,
                @NotBlank String from,
                @NotBlank String productName,
                @NotBlank String subject,

                @NotBlank @Pattern(regexp = "(?s).*\\{link}.*", message = "must contain {link}")
                String bodyTemplate) {}
    }
}
