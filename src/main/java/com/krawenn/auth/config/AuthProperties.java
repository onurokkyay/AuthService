package com.krawenn.auth.config;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
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
        @Valid @NotNull Cors cors) {

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
    public record RefreshToken(@NotNull Duration ttl, @NotBlank String cleanupCron) {}

    /**
     * Brute-force protection.
     *
     * @param maxFailedAttempts consecutive failures before the account is locked
     * @param lockDuration how long the lock lasts
     */
    public record Login(@Positive int maxFailedAttempts, @NotNull Duration lockDuration) {}

    /**
     * @param bootstrapAdminEmails accounts registering with one of these emails become
     *     {@code ADMIN}. This is how the first administrator comes into existence;
     *     afterwards roles are managed through the admin endpoint.
     */
    public record Registration(@NotNull List<String> bootstrapAdminEmails) {}

    /**
     * @param allowedOrigins empty by default — a browser client must be named explicitly
     */
    public record Cors(@NotNull List<String> allowedOrigins, @NotNull List<String> allowedMethods) {}
}
