package com.krawenn.auth;

import com.krawenn.auth.config.AuthProperties;
import java.time.Duration;
import java.util.List;

/** A complete, valid {@link AuthProperties} so tests do not depend on the YAML defaults. */
public final class TestAuthProperties {

    public static final String ISSUER = "https://auth.test";
    public static final String AUDIENCE = "test-clients";
    public static final Duration ACCESS_TOKEN_TTL = Duration.ofMinutes(15);
    public static final Duration REFRESH_TOKEN_TTL = Duration.ofDays(30);
    public static final int MAX_FAILED_ATTEMPTS = 3;
    public static final Duration LOCK_DURATION = Duration.ofMinutes(15);
    public static final String BOOTSTRAP_ADMIN_EMAIL = "admin@example.test";

    private TestAuthProperties() {}

    public static AuthProperties create() {
        return new AuthProperties(
                new AuthProperties.Jwt(ISSUER, AUDIENCE, ACCESS_TOKEN_TTL, null, null),
                new AuthProperties.RefreshToken(REFRESH_TOKEN_TTL, "0 0 3 * * *"),
                new AuthProperties.Login(MAX_FAILED_ATTEMPTS, LOCK_DURATION),
                new AuthProperties.Registration(List.of(BOOTSTRAP_ADMIN_EMAIL)),
                new AuthProperties.Cors(List.of(), List.of("GET", "POST")));
    }
}
