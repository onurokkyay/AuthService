package com.krawenn.auth.security;

/** Endpoints reachable without an access token. Everything not listed requires one. */
public final class PublicEndpoints {

    public static final String[] ALL = {
        // Obtaining a token cannot itself require a token.
        "/api/auth/register",
        "/api/auth/login",
        "/api/auth/refresh",
        // Logout authenticates through the refresh token in the body: a client whose
        // access token already expired must still be able to end its session.
        "/api/auth/logout",
        // Somebody who has forgotten their password has no token to present. Both answer
        // the same way whether or not the account exists, so being reachable leaks nothing.
        // Changing a password while signed in is deliberately not here.
        "/api/auth/password/forgot",
        "/api/auth/password/verify-code",
        "/api/auth/password/reset",
        // Consumers fetch verification keys before they can validate anything.
        "/.well-known/jwks.json",
        "/actuator/health/**",
        "/actuator/info",
        "/v3/api-docs/**",
        "/swagger-ui/**",
        "/swagger-ui.html",
    };

    private PublicEndpoints() {}
}
