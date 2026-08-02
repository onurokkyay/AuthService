package com.krawenn.auth.token;

/**
 * A freshly signed access token.
 *
 * @param value the compact JWT
 * @param expiresInSeconds remaining lifetime, so a client can refresh before expiry
 *     instead of discovering it through a 401
 */
public record AccessToken(String value, long expiresInSeconds) {}
