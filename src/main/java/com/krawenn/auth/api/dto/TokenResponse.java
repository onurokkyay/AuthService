package com.krawenn.auth.api.dto;

/**
 * @param tokenType always {@code Bearer}; present so clients can build the
 *     Authorization header without hardcoding it
 * @param expiresIn lifetime of the access token in seconds
 */
public record TokenResponse(String accessToken, String refreshToken, String tokenType, long expiresIn) {

    private static final String BEARER = "Bearer";

    public static TokenResponse bearer(String accessToken, String refreshToken, long expiresIn) {
        return new TokenResponse(accessToken, refreshToken, BEARER, expiresIn);
    }
}
