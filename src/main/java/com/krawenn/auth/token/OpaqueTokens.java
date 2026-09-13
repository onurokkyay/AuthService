package com.krawenn.auth.token;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Random bearer tokens and the digest they are stored under.
 *
 * <p>Refresh tokens and password reset tokens are the same kind of secret: a random value handed to the client once,
 * kept server-side only as a digest, so that a database dump grants nothing. The logic that makes that true lives here
 * once rather than in each place that issues one — two copies of security-critical code are two chances for one of them
 * to drift.
 */
public final class OpaqueTokens {

    /** 256 bits of entropy, which is why a plain digest is enough and bcrypt is not needed. */
    private static final int TOKEN_BYTES = 32;

    private static final SecureRandom RANDOM = new SecureRandom();

    private OpaqueTokens() {}

    /** @return a new URL-safe token; the caller is the only one who will ever see it */
    public static String generate() {
        byte[] bytes = new byte[TOKEN_BYTES];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    /** @return the SHA-256 digest a token is stored and looked up by */
    public static String hash(String rawToken) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(rawToken.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 is unavailable on this JVM", ex);
        }
    }
}
