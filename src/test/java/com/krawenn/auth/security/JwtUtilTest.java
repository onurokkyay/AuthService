package com.krawenn.auth.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.security.SignatureException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.Date;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(MockitoExtension.class)
class JwtUtilTest {

    @InjectMocks
    private JwtUtil jwtUtil;

    private static final String TEST_SECRET = "testSecretKey1234567890123456789012345678901234567890";
    private static final long TEST_EXPIRATION = 3600000; // 1 hour in milliseconds
    private static final String TEST_USERNAME = "testuser";
    private static final String TEST_ROLE = "USER";

    private String validToken;
    private String expiredToken;
    private String invalidSignatureToken;

    @BeforeEach
    void setUp() {
        ReflectionTestUtils.setField(jwtUtil, "secret", TEST_SECRET);
        ReflectionTestUtils.setField(jwtUtil, "jwtExpirationInMs", TEST_EXPIRATION);

        // Generate valid token
        validToken = jwtUtil.generateToken(TEST_USERNAME, TEST_ROLE);

        // Generate expired token
        ReflectionTestUtils.setField(jwtUtil, "jwtExpirationInMs", -1000L);
        expiredToken = jwtUtil.generateToken(TEST_USERNAME, TEST_ROLE);
        ReflectionTestUtils.setField(jwtUtil, "jwtExpirationInMs", TEST_EXPIRATION);

        // Create invalid signature token
        invalidSignatureToken = validToken.substring(0, validToken.length() - 1) + "X";
    }

    @Test
    @DisplayName("Generate token should create valid JWT")
    void generateToken_shouldCreateValidJWT() {
        String token = jwtUtil.generateToken(TEST_USERNAME, TEST_ROLE);

        assertNotNull(token);
        assertTrue(jwtUtil.validateToken(token, TEST_USERNAME));
        assertEquals(TEST_USERNAME, jwtUtil.extractUsername(token));
        assertEquals(TEST_ROLE, jwtUtil.extractRole(token));
    }

    @Test
    @DisplayName("Generated token should contain correct claims")
    void generateToken_shouldContainCorrectClaims() {
        Claims claims = (Claims) ReflectionTestUtils.invokeMethod(jwtUtil, "extractAllClaims", validToken);
        assertEquals(TEST_USERNAME, claims.getSubject());
        assertEquals(TEST_ROLE, claims.get("role", String.class));
        assertEquals("league-auth-service", claims.get("iss", String.class));
    }

    @Test
    @DisplayName("Token should be valid for correct username")
    void validateToken_shouldBeValidForCorrectUsername() {
        assertTrue(jwtUtil.validateToken(validToken, TEST_USERNAME));
    }

    @Test
    @DisplayName("Token should be invalid for incorrect username")
    void validateToken_shouldBeInvalidForIncorrectUsername() {
        assertFalse(jwtUtil.validateToken(validToken, "wronguser"));
    }

    @Test
    @DisplayName("Token should be invalid when expired")
    void validateToken_shouldBeInvalidWhenExpired() {
        assertThrows(ExpiredJwtException.class, () -> jwtUtil.validateToken(expiredToken, TEST_USERNAME));
    }

    @Test
    @DisplayName("Extract username should return correct username")
    void extractUsername_shouldReturnCorrectUsername() {
        assertEquals(TEST_USERNAME, jwtUtil.extractUsername(validToken));
    }

    @Test
    @DisplayName("Extract role should return correct role")
    void extractRole_shouldReturnCorrectRole() {
        assertEquals(TEST_ROLE, jwtUtil.extractRole(validToken));
    }

    @Test
    @DisplayName("Extract expiration should return correct expiration date")
    void extractExpiration_shouldReturnCorrectExpirationDate() {
        Date expiration = jwtUtil.extractExpiration(validToken);
        assertNotNull(expiration);
        assertTrue(expiration.after(new Date()));
    }

    @Test
    @DisplayName("Should throw exception for malformed token")
    void shouldThrowExceptionForMalformedToken() {
        String malformedToken = "malformed.token.here";
        assertThrows(MalformedJwtException.class, () -> jwtUtil.validateToken(malformedToken, TEST_USERNAME));
    }

    @Test
    @DisplayName("Should throw exception for invalid signature")
    void shouldThrowExceptionForInvalidSignature() {
        assertThrows(SignatureException.class, () -> jwtUtil.validateToken(invalidSignatureToken, TEST_USERNAME));
    }

    @Test
    @DisplayName("Should throw exception for expired token")
    void shouldThrowExceptionForExpiredToken() {
        // Create a token with very short expiration
        ReflectionTestUtils.setField(jwtUtil, "jwtExpirationInMs", 1L);
        String token = jwtUtil.generateToken(TEST_USERNAME, TEST_ROLE);
        
        // Wait for token to expire
        try {
            TimeUnit.MILLISECONDS.sleep(100);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        
        assertThrows(ExpiredJwtException.class, () -> jwtUtil.validateToken(token, TEST_USERNAME));
    }

    @Test
    @DisplayName("Extract claim should return correct value")
    void extractClaim_shouldReturnCorrectValue() {
        String role = jwtUtil.extractClaim(validToken, claims -> claims.get("role", String.class));
        assertEquals(TEST_ROLE, role);
    }

    @Test
    @DisplayName("Token should contain correct expiration time")
    void token_shouldContainCorrectExpirationTime() {
        Date expiration = jwtUtil.extractExpiration(validToken);
        long expectedExpiration = System.currentTimeMillis() + TEST_EXPIRATION;
        // Allow 1 second tolerance for test execution time
        assertTrue(Math.abs(expiration.getTime() - expectedExpiration) < 1000);
    }
} 