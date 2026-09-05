package com.krawenn.auth.token;

import static org.assertj.core.api.Assertions.assertThat;

import com.krawenn.auth.TestAuthProperties;
import com.krawenn.auth.user.Role;
import com.krawenn.auth.user.TestUsers;
import com.krawenn.auth.user.User;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.UUID;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;

/** Signs a token with a real key pair and reads it back, so the claim contract is verified end to end. */
class AccessTokenServiceTest {

    private static final Instant NOW = Instant.parse("2026-01-01T12:00:00Z");

    private static RSAKey key;

    private AccessTokenService accessTokenService;
    private JwtDecoder decoder;

    @BeforeAll
    static void generateKey() throws NoSuchAlgorithmException, JOSEException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair pair = generator.generateKeyPair();
        key = new RSAKey.Builder((RSAPublicKey) pair.getPublic())
                .privateKey((RSAPrivateKey) pair.getPrivate())
                .keyIDFromThumbprint()
                .build();
    }

    @BeforeEach
    void setUp() throws JOSEException {
        accessTokenService = new AccessTokenService(
                new NimbusJwtEncoder(new ImmutableJWKSet<>(new JWKSet(key))),
                TestAuthProperties.create(),
                Clock.fixed(NOW, ZoneOffset.UTC));
        NimbusJwtDecoder nimbusDecoder =
                NimbusJwtDecoder.withPublicKey(key.toRSAPublicKey()).build();
        // The service issues at a fixed instant in the past, so the decoder's default
        // expiry check would reject every token here. Expiry is asserted explicitly
        // below instead; this decoder only has to verify the signature and read claims.
        nimbusDecoder.setJwtValidator(token -> OAuth2TokenValidatorResult.success());
        decoder = nimbusDecoder;
    }

    @Test
    @DisplayName("Subject is the account id, not the username")
    void subjectIsTheAccountId() {
        UUID userId = UUID.randomUUID();

        Jwt decoded = decoder.decode(
                accessTokenService.issue(TestUsers.withId(userId)).value());

        assertThat(decoded.getSubject()).isEqualTo(userId.toString());
        assertThat(decoded.getClaimAsString(AccessTokenService.USERNAME_CLAIM)).isEqualTo("testuser");
    }

    @Test
    @DisplayName("Issuer, audience, jti and role are present")
    void registeredClaimsArePresent() {
        Jwt decoded = decoder.decode(accessTokenService
                .issue(TestUsers.withId(UUID.randomUUID(), Role.ADMIN))
                .value());

        assertThat(decoded.getIssuer()).hasToString(TestAuthProperties.ISSUER);
        assertThat(decoded.getAudience()).containsExactly(TestAuthProperties.AUDIENCE);
        assertThat(decoded.getId()).isNotBlank();
        assertThat(decoded.getClaimAsString(AccessTokenService.ROLE_CLAIM)).isEqualTo("ADMIN");
    }

    @Test
    @DisplayName("Expiry follows the configured lifetime and is reported to the client")
    void expiryMatchesConfiguredTtl() {
        AccessToken issued = accessTokenService.issue(TestUsers.withId(UUID.randomUUID()));

        Jwt decoded = decoder.decode(issued.value());

        assertThat(decoded.getIssuedAt()).isEqualTo(NOW);
        assertThat(decoded.getExpiresAt()).isEqualTo(NOW.plus(TestAuthProperties.ACCESS_TOKEN_TTL));
        assertThat(issued.expiresInSeconds()).isEqualTo(TestAuthProperties.ACCESS_TOKEN_TTL.toSeconds());
    }

    @Test
    @DisplayName("Two tokens for the same user differ by jti")
    void jtiIsUniquePerToken() {
        User user = TestUsers.withId(UUID.randomUUID());

        Jwt first = decoder.decode(accessTokenService.issue(user).value());
        Jwt second = decoder.decode(accessTokenService.issue(user).value());

        assertThat(first.getId()).isNotEqualTo(second.getId());
    }
}
