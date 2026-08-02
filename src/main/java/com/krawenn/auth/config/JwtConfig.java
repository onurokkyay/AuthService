package com.krawenn.auth.config;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.core.io.Resource;
import org.springframework.security.converter.RsaKeyConverters;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.jwt.JwtClaimValidator;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtIssuerValidator;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;

/**
 * RSA signing setup.
 *
 * <p>Asymmetric signing is what makes this service reusable: a consumer verifies tokens
 * with the published public key and never holds anything that could mint one. With a
 * shared HMAC secret every consumer would effectively be an issuer.
 */
@Configuration(proxyBeanMethods = false)
public class JwtConfig {

    private static final Logger log = LoggerFactory.getLogger(JwtConfig.class);

    /** Profiles where an ephemeral key pair is an acceptable convenience. */
    private static final String[] EPHEMERAL_KEY_PROFILES = {"local", "test"};

    private static final int EPHEMERAL_KEY_SIZE = 2048;

    /**
     * The active signing key. Its {@code kid} is the RFC 7638 thumbprint, so it is
     * derived from the key itself and a future second key gets a distinct id for free.
     */
    @Bean
    public RSAKey signingKey(AuthProperties properties, Environment environment) throws IOException, JOSEException {
        Resource privateKey = properties.jwt().privateKey();
        Resource publicKey = properties.jwt().publicKey();

        if (privateKey == null || publicKey == null) {
            requireEphemeralKeysAreAllowed(environment);
            log.warn("No RSA key pair configured; generating an ephemeral one. "
                    + "Every restart invalidates all previously issued access tokens.");
            return fromKeyPair(generateKeyPair());
        }

        try (InputStream privateStream = privateKey.getInputStream();
                InputStream publicStream = publicKey.getInputStream()) {
            RSAPrivateKey parsedPrivate = RsaKeyConverters.pkcs8().convert(privateStream);
            RSAPublicKey parsedPublic = RsaKeyConverters.x509().convert(publicStream);
            return build(parsedPublic, parsedPrivate);
        }
    }

    /** Only the public halves, which is exactly what the JWKS endpoint may publish. */
    @Bean
    public JWKSet publicJwkSet(RSAKey signingKey) {
        return new JWKSet(signingKey.toPublicJWK());
    }

    @Bean
    public JwtEncoder jwtEncoder(RSAKey signingKey) {
        JWKSource<SecurityContext> source = new ImmutableJWKSet<>(new JWKSet(signingKey));
        return new NimbusJwtEncoder(source);
    }

    /**
     * Verifies signature, expiry, issuer and audience. The last two matter: a token
     * minted by a different deployment of this same service must not be accepted here.
     */
    @Bean
    public JwtDecoder jwtDecoder(RSAKey signingKey, AuthProperties properties) throws JOSEException {
        NimbusJwtDecoder decoder =
                NimbusJwtDecoder.withPublicKey(signingKey.toRSAPublicKey()).build();
        String audience = properties.jwt().audience();
        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
                new JwtTimestampValidator(),
                new JwtIssuerValidator(properties.jwt().issuer()),
                new JwtClaimValidator<List<String>>(
                        JwtClaimNames.AUD, claim -> claim != null && claim.contains(audience))));
        return decoder;
    }

    private void requireEphemeralKeysAreAllowed(Environment environment) {
        if (!environment.matchesProfiles(EPHEMERAL_KEY_PROFILES)) {
            throw new IllegalStateException("auth.jwt.private-key and auth.jwt.public-key must be configured. "
                    + "Generating a throwaway key pair is only allowed under the "
                    + String.join(" or ", EPHEMERAL_KEY_PROFILES) + " profile.");
        }
    }

    private RSAKey fromKeyPair(KeyPair keyPair) throws JOSEException {
        return build((RSAPublicKey) keyPair.getPublic(), (RSAPrivateKey) keyPair.getPrivate());
    }

    private RSAKey build(RSAPublicKey publicKey, RSAPrivateKey privateKey) throws JOSEException {
        return new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyUse(KeyUse.SIGNATURE)
                .keyIDFromThumbprint()
                .build();
    }

    private KeyPair generateKeyPair() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(EPHEMERAL_KEY_SIZE);
            return generator.generateKeyPair();
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("RSA key generation is unavailable on this JVM", ex);
        }
    }
}
