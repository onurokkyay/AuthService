package com.krawenn.auth.token;

import com.krawenn.auth.config.AuthProperties;
import com.krawenn.auth.user.User;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;

/** Signs access tokens. Deliberately the only place that decides what a token contains. */
@Service
public class AccessTokenService {

    /** Non-standard claims. Kept few: a token is a credential, not a profile. */
    static final String ROLE_CLAIM = "role";

    static final String USERNAME_CLAIM = "preferred_username";

    private final JwtEncoder jwtEncoder;
    private final AuthProperties properties;
    private final Clock clock;

    public AccessTokenService(JwtEncoder jwtEncoder, AuthProperties properties, Clock clock) {
        this.jwtEncoder = jwtEncoder;
        this.properties = properties;
        this.clock = clock;
    }

    public AccessToken issue(User user) {
        Instant issuedAt = Instant.now(clock);
        Instant expiresAt = issuedAt.plus(properties.jwt().accessTokenTtl());

        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer(properties.jwt().issuer())
                .audience(List.of(properties.jwt().audience()))
                // The account id, never the username: usernames can change, and a token
                // that outlives a rename would then point at nothing (or worse, at
                // whoever took the name).
                .subject(user.getId().toString())
                .issuedAt(issuedAt)
                .expiresAt(expiresAt)
                // Distinguishes two tokens issued in the same second, which is what makes
                // a token identifiable in an audit trail.
                .id(UUID.randomUUID().toString())
                .claim(ROLE_CLAIM, user.getRole().name())
                .claim(USERNAME_CLAIM, user.getUsername())
                .build();

        String value =
                jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
        return new AccessToken(value, Duration.between(issuedAt, expiresAt).toSeconds());
    }
}
