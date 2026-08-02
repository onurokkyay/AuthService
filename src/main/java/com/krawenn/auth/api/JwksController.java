package com.krawenn.auth.api;

import com.nimbusds.jose.jwk.JWKSet;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import java.util.Map;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Publishes the verification keys.
 *
 * <p>This is the whole integration surface for a consuming service: pointing
 * {@code spring.security.oauth2.resourceserver.jwt.jwk-set-uri} at this endpoint is
 * enough to validate tokens, with no shared secret and no code.
 */
@RestController
@Tag(name = "JWKS", description = "Public keys for verifying access tokens")
public class JwksController {

    private final JWKSet publicJwkSet;

    public JwksController(JWKSet publicJwkSet) {
        this.publicJwkSet = publicJwkSet;
    }

    @GetMapping("/.well-known/jwks.json")
    @Operation(summary = "JSON Web Key Set containing the public signing keys")
    public Map<String, Object> jwks() {
        // The bean holds public halves only, so this cannot leak the private key.
        return publicJwkSet.toJSONObject();
    }
}
