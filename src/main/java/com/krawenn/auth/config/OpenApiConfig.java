package com.krawenn.auth.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.security.SecurityScheme;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * API documentation.
 *
 * <p>No server URL is declared. The previous version hardcoded an API gateway, which
 * made the documentation wrong wherever the service ran without one; springdoc infers
 * the URL from the request instead.
 */
@Configuration(proxyBeanMethods = false)
public class OpenApiConfig {

    private static final String BEARER_SCHEME = "bearerAuth";

    @Bean
    public OpenAPI openApi() {
        return new OpenAPI()
                .info(new Info()
                        .title("Auth Service API")
                        .version("v1")
                        .description("Generic authentication and authorization service. "
                                + "Issues RS256 access tokens and rotating refresh tokens; "
                                + "consumers verify tokens through /.well-known/jwks.json."))
                .components(new Components()
                        .addSecuritySchemes(
                                BEARER_SCHEME,
                                new SecurityScheme()
                                        .name(BEARER_SCHEME)
                                        .type(SecurityScheme.Type.HTTP)
                                        .scheme("bearer")
                                        .bearerFormat("JWT")));
    }
}
