package com.krawenn.auth.security;

import com.krawenn.auth.config.AuthProperties;
import com.krawenn.auth.token.AccessTokenService;
import java.util.List;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

/**
 * Stateless bearer-token security.
 *
 * <p>The service is its own resource server: the tokens it issues are the tokens it
 * accepts. That is what lets {@code /api/auth/me} and the admin endpoints be protected
 * without a second authentication mechanism.
 */
@Configuration(proxyBeanMethods = false)
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(
            HttpSecurity http,
            CorsConfigurationSource corsConfigurationSource,
            JwtAuthenticationConverter jwtAuthenticationConverter,
            SecurityErrorHandlers errorHandlers)
            throws Exception {
        return http
                // No cookies are used, so there is no session for an attacker to ride.
                .csrf(csrf -> csrf.disable())
                .cors(cors -> cors.configurationSource(corsConfigurationSource))
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth.requestMatchers(PublicEndpoints.ALL)
                        .permitAll()
                        .requestMatchers("/api/admin/**")
                        .hasRole("ADMIN")
                        .anyRequest()
                        .authenticated())
                .oauth2ResourceServer(
                        oauth2 -> oauth2.jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter))
                                .authenticationEntryPoint(errorHandlers))
                .exceptionHandling(handling ->
                        handling.authenticationEntryPoint(errorHandlers).accessDeniedHandler(errorHandlers))
                .httpBasic(basic -> basic.disable())
                .formLogin(form -> form.disable())
                .build();
    }

    /** Maps the single {@code role} claim onto the authority {@code hasRole} expects. */
    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtGrantedAuthoritiesConverter authorities = new JwtGrantedAuthoritiesConverter();
        authorities.setAuthoritiesClaimName(AccessTokenService.ROLE_CLAIM);
        authorities.setAuthorityPrefix("ROLE_");

        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(authorities);
        return converter;
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource(AuthProperties properties) {
        CorsConfiguration configuration = new CorsConfiguration();
        // Empty by default: browsers get no cross-origin access until an origin is named.
        configuration.setAllowedOrigins(properties.cors().allowedOrigins());
        configuration.setAllowedMethods(properties.cors().allowedMethods());
        configuration.setAllowedHeaders(List.of("*"));
        configuration.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}
