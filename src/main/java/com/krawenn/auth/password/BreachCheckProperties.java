package com.krawenn.auth.password;

import java.net.URI;
import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Whether a new password is checked against passwords known from data breaches, and where.
 *
 * @param enabled off only where nothing outside can reach the service, or in tests
 * @param baseUrl the Pwned Passwords range API; only the first five hex characters of the password's SHA-1
 *     are ever sent to it
 * @param timeout how long to wait; a check that does not answer in time lets the password through
 */
@ConfigurationProperties(prefix = "auth.password-policy.breach-check")
public record BreachCheckProperties(boolean enabled, URI baseUrl, Duration timeout) {}
