package com.krawenn.auth.password;

import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Locale;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

/**
 * Whether a password is known from a data breach, by k-anonymity against Pwned Passwords.
 *
 * <p>The minimum length is 8, short enough to type on a phone. What makes a short password acceptable is
 * that it is not one of the hundreds of millions attackers try first, and this is the check for that:
 * {@code password1}, {@code 12345678} and {@code iloveyou} are all eight characters long.
 *
 * <p>The password never leaves this service. Only the first five hex characters of its SHA-1 are sent, the
 * answer lists every known suffix under that prefix (padded with fake ones so the response size says
 * nothing), and the comparison is made here.
 *
 * <p>When the service cannot be reached the password is let through: an outage there must not stop anyone
 * registering or resetting a password here. Length and the login lockout still apply.
 */
@Component
public class BreachedPasswords {

    private static final Logger log = LoggerFactory.getLogger(BreachedPasswords.class);

    private final BreachCheckProperties properties;
    private final RestClient http;

    @Autowired
    public BreachedPasswords(BreachCheckProperties properties) {
        this(properties, client(properties));
    }

    BreachedPasswords(BreachCheckProperties properties, RestClient http) {
        this.properties = properties;
        this.http = http;
    }

    public boolean isBreached(String password) {
        if (!properties.enabled() || password == null || password.isEmpty()) {
            return false;
        }
        String hash = sha1(password);
        String prefix = hash.substring(0, 5);
        String suffix = hash.substring(5);
        try {
            String range = http.get()
                    .uri(properties.baseUrl().resolve("range/" + prefix))
                    .header("Add-Padding", "true")
                    .retrieve()
                    .body(String.class);
            return range != null && range.lines().anyMatch(line -> isFound(line, suffix));
        } catch (RestClientException ex) {
            log.warn("The breached-password check did not answer; letting the password through ({})", ex.getMessage());
            return false;
        }
    }

    /** {@code SUFFIX:COUNT}; padding lines carry a count of zero and are not breaches. */
    private static boolean isFound(String line, String suffix) {
        int colon = line.indexOf(':');
        return colon > 0
                && line.substring(0, colon).equalsIgnoreCase(suffix)
                && !"0".equals(line.substring(colon + 1).strip());
    }

    private static String sha1(String password) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-1").digest(password.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest).toUpperCase(Locale.ROOT);
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("Every JVM provides SHA-1", ex);
        }
    }

    private static RestClient client(BreachCheckProperties properties) {
        JdkClientHttpRequestFactory requestFactory = new JdkClientHttpRequestFactory(
                HttpClient.newBuilder().connectTimeout(properties.timeout()).build());
        requestFactory.setReadTimeout(properties.timeout());
        return RestClient.builder().requestFactory(requestFactory).build();
    }
}
