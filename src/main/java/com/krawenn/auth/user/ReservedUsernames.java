package com.krawenn.auth.user;

import java.util.Collection;
import java.util.Locale;
import java.util.Set;

/**
 * Names no account may take, because a username can be a public identity: a consumer may show profiles
 * at an address built from it, and a user called "admin" or "support" would be read as speaking for the
 * service.
 *
 * <p>The built-in list is generic. Names that belong to one product (its own name, its brand) come from
 * configuration, {@code auth.registration.reserved-usernames}, since this service names no consumer.
 */
public final class ReservedUsernames {

    private static final Set<String> BUILT_IN = Set.of(
            "admin",
            "administrator",
            "root",
            "system",
            "support",
            "help",
            "staff",
            "moderator",
            "mod",
            "official",
            "api",
            "auth",
            "login",
            "logout",
            "register",
            "settings",
            "privacy",
            "security",
            "users",
            "user",
            "feed",
            "profile",
            "account",
            "null",
            "undefined",
            "anonymous",
            "everyone",
            "nobody");

    private ReservedUsernames() {}

    /** Case-insensitive, like username uniqueness itself. */
    public static boolean isReserved(String username, Collection<String> configured) {
        String lower = username.toLowerCase(Locale.ROOT);
        return BUILT_IN.contains(lower)
                || configured.stream()
                        .anyMatch(name -> name.toLowerCase(Locale.ROOT).equals(lower));
    }
}
