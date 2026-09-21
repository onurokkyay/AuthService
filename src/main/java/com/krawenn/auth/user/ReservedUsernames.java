package com.krawenn.auth.user;

import java.util.Locale;
import java.util.Set;

/**
 * Names no account may take, because a username is now a public identity: profiles live at
 * {@code /users/{username}}, and a user called "admin" or "support" would be read as speaking for the
 * service.
 */
public final class ReservedUsernames {

    private static final Set<String> RESERVED = Set.of(
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
            "gameatlas",
            "krawenn",
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
    public static boolean isReserved(String username) {
        return RESERVED.contains(username.toLowerCase(Locale.ROOT));
    }
}
