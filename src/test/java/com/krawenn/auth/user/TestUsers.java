package com.krawenn.auth.user;

import java.util.UUID;
import org.springframework.test.util.ReflectionTestUtils;

/**
 * Builds users with a known id.
 *
 * <p>Identifiers are assigned by Hibernate on persist, so a unit test that never touches
 * the database has to inject one. Reflection is the price of not adding a setter that
 * production code would then be able to call.
 */
public final class TestUsers {

    public static final String PASSWORD_HASH = "$2a$12$irrelevant-for-unit-tests";

    private TestUsers() {}

    public static User withId(UUID id) {
        return withId(id, Role.USER);
    }

    public static User withId(UUID id, Role role) {
        User user = new User("testuser", "test@example.test", PASSWORD_HASH, role);
        ReflectionTestUtils.setField(user, "id", id);
        return user;
    }
}
