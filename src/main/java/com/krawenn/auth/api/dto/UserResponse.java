package com.krawenn.auth.api.dto;

import com.krawenn.auth.user.Role;
import com.krawenn.auth.user.User;
import java.time.Instant;
import java.util.UUID;

/** The public view of an account. Carries no password material by construction. */
public record UserResponse(UUID id, String username, String email, Role role, boolean enabled, Instant createdAt) {

    public static UserResponse from(User user) {
        return new UserResponse(
                user.getId(),
                user.getUsername(),
                user.getEmail(),
                user.getRole(),
                user.isEnabled(),
                user.getCreatedAt());
    }
}
