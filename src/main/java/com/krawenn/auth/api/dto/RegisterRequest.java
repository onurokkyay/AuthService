package com.krawenn.auth.api.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record RegisterRequest(
        @NotBlank
        @Size(min = 3, max = 32)
        @Pattern(regexp = "^[A-Za-z0-9._-]+$", message = "must contain only letters, digits, dot, underscore or hyphen")
        String username,

        @NotBlank @Email @Size(max = 254) String email,
        // 12 rather than the 6 this service used to accept. The upper bound exists
        // because bcrypt silently ignores input beyond 72 bytes.
        @NotBlank @Size(min = 12, max = 72) String password) {}
