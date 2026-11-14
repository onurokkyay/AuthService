package com.krawenn.auth.api.dto;

import com.krawenn.auth.password.NotBreached;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record RegisterRequest(
        @NotBlank
        // A username is a public identity (profile addresses, follows), so it is limited to what reads the
        // same everywhere: letters, digits and underscore, 3 to 20. Unique regardless of case.
        @Size(min = 3, max = 20)
        @Pattern(regexp = "^[A-Za-z0-9_]+$", message = "must contain only letters, digits or underscore")
        String username,

        @NotBlank @Email @Size(max = 254) String email,
        // 8, short enough to type on a phone, and never one known from a breach, which is what makes 8 enough
        // (see BreachedPasswords). The upper bound exists because bcrypt silently ignores input beyond 72 bytes.
        @NotBlank @Size(min = 8, max = 72) @NotBreached String password) {}
