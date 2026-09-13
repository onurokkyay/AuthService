package com.krawenn.auth.api.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * @param token the value from the reset link; bounded so an absurd body is refused before anything hashes it
 * @param newPassword held to the rules registration applies, for the same reasons
 */
public record ResetPasswordRequest(
        @NotBlank @Size(max = 128) String token,
        @NotBlank @Size(min = 12, max = 72) String newPassword) {}
