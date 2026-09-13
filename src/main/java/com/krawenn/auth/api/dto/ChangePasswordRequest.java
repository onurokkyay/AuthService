package com.krawenn.auth.api.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * @param currentPassword checked for presence only, like a login, so the rules cannot hint at its length
 * @param newPassword held to the rules registration applies
 */
public record ChangePasswordRequest(
        @NotBlank String currentPassword,
        @NotBlank @Size(min = 12, max = 72) String newPassword) {}
