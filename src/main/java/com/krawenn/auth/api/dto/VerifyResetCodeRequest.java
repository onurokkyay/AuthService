package com.krawenn.auth.api.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

/**
 * @param email the address the code was sent to; a code alone would be one of a million shared by every open request
 * @param code the six digits from the email
 */
public record VerifyResetCodeRequest(
        @NotBlank @Email @Size(max = 254) String email,

        @NotBlank @Pattern(regexp = "\\d{6}", message = "must be six digits")
        String code) {}
