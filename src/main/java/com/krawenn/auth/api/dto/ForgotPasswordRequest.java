package com.krawenn.auth.api.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/** The address to send a reset link to, if it belongs to an account. */
public record ForgotPasswordRequest(
        @NotBlank @Email @Size(max = 254) String email) {}
