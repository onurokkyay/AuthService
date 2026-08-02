package com.krawenn.auth.api.dto;

import jakarta.validation.constraints.NotBlank;

/** Login validates only presence: length rules belong to registration, and applying them
 * here would tell a caller how long the real password is. */
public record LoginRequest(@NotBlank String username, @NotBlank String password) {}
