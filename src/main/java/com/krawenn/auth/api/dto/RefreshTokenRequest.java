package com.krawenn.auth.api.dto;

import jakarta.validation.constraints.NotBlank;

/** Body of both refresh and logout: the same token identifies the session either way. */
public record RefreshTokenRequest(@NotBlank String refreshToken) {}
