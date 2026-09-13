package com.krawenn.auth.api.dto;

/**
 * @param resetToken posted to {@code /api/auth/password/reset} exactly like the token from the emailed link
 */
public record ResetCodeResponse(String resetToken) {}
