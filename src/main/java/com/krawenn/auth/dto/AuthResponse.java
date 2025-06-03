package com.krawenn.auth.dto;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class AuthResponse {
    private String token;
    private String refreshToken;

    public AuthResponse(String token) {
        this.token = token;
    }
} 