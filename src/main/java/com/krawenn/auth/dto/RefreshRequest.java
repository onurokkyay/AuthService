package com.krawenn.auth.dto;

import lombok.Data;

@Data
public class RefreshRequest {
    private String refreshToken;
} 