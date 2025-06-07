package com.krawenn.auth.service;

import com.krawenn.auth.dto.AuthRequest;
import com.krawenn.auth.dto.RefreshRequest;
import com.krawenn.auth.dto.AuthResponse;

public interface AuthService {
    void register(AuthRequest request);
    AuthResponse login(AuthRequest request);
    AuthResponse refreshToken(RefreshRequest request);
}