package com.krawenn.auth.service;

import com.krawenn.auth.dto.AuthRequest;

public interface AuthService {
    void register(AuthRequest request);
    String login(AuthRequest request);
}