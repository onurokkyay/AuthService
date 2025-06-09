package com.krawenn.auth.service.impl;

import com.krawenn.auth.dto.AuthRequest;
import com.krawenn.auth.dto.AuthResponse;
import com.krawenn.auth.dto.RefreshRequest;
import com.krawenn.auth.exception.InvalidCredentialsException;
import com.krawenn.auth.exception.UserAlreadyExistsException;
import com.krawenn.auth.exception.UserNotFoundException;
import com.krawenn.auth.model.RefreshToken;
import com.krawenn.auth.model.User;
import com.krawenn.auth.repository.RefreshTokenRepository;
import com.krawenn.auth.repository.UserRepository;
import com.krawenn.auth.security.JwtUtil;
import com.krawenn.auth.service.AuthService;

import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;
    private final RefreshTokenRepository refreshTokenRepository;
    private static final long REFRESH_TOKEN_DURATION_MS = 7 * 24 * 60 * 60 * 1000; // 7 days

    @Override
    public void register(AuthRequest request) {
        if (userRepository.findByUsername(request.getUsername()).isPresent() ||
            userRepository.findByEmail(request.getEmail()).isPresent()) {
            throw new UserAlreadyExistsException();
        }
        User user = new User();
        user.setUsername(request.getUsername());
        user.setEmail(request.getEmail());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setRole("USER");
        userRepository.save(user);
    }

    @Override
    public AuthResponse login(AuthRequest request) {
        User user = userRepository.findByUsername(request.getUsername())
                .orElseThrow(UserNotFoundException::new);
        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            throw new InvalidCredentialsException();
        }
        // Remove old refresh tokens
        refreshTokenRepository.deleteByUserId(user.getId());
        // Generate new refresh token
        String refreshTokenStr = UUID.randomUUID().toString();
        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setUserId(user.getId());
        refreshToken.setToken(refreshTokenStr);
        refreshToken.setExpiryDate(Instant.now().plusMillis(REFRESH_TOKEN_DURATION_MS));
        refreshTokenRepository.save(refreshToken);
        // Return both tokens
        return new AuthResponse(jwtUtil.generateToken(user.getUsername(), user.getRole()), refreshTokenStr, user.getRole());
    }

    @Override
    public AuthResponse refreshToken(RefreshRequest request) {
        RefreshToken refreshToken = refreshTokenRepository.findByToken(request.getRefreshToken())
                .orElseThrow(() -> new InvalidCredentialsException("Invalid refresh token"));
        if (refreshToken.getExpiryDate().isBefore(Instant.now())) {
            refreshTokenRepository.delete(refreshToken);
            throw new InvalidCredentialsException("Refresh token expired");
        }
        User user = userRepository.findById(refreshToken.getUserId())
                .orElseThrow(UserNotFoundException::new);
        String newJwt = jwtUtil.generateToken(user.getUsername(), user.getRole());
        return new AuthResponse(newJwt, refreshToken.getToken(), user.getRole());
    }
} 