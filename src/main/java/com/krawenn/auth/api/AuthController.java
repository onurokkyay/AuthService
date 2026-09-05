package com.krawenn.auth.api;

import com.krawenn.auth.api.dto.LoginRequest;
import com.krawenn.auth.api.dto.RefreshTokenRequest;
import com.krawenn.auth.api.dto.RegisterRequest;
import com.krawenn.auth.api.dto.TokenResponse;
import com.krawenn.auth.api.dto.UserResponse;
import com.krawenn.auth.authentication.AuthService;
import com.krawenn.auth.user.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

/** The authentication API. Holds no logic: it validates, delegates and maps to a DTO. */
@RestController
@RequestMapping("/api/auth")
@Tag(name = "Authentication", description = "Registration and session lifecycle")
public class AuthController {

    private final AuthService authService;
    private final UserService userService;

    public AuthController(AuthService authService, UserService userService) {
        this.authService = authService;
        this.userService = userService;
    }

    @PostMapping("/register")
    @ResponseStatus(HttpStatus.CREATED)
    @Operation(summary = "Create an account")
    public UserResponse register(@Valid @RequestBody RegisterRequest request) {
        return UserResponse.from(authService.register(request));
    }

    @PostMapping("/login")
    @Operation(summary = "Exchange credentials for an access and refresh token")
    public TokenResponse login(@Valid @RequestBody LoginRequest request) {
        return authService.login(request);
    }

    @PostMapping("/refresh")
    @Operation(summary = "Rotate a refresh token into a new token pair")
    public TokenResponse refresh(@Valid @RequestBody RefreshTokenRequest request) {
        return authService.refresh(request.refreshToken());
    }

    @PostMapping("/logout")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @Operation(summary = "Revoke a refresh token")
    public void logout(@Valid @RequestBody RefreshTokenRequest request) {
        authService.logout(request.refreshToken());
    }

    @GetMapping("/me")
    @Operation(summary = "The account behind the presented access token")
    public UserResponse me(@AuthenticationPrincipal Jwt jwt) {
        // The subject is this service's own account id; it was put there by
        // AccessTokenService and verified by the resource server before arriving here.
        return UserResponse.from(userService.require(UUID.fromString(jwt.getSubject())));
    }
}
