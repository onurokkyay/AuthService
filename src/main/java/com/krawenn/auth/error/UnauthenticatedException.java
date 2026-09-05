package com.krawenn.auth.error;

/**
 * Raised when a protected endpoint is reached without a usable access token.
 *
 * <p>Exists so that the Spring Security entry point can route through the same handler
 * as application errors, instead of emitting the framework's default empty 401 body.
 */
public class UnauthenticatedException extends AuthException {

    public UnauthenticatedException() {
        super(ErrorCode.UNAUTHENTICATED, "Authentication is required");
    }
}
