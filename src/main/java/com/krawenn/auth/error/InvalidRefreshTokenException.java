package com.krawenn.auth.error;

/** Raised when a refresh token is unknown, expired, or already rotated away. */
public class InvalidRefreshTokenException extends AuthException {

    public InvalidRefreshTokenException() {
        super(ErrorCode.INVALID_REFRESH_TOKEN, "Refresh token is invalid or expired");
    }
}
