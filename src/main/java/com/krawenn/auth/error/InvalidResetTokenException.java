package com.krawenn.auth.error;

/** Raised when a reset token is unknown, expired or already used. One answer for all three. */
public class InvalidResetTokenException extends AuthException {

    public InvalidResetTokenException() {
        super(ErrorCode.INVALID_RESET_TOKEN, "Password reset link is invalid, expired or already used");
    }
}
