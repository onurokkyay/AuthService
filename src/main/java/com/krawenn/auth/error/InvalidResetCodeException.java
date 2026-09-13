package com.krawenn.auth.error;

/**
 * Raised when a reset code does not unlock a reset: wrong, expired, already exchanged, retired after too many attempts,
 * or sent for an address with no account. One answer for all of them.
 */
public class InvalidResetCodeException extends AuthException {

    public InvalidResetCodeException() {
        super(ErrorCode.INVALID_RESET_CODE, "Password reset code is invalid or expired");
    }
}
