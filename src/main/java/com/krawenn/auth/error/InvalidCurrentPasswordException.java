package com.krawenn.auth.error;

/**
 * Raised when a signed-in account supplies the wrong current password while changing it.
 *
 * <p>Not a 401. The caller <em>is</em> authenticated, and a client that reads 401 as "refresh and retry" would spend a
 * refresh token and then fail again on the same wrong password.
 */
public class InvalidCurrentPasswordException extends AuthException {

    public InvalidCurrentPasswordException() {
        super(ErrorCode.INVALID_CURRENT_PASSWORD, "Current password is incorrect");
    }
}
