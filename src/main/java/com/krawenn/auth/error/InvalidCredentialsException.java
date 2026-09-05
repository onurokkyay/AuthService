package com.krawenn.auth.error;

/**
 * Raised for every failed login: unknown user, wrong password, disabled account and
 * locked account all produce this exact exception and message.
 *
 * <p>That uniformity is the point. Distinguishing the cases in the response would let a
 * caller enumerate accounts; the real reason is recorded in the log instead.
 */
public class InvalidCredentialsException extends AuthException {

    public InvalidCredentialsException() {
        super(ErrorCode.INVALID_CREDENTIALS, "Invalid username or password");
    }
}
