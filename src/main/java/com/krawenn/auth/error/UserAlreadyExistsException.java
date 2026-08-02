package com.krawenn.auth.error;

/** Raised when a registration collides with an existing username or email. */
public class UserAlreadyExistsException extends AuthException {

    public UserAlreadyExistsException() {
        super(ErrorCode.USER_ALREADY_EXISTS, "Username or email is already registered");
    }
}
