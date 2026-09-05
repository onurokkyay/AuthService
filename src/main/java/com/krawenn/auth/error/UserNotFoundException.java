package com.krawenn.auth.error;

import java.util.UUID;

/**
 * Raised when an administrative lookup targets an account that does not exist.
 *
 * <p>Only reachable by an authenticated administrator, so unlike the login path it may
 * safely say that the account is unknown.
 */
public class UserNotFoundException extends AuthException {

    public UserNotFoundException(UUID userId) {
        super(ErrorCode.USER_NOT_FOUND, "No user with id " + userId);
    }
}
