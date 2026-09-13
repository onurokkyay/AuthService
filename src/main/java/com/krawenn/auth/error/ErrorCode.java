package com.krawenn.auth.error;

import org.springframework.http.HttpStatus;

/**
 * Machine-readable error codes returned to clients.
 *
 * <p>These are part of the public contract: consuming services may branch on them, so a
 * code is never renamed or reused for a different meaning.
 *
 * <p>Note what is <em>missing</em>: there is no code for "user not found" on login and
 * none for "account locked". Both collapse into {@link #INVALID_CREDENTIALS} so that a
 * caller cannot use the response to learn which accounts exist.
 */
public enum ErrorCode {
    VALIDATION_FAILED(HttpStatus.BAD_REQUEST),
    MALFORMED_REQUEST(HttpStatus.BAD_REQUEST),
    INVALID_CREDENTIALS(HttpStatus.UNAUTHORIZED),
    INVALID_REFRESH_TOKEN(HttpStatus.UNAUTHORIZED),
    INVALID_RESET_TOKEN(HttpStatus.BAD_REQUEST),
    INVALID_RESET_CODE(HttpStatus.BAD_REQUEST),
    // 400 rather than 401: the caller is authenticated, and a client that reads 401 as
    // "refresh and retry" would spend a refresh token to fail again on the same password.
    INVALID_CURRENT_PASSWORD(HttpStatus.BAD_REQUEST),
    UNAUTHENTICATED(HttpStatus.UNAUTHORIZED),
    FORBIDDEN(HttpStatus.FORBIDDEN),
    RESOURCE_NOT_FOUND(HttpStatus.NOT_FOUND),
    USER_NOT_FOUND(HttpStatus.NOT_FOUND),
    USER_ALREADY_EXISTS(HttpStatus.CONFLICT),
    INTERNAL_ERROR(HttpStatus.INTERNAL_SERVER_ERROR);

    private final HttpStatus httpStatus;

    ErrorCode(HttpStatus httpStatus) {
        this.httpStatus = httpStatus;
    }

    public HttpStatus httpStatus() {
        return httpStatus;
    }
}
