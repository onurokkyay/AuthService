package com.krawenn.auth.error;

/** Base class for failures this service raises deliberately, each carrying an {@link ErrorCode}. */
public abstract class AuthException extends RuntimeException {

    private final transient ErrorCode errorCode;

    protected AuthException(ErrorCode errorCode, String message) {
        super(message);
        this.errorCode = errorCode;
    }

    public ErrorCode errorCode() {
        return errorCode;
    }
}
