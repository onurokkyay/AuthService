package com.krawenn.auth.error;

import java.time.Instant;
import java.util.List;

/**
 * The single error body shape of this service, used by controller advice and by the
 * Spring Security entry points alike so that a 401 from the filter chain looks exactly
 * like a 401 from application code.
 *
 * @param fieldErrors populated for validation failures only, omitted otherwise
 */
public record ErrorResponse(
        Instant timestamp, ErrorCode code, String message, String path, List<FieldError> fieldErrors) {

    /**
     * A single rejected field.
     *
     * <p>The rejected <em>value</em> is deliberately not part of this record: validation
     * failures happen on registration and login payloads, and echoing the value back
     * would put raw passwords into responses and error logs.
     */
    public record FieldError(String field, String message) {}

    public static ErrorResponse of(Instant timestamp, ErrorCode code, String message, String path) {
        return new ErrorResponse(timestamp, code, message, path, null);
    }

    public static ErrorResponse ofValidation(
            Instant timestamp, String message, String path, List<FieldError> fieldErrors) {
        return new ErrorResponse(timestamp, ErrorCode.VALIDATION_FAILED, message, path, fieldErrors);
    }
}
