package com.krawenn.auth.error;

import jakarta.servlet.http.HttpServletRequest;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;
import org.springframework.web.servlet.resource.NoResourceFoundException;

/**
 * Turns every exception leaving the web layer into an {@link ErrorResponse}.
 *
 * <p>Anything unexpected is logged with its stack trace and reported as an opaque 500:
 * an authentication service must never let internals reach the caller, since the caller
 * is by definition untrusted.
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    private final Clock clock;

    public GlobalExceptionHandler(Clock clock) {
        this.clock = clock;
    }

    @ExceptionHandler(AuthException.class)
    public ResponseEntity<ErrorResponse> handleAuthException(AuthException ex, HttpServletRequest request) {
        // Expected outcomes, not incidents: the security-relevant detail is logged where
        // it happens, with the identifiers this layer does not have.
        log.debug("Handled [{}] on {}", ex.errorCode(), request.getRequestURI());
        return respond(ErrorResponse.of(now(), ex.errorCode(), ex.getMessage(), request.getRequestURI()));
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ErrorResponse> handleValidation(
            MethodArgumentNotValidException ex, HttpServletRequest request) {
        List<ErrorResponse.FieldError> fieldErrors = ex.getBindingResult().getFieldErrors().stream()
                .map(error -> new ErrorResponse.FieldError(error.getField(), error.getDefaultMessage()))
                .toList();
        return respond(
                ErrorResponse.ofValidation(now(), "Request validation failed", request.getRequestURI(), fieldErrors));
    }

    @ExceptionHandler({HttpMessageNotReadableException.class, MethodArgumentTypeMismatchException.class})
    public ResponseEntity<ErrorResponse> handleMalformedRequest(Exception ex, HttpServletRequest request) {
        log.debug("Malformed request on {}: {}", request.getRequestURI(), ex.getMessage());
        return respond(ErrorResponse.of(
                now(), ErrorCode.MALFORMED_REQUEST, "Request could not be parsed", request.getRequestURI()));
    }

    /**
     * Method security denials. Requests without any authentication are already rejected
     * by the filter chain, so reaching here means an authenticated user lacked the role.
     */
    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ErrorResponse> handleAccessDenied(AccessDeniedException ex, HttpServletRequest request) {
        log.warn("Access denied on {} {}", request.getMethod(), request.getRequestURI());
        return respond(ErrorResponse.of(now(), ErrorCode.FORBIDDEN, "Access denied", request.getRequestURI()));
    }

    @ExceptionHandler(NoResourceFoundException.class)
    public ResponseEntity<ErrorResponse> handleNoResourceFound(
            NoResourceFoundException ex, HttpServletRequest request) {
        return respond(
                ErrorResponse.of(now(), ErrorCode.RESOURCE_NOT_FOUND, "Resource not found", request.getRequestURI()));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleUnexpected(Exception ex, HttpServletRequest request) {
        log.error("Unhandled exception on {} {}", request.getMethod(), request.getRequestURI(), ex);
        return respond(ErrorResponse.of(
                now(), ErrorCode.INTERNAL_ERROR, "An unexpected error occurred", request.getRequestURI()));
    }

    private Instant now() {
        return Instant.now(clock);
    }

    private ResponseEntity<ErrorResponse> respond(ErrorResponse body) {
        return ResponseEntity.status(body.code().httpStatus()).body(body);
    }
}
