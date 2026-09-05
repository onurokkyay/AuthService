package com.krawenn.auth.security;

import com.krawenn.auth.error.UnauthenticatedException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerExceptionResolver;

/**
 * Routes filter-chain rejections through the ordinary exception handling.
 *
 * <p>Spring Security would otherwise answer with an empty 401/403 body while application
 * errors return an {@link com.krawenn.auth.error.ErrorResponse}. Delegating to the
 * resolver keeps one error shape across the whole service, which is what lets a consumer
 * parse failures without special-casing where they came from.
 */
@Component
public class SecurityErrorHandlers implements AuthenticationEntryPoint, AccessDeniedHandler {

    private final HandlerExceptionResolver resolver;

    public SecurityErrorHandlers(@Qualifier("handlerExceptionResolver") HandlerExceptionResolver resolver) {
        this.resolver = resolver;
    }

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) {
        resolver.resolveException(request, response, null, new UnauthenticatedException());
    }

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException exception) {
        resolver.resolveException(request, response, null, exception);
    }
}
