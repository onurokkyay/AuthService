package com.krawenn.auth.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.UUID;
import java.util.regex.Pattern;
import org.slf4j.MDC;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Puts a request id into the logging context and echoes it back, so a report of "my
 * login failed at 14:02" can be traced to exact log lines.
 *
 * <p>An inbound id is accepted only if it looks like an id. It is caller-controlled and
 * ends up in log output, where newlines or control characters would let a caller forge
 * log entries.
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class RequestIdFilter extends OncePerRequestFilter {

    public static final String HEADER = "X-Request-Id";

    static final String MDC_KEY = "requestId";

    private static final Pattern SAFE_ID = Pattern.compile("^[A-Za-z0-9._-]{1,64}$");

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String requestId = resolve(request.getHeader(HEADER));
        MDC.put(MDC_KEY, requestId);
        response.setHeader(HEADER, requestId);
        try {
            chain.doFilter(request, response);
        } finally {
            // Mandatory with pooled or virtual threads: a leaked value would be attached
            // to whichever request runs next.
            MDC.remove(MDC_KEY);
        }
    }

    private String resolve(String inbound) {
        if (inbound != null && SAFE_ID.matcher(inbound).matches()) {
            return inbound;
        }
        return UUID.randomUUID().toString();
    }
}
