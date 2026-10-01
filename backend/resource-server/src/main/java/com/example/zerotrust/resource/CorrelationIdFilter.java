package com.example.zerotrust.resource;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.MDC;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.UUID;
import java.util.regex.Pattern;

/**
 * Gives every request a correlation id and puts it in the log context, so a
 * security decision can be tied to the request that caused it (ADR-SEC-023).
 * A caller-supplied id is kept only if it looks like one - otherwise a client
 * could inject newlines or forged fields into the audit log.
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class CorrelationIdFilter extends OncePerRequestFilter {

    static final String HEADER = "X-Request-Id";
    private static final Pattern SAFE = Pattern.compile("[A-Za-z0-9._-]{8,64}");

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        String supplied = request.getHeader(HEADER);
        String id = supplied != null && SAFE.matcher(supplied).matches() ? supplied : UUID.randomUUID().toString();
        MDC.put("requestId", id);
        response.setHeader(HEADER, id);
        try {
            chain.doFilter(request, response);
        } finally {
            MDC.remove("requestId");
        }
    }
}
