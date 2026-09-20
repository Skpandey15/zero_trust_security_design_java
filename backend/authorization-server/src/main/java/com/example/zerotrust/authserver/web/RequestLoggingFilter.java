package com.example.zerotrust.authserver.web;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.UUID;

/**
 * Correlation + access logging.
 *
 * Puts a requestId into the MDC so EVERY log line produced while handling a
 * request carries it (essential for tracing across async/aggregated logs),
 * echoes it back in the X-Request-Id response header so clients can quote it
 * in bug reports, and emits one structured access line per request.
 */
@Component
@Order(1)
public class RequestLoggingFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger("http.access");

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        String incoming = request.getHeader("X-Request-Id");
        String requestId = (incoming != null && incoming.matches("[A-Za-z0-9\\-]{8,64}"))
                ? incoming
                : UUID.randomUUID().toString();

        MDC.put("requestId", requestId);
        response.setHeader("X-Request-Id", requestId);
        long start = System.nanoTime();
        try {
            chain.doFilter(request, response);
        } finally {
            long ms = (System.nanoTime() - start) / 1_000_000;
            // never log query strings — they may carry emails or other PII
            log.info("{} {} -> {} ({} ms)",
                    request.getMethod(), request.getRequestURI(), response.getStatus(), ms);
            MDC.clear();
        }
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return request.getRequestURI().startsWith("/actuator/health");
    }
}
