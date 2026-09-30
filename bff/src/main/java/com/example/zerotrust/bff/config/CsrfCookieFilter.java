package com.example.zerotrust.bff.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Spring Security defers CSRF token creation: the XSRF-TOKEN cookie is only
 * written once something reads the token. A single-page app never renders a
 * server template that would, so its first state-changing request would carry
 * no token and be rejected. Reading it here makes every response set the
 * cookie the SPA echoes back in a header.
 */
final class CsrfCookieFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        CsrfToken token = (CsrfToken) request.getAttribute(CsrfToken.class.getName());
        if (token != null) {
            token.getToken();   // forces the deferred token to be generated and the cookie set
        }
        chain.doFilter(request, response);
    }
}
