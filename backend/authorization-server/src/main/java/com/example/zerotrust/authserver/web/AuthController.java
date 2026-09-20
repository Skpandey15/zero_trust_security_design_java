package com.example.zerotrust.authserver.web;

import com.example.zerotrust.authserver.config.SecurityProperties;
import com.example.zerotrust.authserver.dto.AuthDtos.*;
import com.example.zerotrust.authserver.service.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    /**
     * The refresh token travels ONLY in this cookie — httpOnly (JS can't read it),
     * Secure, SameSite=Strict (not sent cross-site → CSRF-safe), and path-scoped to
     * /api/auth so it's attached only to refresh/logout. The access token stays in
     * the JSON body (held in the SPA's memory, never persisted). This keeps an XSS
     * from stealing the long-lived credential.
     */
    private static final String REFRESH_COOKIE = "refresh_token";
    private static final String COOKIE_PATH = "/api/auth";

    private final AuthService authService;
    private final SecurityProperties props;

    public AuthController(AuthService authService, SecurityProperties props) {
        this.authService = authService;
        this.props = props;
    }

    @PostMapping("/register")
    @ResponseStatus(HttpStatus.CREATED)
    public UserResponse register(@Valid @RequestBody RegisterRequest request) {
        return authService.register(request);
    }

    @PostMapping("/login")
    public ResponseEntity<TokenResponse> login(@Valid @RequestBody LoginRequest request, HttpServletRequest http) {
        // getRemoteAddr() is the proxy-validated client IP (server.forward-headers-strategy).
        TokenResponse tokens = authService.login(request, http.getRemoteAddr(), http.getHeader("User-Agent"));
        return withRefreshCookie(tokens);
    }

    @PostMapping("/refresh")
    public ResponseEntity<TokenResponse> refresh(
            @CookieValue(name = REFRESH_COOKIE, required = false) String refreshToken) {
        if (refreshToken == null || refreshToken.isBlank()) {
            throw new BadCredentialsException("Missing refresh token");
        }
        TokenResponse tokens = authService.refresh(new RefreshRequest(refreshToken));
        return withRefreshCookie(tokens);
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@AuthenticationPrincipal Jwt jwt) {
        if (jwt != null) {
            authService.logout(jwt.getSubject());
        }
        ResponseCookie cleared = baseCookie("").maxAge(0).build();   // expire the cookie
        return ResponseEntity.noContent().header(HttpHeaders.SET_COOKIE, cleared.toString()).build();
    }

    /** Set the refresh token as a cookie; return only the access token in the body. */
    private ResponseEntity<TokenResponse> withRefreshCookie(TokenResponse tokens) {
        ResponseCookie cookie = baseCookie(tokens.refreshToken())
                .maxAge(props.refreshTokenTtl())
                .build();
        TokenResponse body = new TokenResponse(
                tokens.accessToken(), null, tokens.tokenType(), tokens.expiresInSeconds());
        return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, cookie.toString()).body(body);
    }

    private ResponseCookie.ResponseCookieBuilder baseCookie(String value) {
        return ResponseCookie.from(REFRESH_COOKIE, value)
                .httpOnly(true)
                .secure(props.cookieSecure())   // false only for local http dev
                .sameSite("Strict")
                .path(COOKIE_PATH);
    }
}
