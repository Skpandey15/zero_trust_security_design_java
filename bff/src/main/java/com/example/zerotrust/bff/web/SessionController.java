package com.example.zerotrust.bff.web;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * The only authentication state the browser can observe.
 *
 * <p>ADR-SEC-007: this endpoint reports whether the session is authenticated
 * and who it belongs to. It never returns a token, a refresh token, or anything
 * usable as a credential.
 */
@RestController
@RequestMapping("/api/session")
public class SessionController {

    @GetMapping
    public Map<String, Object> session(Authentication authentication,
                                       @AuthenticationPrincipal OidcUser user) {
        boolean authenticated = authentication != null && authentication.isAuthenticated()
                && user != null;
        if (!authenticated) {
            return Map.of("authenticated", false);
        }
        return Map.of(
                "authenticated", true,
                "subject", user.getSubject(),
                // Assurance level is read from server-side session state, not
                // from anything the browser supplied (ADR-SEC-011).
                "authenticationLevel", "PASSWORD");
    }

    /**
     * Terminates the server-side session. ADR-SEC-011: revocation is immediate
     * because the session is authoritative — it does not wait for a token to
     * expire, and it does not rely on the cookie being discarded.
     */
    @PostMapping("/logout")
    public ResponseEntity<Void> logout(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session != null) {
            session.invalidate();
        }
        return ResponseEntity.noContent().build();
    }
}
