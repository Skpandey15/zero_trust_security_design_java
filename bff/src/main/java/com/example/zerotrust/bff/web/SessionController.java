package com.example.zerotrust.bff.web;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.LinkedHashMap;
import java.util.List;
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

    private final ClientRegistrationRepository registrations;

    public SessionController(ClientRegistrationRepository registrations) {
        this.registrations = registrations;
    }

    @GetMapping
    public Map<String, Object> session(Authentication authentication,
                                       @AuthenticationPrincipal OidcUser user) {
        boolean authenticated = authentication != null && authentication.isAuthenticated()
                && user != null;
        if (!authenticated) {
            return Map.of("authenticated", false);
        }
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("authenticated", true);
        body.put("subject", user.getSubject());
        // What THIS session proved, read from the ID token's amr claim that the
        // Authorization Server wrote from the authenticated session - never from
        // anything the browser supplied (ADR-SEC-004, ADR-SEC-011).
        body.put("authenticationLevel", levelOf(user));
        String settings = securitySettingsUrl(authentication);
        if (settings != null) {
            body.put("securitySettingsUrl", settings);
        }
        return body;
    }

    /** "MFA" only when the session proved a second factor; anything else is password assurance. */
    static String levelOf(OidcUser user) {
        List<String> amr = user.getClaimAsStringList("amr");
        return amr != null && amr.contains("otp") ? "MFA" : "PASSWORD";
    }

    /**
     * Where the user manages two-step verification. It lives on the Authorization
     * Server, not in the SPA: the TOTP secret is the factor itself, and showing
     * it in the SPA would put it where any script in that page can read it. A URL
     * is not a credential, so handing it to the browser is fine.
     */
    private String securitySettingsUrl(Authentication authentication) {
        if (!(authentication instanceof OAuth2AuthenticationToken oauth)) return null;
        ClientRegistration registration = registrations.findByRegistrationId(oauth.getAuthorizedClientRegistrationId());
        if (registration == null) return null;
        String issuer = registration.getProviderDetails().getIssuerUri();
        return issuer == null ? null : issuer.replaceAll("/+$", "") + "/oauth2/account/mfa";
    }

    /**
     * Ends the session on both sides.
     *
     * <p>ADR-SEC-011: revocation is immediate because the session is
     * authoritative - it does not wait for a token to expire. The BFF session
     * (and the tokens it holds) is destroyed here; the response carries the
     * Authorization Server's end-session URL so the browser can end that
     * session too. The URL holds the ID token as a hint, and the ID token is
     * not a credential for any API - it identifies the session to end.
     */
    @PostMapping("/logout")
    public Map<String, Object> logout(HttpServletRequest request, Authentication authentication) {
        String logoutUrl = null;
        if (authentication instanceof OAuth2AuthenticationToken oauth
                && oauth.getPrincipal() instanceof OidcUser oidc) {
            logoutUrl = endSessionUrl(request, oauth.getAuthorizedClientRegistrationId(), oidc);
        }

        HttpSession session = request.getSession(false);
        if (session != null) {
            session.invalidate();
        }
        SecurityContextHolder.clearContext();

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("loggedOut", true);
        if (logoutUrl != null) {
            body.put("logoutUrl", logoutUrl);
        }
        return body;
    }

    private String endSessionUrl(HttpServletRequest request, String registrationId, OidcUser user) {
        ClientRegistration registration = registrations.findByRegistrationId(registrationId);
        if (registration == null) return null;
        Object endpoint = registration.getProviderDetails().getConfigurationMetadata().get("end_session_endpoint");
        if (endpoint == null) return null;

        // Forwarded headers are honoured (server.forward-headers-strategy), so this
        // is the public https origin, and it must match a registered post-logout URI.
        String home = ServletUriComponentsBuilder.fromContextPath(request).path("/").build().toUriString();
        return UriComponentsBuilder.fromUriString(endpoint.toString())
                .queryParam("id_token_hint", user.getIdToken().getTokenValue())
                .queryParam("post_logout_redirect_uri", home)
                .build().encode().toUriString();
    }
}
