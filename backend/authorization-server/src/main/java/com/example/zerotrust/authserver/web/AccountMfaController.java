package com.example.zerotrust.authserver.web;

import com.example.zerotrust.authserver.dto.AuthDtos.MfaSetupResponse;
import com.example.zerotrust.authserver.service.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.List;

/**
 * Two-step verification enrolment, hosted on the Authorization Server.
 *
 * <p><b>Why here and not in the SPA.</b> The TOTP secret is the factor itself.
 * Showing it in the SPA would put it where any script in that page could read
 * it, which is the exact exposure the BFF architecture removes for tokens. So
 * enrolment follows the same rule as sign-in: the user is sent to the
 * Authorization Server, which already holds the session, and comes back after.
 *
 * <p>ADR-SEC-004: adding a factor is a sensitive change and needs <i>recent</i>
 * authentication, not just a session - a session left open on a shared machine
 * must not be enough to enrol an attacker's authenticator.
 */
@Controller
public class AccountMfaController {

    /** Session attribute stamped at sign-in; see SecurityConfig's success handler. */
    public static final String AUTH_TIME = "zt.auth_time";
    private static final Duration RECENT = Duration.ofMinutes(10);

    private final AuthService authService;
    private final String returnUrl;

    public AccountMfaController(AuthService authService,
                                @Value("${app.account.return-url:}") String returnUrl,
                                @Value("${app.oidc.bff-redirect-origins:http://localhost:5173}") List<String> origins) {
        this.authService = authService;
        this.returnUrl = returnUrl.isBlank() ? origins.get(0).trim() + "/" : returnUrl;
    }

    @GetMapping(value = "/oauth2/account/mfa", produces = MediaType.TEXT_HTML_VALUE)
    @ResponseBody
    public String status(Authentication auth, CsrfToken csrf, HttpServletRequest request,
                         HttpServletResponse response) throws IOException {
        if (!recent(request)) { reauthenticate(request, response); return null; }
        PageShell.secure(response);

        if (authService.isMfaEnabled(auth.getName())) {
            return PageShell.page("Two-step verification", """
                    <h1>Two-step verification</h1>
                    <p>Two-step verification is <strong>on</strong> for this account.</p>
                    <a class="button" href="%s">Back to the console</a>
                    """.formatted(PageShell.esc(returnUrl)));
        }
        return PageShell.page("Two-step verification", """
                <h1>Two-step verification</h1>
                <p>Add a second step to sign-in using an authenticator app. After this, a password alone will no longer be enough to sign in to your account.</p>
                <form method="post" action="/oauth2/account/mfa/start">
                <input type="hidden" name="%s" value="%s">
                <button type="submit">Set up two-step verification</button>
                </form>
                """.formatted(PageShell.esc(csrf.getParameterName()), PageShell.esc(csrf.getToken())));
    }

    /** State-changing, so POST + CSRF: starting enrolment replaces any unconfirmed secret. */
    @PostMapping(value = "/oauth2/account/mfa/start", produces = MediaType.TEXT_HTML_VALUE)
    @ResponseBody
    public String start(Authentication auth, CsrfToken csrf, HttpServletRequest request,
                        HttpServletResponse response) throws IOException {
        if (!recent(request)) { response.sendRedirect("/oauth2/account/mfa"); return null; }
        if (authService.isMfaEnabled(auth.getName())) { response.sendRedirect("/oauth2/account/mfa"); return null; }

        MfaSetupResponse setup = authService.startMfaSetup(auth.getName());
        PageShell.secure(response);
        return setupPage(setup, csrf, null);
    }

    @PostMapping(value = "/oauth2/account/mfa/activate", produces = MediaType.TEXT_HTML_VALUE)
    @ResponseBody
    public String activate(Authentication auth, CsrfToken csrf, @RequestParam String code,
                           HttpServletRequest request, HttpServletResponse response) throws IOException {
        if (!recent(request)) { response.sendRedirect("/oauth2/account/mfa"); return null; }
        PageShell.secure(response);

        try {
            authService.activateMfa(auth.getName(), code.trim());
        } catch (BadCredentialsException e) {
            // Re-show the pending secret so the user can try the next code.
            return authService.pendingMfaSetup(auth.getName())
                    .map(s -> setupPage(s, csrf, "That code did not match. Check the code and try again."))
                    .orElseGet(() -> "");
        }

        // Activation is a fresh trust boundary (it also revokes issued tokens).
        // End this session so the next sign-in proves the new factor.
        HttpSession session = request.getSession(false);
        if (session != null) session.invalidate();
        SecurityContextHolder.clearContext();

        return PageShell.page("Two-step verification", """
                <h1>Two-step verification is on</h1>
                <p>For your protection you have been signed out. Sign in again and you will be asked for a code from your authenticator app.</p>
                <a class="button" href="%s">Continue</a>
                """.formatted(PageShell.esc(returnUrl)));
    }

    private String setupPage(MfaSetupResponse setup, CsrfToken csrf, String error) {
        String notice = error == null ? "" : "<p class=\"error\" role=\"alert\">" + PageShell.esc(error) + "</p>";
        return PageShell.page("Set up two-step verification", """
                <h1>Set up two-step verification</h1>%s
                <p>1. Add this account to your authenticator app. On a phone, <a href="%s">open it in your authenticator</a>, or enter this key by hand:</p>
                <code>%s</code>
                <p>2. Enter the 6-digit code the app shows.</p>
                <form method="post" action="/oauth2/account/mfa/activate">
                <input type="hidden" name="%s" value="%s">
                <label>Authentication code<input name="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" maxlength="6" required autofocus></label>
                <button type="submit">Turn on</button>
                </form>
                """.formatted(notice, PageShell.esc(setup.otpauthUri()), PageShell.esc(setup.secret()),
                PageShell.esc(csrf.getParameterName()), PageShell.esc(csrf.getToken())));
    }

    private static boolean recent(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        return session != null
                && session.getAttribute(AUTH_TIME) instanceof Instant at
                && at.isAfter(Instant.now().minus(RECENT));
    }

    /** Send the user back through sign-in, then return here. */
    private static void reauthenticate(HttpServletRequest request, HttpServletResponse response) throws IOException {
        new HttpSessionRequestCache().saveRequest(request, response);
        response.sendRedirect("/oauth2/login?reauth");
    }
}
