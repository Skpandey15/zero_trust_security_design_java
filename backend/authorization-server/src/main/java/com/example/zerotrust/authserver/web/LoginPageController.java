package com.example.zerotrust.authserver.web;

import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

/**
 * The interactive sign-in page for the authorization_code flow.
 *
 * <p>The web chain declares {@code loginPage("/oauth2/login")}, which tells
 * Spring Security that the application supplies the page - it generates none -
 * so without this the login redirect lands on a 404. This is where a user
 * enters their password: on the Authorization Server, never in the SPA
 * (ADR-SEC-003, ADR-SEC-007).
 *
 * <p>The authentication-code field is always present, and optional in the
 * markup, so the page does not reveal whether an account has two-step
 * verification. The server requires the code for accounts that do.
 */
@Controller
public class LoginPageController {

    @GetMapping(value = "/oauth2/login", produces = MediaType.TEXT_HTML_VALUE)
    @ResponseBody
    public String login(CsrfToken csrf, @RequestParam(required = false) String error,
                        @RequestParam(required = false) String reauth, HttpServletResponse response) {
        PageShell.secure(response);

        // One message whatever went wrong: unknown user, wrong password, missing or
        // wrong code, and a locked account are indistinguishable to the caller.
        String notice = error != null
                ? "<p class=\"error\" role=\"alert\">Sign-in failed. Check your details and try again.</p>"
                : reauth != null
                ? "<p class=\"hint\">Confirm it is you to continue.</p>"
                : "";

        return PageShell.page("Sign in", """
                <h1>Sign in</h1>%s
                <form method="post" action="/oauth2/login">
                <input type="hidden" name="%s" value="%s">
                <label>Email<input name="username" type="email" autocomplete="username" required autofocus></label>
                <label>Password<input name="password" type="password" autocomplete="current-password" required></label>
                <label>Authentication code<input name="otp" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" maxlength="6"></label>
                <p class="hint">Only needed if you have turned on two-step verification.</p>
                <button type="submit">Sign in</button>
                </form>
                """.formatted(notice, PageShell.esc(csrf.getParameterName()), PageShell.esc(csrf.getToken())));
    }
}
