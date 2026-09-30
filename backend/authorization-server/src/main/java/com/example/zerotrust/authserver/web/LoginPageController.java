package com.example.zerotrust.authserver.web;

import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.util.HtmlUtils;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

/**
 * The interactive sign-in page for the authorization_code flow.
 *
 * <p>The web chain declares {@code loginPage("/oauth2/login")}, which tells
 * Spring Security that the application supplies the page - it generates none -
 * so without this the login redirect lands on a 404. This is where a user
 * enters their password: on the Authorization Server, never in the SPA
 * (ADR-SEC-003, ADR-SEC-007).
 *
 * <p>Deliberately static HTML with no template engine and no script. The CSP
 * allows only this page's own stylesheet, by hash, so nothing injected can run
 * or restyle it. It sets no {@code form-action}: the flow ends in a redirect to
 * the client origin, and browsers apply form-action to the redirect target.
 */
@Controller
public class LoginPageController {

    private static final String STYLE = """
            body{margin:0;font:16px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif;background:#f6f7f9;color:#16202a}
            main{max-width:24rem;margin:3rem auto;padding:1.5rem;background:#fff;border:1px solid #d8dee5;border-radius:8px}
            h1{margin:0 0 1rem;font-size:1.4rem}
            form{display:grid;gap:.9rem}
            label{display:grid;gap:.25rem;font-weight:500}
            input{font:inherit;padding:.55rem .65rem;border:1px solid #d8dee5;border-radius:6px}
            button{font:inherit;font-weight:600;padding:.6rem 1rem;border:0;border-radius:6px;background:#12304a;color:#fff;cursor:pointer}
            .error{color:#b3261e;margin:0}
            """;

    private static final String CSP = "default-src 'none'; style-src 'sha256-" + sha256(STYLE)
            + "'; frame-ancestors 'none'; base-uri 'none'";

    @GetMapping(value = "/oauth2/login", produces = MediaType.TEXT_HTML_VALUE)
    @ResponseBody
    public String login(CsrfToken csrf, @RequestParam(required = false) String error,
                        HttpServletResponse response) {
        response.setHeader("Content-Security-Policy", CSP);
        response.setHeader("Cache-Control", "no-store");

        // Same message whatever went wrong: unknown user, bad password and a locked
        // account are indistinguishable to the caller.
        String failure = error == null ? ""
                : "<p class=\"error\" role=\"alert\">Sign-in failed. Check your email and password.</p>";

        return """
                <!doctype html>
                <html lang="en"><head><meta charset="utf-8">
                <meta name="viewport" content="width=device-width,initial-scale=1">
                <title>Sign in</title><style>%s</style></head>
                <body><main><h1>Sign in</h1>%s
                <form method="post" action="/oauth2/login">
                <input type="hidden" name="%s" value="%s">
                <label>Email<input name="username" type="email" autocomplete="username" required autofocus></label>
                <label>Password<input name="password" type="password" autocomplete="current-password" required></label>
                <button type="submit">Sign in</button>
                </form></main></body></html>
                """.formatted(STYLE, failure,
                HtmlUtils.htmlEscape(csrf.getParameterName()), HtmlUtils.htmlEscape(csrf.getToken()));
    }

    private static String sha256(String value) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(digest);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
