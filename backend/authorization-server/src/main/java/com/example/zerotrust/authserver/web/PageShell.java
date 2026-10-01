package com.example.zerotrust.authserver.web;

import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.util.HtmlUtils;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

/**
 * The shell shared by the Authorization Server's own pages (sign-in, two-step
 * verification). Deliberately static HTML: no template engine, no script, and a
 * CSP that allows only this stylesheet, by hash, so nothing injected can run or
 * restyle a page that handles credentials.
 *
 * <p>No {@code form-action} directive: the sign-in flow ends in a redirect to
 * the client origin, and browsers apply form-action to the redirect target.
 */
final class PageShell {

    private static final String STYLE = """
            body{margin:0;font:16px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif;background:#f6f7f9;color:#16202a}
            main{max-width:26rem;margin:3rem auto;padding:1.5rem;background:#fff;border:1px solid #d8dee5;border-radius:8px}
            h1{margin:0 0 1rem;font-size:1.4rem}
            form{display:grid;gap:.9rem;margin:1rem 0 0}
            label{display:grid;gap:.25rem;font-weight:500}
            input{font:inherit;padding:.55rem .65rem;border:1px solid #d8dee5;border-radius:6px}
            button,a.button{font:inherit;font-weight:600;padding:.6rem 1rem;border:0;border-radius:6px;background:#12304a;color:#fff;cursor:pointer;text-decoration:none;display:inline-block;text-align:center}
            .error{color:#b3261e;margin:0}
            .hint{color:#5b6673;font-size:.875rem;margin:0}
            code{display:block;padding:.6rem .65rem;background:#f6f7f9;border:1px solid #d8dee5;border-radius:6px;word-break:break-all;letter-spacing:.05em}
            """;

    private static final String CSP = "default-src 'none'; style-src 'sha256-" + sha256(STYLE)
            + "'; frame-ancestors 'none'; base-uri 'none'";

    private PageShell() {}

    /** Sets the headers every credential-handling page needs. */
    static void secure(HttpServletResponse response) {
        response.setHeader("Content-Security-Policy", CSP);
        response.setHeader("Cache-Control", "no-store");
        response.setContentType("text/html;charset=UTF-8");
    }

    static String page(String title, String body) {
        return """
                <!doctype html>
                <html lang="en"><head><meta charset="utf-8">
                <meta name="viewport" content="width=device-width,initial-scale=1">
                <title>%s</title><style>%s</style></head>
                <body><main>%s</main></body></html>
                """.formatted(esc(title), STYLE, body);
    }

    static String esc(String value) {
        return HtmlUtils.htmlEscape(value == null ? "" : value);
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
