package com.example.zerotrust.bff.config;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestCustomizers;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;

/**
 * The browser trust boundary.
 *
 * <p>ADR-SEC-007. Cookie authentication is <b>ambient</b>: the browser attaches
 * the session cookie to qualifying cross-site requests without the page's
 * involvement. Moving from an {@code Authorization} header to a cookie
 * therefore reintroduces CSRF, which bearer tokens had removed. That is a real
 * cost, paid deliberately, and it is mitigated by an explicit anti-CSRF token -
 * {@code SameSite} is defence in depth, not the control.
 *
 * <p>The CSRF token is deliberately readable by JavaScript. It is not a
 * credential; the session cookie is, and that one is HttpOnly.
 */
@Configuration
@EnableWebSecurity
@EnableConfigurationProperties(BffProperties.class)
public class BffSecurityConfig {

    @Bean
    SecurityFilterChain bffSecurityFilterChain(HttpSecurity http, BffProperties props,
                                               ClientRegistrationRepository registrations) throws Exception {
        CookieCsrfTokenRepository csrfRepository = CookieCsrfTokenRepository.withHttpOnlyFalse();

        // ADR-SEC-003: PKCE on every authorization request. Spring applies it to
        // public clients by default; for this confidential client it must be
        // asked for, or the code is bound to nothing but the client secret.
        DefaultOAuth2AuthorizationRequestResolver authorizationRequests =
                new DefaultOAuth2AuthorizationRequestResolver(registrations, "/oauth2/authorization");
        authorizationRequests.setAuthorizationRequestCustomizer(OAuth2AuthorizationRequestCustomizers.withPkce());

        http
            .csrf(csrf -> csrf
                .csrfTokenRepository(csrfRepository)
                .csrfTokenRequestHandler(new CsrfTokenRequestAttributeHandler()))
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/api/session", "/actuator/health", "/actuator/health/**").permitAll()
                // Registration is the one unauthenticated write; CSRF still applies to it.
                .requestMatchers("/api/auth/register").permitAll()
                .requestMatchers("/login/**", "/oauth2/**").permitAll()
                // ZERO TRUST DEFAULT: nothing else is reachable unauthenticated.
                .anyRequest().authenticated())
            // The BFF is a confidential OAuth client; tokens stay server-side.
            .oauth2Login(login -> login
                .authorizationEndpoint(endpoint -> endpoint.authorizationRequestResolver(authorizationRequests))
                // The SPA owns the pages; the BFF only redirects to them.
                .defaultSuccessUrl("/", true)
                .failureUrl("/login?error"))
            .addFilterAfter(new CsrfCookieFilter(), BasicAuthenticationFilter.class)
            .headers(headers -> headers
                .httpStrictTransportSecurity(hsts -> hsts
                        .includeSubDomains(true)
                        .maxAgeInSeconds(31536000))
                .contentSecurityPolicy(csp -> csp.policyDirectives(props.contentSecurityPolicy())))
            .exceptionHandling(ex -> ex
                // An SPA wants a status code, not a redirect to a login page.
                .authenticationEntryPoint((req, res, e) ->
                        res.sendError(HttpStatus.UNAUTHORIZED.value())));

        return http.build();
    }
}
