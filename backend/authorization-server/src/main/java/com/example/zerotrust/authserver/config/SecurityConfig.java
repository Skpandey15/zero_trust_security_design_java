package com.example.zerotrust.authserver.config;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.core.env.Environment;
import org.springframework.core.env.Profiles;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/**
 * Three security filter chains, in order:
 *   1. {@code AuthorizationServerConfig} (Order 1) — the OAuth2/OIDC endpoints.
 *   2. API chain (Order 2, here) — stateless, JWT-verified, deny-by-default; scoped
 *      to /api, /actuator, docs (and the local H2 console). Zero-trust posture.
 *   3. Web/login chain (Order 3, here) — session + form login, so the interactive
 *      authorization_code flow can authenticate the user (backed by the JPA user store).
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    @Bean
    @Order(2)
    SecurityFilterChain apiSecurityFilterChain(HttpSecurity http, Environment env,
                                               @Qualifier("apiJwtDecoder") JwtDecoder apiJwtDecoder) throws Exception {
        boolean local = env.acceptsProfiles(Profiles.of("local"));

        List<String> matched = new ArrayList<>(List.of(
                "/api/**", "/actuator/**", "/v3/api-docs/**", "/swagger-ui/**", "/swagger-ui.html"));
        if (local) matched.add("/h2-console/**");   // LOCAL-only dev surface

        http
            .securityMatcher(matched.toArray(String[]::new))
            .csrf(csrf -> csrf.disable())   // stateless bearer-token API — no cookies, no CSRF surface
            .cors(Customizer.withDefaults())
            .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(auth -> {
                auth.requestMatchers("/api/auth/register", "/api/auth/login", "/api/auth/refresh").permitAll()
                    .requestMatchers("/v3/api-docs/**", "/swagger-ui/**", "/swagger-ui.html").permitAll()
                    .requestMatchers("/actuator/health", "/actuator/health/**").permitAll();
                if (local) {
                    auth.requestMatchers("/h2-console/**").permitAll();
                }
                auth.requestMatchers("/actuator/**").authenticated()   // metrics/prometheus require a token
                    .requestMatchers("/api/auth/logout").authenticated()
                    .requestMatchers("/api/users/me/**").hasAuthority("profile:read")
                    .requestMatchers("/api/admin/security/**").hasAuthority("security:insights")
                    .requestMatchers("/api/admin/**").hasRole("ADMIN")
                    // ZERO TRUST DEFAULT: everything else in this chain's scope is denied outright
                    .anyRequest().denyAll();
            })
            .headers(headers -> {
                headers.httpStrictTransportSecurity(hsts -> hsts
                        .includeSubDomains(true)
                        .maxAgeInSeconds(31536000))
                    .contentSecurityPolicy(csp -> csp.policyDirectives("default-src 'self'"));
                if (local) {
                    headers.frameOptions(f -> f.sameOrigin());   // H2 console frames itself
                }
            })
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> jwt
                    .decoder(apiJwtDecoder)   // strict: at+jwt profile + pinned audience
                    .jwtAuthenticationConverter(jwtAuthenticationConverter())))
            .exceptionHandling(ex -> ex
                .authenticationEntryPoint((req, res, e) -> res.sendError(HttpStatus.UNAUTHORIZED.value()))
                .accessDeniedHandler((req, res, e) -> res.sendError(HttpStatus.FORBIDDEN.value())));
        return http.build();
    }

    /**
     * Interactive login chain for the OAuth2 authorization_code flow: a user hitting
     * /oauth2/authorize without a session is redirected here to authenticate via the
     * form-login page (username/password checked against the JPA user store with
     * Argon2id). Session-based; CSRF stays enabled for the login POST.
     *
     * NOTE: this path authenticates password-only — MFA / lockout / step-up (in the
     * custom /api/auth pipeline) are not yet enforced on the OIDC login. Tracked as
     * a follow-up (an MFA-aware authentication flow).
     */
    @Bean
    @Order(3)
    SecurityFilterChain webLoginSecurityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/oauth2/login", "/error").permitAll()
                .anyRequest().authenticated())
            // login page at /oauth2/login so the ingress routes it to the backend,
            // keeping clear of the SPA's own /login route.
            .formLogin(form -> form
                .loginPage("/oauth2/login")
                .loginProcessingUrl("/oauth2/login")
                .permitAll());
        return http.build();
    }

    /**
     * The token's "authorities" claim carries both ROLE_* entries and fine-grained
     * permissions (e.g. "users:manage"), already prefixed — so no additional prefix.
     */
    private JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtGrantedAuthoritiesConverter authorities = new JwtGrantedAuthoritiesConverter();
        authorities.setAuthoritiesClaimName("authorities");
        authorities.setAuthorityPrefix("");
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(authorities);
        return converter;
    }

    /**
     * CORS policy driven by app.cors.allowed-origins. With no origins configured the
     * source registers nothing, so cross-origin browser calls are blocked (same-origin
     * still works). Bearer tokens travel in the Authorization header, so credentials
     * (cookies) are not allowed — which also permits an explicit origin allow-list.
     */
    @Bean
    CorsConfigurationSource corsConfigurationSource(CorsProperties props) {
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        if (!props.allowedOrigins().isEmpty()) {
            CorsConfiguration config = new CorsConfiguration();
            config.setAllowedOrigins(props.allowedOrigins());
            config.setAllowedMethods(List.of("GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"));
            config.setAllowedHeaders(List.of("Authorization", "Content-Type"));
            config.setAllowCredentials(false);
            config.setMaxAge(Duration.ofHours(1));
            source.registerCorsConfiguration("/api/**", config);
        }
        return source;
    }

    /** Argon2id — OWASP's first-choice password hashing algorithm. */
    @Bean
    PasswordEncoder passwordEncoder() {
        return Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8();
    }

    @Bean
    AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }
}
