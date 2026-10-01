package com.example.zerotrust.resource.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Deny-by-default resource-server chain with strict token validation.
 *
 * <p>ADR-SEC-008. Two details that are easy to get wrong:
 *
 * <ul>
 *   <li>{@code JwtValidators.createDefaultWithIssuer()} wires only the
 *       timestamp and issuer validators - it does <b>not</b> check audience.
 *       Using it leaves any token minted under the same issuer and key
 *       acceptable here, including OAuth2 tokens meant for another audience.
 *       {@code createAtJwtValidator()} refuses to build without an audience,
 *       which turns that mistake into a startup failure.</li>
 *   <li>{@code NimbusJwtDecoder} rejects {@code typ=at+jwt} at the Nimbus layer
 *       before any validator runs, because its default JOSE type verifier
 *       allows only {@code JWT}. {@code validateType(false)} moves type
 *       checking into the validator chain, where the at+jwt profile enforces
 *       it.</li>
 * </ul>
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class ResourceServerSecurityConfig {

    @Bean
    SecurityFilterChain apiSecurityFilterChain(HttpSecurity http, JwtDecoder jwtDecoder) throws Exception {
        http
            .securityMatcher("/api/**", "/actuator/**")
            .csrf(csrf -> csrf.disable())          // bearer-token API; no cookies here
            .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/actuator/health", "/actuator/health/**").permitAll()
                // Authenticated is the coarse gate only. The decision that matters is made
                // per operation, against the resource's own tenant (ADR-SEC-013/015).
                .requestMatchers("/api/documents", "/api/documents/**", "/api/tenants").authenticated()
                // ZERO TRUST DEFAULT: anything not listed above does not exist.
                .anyRequest().denyAll())
            .oauth2ResourceServer(oauth2 -> oauth2.jwt(jwt -> jwt.decoder(jwtDecoder)))
            .exceptionHandling(ex -> ex
                .authenticationEntryPoint((req, res, e) -> res.sendError(HttpStatus.UNAUTHORIZED.value()))
                .accessDeniedHandler((req, res, e) -> res.sendError(HttpStatus.FORBIDDEN.value())));
        return http.build();
    }

    @Bean
    JwtDecoder jwtDecoder(@Value("${app.token.jwk-set-uri}") String jwkSetUri,
                          @Value("${app.token.issuer}") String issuer,
                          @Value("${app.token.api-audience}") String audience,
                          @Value("${app.token.client-id}") String clientId) {

        NimbusJwtDecoder decoder = NimbusJwtDecoder.withJwkSetUri(jwkSetUri)
                .validateType(false)   // see the class javadoc
                .build();

        decoder.setJwtValidator(accessTokenValidator(issuer, audience, clientId));
        return decoder;
    }

    /**
     * The one definition of what an acceptable access token is: RFC 9068 at+jwt,
     * from this issuer, for THIS audience, with a client_id. Shared by the decoder
     * and the tests, so the tests exercise the real chain rather than a copy.
     */
    public static OAuth2TokenValidator<Jwt> accessTokenValidator(String issuer, String audience, String clientId) {
        return JwtValidators.createAtJwtValidator()
                .issuer(issuer)
                .audience(audience)
                .clientId(clientId)
                .build();
    }
}
