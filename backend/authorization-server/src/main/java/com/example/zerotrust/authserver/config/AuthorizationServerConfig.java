package com.example.zerotrust.authserver.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

import java.util.UUID;

/**
 * Standards-compliant OAuth2.1 / OIDC provider (Spring Authorization Server). Makes
 * this service pluggable: any resource server can validate its tokens via the JWKS
 * endpoint + OIDC discovery, and clients obtain tokens via the standard grants.
 *
 * Endpoints (from OIDC discovery at /.well-known/openid-configuration):
 *   - JWKS:          /oauth2/jwks
 *   - Token:         /oauth2/token       (authorization_code, client_credentials, refresh_token)
 *   - Authorize:     /oauth2/authorize   (authorization_code + PKCE)
 *   - UserInfo:      /userinfo
 */
@Configuration
public class AuthorizationServerConfig {

    @Bean
    @Order(1)
    SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        // Spring Security 7 relocated this configurer into spring-security-config
        // and removed the authorizationServer() static factory; construct it directly.
        OAuth2AuthorizationServerConfigurer authorizationServer =
                new OAuth2AuthorizationServerConfigurer();
        http
            .securityMatcher(authorizationServer.getEndpointsMatcher())
            .with(authorizationServer, as -> as.oidc(Customizer.withDefaults()))
            .authorizeHttpRequests(a -> a.anyRequest().authenticated())
            // Interactive (authorization_code) callers without a session are redirected to
            // the login page; machine (client_credentials) callers authenticate inline.
            .exceptionHandling(e -> e.defaultAuthenticationEntryPointFor(
                    // login page lives under /oauth2 so it routes to the backend (not the SPA's /login)
                    new LoginUrlAuthenticationEntryPoint("/oauth2/login"),
                    new MediaTypeRequestMatcher(MediaType.TEXT_HTML)))
            // OIDC UserInfo is a resource-server endpoint — validate the bearer token.
            .oauth2ResourceServer(rs -> rs.jwt(Customizer.withDefaults()));
        return http.build();
    }

    @Bean
    RegisteredClientRepository registeredClientRepository(
            PasswordEncoder passwordEncoder,
            @Value("${app.oidc.service-client-secret:service-secret}") String serviceSecret) {

        // Public SPA client: Authorization Code + PKCE, no client secret.
        RegisteredClient spa = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("auth-ui")
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri("http://localhost:5173/callback")
                .redirectUri("https://localhost:8443/callback")
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE)
                .clientSettings(ClientSettings.builder()
                        .requireProofKey(true)            // PKCE mandatory for the public client
                        .requireAuthorizationConsent(false) // first-party client — no consent screen
                        .build())
                .build();

        // Confidential service client: Client Credentials (machine-to-machine).
        // Secret is externalized (app.oidc.service-client-secret / a k8s Secret in prod).
        RegisteredClient service = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("service-account")
                .clientSecret(passwordEncoder.encode(serviceSecret))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .scope("api.read")
                .build();

        return new InMemoryRegisteredClientRepository(spa, service);
    }

    @Bean
    AuthorizationServerSettings authorizationServerSettings(SecurityProperties props) {
        return AuthorizationServerSettings.builder().issuer(props.issuer()).build();
    }
}
