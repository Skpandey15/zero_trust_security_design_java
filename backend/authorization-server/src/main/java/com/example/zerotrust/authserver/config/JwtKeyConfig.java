package com.example.zerotrust.authserver.config;

import com.example.zerotrust.authserver.repository.UserRepository;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.*;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

/**
 * One RS256 key pair, shared by both token systems:
 *   - the OAuth2/OIDC authorization server (via the {@link JWKSource}, which also
 *     backs the public JWKS endpoint used by external resource servers), and
 *   - the custom /api/auth tokens.
 * The decoder validates signature + issuer, plus continuous verification for our
 * own tokens (see {@link TokenRevocationValidator}). The JwtEncoder is provided by
 * the authorization server's auto-configuration from the JWKSource below.
 */
@Configuration
public class JwtKeyConfig {

    private static final Logger log = LoggerFactory.getLogger(JwtKeyConfig.class);

    @Bean
    RSAKey rsaKey(SecurityProperties props) throws Exception {
        if (props.rsaPrivateKey() != null && props.rsaPublicKey() != null) {
            return new RSAKey.Builder(props.rsaPublicKey())
                    .privateKey(props.rsaPrivateKey())
                    .keyID("configured")
                    .build();
        }
        log.warn("No RSA key pair configured — generating an ephemeral one. "
                + "All tokens become invalid on restart. Do NOT use in production.");
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair pair = generator.generateKeyPair();
        return new RSAKey.Builder((RSAPublicKey) pair.getPublic())
                .privateKey((RSAPrivateKey) pair.getPrivate())
                .keyID(UUID.randomUUID().toString())
                .build();
    }

    /** Publishes the public key at the JWKS endpoint and signs authorization-server tokens. */
    @Bean
    JWKSource<SecurityContext> jwkSource(RSAKey rsaKey) {
        return new ImmutableJWKSet<>(new JWKSet(rsaKey));
    }

    /** Shared encoder for both the custom /api/auth tokens and the authorization server. */
    @Bean
    JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource) {
        return new NimbusJwtEncoder(jwkSource);
    }

    /**
     * Default decoder, used by the authorization-server chain (e.g. OIDC /userinfo).
     * Validates signature + issuer + time, plus continuous verification for our own
     * uid-bearing tokens. It deliberately does NOT pin an audience: OIDC tokens are
     * issued for their own clients/resources.
     */
    @Bean
    @Primary
    JwtDecoder jwtDecoder(RSAKey rsaKey, SecurityProperties props, UserRepository users) throws Exception {
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withPublicKey(rsaKey.toRSAPublicKey()).build();

        OAuth2TokenValidator<Jwt> withIssuer = JwtValidators.createDefaultWithIssuer(props.issuer());
        // Continuous verification applies to our own tokens (identified by the uid claim);
        // authorization-server/OIDC tokens pass through the standard issuer/signature checks.
        OAuth2TokenValidator<Jwt> revocation = new TokenRevocationValidator(users);

        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(withIssuer, revocation));
        return decoder;
    }

    /**
     * Strict decoder for the /api chain. Enforces the RFC 9068 access-token profile
     * (typ=at+jwt plus the required claims) AND pins the audience, so a token minted
     * for another audience under the same issuer and key -- notably an OAuth2/OIDC
     * token from the authorization server -- cannot be replayed against this API.
     *
     * JwtValidators.createDefaultWithIssuer() does NOT validate audience: it wires
     * only JwtTimestampValidator + JwtIssuerValidator. Minting an aud claim is not
     * the same as checking one.
     */
    @Bean
    JwtDecoder apiJwtDecoder(RSAKey rsaKey, SecurityProperties props, UserRepository users) throws Exception {
        // validateType(false) turns OFF Nimbus's own JOSE type check, which allows only
        // typ=JWT and would reject at+jwt before any validator runs. Type validation then
        // happens in the chain below, where the at+jwt profile validator enforces it.
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withPublicKey(rsaKey.toRSAPublicKey())
                .validateType(false)
                .build();

        OAuth2TokenValidator<Jwt> accessTokenProfile = JwtValidators.createAtJwtValidator()
                .issuer(props.issuer())
                .audience(props.apiAudience())
                .clientId(props.firstPartyClientId())
                .build();
        OAuth2TokenValidator<Jwt> revocation = new TokenRevocationValidator(users);

        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(accessTokenProfile, revocation));
        return decoder;
    }
}
