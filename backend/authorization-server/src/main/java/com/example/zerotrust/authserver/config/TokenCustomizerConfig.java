package com.example.zerotrust.authserver.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

/**
 * The ONE token customizer the authorization server looks up. Spring
 * Authorization Server resolves a single {@code OAuth2TokenCustomizer} bean, so
 * two separate beans would leave one of them silently unused. Each concern lives
 * in its own class and is composed here.
 */
@Configuration
class TokenCustomizerConfig {

    @Bean
    OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer(AssuranceClaims assurance,
                                                              TokenExchangeClaims exchange) {
        return context -> {
            assurance.customize(context);
            exchange.customize(context);
        };
    }
}
