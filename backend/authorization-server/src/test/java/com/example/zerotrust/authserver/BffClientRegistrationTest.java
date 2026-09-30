package com.example.zerotrust.authserver;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * ADR-SEC-003 / ADR-SEC-007: the BFF is a confidential client, PKCE is required
 * of it anyway, and only exact, configured redirect URIs are accepted.
 */
@SpringBootTest(properties = "app.oidc.bff-redirect-origins=https://console.example.com")
class BffClientRegistrationTest {

    @Autowired RegisteredClientRepository clients;

    @Test
    void bffIsAConfidentialClientThatRequiresPkce() {
        RegisteredClient bff = clients.findByClientId("zero-trust-web");

        assertThat(bff).isNotNull();
        assertThat(bff.getClientAuthenticationMethods())
                .containsExactly(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
        assertThat(bff.getAuthorizationGrantTypes())
                .contains(AuthorizationGrantType.AUTHORIZATION_CODE)
                .doesNotContain(AuthorizationGrantType.CLIENT_CREDENTIALS);
        assertThat(bff.getClientSettings().isRequireProofKey()).isTrue();
    }

    @Test
    void onlyTheConfiguredOriginIsRegistered() {
        RegisteredClient bff = clients.findByClientId("zero-trust-web");

        assertThat(bff.getRedirectUris())
                .containsExactly("https://console.example.com/login/oauth2/code/zero-trust-web");
        assertThat(bff.getPostLogoutRedirectUris())
                .containsExactly("https://console.example.com/");
    }
}
