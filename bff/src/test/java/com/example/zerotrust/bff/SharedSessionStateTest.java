package com.example.zerotrust.bff;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.util.ReflectionTestUtils;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The BFF runs as several replicas, so anything a signed-in user needs on their
 * NEXT request must live in the shared session, not in a pod's memory.
 *
 * <p>The login token is the one that bit: Spring's default keeps an authenticated
 * user's token in an in-memory service local to one pod, so every second request
 * landed on a replica that had never heard of the user and bounced them to sign in
 * again. No single-replica test can see that; this pins the cause instead.
 */
@SpringBootTest
@ActiveProfiles("test")
class SharedSessionStateTest {

    @Autowired OAuth2AuthorizedClientRepository authorizedClients;
    @Autowired OAuth2AuthorizedClientManager manager;

    @Test
    void theLoginTokenIsKeptInTheSessionNotInOnePodsMemory() {
        assertThat(authorizedClients)
                .as("an in-memory or per-principal service is local to one replica")
                .isInstanceOf(HttpSessionOAuth2AuthorizedClientRepository.class);
    }

    @Test
    void theClientManagerUsesThatSameSessionBackedRepository() {
        // The manager (used when a token is refreshed) must read and write the same place,
        // or a refresh on one pod would be invisible to the other.
        Object repo = ReflectionTestUtils.getField(manager, "authorizedClientRepository");

        assertThat(repo).isSameAs(authorizedClients);
    }
}
