package com.example.zerotrust.resource;

import com.example.zerotrust.resource.documents.Document;
import org.junit.jupiter.api.Test;

import static org.hamcrest.Matchers.hasSize;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** Where the caller can act - answered from their own stored membership, with nothing to tamper with. */
class TenantsEndpointTest extends ResourceServerTestSupport {

    private static String token(long uid) {
        return bearer(TestTokens.token().uid(uid).build());
    }

    @Test
    void listsOnlyTheTenantsTheCallerBelongsToWithTheirRole() throws Exception {
        member(1, TENANT_A, "OWNER");
        member(1, TENANT_B, "VIEWER");
        member(2, "tenant-c", "OWNER");   // someone else's

        mvc.perform(get("/api/tenants").header("Authorization", token(1)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$", hasSize(2)))
                .andExpect(jsonPath("$[?(@.id == 'tenant-c')]", hasSize(0)));
    }

    @Test
    void aTenantParameterCannotAskAboutSomeoneElsesMembership() throws Exception {
        member(2, "tenant-c", "OWNER");

        mvc.perform(get("/api/tenants").header("Authorization", token(1)).param("userId", "2").param("tenantId", "tenant-c"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$", hasSize(0)));
    }

    @Test
    void aUnrecognisedRoleIsNotListedAsAPlace() throws Exception {
        member(1, TENANT_A, "SUPERUSER");

        mvc.perform(get("/api/tenants").header("Authorization", token(1)))
                .andExpect(jsonPath("$", hasSize(0)));
    }

    @Test
    void failsClosedWhenMembershipCannotBeRead() throws Exception {
        member(1, TENANT_A, "OWNER");
        failures.membershipDown.set(true);

        mvc.perform(get("/api/tenants").header("Authorization", token(1)))
                .andExpect(status().isServiceUnavailable());
    }

    @Test
    void aDocumentSaysWhetherItIsMineWithoutExposingWhoWroteIt() throws Exception {
        member(1, TENANT_A, "MEMBER");
        member(2, TENANT_A, "MEMBER");
        Document mine = draft(TENANT_A, 1, "mine");
        Document theirs = draft(TENANT_A, 2, "theirs");

        mvc.perform(get("/api/documents/" + mine.getId()).header("Authorization", token(1)))
                .andExpect(jsonPath("$.mine").value(true))
                .andExpect(jsonPath("$.createdBy").doesNotExist());
        mvc.perform(get("/api/documents/" + theirs.getId()).header("Authorization", token(1)))
                .andExpect(jsonPath("$.mine").value(false));
    }
}
