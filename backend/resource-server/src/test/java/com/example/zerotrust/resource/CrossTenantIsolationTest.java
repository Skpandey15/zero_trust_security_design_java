package com.example.zerotrust.resource;

import com.example.zerotrust.resource.documents.Document;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MvcResult;

import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.hasSize;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * ADR-SEC-015: cross-tenant access is the highest-impact authorization failure,
 * and it is almost never exotic - a guessed id, a tenant taken from the request,
 * a list that forgot its predicate. This is the suite for those
 * (rejectsCrossTenantResourceAccess).
 */
class CrossTenantIsolationTest extends ResourceServerTestSupport {

    private static String tokenFor(long uid) {
        return bearer(TestTokens.token().uid(uid).build());
    }

    @Test
    void aMemberReadsADocumentInTheirOwnTenant() throws Exception {
        member(1, TENANT_A, "MEMBER");
        Document doc = draft(TENANT_A, 1, "mine");

        mvc.perform(get("/api/documents/" + doc.getId()).header("Authorization", tokenFor(1)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.title").value("mine"));
    }

    @Test
    void aGuessedIdForAnotherTenantsDocumentIsNotFound() throws Exception {
        member(1, TENANT_A, "OWNER");          // user 1 is in A only
        Document theirs = draft(TENANT_B, 2, "secret");

        mvc.perform(get("/api/documents/" + theirs.getId()).header("Authorization", tokenFor(1)))
                .andExpect(status().isNotFound());
    }

    @Test
    void notYoursLooksExactlyLikeDoesNotExist() throws Exception {
        // Identifiers are assumed guessable, so the answer must not reveal which ids are real.
        member(1, TENANT_A, "OWNER");
        Document theirs = draft(TENANT_B, 2, "secret");

        MvcResult exists = mvc.perform(get("/api/documents/" + theirs.getId()).header("Authorization", tokenFor(1))).andReturn();
        MvcResult absent = mvc.perform(get("/api/documents/" + UUID.randomUUID()).header("Authorization", tokenFor(1))).andReturn();

        assertThat(exists.getResponse().getStatus()).isEqualTo(absent.getResponse().getStatus());
        assertThat(exists.getResponse().getContentAsString()).isEqualTo(absent.getResponse().getContentAsString());
    }

    @Test
    void aTenantClaimInTheTokenIsNotTheAuthority() throws Exception {
        // A token that CLAIMS tenant B must not open tenant B: tenancy comes from the
        // stored membership, never from anything the caller presents (ADR-SEC-015).
        member(1, TENANT_A, "OWNER");
        Document theirs = draft(TENANT_B, 2, "secret");
        String forged = bearer(TestTokens.token().uid(1).claim("tenant_id", TENANT_B).claim("tenants", List.of(TENANT_B)).build());

        mvc.perform(get("/api/documents/" + theirs.getId()).header("Authorization", forged))
                .andExpect(status().isNotFound());
    }

    @Test
    void aTenantHeaderDoesNotOpenAnotherTenant() throws Exception {
        member(1, TENANT_A, "OWNER");
        Document theirs = draft(TENANT_B, 2, "secret");

        mvc.perform(get("/api/documents/" + theirs.getId()).header("Authorization", tokenFor(1))
                        .header("X-Tenant-Id", TENANT_B).param("tenantId", TENANT_B))
                .andExpect(status().isNotFound());
    }

    @Test
    void theListContainsOnlyTenantsTheSubjectBelongsTo() throws Exception {
        // The list endpoint is where the tenant predicate is most often forgotten.
        member(1, TENANT_A, "MEMBER");
        draft(TENANT_A, 1, "in A");
        draft(TENANT_B, 2, "in B - not for user 1");

        mvc.perform(get("/api/documents").header("Authorization", tokenFor(1)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$", hasSize(1)))
                .andExpect(jsonPath("$[0].title").value("in A"));
    }

    @Test
    void aSubjectInSeveralTenantsSeesAllOfThemAndNoOthers() throws Exception {
        member(1, TENANT_A, "MEMBER");
        member(1, TENANT_B, "VIEWER");
        draft(TENANT_A, 1, "in A");
        draft(TENANT_B, 2, "in B");
        draft("tenant-c", 3, "in C - not a member");

        mvc.perform(get("/api/documents").header("Authorization", tokenFor(1)))
                .andExpect(jsonPath("$", hasSize(2)));
    }

    @Test
    void aSubjectWithNoMembershipSeesAnEmptyListNotAnError() throws Exception {
        draft(TENANT_A, 2, "someone else's");

        mvc.perform(get("/api/documents").header("Authorization", tokenFor(99)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$", hasSize(0)));
    }

    @Test
    void creatingInATenantYouDoNotBelongToIsRefusedAndWritesNothing() throws Exception {
        member(1, TENANT_A, "OWNER");
        long before = documents.count();

        // The tenant in the body is only a REQUEST to act there; membership decides.
        mvc.perform(post("/api/documents").header("Authorization", tokenFor(1))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"tenantId\":\"" + TENANT_B + "\",\"title\":\"planted\",\"body\":\"x\"}"))
                .andExpect(status().isNotFound());

        assertThat(documents.count()).as("nothing was written").isEqualTo(before);
    }

    @Test
    void theRightRoleInTheWrongTenantReachesNoPermit() throws Exception {
        // Approver in A, nothing in B: membership is checked BEFORE the role.
        member(1, TENANT_A, "APPROVER");
        Document inB = submitted(TENANT_B, 2, "needs approval");
        String token = bearer(TestTokens.token().uid(1).withSecondFactor().build());

        mvc.perform(post("/api/documents/" + inB.getId() + "/approve").header("Authorization", token))
                .andExpect(status().isNotFound());
        assertThat(documents.findById(inB.getId()).orElseThrow().getStatus()).isEqualTo(Document.Status.SUBMITTED);
    }

    @Test
    void aRoleIsPerTenantNotPerPerson() throws Exception {
        // The same person can write in A and only read in B.
        member(1, TENANT_A, "MEMBER");
        member(1, TENANT_B, "VIEWER");

        mvc.perform(post("/api/documents").header("Authorization", tokenFor(1)).contentType(MediaType.APPLICATION_JSON)
                        .content("{\"tenantId\":\"" + TENANT_A + "\",\"title\":\"ok\",\"body\":\"x\"}"))
                .andExpect(status().isCreated());
        mvc.perform(post("/api/documents").header("Authorization", tokenFor(1)).contentType(MediaType.APPLICATION_JSON)
                        .content("{\"tenantId\":\"" + TENANT_B + "\",\"title\":\"no\",\"body\":\"x\"}"))
                .andExpect(status().isForbidden());
    }

    @Test
    void anUnrecognisedRoleInTheDataGrantsNothing() throws Exception {
        // An unknown role string is never read as a default permission.
        member(1, TENANT_A, "SUPERUSER");
        Document doc = draft(TENANT_A, 2, "x");

        mvc.perform(get("/api/documents/" + doc.getId()).header("Authorization", tokenFor(1)))
                .andExpect(status().isNotFound());
    }

    @Test
    void aTokenWithoutTheScopeCannotWriteEvenAsOwner() throws Exception {
        // Scope is the coarse gate: a token minted for reading cannot write.
        member(1, TENANT_A, "OWNER");
        String readOnly = bearer(TestTokens.token().uid(1).scope("documents.read").build());

        mvc.perform(post("/api/documents").header("Authorization", readOnly).contentType(MediaType.APPLICATION_JSON)
                        .content("{\"tenantId\":\"" + TENANT_A + "\",\"title\":\"x\",\"body\":\"x\"}"))
                .andExpect(status().isForbidden());
    }

    @Test
    void aTokenWithNoIdentityIsRefused() throws Exception {
        // No uid means no membership can be looked up: nothing may proceed.
        String withoutUid = bearer(TestTokens.token().claim("uid", null).build());

        mvc.perform(get("/api/documents").header("Authorization", withoutUid)).andExpect(status().isUnauthorized());
    }
}
