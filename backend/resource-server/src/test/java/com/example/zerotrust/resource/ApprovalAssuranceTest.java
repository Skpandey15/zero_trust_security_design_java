package com.example.zerotrust.resource;

import com.example.zerotrust.resource.documents.Document;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Approval is the sensitive operation, and it layers three different kinds of
 * rule (ADR-SEC-013): a role in the tenant (RBAC), a second factor in the
 * session (ABAC, ADR-SEC-004), and maker-is-not-checker (a domain invariant that
 * lives in the aggregate).
 */
class ApprovalAssuranceTest extends ResourceServerTestSupport {

    private static final long AUTHOR = 1;
    private static final long APPROVER = 2;

    @Test
    void aPasswordOnlySessionIsAskedToStepUpNotRefusedOutright() throws Exception {
        // rejectsMissingRequiredAuthenticationLevel
        member(AUTHOR, TENANT_A, "MEMBER");
        member(APPROVER, TENANT_A, "APPROVER");
        Document doc = submitted(TENANT_A, AUTHOR, "needs approval");
        String passwordOnly = TestTokens.token().uid(APPROVER).amr("pwd").build();

        mvc.perform(post("/api/documents/" + doc.getId() + "/approve").header("Authorization", bearer(passwordOnly)))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("STEP_UP_REQUIRED"))
                // RFC 9470: say so in the standard way, so a client can act on it.
                .andExpect(header().string("WWW-Authenticate", containsString("insufficient_user_authentication")));

        assertThat(documents.findById(doc.getId()).orElseThrow().getStatus()).isEqualTo(Document.Status.SUBMITTED);
    }

    @Test
    void aSessionThatProvedASecondFactorMayApprove() throws Exception {
        member(AUTHOR, TENANT_A, "MEMBER");
        member(APPROVER, TENANT_A, "APPROVER");
        Document doc = submitted(TENANT_A, AUTHOR, "needs approval");
        String withFactor = TestTokens.token().uid(APPROVER).withSecondFactor().build();

        mvc.perform(post("/api/documents/" + doc.getId() + "/approve").header("Authorization", bearer(withFactor)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("APPROVED"))
                .andExpect(jsonPath("$.approvedBy").value(APPROVER));
    }

    @Test
    void anAmrClaimWithoutOtpDoesNotCountAsASecondFactor() throws Exception {
        // Only "otp" proves the factor; other values - or none - are not evidence.
        member(AUTHOR, TENANT_A, "MEMBER");
        member(APPROVER, TENANT_A, "APPROVER");
        Document doc = submitted(TENANT_A, AUTHOR, "x");

        for (String[] amr : new String[][] {{"pwd", "sms"}, {"mfa"}, {}}) {
            String token = TestTokens.token().uid(APPROVER).amr(amr).build();
            mvc.perform(post("/api/documents/" + doc.getId() + "/approve").header("Authorization", bearer(token)))
                    .andExpect(status().isForbidden());
        }
        assertThat(documents.findById(doc.getId()).orElseThrow().getStatus()).isEqualTo(Document.Status.SUBMITTED);
    }

    @Test
    void theAuthorCannotApproveTheirOwnDocumentEvenWithEveryOtherQualification() throws Exception {
        // Maker is not checker: an OWNER, with the second factor, still cannot approve what they wrote.
        member(AUTHOR, TENANT_A, "OWNER");
        Document doc = submitted(TENANT_A, AUTHOR, "mine");
        String token = TestTokens.token().uid(AUTHOR).withSecondFactor().build();

        mvc.perform(post("/api/documents/" + doc.getId() + "/approve").header("Authorization", bearer(token)))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.code").value("RULE_VIOLATION"));
        assertThat(documents.findById(doc.getId()).orElseThrow().getStatus()).isEqualTo(Document.Status.SUBMITTED);
    }

    @Test
    void aDraftCannotBeApproved() throws Exception {
        member(AUTHOR, TENANT_A, "MEMBER");
        member(APPROVER, TENANT_A, "APPROVER");
        Document draft = draft(TENANT_A, AUTHOR, "not submitted yet");
        String token = TestTokens.token().uid(APPROVER).withSecondFactor().build();

        mvc.perform(post("/api/documents/" + draft.getId() + "/approve").header("Authorization", bearer(token)))
                .andExpect(status().isConflict());
    }

    @Test
    void aRoleThatCannotApproveIsRefusedNotOfferedAStepUp() throws Exception {
        // Stepping up would not help a MEMBER, so suggesting it would be misleading.
        member(AUTHOR, TENANT_A, "MEMBER");
        member(APPROVER, TENANT_A, "MEMBER");
        Document doc = submitted(TENANT_A, AUTHOR, "x");
        String token = TestTokens.token().uid(APPROVER).withSecondFactor().build();

        mvc.perform(post("/api/documents/" + doc.getId() + "/approve").header("Authorization", bearer(token)))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("FORBIDDEN"));
    }

    @Test
    void aNonMemberCannotLearnThatTheDocumentIsAwaitingApproval() throws Exception {
        member(AUTHOR, TENANT_A, "MEMBER");
        Document doc = submitted(TENANT_A, AUTHOR, "x");
        String token = TestTokens.token().uid(77).withSecondFactor().build();

        mvc.perform(post("/api/documents/" + doc.getId() + "/approve").header("Authorization", bearer(token)))
                .andExpect(status().isNotFound());
    }

    @Test
    void onlyTheAuthorSubmitsAndOnlyOnce() throws Exception {
        member(AUTHOR, TENANT_A, "MEMBER");
        member(APPROVER, TENANT_A, "OWNER");
        Document doc = draft(TENANT_A, AUTHOR, "draft");

        // Someone else - even an OWNER - cannot submit another person's draft.
        mvc.perform(post("/api/documents/" + doc.getId() + "/submit")
                        .header("Authorization", bearer(TestTokens.token().uid(APPROVER).build())))
                .andExpect(status().isConflict());
        // The author can, once.
        String authorToken = bearer(TestTokens.token().uid(AUTHOR).build());
        mvc.perform(post("/api/documents/" + doc.getId() + "/submit").header("Authorization", authorToken))
                .andExpect(status().isOk()).andExpect(jsonPath("$.status").value("SUBMITTED"));
        mvc.perform(post("/api/documents/" + doc.getId() + "/submit").header("Authorization", authorToken))
                .andExpect(status().isConflict());
    }

    @Test
    void aTokenCarryingScopeAsAnArrayWorksEndToEnd() throws Exception {
        // Spring Authorization Server emits scope as a JSON array; the unit tests once minted
        // only the string form, and a real deployment denied every write.
        member(AUTHOR, TENANT_A, "OWNER");
        String token = TestTokens.token().uid(AUTHOR).scopeArray("documents.read", "documents.write").build();

        mvc.perform(post("/api/documents").header("Authorization", bearer(token))
                        .contentType(org.springframework.http.MediaType.APPLICATION_JSON)
                        .content("{\"tenantId\":\"" + TENANT_A + "\",\"title\":\"t\",\"body\":\"b\"}"))
                .andExpect(status().isCreated());
    }
}
