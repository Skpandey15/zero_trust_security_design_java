package com.example.zerotrust.authserver;

import com.example.zerotrust.authserver.domain.TenantMembership;
import com.example.zerotrust.authserver.dto.AuthDtos.RegisterRequest;
import com.example.zerotrust.authserver.repository.TenantMembershipRepository;
import com.example.zerotrust.authserver.repository.TenantRepository;
import com.example.zerotrust.authserver.service.AuthService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * ADR-SEC-015: membership is explicit. A new account must have standing somewhere
 * (its own workspace) and nowhere else - registering never grants access to
 * anyone else's tenant.
 */
@SpringBootTest
class RegistrationTenancyTest {

    @Autowired AuthService authService;
    @Autowired TenantMembershipRepository memberships;
    @Autowired TenantRepository tenants;

    private long register(String name) {
        String email = "t-" + UUID.randomUUID().toString().substring(0, 8) + "@example.com";
        return authService.register(new RegisterRequest(email, "tenancy-pass-1234", name)).id();
    }

    @Test
    void aNewAccountOwnsExactlyOneWorkspaceOfItsOwn() {
        long id = register("Ada");

        List<TenantMembership> mine = memberships.findByUserId(id);

        assertThat(mine).hasSize(1);
        assertThat(mine.get(0).getRole()).isEqualTo("OWNER");
        assertThat(tenants.findById(mine.get(0).getTenantId()).orElseThrow().getName()).isEqualTo("Ada's workspace");
    }

    @Test
    void twoAccountsNeverShareAWorkspace() {
        long a = register("Ada");
        long b = register("Bea");

        String tenantA = memberships.findByUserId(a).get(0).getTenantId();
        String tenantB = memberships.findByUserId(b).get(0).getTenantId();

        assertThat(tenantA).isNotEqualTo(tenantB);
        assertThat(memberships.findByUserId(a)).extracting(TenantMembership::getTenantId).doesNotContain(tenantB);
    }
}
