package com.example.zerotrust.resource.documents;

import com.example.zerotrust.resource.authz.MembershipRepository.TenantInfo;
import com.example.zerotrust.resource.authz.PolicyEnforcement;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * Where the caller can act. The answer comes from stored membership for the
 * caller's own identity - there is no tenant parameter, so there is nothing to
 * tamper with and no way to ask about someone else's.
 */
@RestController
@RequestMapping("/api/tenants")
public class TenantController {

    private final PolicyEnforcement policy;

    public TenantController(PolicyEnforcement policy) {
        this.policy = policy;
    }

    @GetMapping
    @PreAuthorize("hasAuthority('SCOPE_documents.read')")
    public List<TenantInfo> mine(@AuthenticationPrincipal Jwt jwt) {
        return policy.visibleTenants(DocumentController.subject(jwt));
    }
}
