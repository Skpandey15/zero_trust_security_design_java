package com.example.zerotrust.authserver.repository;

import com.example.zerotrust.authserver.domain.TenantMembership;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface TenantMembershipRepository extends JpaRepository<TenantMembership, TenantMembership.Key> {

    List<TenantMembership> findByUserId(Long userId);
}
