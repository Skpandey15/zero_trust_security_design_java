package com.example.zerotrust.authserver.repository;

import com.example.zerotrust.authserver.domain.Tenant;
import org.springframework.data.jpa.repository.JpaRepository;

public interface TenantRepository extends JpaRepository<Tenant, String> {
}
