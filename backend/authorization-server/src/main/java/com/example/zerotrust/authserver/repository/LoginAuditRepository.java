package com.example.zerotrust.authserver.repository;

import com.example.zerotrust.authserver.domain.LoginAudit;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface LoginAuditRepository extends JpaRepository<LoginAudit, Long> {

    List<LoginAudit> findTop50ByEmailIgnoreCaseOrderByOccurredAtDesc(String email);

    /** Has this account ever logged in successfully? (established vs brand-new account) */
    boolean existsByEmailAndSuccessTrue(String email);

    /** Has this account ever logged in successfully from this exact IP? (known device/location) */
    boolean existsByEmailAndIpAddressAndSuccessTrue(String email, String ipAddress);
}
