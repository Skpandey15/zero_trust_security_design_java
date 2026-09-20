package com.example.zerotrust.authserver.repository;

import com.example.zerotrust.authserver.domain.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {

    Optional<RefreshToken> findByTokenHash(String tokenHash);

    /**
     * Atomically claim a token for rotation. Returns 1 for the caller that wins
     * the race and 0 for any concurrent caller presenting the same still-active
     * token — the loser is then treated as reuse. This closes the check-then-act
     * window that a plain isActive()/revoke() pair would leave open.
     */
    @Modifying
    @Query("update RefreshToken rt set rt.revoked = true where rt.id = :id and rt.revoked = false")
    int markRotated(@Param("id") Long id);

    @Modifying
    @Query("update RefreshToken rt set rt.revoked = true where rt.user.id = :userId and rt.revoked = false")
    void revokeAllForUser(@Param("userId") Long userId);

    @Modifying
    @Query("update RefreshToken rt set rt.revoked = true where rt.familyId = :familyId and rt.revoked = false")
    void revokeFamily(@Param("familyId") String familyId);
}
