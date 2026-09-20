package com.example.zerotrust.authserver.service;

import com.example.zerotrust.authserver.config.SecurityProperties;
import com.example.zerotrust.authserver.domain.Permission;
import com.example.zerotrust.authserver.domain.RefreshToken;
import com.example.zerotrust.authserver.domain.User;
import com.example.zerotrust.authserver.repository.RefreshTokenRepository;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Service
public class TokenService {

    public static final String ISSUER = "auth-service";
    public static final String AUDIENCE = "auth-service-api";

    /** Step-up tokens are enrolment-only, so they live far shorter than a session. */
    private static final Duration STEP_UP_TTL = Duration.ofMinutes(5);

    private final JwtEncoder jwtEncoder;
    private final RefreshTokenRepository refreshTokenRepository;
    private final SecurityProperties props;
    private final SecureRandom secureRandom = new SecureRandom();

    public TokenService(JwtEncoder jwtEncoder,
                        RefreshTokenRepository refreshTokenRepository,
                        SecurityProperties props) {
        this.jwtEncoder = jwtEncoder;
        this.refreshTokenRepository = refreshTokenRepository;
        this.props = props;
    }

    /**
     * Short-lived RS256 access token. Carries roles AND fine-grained
     * permissions as authorities, plus jti / iss / aud claims that the
     * resource-server side strictly validates.
     */
    public String createAccessToken(User user) {
        Instant now = Instant.now();
        List<String> authorities = new ArrayList<>();
        user.getRoles().forEach(role -> {
            authorities.add("ROLE_" + role.name());
            role.permissions().stream().map(Permission::value).forEach(authorities::add);
        });
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer(props.issuer())
                .audience(List.of(props.apiAudience()))
                .id(UUID.randomUUID().toString())          // jti — unique per token
                .issuedAt(now)
                .expiresAt(now.plus(props.accessTokenTtl()))
                .subject(user.getEmail())
                .claim("uid", user.getId())
                // RFC 9068 requires client_id on an access token; the API chain's
                // at+jwt validator rejects the token without it.
                .claim("client_id", props.firstPartyClientId())
                .claim("authorities", authorities.stream().distinct().sorted().toList())
                .build();
        // typ=at+jwt marks this as an OAuth2 access token (RFC 9068), so a token
        // minted for one purpose cannot be replayed as another token type.
        JwsHeader header = JwsHeader.with(SignatureAlgorithm.RS256)
                .type("at+jwt")
                .build();
        return jwtEncoder.encode(JwtEncoderParameters.from(header, claims)).getTokenValue();
    }

    /**
     * Restricted token issued when a risky login hits an account with no second
     * factor. It carries ONLY profile:read -- enough to reach /api/users/me/mfa/**
     * and enrol -- and no role authorities, so admin surfaces stay closed. Without
     * this the step-up demand is unsatisfiable: enrolling MFA needs a token, and
     * getting a token needs MFA, so the account locks out permanently.
     */
    public String createStepUpToken(User user) {
        Instant now = Instant.now();
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer(props.issuer())
                .audience(List.of(props.apiAudience()))
                .id(UUID.randomUUID().toString())
                .issuedAt(now)
                .expiresAt(now.plus(STEP_UP_TTL))
                .subject(user.getEmail())
                .claim("uid", user.getId())
                .claim("client_id", props.firstPartyClientId())
                .claim("step_up", "mfa_enrollment")
                .claim("authorities", List.of(Permission.PROFILE_READ.value()))
                .build();
        JwsHeader header = JwsHeader.with(SignatureAlgorithm.RS256).type("at+jwt").build();
        return jwtEncoder.encode(JwtEncoderParameters.from(header, claims)).getTokenValue();
    }

    public long stepUpTtlSeconds() {
        return STEP_UP_TTL.toSeconds();
    }

    /** First refresh token of a brand-new family (one family per login). */
    public String createRefreshTokenFamily(User user) {
        return createRefreshToken(user, UUID.randomUUID().toString());
    }

    /** Next token within an existing family (rotation). */
    public String rotateWithinFamily(User user, String familyId) {
        return createRefreshToken(user, familyId);
    }

    private String createRefreshToken(User user, String familyId) {
        byte[] bytes = new byte[48];
        secureRandom.nextBytes(bytes);
        String raw = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        refreshTokenRepository.save(new RefreshToken(
                sha256(raw), familyId, user, Instant.now().plus(props.refreshTokenTtl())));
        return raw;
    }

    /** Any stored record for this raw token — active, revoked, or expired. */
    public Optional<RefreshToken> findAny(String rawToken) {
        return refreshTokenRepository.findByTokenHash(sha256(rawToken));
    }

    /**
     * Atomically flip a token to revoked, returning true only for the caller
     * that won the race. Runs in the caller's transaction so it commits with the
     * rotation. See RefreshTokenRepository.markRotated.
     */
    public boolean claimForRotation(Long tokenId) {
        return refreshTokenRepository.markRotated(tokenId) == 1;
    }

    /**
     * Reuse detection: kill every token descended from the same login.
     * Runs in its own transaction — the caller throws right after this to
     * reject the request, and the revocation must survive that rollback.
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void revokeFamily(String familyId) {
        refreshTokenRepository.revokeFamily(familyId);
    }

    public long accessTokenTtlSeconds() {
        return props.accessTokenTtl().toSeconds();
    }

    static String sha256(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
