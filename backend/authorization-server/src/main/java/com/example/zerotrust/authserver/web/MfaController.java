package com.example.zerotrust.authserver.web;

import com.example.zerotrust.authserver.dto.AuthDtos.MfaActivateRequest;
import com.example.zerotrust.authserver.dto.AuthDtos.MfaSetupResponse;
import com.example.zerotrust.authserver.service.AuthService;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/users/me/mfa")
@PreAuthorize("hasAuthority('profile:read')")
public class MfaController {

    private final AuthService authService;

    public MfaController(AuthService authService) {
        this.authService = authService;
    }

    /** Returns the TOTP secret + otpauth:// URI to scan with an authenticator app. */
    @PostMapping("/setup")
    public MfaSetupResponse setup(@AuthenticationPrincipal Jwt jwt) {
        return authService.startMfaSetup(jwt.getSubject());
    }

    /** Confirms a 6-digit code and switches MFA on. Existing refresh tokens are revoked. */
    @PostMapping("/activate")
    public ResponseEntity<Void> activate(@AuthenticationPrincipal Jwt jwt,
                                         @Valid @RequestBody MfaActivateRequest request) {
        authService.activateMfa(jwt.getSubject(), request.code());
        return ResponseEntity.noContent().build();
    }
}
