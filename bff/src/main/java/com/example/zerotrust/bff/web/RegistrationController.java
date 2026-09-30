package com.example.zerotrust.bff.web;

import com.example.zerotrust.bff.web.AuthServerClient.RegisterPayload;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * Account registration, the one unauthenticated write the browser makes.
 *
 * <p>The browser talks only to the BFF (ADR-SEC-007), so this relays to the
 * Authorization Server, which owns identity. The BFF re-declares and validates
 * the request shape rather than forwarding whatever arrives, so an unexpected
 * field never reaches the identity service. CSRF still applies: the request
 * must carry the anti-CSRF token like any other state-changing call.
 */
@RestController
@RequestMapping("/api/auth")
public class RegistrationController {

    private final AuthServerClient authServer;

    public RegistrationController(AuthServerClient authServer) {
        this.authServer = authServer;
    }

    @PostMapping("/register")
    public ResponseEntity<Map<String, Object>> register(@Valid @RequestBody RegisterRequest request) {
        return authServer.register(new RegisterPayload(request.email(), request.password(), request.displayName()));
    }

    /** Mirrors the Authorization Server's own limits; it remains the authority. */
    public record RegisterRequest(
            @NotBlank @Email @Size(max = 320) String email,
            @NotBlank @Size(min = 12, max = 128) String password,
            @NotBlank @Size(max = 120) String displayName) {}
}
