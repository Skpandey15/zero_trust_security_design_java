package com.example.zerotrust.resource.documents;

import com.example.zerotrust.resource.authz.Subject;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.time.Instant;
import java.util.List;

/**
 * The coarse gate here ({@code @PreAuthorize} on the token's scope) is a filter,
 * never the authorization: a token can carry documents.read and still be refused
 * a specific document because it belongs to another tenant. The real decision is
 * made per operation in {@link DocumentService} (ADR-SEC-013).
 */
@RestController
@RequestMapping("/api/documents")
public class DocumentController {

    public record CreateRequest(
            // A request to act in this tenant - verified against membership, never trusted.
            @NotBlank @Size(max = 36) String tenantId,
            @NotBlank @Size(max = 200) String title,
            @NotBlank @Size(max = 10000) String body) {}

    /** {@code mine} lets the UI offer the right actions; the server still decides every one of them. */
    public record DocumentView(String id, String tenantId, String title, String body, String status,
                               boolean mine, Long approvedBy, Instant createdAt, Instant approvedAt) {
        static DocumentView of(Document d, long viewer) {
            return new DocumentView(d.getId(), d.getTenantId(), d.getTitle(), d.getBody(),
                    d.getStatus().name(), d.getCreatedBy() == viewer, d.getApprovedBy(), d.getCreatedAt(), d.getApprovedAt());
        }
    }

    private final DocumentService service;

    public DocumentController(DocumentService service) {
        this.service = service;
    }

    @GetMapping
    @PreAuthorize("hasAuthority('SCOPE_documents.read')")
    public List<DocumentView> list(@AuthenticationPrincipal Jwt jwt) {
        Subject me = subject(jwt);
        return service.list(me).stream().map(d -> DocumentView.of(d, me.uid())).toList();
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasAuthority('SCOPE_documents.read')")
    public DocumentView get(@AuthenticationPrincipal Jwt jwt, @PathVariable String id) {
        Subject me = subject(jwt);
        return DocumentView.of(service.get(me, id), me.uid());
    }

    @PostMapping
    @PreAuthorize("hasAuthority('SCOPE_documents.write')")
    public ResponseEntity<DocumentView> create(@AuthenticationPrincipal Jwt jwt, @Valid @RequestBody CreateRequest request) {
        Subject me = subject(jwt);
        Document created = service.create(me, request.tenantId(), request.title(), request.body());
        return ResponseEntity.status(HttpStatus.CREATED).body(DocumentView.of(created, me.uid()));
    }

    @PostMapping("/{id}/submit")
    @PreAuthorize("hasAuthority('SCOPE_documents.write')")
    public DocumentView submit(@AuthenticationPrincipal Jwt jwt, @PathVariable String id) {
        Subject me = subject(jwt);
        return DocumentView.of(service.submit(me, id), me.uid());
    }

    @PostMapping("/{id}/approve")
    @PreAuthorize("hasAuthority('SCOPE_documents.approve')")
    public DocumentView approve(@AuthenticationPrincipal Jwt jwt, @PathVariable String id) {
        Subject me = subject(jwt);
        return DocumentView.of(service.approve(me, id), me.uid());
    }

    static Subject subject(Jwt jwt) {
        try {
            return Subject.from(jwt);
        } catch (IllegalArgumentException e) {
            // A token with no identity cannot be matched to any membership.
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "token has no subject identity");
        }
    }
}
