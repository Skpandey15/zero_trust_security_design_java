package com.example.zerotrust.resource.documents;

import com.example.zerotrust.resource.authz.AccessExceptions.NotFound;
import com.example.zerotrust.resource.authz.Action;
import com.example.zerotrust.resource.authz.PolicyEnforcement;
import com.example.zerotrust.resource.authz.Subject;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Set;

/**
 * Document operations, each passing through the enforcement point before it
 * touches a row, and then through the aggregate's own rules.
 *
 * <p>The tenant of an existing document is ALWAYS read from the stored record.
 * The one place a caller names a tenant is creation, and there it is only a
 * request to act in that tenant - membership is verified before anything is
 * written (ADR-SEC-015).
 */
@Service
public class DocumentService {

    private final DocumentRepository documents;
    private final PolicyEnforcement policy;

    public DocumentService(DocumentRepository documents, PolicyEnforcement policy) {
        this.documents = documents;
        this.policy = policy;
    }

    /** Documents in every tenant the subject may read - the tenants come from membership, not the request. */
    @Transactional(readOnly = true)
    public List<Document> list(Subject subject) {
        Set<String> tenants = policy.permittedTenants(subject, Action.DOCUMENT_READ);
        return tenants.isEmpty() ? List.of() : documents.findByTenantIdInOrderByCreatedAtDesc(tenants);
    }

    @Transactional(readOnly = true)
    public Document get(Subject subject, String id) {
        Document doc = load(id, subject, Action.DOCUMENT_READ);
        return doc;
    }

    @Transactional
    public Document create(Subject subject, String tenantId, String title, String body) {
        // The tenant here is a REQUEST to act in it, checked before anything is written.
        policy.authorize(subject, Action.DOCUMENT_CREATE, tenantId, null);
        return documents.save(Document.draft(tenantId, title, body, subject.uid()));
    }

    @Transactional
    public Document submit(Subject subject, String id) {
        Document doc = load(id, subject, Action.DOCUMENT_SUBMIT);
        doc.submit(subject.uid());
        return doc;
    }

    @Transactional
    public Document approve(Subject subject, String id) {
        // Policy first (membership, role, second factor), then the domain's own rules.
        Document doc = load(id, subject, Action.DOCUMENT_APPROVE);
        doc.approve(subject.uid());
        return doc;
    }

    /** Load by id, derive the tenant from the stored record, then authorize against THAT tenant. */
    private Document load(String id, Subject subject, Action action) {
        Document doc = documents.findById(id).orElseThrow(NotFound::new);
        policy.authorize(subject, action, doc.getTenantId(), doc.getId());
        return doc;
    }
}
