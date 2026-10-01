package com.example.zerotrust.resource.documents;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Collection;
import java.util.List;

/**
 * Data access for documents.
 *
 * <p>There is deliberately no unscoped "find all": the only way to list is by a
 * set of tenant ids, so a new endpoint cannot return every tenant's rows by
 * forgetting a predicate (ADR-SEC-015). {@code findById} exists because the
 * authorization flow loads a resource FIRST to learn which tenant owns it - the
 * caller must then check membership before using the result.
 */
public interface DocumentRepository extends JpaRepository<Document, String> {

    List<Document> findByTenantIdInOrderByCreatedAtDesc(Collection<String> tenantIds);
}
