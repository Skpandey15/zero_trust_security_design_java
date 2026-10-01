-- Resource Server data (WP-BE-02). Lives in its own schema, owned by its own
-- database role (ADR-SEC-019): it holds no rights over the identity schema
-- beyond reading tenant membership.
CREATE TABLE documents (
    id          VARCHAR(36)   PRIMARY KEY,
    tenant_id   VARCHAR(36)   NOT NULL,
    title       VARCHAR(200)  NOT NULL,
    body        VARCHAR(10000) NOT NULL,
    status      VARCHAR(16)   NOT NULL,
    created_by  BIGINT        NOT NULL,
    approved_by BIGINT,
    created_at  TIMESTAMP     NOT NULL,
    approved_at TIMESTAMP,
    CONSTRAINT chk_documents_status CHECK (status IN ('DRAFT', 'SUBMITTED', 'APPROVED')),
    -- Maker is not checker, enforced where it cannot be bypassed by a code path
    -- that forgets the domain rule.
    CONSTRAINT chk_documents_maker_not_checker CHECK (approved_by IS NULL OR approved_by <> created_by)
);

-- Every read is tenant-scoped, so the tenant is the access path.
CREATE INDEX idx_documents_tenant ON documents (tenant_id, created_at);
