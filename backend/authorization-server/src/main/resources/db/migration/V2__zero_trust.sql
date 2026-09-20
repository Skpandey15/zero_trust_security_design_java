-- MFA (TOTP)
ALTER TABLE users ADD COLUMN mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE users ADD COLUMN mfa_secret VARCHAR(64);

-- Refresh-token families for theft / reuse detection
ALTER TABLE refresh_tokens ADD COLUMN family_id VARCHAR(36);
UPDATE refresh_tokens SET family_id = 'legacy' WHERE family_id IS NULL;
ALTER TABLE refresh_tokens ALTER COLUMN family_id SET NOT NULL;
CREATE INDEX idx_refresh_family ON refresh_tokens (family_id);
