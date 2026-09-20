-- Replay protection for TOTP: remember the highest time-step already spent on a
-- login so the same 6-digit code cannot be reused within its validity window.
ALTER TABLE users ADD COLUMN mfa_last_used_step BIGINT;
