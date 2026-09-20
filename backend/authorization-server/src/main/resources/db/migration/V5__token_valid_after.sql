-- Continuous verification: access tokens issued before this instant are rejected
-- on every request (bumped on logout-all / disable / MFA activation).
ALTER TABLE users ADD COLUMN token_valid_after TIMESTAMP;
