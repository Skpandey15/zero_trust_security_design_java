-- Dedicated, race-free per-account failed-login counter. Replaces deriving the
-- lockout from a COUNT over the append-only audit table (which was both a
-- check-then-act race and a growing scan). Audit rows are still written for
-- forensics; this table is the authoritative lockout state.
CREATE TABLE login_attempt (
    email        VARCHAR(320) PRIMARY KEY,
    failed_count INT       NOT NULL DEFAULT 0,
    window_start TIMESTAMP NOT NULL,
    locked_until TIMESTAMP
);

-- Seed a row for every existing account so the login path never needs to insert
-- (and thus never races on insert); new accounts get a row at registration time.
INSERT INTO login_attempt (email, failed_count, window_start)
    SELECT email, 0, CURRENT_TIMESTAMP FROM users;
