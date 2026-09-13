-- Password reset tokens: the link a person is emailed when they cannot sign in.
--
-- Shaped like refresh_token on purpose, because the threat is the same one. The token is a
-- credential for as long as it lives -- whoever holds the link can set the password -- so only
-- its SHA-256 digest is stored, and a database dump hands out no resets.

CREATE TABLE password_reset_token (
    id         uuid PRIMARY KEY,
    user_id    uuid        NOT NULL REFERENCES app_user (id) ON DELETE CASCADE,
    -- SHA-256 of the opaque token. The raw value exists only in the email that was sent.
    token_hash text        NOT NULL,
    expires_at timestamptz NOT NULL,
    -- Set when the token is spent, and when a newer request retires it. A token is usable only
    -- while this is null and expires_at is still ahead.
    used_at    timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT uk_password_reset_token_hash UNIQUE (token_hash)
);

-- The cooldown asks when this account was last sent a link, which is the newest row per user.
CREATE INDEX ix_password_reset_token_user_created ON password_reset_token (user_id, created_at DESC);
-- The cleanup job deletes by expiry.
CREATE INDEX ix_password_reset_token_expires_at ON password_reset_token (expires_at);
