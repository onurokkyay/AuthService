-- Baseline schema for the authentication service.
--
-- The service owns exactly two tables: accounts and the refresh tokens issued to
-- them. Anything domain-specific belongs to the services that consume this one.

CREATE TABLE app_user (
    id                    uuid PRIMARY KEY,
    username              text        NOT NULL,
    email                 text        NOT NULL,
    password_hash         text        NOT NULL,
    role                  text        NOT NULL DEFAULT 'USER',
    enabled               boolean     NOT NULL DEFAULT true,
    failed_login_attempts integer     NOT NULL DEFAULT 0,
    locked_until          timestamptz,
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now(),
    -- Two roles, enforced by the database as well as the enum. A permission model
    -- belongs to the consuming services, not here.
    CONSTRAINT chk_app_user_role CHECK (role IN ('USER', 'ADMIN'))
);

-- Case-insensitive uniqueness. Lookups also go through lower(...), so these indexes
-- serve both the constraint and the read path.
CREATE UNIQUE INDEX ux_app_user_username ON app_user (lower(username));
CREATE UNIQUE INDEX ux_app_user_email ON app_user (lower(email));

CREATE TABLE refresh_token (
    id         uuid PRIMARY KEY,
    user_id    uuid        NOT NULL REFERENCES app_user (id) ON DELETE CASCADE,
    -- SHA-256 of the opaque token. The token value is returned to the client once and
    -- is not recoverable from this table.
    token_hash text        NOT NULL,
    expires_at timestamptz NOT NULL,
    -- Set on rotation and on logout. Rows are kept until they expire so that replaying
    -- a rotated token can still be recognized as reuse rather than as an unknown token.
    revoked_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT uk_refresh_token_hash UNIQUE (token_hash)
);

-- Reuse detection revokes every token of one user; the cleanup job deletes by expiry.
CREATE INDEX ix_refresh_token_user ON refresh_token (user_id);
CREATE INDEX ix_refresh_token_expires_at ON refresh_token (expires_at);
