-- Create an ENUM for user roles
CREATE TYPE user_role AS ENUM ('user', 'admin');

-- Users Table
CREATE TABLE users
(
    id            UUID PRIMARY KEY             DEFAULT gen_random_uuid(),
    username      VARCHAR(255) UNIQUE NOT NULL,
    email         VARCHAR(255) UNIQUE NOT NULL,
    password_hash TEXT                NOT NULL,
    role          user_role           NOT NULL DEFAULT 'user',
    created_at    TIMESTAMPTZ         NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ         NOT NULL DEFAULT NOW()
);

-- Refresh Tokens Table
CREATE TABLE refresh_tokens
(
    id         UUID PRIMARY KEY     DEFAULT gen_random_uuid(),
    user_id    UUID        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    token_hash TEXT        NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked    BOOLEAN     NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Index for fast token lookups
CREATE INDEX idx_refresh_tokens_user_id ON refresh_tokens (user_id);