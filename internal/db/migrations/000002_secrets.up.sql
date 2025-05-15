CREATE TABLE secrets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    path TEXT NOT NULL, --'users/{user_id}/secret_name'
    encrypted_value BYTEA NOT NULL,
    nonce BYTEA NOT NULL, -- needed for decryption
    created_at TIMESTAMP DEFAULT now(),
    updated_at TIMESTAMP DEFAULT now(),
    UNIQUE(user_id, path) -- prevent duplicate secrets for same user & path
);
