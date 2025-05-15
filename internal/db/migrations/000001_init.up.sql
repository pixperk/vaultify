CREATE TABLE users(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT now()
);


CREATE INDEX ON users(email);

CREATE TABLE secrets(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id),
    name TEXT NOT NULL,
    encrypted_value BYTEA NOT NULL,
    created_at TIMESTAMP DEFAULT now()
);

CREATE INDEX ON secrets(user_id);