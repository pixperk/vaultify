CREATE TABLE sharing_rules (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  owner_email TEXT NOT NULL,
  target_email TEXT NOT NULL,
  path TEXT NOT NULL,
  permission TEXT CHECK (permission IN ('read', 'write')) NOT NULL,
  created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_sharing_lookup ON sharing_rules(target_email, path);
