CREATE TABLE audit_logs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id),
  user_email TEXT NOT NULL,
  action TEXT NOT NULL,                 -- 'secret.view', 'secret.update', etc.
  resource_type TEXT NOT NULL,         -- 'secret', 'hmac_key', etc.
  resource_path TEXT NOT NULL,         -- like 'prod/api/stripe_key'
  success BOOLEAN NOT NULL,
  reason TEXT,
  created_at TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX idx_audit_logs_user_email ON audit_logs(user_email);
CREATE INDEX idx_audit_logs_action ON audit_logs(action);
CREATE INDEX idx_audit_logs_resource_type ON audit_logs(resource_type);
CREATE INDEX idx_audit_logs_created_at ON audit_logs(created_at);
