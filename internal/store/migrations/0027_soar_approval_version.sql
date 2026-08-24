ALTER TABLE soar_approvals
    ADD COLUMN version INTEGER NOT NULL DEFAULT 1 CHECK (version > 0);
