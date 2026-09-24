-- Smart Asset Inventory & Predictive Maintenance
-- PostgreSQL secure schema, 12 tables.
-- Security highlights:
--   1. Passwords are never stored as plain text. Only users.password_hash is stored.
--   2. Hashing should happen in the application with Argon2id or bcrypt before INSERT/UPDATE.
--   3. The database enforces hash-shaped values and rejects common plain-text-looking values.
--   4. Row Level Security is enabled on business tables and scoped by org unit.
--   5. Asset history and audit log are append-only.
-- Runtime recommendation:
--   Use a non-owner application DB role. Reserve table ownership and migrations for a separate role.
--   A privileged service connection, if needed for jobs/imports, should use the app_service DB role.

BEGIN;

CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS citext;

CREATE TYPE org_unit_type AS ENUM ('university', 'campus', 'college', 'department', 'unit');
CREATE TYPE location_type AS ENUM ('campus', 'building', 'college', 'department', 'floor', 'room', 'office', 'storage');
CREATE TYPE user_status AS ENUM ('active', 'disabled', 'locked');
CREATE TYPE asset_condition AS ENUM ('new', 'good', 'fair', 'poor', 'failed', 'unknown');
CREATE TYPE asset_status AS ENUM ('draft', 'active', 'in_transfer', 'in_maintenance', 'retired', 'disposed', 'lost');
CREATE TYPE document_type AS ENUM ('supplier', 'purchase_order', 'invoice', 'receipt', 'warranty', 'manual', 'retirement_evidence', 'other');
CREATE TYPE malware_scan_status AS ENUM ('pending', 'clean', 'infected', 'failed');
CREATE TYPE event_type AS ENUM ('created', 'imported', 'transfer_requested', 'transfer_approved', 'checked_in', 'checked_out', 'custody_changed', 'location_changed', 'condition_changed', 'stocktake_observed', 'maintenance_completed', 'retirement_requested', 'retired', 'disposed');
CREATE TYPE trigger_type AS ENUM ('calendar', 'runtime', 'condition');
CREATE TYPE work_order_priority AS ENUM ('low', 'medium', 'high', 'critical');
CREATE TYPE work_order_status AS ENUM ('open', 'scheduled', 'in_progress', 'completed', 'cancelled');

CREATE TABLE org_units (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    parent_id uuid REFERENCES org_units(id) ON DELETE RESTRICT,
    name text NOT NULL,
    unit_type org_unit_type NOT NULL,
    is_active boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT org_units_name_not_blank CHECK (btrim(name) <> ''),
    CONSTRAINT org_units_no_self_parent CHECK (parent_id IS NULL OR parent_id <> id)
);

CREATE TABLE locations (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    parent_id uuid REFERENCES locations(id) ON DELETE RESTRICT,
    org_unit_id uuid NOT NULL REFERENCES org_units(id) ON DELETE RESTRICT,
    location_type location_type NOT NULL,
    name text NOT NULL,
    code text,
    is_active boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    created_by uuid,
    updated_by uuid,
    CONSTRAINT locations_name_not_blank CHECK (btrim(name) <> ''),
    CONSTRAINT locations_code_not_blank CHECK (code IS NULL OR btrim(code) <> ''),
    CONSTRAINT locations_no_self_parent CHECK (parent_id IS NULL OR parent_id <> id),
    CONSTRAINT locations_unique_code_per_org UNIQUE (org_unit_id, code)
);

CREATE TABLE users (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    email citext NOT NULL UNIQUE,
    full_name text NOT NULL,
    password_hash text NOT NULL,
    status user_status NOT NULL DEFAULT 'active',
    mfa_enabled boolean NOT NULL DEFAULT false,
    last_login_at timestamptz,
    failed_login_count integer NOT NULL DEFAULT 0,
    locked_until timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT users_email_basic_shape CHECK (email::text ~* '^[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}$'),
    CONSTRAINT users_full_name_not_blank CHECK (btrim(full_name) <> ''),
    CONSTRAINT users_failed_login_non_negative CHECK (failed_login_count >= 0),
    CONSTRAINT users_password_hash_strong_shape CHECK (
        password_hash ~ '^(\$argon2(id|i|d)\$v=[0-9]+\$m=[0-9]+,t=[0-9]+,p=[0-9]+\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+|\$2[aby]\$[0-9]{2}\$[./A-Za-z0-9]{53})$'
    ),
    CONSTRAINT users_password_hash_not_common_plaintext CHECK (
        length(password_hash) >= 55
        AND password_hash !~* '^(password|passw0rd|admin|admin123|123456|qwerty|letmein|welcome)$'
    )
);

CREATE TABLE roles (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    code text NOT NULL UNIQUE,
    name text NOT NULL,
    is_system boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT roles_code_shape CHECK (code ~ '^[a-z][a-z0-9_]{2,63}$'),
    CONSTRAINT roles_name_not_blank CHECK (btrim(name) <> '')
);

CREATE TABLE user_roles (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id uuid NOT NULL REFERENCES roles(id) ON DELETE RESTRICT,
    org_unit_id uuid REFERENCES org_units(id) ON DELETE RESTRICT,
    granted_by uuid REFERENCES users(id) ON DELETE SET NULL,
    expires_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT user_roles_expiry_future CHECK (expires_at IS NULL OR expires_at > created_at)
);

CREATE UNIQUE INDEX user_roles_unique_open_ended
    ON user_roles (user_id, role_id, COALESCE(org_unit_id, '00000000-0000-0000-0000-000000000000'::uuid))
    WHERE expires_at IS NULL;

CREATE TABLE asset_categories (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    parent_id uuid REFERENCES asset_categories(id) ON DELETE RESTRICT,
    code text NOT NULL UNIQUE,
    name text NOT NULL,
    useful_life_months integer,
    requires_serial boolean NOT NULL DEFAULT false,
    default_specs jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT asset_categories_code_shape CHECK (code ~ '^[A-Z0-9_\-]{2,40}$'),
    CONSTRAINT asset_categories_name_not_blank CHECK (btrim(name) <> ''),
    CONSTRAINT asset_categories_life_positive CHECK (useful_life_months IS NULL OR useful_life_months > 0),
    CONSTRAINT asset_categories_no_self_parent CHECK (parent_id IS NULL OR parent_id <> id)
);

CREATE TABLE assets (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    category_id uuid NOT NULL REFERENCES asset_categories(id) ON DELETE RESTRICT,
    current_location_id uuid NOT NULL REFERENCES locations(id) ON DELETE RESTRICT,
    custodian_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
    asset_tag text NOT NULL UNIQUE,
    serial_number text UNIQUE,
    brand text,
    model text,
    specifications jsonb NOT NULL DEFAULT '{}'::jsonb,
    condition asset_condition NOT NULL DEFAULT 'unknown',
    status asset_status NOT NULL DEFAULT 'draft',
    purchase_date date,
    purchase_cost numeric(14,2),
    next_maintenance_due_at timestamptz,
    risk_band text NOT NULL DEFAULT 'unknown',
    risk_reasons jsonb NOT NULL DEFAULT '[]'::jsonb,
    retired_at timestamptz,
    retirement_reason text,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    created_by uuid REFERENCES users(id) ON DELETE SET NULL,
    updated_by uuid REFERENCES users(id) ON DELETE SET NULL,
    CONSTRAINT assets_tag_shape CHECK (asset_tag ~ '^[A-Z0-9][A-Z0-9_\-]{2,63}$'),
    CONSTRAINT assets_serial_not_blank CHECK (serial_number IS NULL OR btrim(serial_number) <> ''),
    CONSTRAINT assets_cost_non_negative CHECK (purchase_cost IS NULL OR purchase_cost >= 0),
    CONSTRAINT assets_risk_band_allowed CHECK (risk_band IN ('unknown', 'low', 'medium', 'high', 'critical')),
    CONSTRAINT assets_retired_fields CHECK (
        (status NOT IN ('retired', 'disposed') AND retired_at IS NULL)
        OR (status IN ('retired', 'disposed') AND retired_at IS NOT NULL AND btrim(COALESCE(retirement_reason, '')) <> '')
    )
);

CREATE TABLE asset_documents (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id uuid NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    document_type document_type NOT NULL,
    supplier_name text,
    purchase_order_number text,
    invoice_number text,
    warranty_provider text,
    warranty_expires_at date,
    storage_bucket text NOT NULL,
    storage_key text NOT NULL,
    mime_type text NOT NULL,
    byte_size bigint NOT NULL,
    sha256_hex text NOT NULL,
    malware_scan_status malware_scan_status NOT NULL DEFAULT 'pending',
    uploaded_by uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT asset_documents_storage_not_blank CHECK (btrim(storage_bucket) <> '' AND btrim(storage_key) <> ''),
    CONSTRAINT asset_documents_byte_size_positive CHECK (byte_size > 0),
    CONSTRAINT asset_documents_sha256_shape CHECK (sha256_hex ~ '^[a-f0-9]{64}$'),
    CONSTRAINT asset_documents_no_public_urls CHECK (storage_key !~* '^https?://')
);

CREATE TABLE asset_events (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id uuid NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    actor_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
    event_type event_type NOT NULL,
    from_location_id uuid REFERENCES locations(id) ON DELETE SET NULL,
    to_location_id uuid REFERENCES locations(id) ON DELETE SET NULL,
    from_custodian_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
    to_custodian_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
    event_data jsonb NOT NULL DEFAULT '{}'::jsonb,
    occurred_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT asset_events_transfer_has_target CHECK (
        event_type NOT IN ('transfer_requested', 'transfer_approved', 'location_changed')
        OR to_location_id IS NOT NULL
    )
);

CREATE TABLE maintenance_templates (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    category_id uuid NOT NULL REFERENCES asset_categories(id) ON DELETE CASCADE,
    name text NOT NULL,
    trigger_type trigger_type NOT NULL,
    interval_days integer,
    runtime_hours integer,
    condition_rule jsonb NOT NULL DEFAULT '{}'::jsonb,
    checklist jsonb NOT NULL DEFAULT '[]'::jsonb,
    is_active boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    created_by uuid REFERENCES users(id) ON DELETE SET NULL,
    updated_by uuid REFERENCES users(id) ON DELETE SET NULL,
    CONSTRAINT maintenance_templates_name_not_blank CHECK (btrim(name) <> ''),
    CONSTRAINT maintenance_templates_trigger_config CHECK (
        (trigger_type = 'calendar' AND interval_days IS NOT NULL AND interval_days > 0)
        OR (trigger_type = 'runtime' AND runtime_hours IS NOT NULL AND runtime_hours > 0)
        OR (trigger_type = 'condition' AND condition_rule <> '{}'::jsonb)
    )
);

CREATE TABLE work_orders (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id uuid NOT NULL REFERENCES assets(id) ON DELETE RESTRICT,
    template_id uuid REFERENCES maintenance_templates(id) ON DELETE SET NULL,
    technician_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
    priority work_order_priority NOT NULL DEFAULT 'medium',
    status work_order_status NOT NULL DEFAULT 'open',
    scheduled_at timestamptz,
    started_at timestamptz,
    completed_at timestamptz,
    checklist_result jsonb NOT NULL DEFAULT '{}'::jsonb,
    parts_cost numeric(14,2) NOT NULL DEFAULT 0,
    labor_cost numeric(14,2) NOT NULL DEFAULT 0,
    downtime_minutes integer NOT NULL DEFAULT 0,
    outcome text,
    completion_notes text,
    next_due_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    created_by uuid REFERENCES users(id) ON DELETE SET NULL,
    updated_by uuid REFERENCES users(id) ON DELETE SET NULL,
    CONSTRAINT work_orders_costs_non_negative CHECK (parts_cost >= 0 AND labor_cost >= 0),
    CONSTRAINT work_orders_downtime_non_negative CHECK (downtime_minutes >= 0),
    CONSTRAINT work_orders_completed_fields CHECK (
        status <> 'completed'
        OR (completed_at IS NOT NULL AND btrim(COALESCE(outcome, '')) <> '')
    )
);

CREATE TABLE audit_log (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    actor_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
    action text NOT NULL,
    table_name text,
    record_id uuid,
    ip_address inet,
    user_agent text,
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT audit_log_action_shape CHECK (action ~ '^[a-z][a-z0-9_.-]{2,120}$'),
    CONSTRAINT audit_log_no_secret_metadata CHECK (
        metadata::text !~* '(password|token|secret|authorization|cookie)'
    )
);

ALTER TABLE locations
    ADD CONSTRAINT locations_created_by_fk FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL,
    ADD CONSTRAINT locations_updated_by_fk FOREIGN KEY (updated_by) REFERENCES users(id) ON DELETE SET NULL;

CREATE INDEX org_units_parent_idx ON org_units(parent_id);
CREATE INDEX locations_parent_idx ON locations(parent_id);
CREATE INDEX locations_org_unit_idx ON locations(org_unit_id);
CREATE INDEX user_roles_user_idx ON user_roles(user_id);
CREATE INDEX user_roles_role_scope_idx ON user_roles(role_id, org_unit_id);
CREATE INDEX assets_category_idx ON assets(category_id);
CREATE INDEX assets_location_idx ON assets(current_location_id);
CREATE INDEX assets_custodian_idx ON assets(custodian_user_id);
CREATE INDEX assets_status_idx ON assets(status);
CREATE INDEX asset_documents_asset_idx ON asset_documents(asset_id);
CREATE INDEX asset_events_asset_time_idx ON asset_events(asset_id, occurred_at DESC);
CREATE INDEX maintenance_templates_category_idx ON maintenance_templates(category_id);
CREATE INDEX work_orders_asset_status_idx ON work_orders(asset_id, status);
CREATE INDEX work_orders_technician_idx ON work_orders(technician_user_id);
CREATE INDEX audit_log_actor_time_idx ON audit_log(actor_user_id, created_at DESC);
CREATE INDEX audit_log_action_time_idx ON audit_log(action, created_at DESC);

CREATE OR REPLACE FUNCTION app_current_user_id()
RETURNS uuid
LANGUAGE sql
STABLE
AS $$
    SELECT NULLIF(current_setting('app.current_user_id', true), '')::uuid
$$;

CREATE OR REPLACE FUNCTION app_is_service_role()
RETURNS boolean
LANGUAGE sql
STABLE
AS $$
    SELECT current_user IN ('postgres', 'app_service')
        OR session_user IN ('postgres', 'app_service')
$$;

CREATE OR REPLACE FUNCTION touch_updated_at()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$;

CREATE TRIGGER org_units_touch_updated_at
BEFORE UPDATE ON org_units
FOR EACH ROW EXECUTE FUNCTION touch_updated_at();

CREATE TRIGGER locations_touch_updated_at
BEFORE UPDATE ON locations
FOR EACH ROW EXECUTE FUNCTION touch_updated_at();

CREATE TRIGGER users_touch_updated_at
BEFORE UPDATE ON users
FOR EACH ROW EXECUTE FUNCTION touch_updated_at();

CREATE TRIGGER asset_categories_touch_updated_at
BEFORE UPDATE ON asset_categories
FOR EACH ROW EXECUTE FUNCTION touch_updated_at();

CREATE TRIGGER assets_touch_updated_at
BEFORE UPDATE ON assets
FOR EACH ROW EXECUTE FUNCTION touch_updated_at();

CREATE TRIGGER asset_documents_touch_updated_at
BEFORE UPDATE ON asset_documents
FOR EACH ROW EXECUTE FUNCTION touch_updated_at();

CREATE TRIGGER maintenance_templates_touch_updated_at
BEFORE UPDATE ON maintenance_templates
FOR EACH ROW EXECUTE FUNCTION touch_updated_at();

CREATE TRIGGER work_orders_touch_updated_at
BEFORE UPDATE ON work_orders
FOR EACH ROW EXECUTE FUNCTION touch_updated_at();

CREATE OR REPLACE FUNCTION reject_plain_password_hash()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.password_hash IS NULL
       OR NEW.password_hash !~ '^(\$argon2(id|i|d)\$v=[0-9]+\$m=[0-9]+,t=[0-9]+,p=[0-9]+\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+|\$2[aby]\$[0-9]{2}\$[./A-Za-z0-9]{53})$'
    THEN
        RAISE EXCEPTION 'users.password_hash must contain an Argon2 or bcrypt hash, never a plain password';
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER users_reject_plain_password_hash
BEFORE INSERT OR UPDATE OF password_hash ON users
FOR EACH ROW EXECUTE FUNCTION reject_plain_password_hash();

CREATE OR REPLACE FUNCTION block_append_only_changes()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION '% is append-only; updates and deletes are not allowed', TG_TABLE_NAME;
END;
$$;

CREATE TRIGGER asset_events_append_only
BEFORE UPDATE OR DELETE ON asset_events
FOR EACH ROW EXECUTE FUNCTION block_append_only_changes();

CREATE TRIGGER audit_log_append_only
BEFORE UPDATE OR DELETE ON audit_log
FOR EACH ROW EXECUTE FUNCTION block_append_only_changes();

CREATE OR REPLACE FUNCTION block_retired_asset_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.status IN ('retired', 'disposed') AND NOT app_is_service_role() THEN
        RAISE EXCEPTION 'retired or disposed assets are read-only';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER assets_block_retired_mutation
BEFORE UPDATE ON assets
FOR EACH ROW EXECUTE FUNCTION block_retired_asset_mutation();

CREATE OR REPLACE FUNCTION log_asset_event_from_work_order()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.status = 'completed' AND OLD.status IS DISTINCT FROM NEW.status THEN
        INSERT INTO asset_events (
            asset_id,
            actor_user_id,
            event_type,
            event_data
        )
        VALUES (
            NEW.asset_id,
            COALESCE(NEW.updated_by, NEW.technician_user_id),
            'maintenance_completed',
            jsonb_build_object(
                'work_order_id', NEW.id,
                'parts_cost', NEW.parts_cost,
                'labor_cost', NEW.labor_cost,
                'downtime_minutes', NEW.downtime_minutes,
                'outcome', NEW.outcome,
                'next_due_at', NEW.next_due_at
            )
        );
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER work_orders_log_completion
AFTER UPDATE ON work_orders
FOR EACH ROW EXECUTE FUNCTION log_asset_event_from_work_order();

CREATE OR REPLACE FUNCTION org_unit_is_visible(target_org_unit_id uuid)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
    WITH RECURSIVE granted AS (
        SELECT ur.org_unit_id
        FROM user_roles ur
        JOIN roles r ON r.id = ur.role_id
        WHERE ur.user_id = app_current_user_id()
          AND (ur.expires_at IS NULL OR ur.expires_at > now())
          AND (
                ur.org_unit_id IS NOT NULL
                OR r.code IN ('super_admin', 'auditor')
          )
    ),
    descendants AS (
        SELECT ou.id
        FROM org_units ou
        JOIN granted g ON g.org_unit_id IS NULL OR g.org_unit_id = ou.id
        UNION ALL
        SELECT child.id
        FROM org_units child
        JOIN descendants d ON child.parent_id = d.id
    )
    SELECT app_is_service_role()
        OR EXISTS (SELECT 1 FROM descendants WHERE id = target_org_unit_id)
$$;

CREATE OR REPLACE FUNCTION has_role(role_code text, target_org_unit_id uuid DEFAULT NULL)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
    WITH RECURSIVE matching_grants AS (
        SELECT ur.org_unit_id
        FROM user_roles ur
        JOIN roles r ON r.id = ur.role_id
        WHERE ur.user_id = app_current_user_id()
          AND r.code = role_code
          AND (ur.expires_at IS NULL OR ur.expires_at > now())
    ),
    role_scope AS (
        SELECT ou.id
        FROM org_units ou
        JOIN matching_grants mg ON mg.org_unit_id IS NULL OR mg.org_unit_id = ou.id
        UNION ALL
        SELECT child.id
        FROM org_units child
        JOIN role_scope rs ON child.parent_id = rs.id
    )
    SELECT app_is_service_role()
        OR (
            target_org_unit_id IS NULL
            AND EXISTS (SELECT 1 FROM matching_grants)
        )
        OR EXISTS (SELECT 1 FROM role_scope WHERE id = target_org_unit_id)
$$;

CREATE OR REPLACE FUNCTION asset_org_unit_id(asset_id uuid)
RETURNS uuid
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
    SELECT l.org_unit_id
    FROM assets a
    JOIN locations l ON l.id = a.current_location_id
    WHERE a.id = asset_id
$$;

ALTER TABLE org_units ENABLE ROW LEVEL SECURITY;
ALTER TABLE locations ENABLE ROW LEVEL SECURITY;
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE asset_categories ENABLE ROW LEVEL SECURITY;
ALTER TABLE assets ENABLE ROW LEVEL SECURITY;
ALTER TABLE asset_documents ENABLE ROW LEVEL SECURITY;
ALTER TABLE asset_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE maintenance_templates ENABLE ROW LEVEL SECURITY;
ALTER TABLE work_orders ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY;

CREATE POLICY org_units_select_scoped ON org_units
FOR SELECT USING (org_unit_is_visible(id));

CREATE POLICY locations_select_scoped ON locations
FOR SELECT USING (org_unit_is_visible(org_unit_id));

CREATE POLICY locations_admin_write ON locations
FOR ALL USING (has_role('asset_admin', org_unit_id))
WITH CHECK (has_role('asset_admin', org_unit_id));

CREATE POLICY users_self_select ON users
FOR SELECT USING (id = app_current_user_id() OR has_role('super_admin'));

CREATE POLICY users_super_admin_write ON users
FOR ALL USING (has_role('super_admin'))
WITH CHECK (has_role('super_admin'));

CREATE POLICY roles_read_authenticated ON roles
FOR SELECT USING (app_current_user_id() IS NOT NULL OR app_is_service_role());

CREATE POLICY roles_super_admin_write ON roles
FOR ALL USING (has_role('super_admin'))
WITH CHECK (has_role('super_admin'));

CREATE POLICY user_roles_self_or_admin_read ON user_roles
FOR SELECT USING (
    user_id = app_current_user_id()
    OR has_role('super_admin')
    OR (org_unit_id IS NOT NULL AND has_role('asset_admin', org_unit_id))
);

CREATE POLICY user_roles_super_admin_write ON user_roles
FOR ALL USING (has_role('super_admin'))
WITH CHECK (has_role('super_admin'));

CREATE POLICY asset_categories_read_authenticated ON asset_categories
FOR SELECT USING (app_current_user_id() IS NOT NULL OR app_is_service_role());

CREATE POLICY asset_categories_admin_write ON asset_categories
FOR ALL USING (has_role('asset_admin'))
WITH CHECK (has_role('asset_admin'));

CREATE POLICY assets_select_scoped ON assets
FOR SELECT USING (org_unit_is_visible(asset_org_unit_id(id)));

CREATE POLICY assets_admin_write_scoped ON assets
FOR ALL USING (has_role('asset_admin', asset_org_unit_id(id)))
WITH CHECK (
    has_role(
        'asset_admin',
        (SELECT l.org_unit_id FROM locations l WHERE l.id = current_location_id)
    )
);

CREATE POLICY asset_documents_procurement_read ON asset_documents
FOR SELECT USING (
    org_unit_is_visible(asset_org_unit_id(asset_id))
    AND (
        has_role('procurement_viewer', asset_org_unit_id(asset_id))
        OR has_role('asset_admin', asset_org_unit_id(asset_id))
        OR has_role('auditor', asset_org_unit_id(asset_id))
    )
);

CREATE POLICY asset_documents_procurement_write ON asset_documents
FOR ALL USING (
    has_role('procurement_viewer', asset_org_unit_id(asset_id))
    OR has_role('asset_admin', asset_org_unit_id(asset_id))
)
WITH CHECK (
    has_role('procurement_viewer', asset_org_unit_id(asset_id))
    OR has_role('asset_admin', asset_org_unit_id(asset_id))
);

CREATE POLICY asset_events_read_scoped ON asset_events
FOR SELECT USING (
    org_unit_is_visible(asset_org_unit_id(asset_id))
    OR EXISTS (
        SELECT 1
        FROM locations l
        WHERE l.id IN (from_location_id, to_location_id)
          AND org_unit_is_visible(l.org_unit_id)
    )
);

CREATE POLICY asset_events_insert_authorized ON asset_events
FOR INSERT WITH CHECK (
    has_role('asset_admin', asset_org_unit_id(asset_id))
    OR has_role('technician', asset_org_unit_id(asset_id))
    OR has_role('custodian', asset_org_unit_id(asset_id))
    OR has_role('auditor', asset_org_unit_id(asset_id))
);

CREATE POLICY maintenance_templates_read_scoped ON maintenance_templates
FOR SELECT USING (app_current_user_id() IS NOT NULL OR app_is_service_role());

CREATE POLICY maintenance_templates_admin_write ON maintenance_templates
FOR ALL USING (has_role('asset_admin'))
WITH CHECK (has_role('asset_admin'));

CREATE POLICY work_orders_read_scoped ON work_orders
FOR SELECT USING (
    org_unit_is_visible(asset_org_unit_id(asset_id))
    OR technician_user_id = app_current_user_id()
);

CREATE POLICY work_orders_write_authorized ON work_orders
FOR ALL USING (
    has_role('asset_admin', asset_org_unit_id(asset_id))
    OR has_role('technician', asset_org_unit_id(asset_id))
    OR technician_user_id = app_current_user_id()
)
WITH CHECK (
    has_role('asset_admin', asset_org_unit_id(asset_id))
    OR has_role('technician', asset_org_unit_id(asset_id))
    OR technician_user_id = app_current_user_id()
);

CREATE POLICY audit_log_read_auditors ON audit_log
FOR SELECT USING (
    has_role('auditor')
    OR has_role('super_admin')
);

CREATE POLICY audit_log_insert_service ON audit_log
FOR INSERT WITH CHECK (
    app_is_service_role()
    OR actor_user_id = app_current_user_id()
);

INSERT INTO roles (code, name, is_system) VALUES
    ('super_admin', 'Super Administrator', true),
    ('asset_admin', 'Asset Administrator', true),
    ('procurement_viewer', 'Procurement and Finance Viewer', true),
    ('custodian', 'Custodian or Department Manager', true),
    ('technician', 'Maintenance Technician', true),
    ('auditor', 'Auditor', true),
    ('retirement_approver', 'Retirement Approver', true)
ON CONFLICT (code) DO NOTHING;

COMMENT ON TABLE users IS 'Stores user identities. Never store plain passwords; password_hash must be Argon2id or bcrypt.';
COMMENT ON COLUMN users.password_hash IS 'Strong one-way password hash only. Generate in application with Argon2id preferred or bcrypt.';
COMMENT ON TABLE asset_documents IS 'Stores document metadata only. Files must live in private object storage with short-lived download authorization.';
COMMENT ON TABLE asset_events IS 'Append-only asset movement, custody, stocktake, maintenance, and retirement history.';
COMMENT ON TABLE audit_log IS 'Append-only sanitized security audit events. Do not store passwords, tokens, cookies, or secret payloads.';

COMMIT;
