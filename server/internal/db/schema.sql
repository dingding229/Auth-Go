-- Initial schema for Auth Go 1.0.0.

CREATE TABLE activation_instance_sessions (activation_id integer NOT NULL REFERENCES activations(id) ON DELETE CASCADE,
  session text NOT NULL,
  PRIMARY KEY(activation_id,session));

CREATE TABLE `activations` (unbound_at datetime,`id` integer PRIMARY KEY AUTOINCREMENT,
  `created_at` datetime,
  `updated_at` datetime,
  `license_id` integer NOT NULL,
  `kind` text NOT NULL,
  `value` text NOT NULL,
  `fingerprint_detail` text,
  `hostname` text,
  `os` text,
  `client_version` text,
  `first_ip` text,
  `last_ip` text,
  `last_seen_at` datetime,
  `status` text NOT NULL DEFAULT "active",
  `offline_at` datetime,
  `token` text NOT NULL,
  `lease_expires_at` datetime,
  instance_session text NOT NULL DEFAULT '',
  CONSTRAINT `fk_activations_license` FOREIGN KEY (`license_id`) REFERENCES `licenses`(`id`) ON DELETE RESTRICT);

CREATE TABLE `admin_sessions` (`id` text,
  `admin_id` integer NOT NULL,
  `token_hash` text NOT NULL,
  `auth_version` integer NOT NULL,
  `created_at` datetime,
  `updated_at` datetime,
  `expires_at` datetime NOT NULL,
  `revoked_at` datetime,
  PRIMARY KEY (`id`),
  CONSTRAINT `fk_admin_sessions_admin` FOREIGN KEY (`admin_id`) REFERENCES `admins`(`id`) ON DELETE RESTRICT);

CREATE TABLE "admins" (`id` integer PRIMARY KEY AUTOINCREMENT,
  `created_at` datetime,
  `updated_at` datetime,
  `username` text NOT NULL,
  `password_hash` text NOT NULL,
  `totp_secret` text,
  `last_login_at` datetime,
  `auth_version` integer NOT NULL DEFAULT 0,
  `totp_enabled` numeric NOT NULL DEFAULT false,
  `pending_totp_secret` text,
  `pending_totp_expires_at` datetime,
  `last_totp_step` integer NOT NULL DEFAULT 0);

CREATE TABLE `announcements` (`id` integer PRIMARY KEY AUTOINCREMENT,
  `created_at` datetime,
  `updated_at` datetime,
  `app_id` integer NOT NULL,
  `title` text NOT NULL,
  `content` text,
  `published_at` datetime,
  `expires_at` datetime,
  CONSTRAINT `fk_announcements_application` FOREIGN KEY (`app_id`) REFERENCES `applications`(`id`) ON DELETE RESTRICT);

CREATE TABLE `app_versions` (`id` integer PRIMARY KEY AUTOINCREMENT,
  `created_at` datetime,
  `updated_at` datetime,
  `app_id` integer NOT NULL,
  `version` text NOT NULL,
  `changelog` text,
  `mandatory` numeric,
  `published_at` datetime,
  source text NOT NULL DEFAULT 'manual',
  withdrawn numeric NOT NULL DEFAULT 0,
  mandatory_override numeric NOT NULL DEFAULT 0,
  disabled numeric NOT NULL DEFAULT 0,
  encrypted integer NOT NULL DEFAULT 0 CHECK(encrypted IN (0,1)),
  built_at datetime,
  CONSTRAINT `fk_app_versions_application` FOREIGN KEY (`app_id`) REFERENCES `applications`(`id`) ON DELETE RESTRICT);

CREATE TABLE "applications" (`id` integer PRIMARY KEY AUTOINCREMENT,
  `created_at` datetime,
  `updated_at` datetime,
  `name` text NOT NULL,
  `app_key` text NOT NULL,
  `app_secret_encrypted` text NOT NULL,
  `private_key_encrypted` text NOT NULL,
  `public_key` text NOT NULL,
  `status` text NOT NULL DEFAULT "active",
  `description` text,
  `previous_public_key` text,
  `next_check_in` integer NOT NULL DEFAULT 3600,
  `grace_hours` integer NOT NULL DEFAULT 72,
  `heartbeat_interval` integer NOT NULL DEFAULT 60,
  unlock_secret_encrypted text NOT NULL DEFAULT '',
  license_salt text NOT NULL DEFAULT '',
  docker_image text NOT NULL DEFAULT '',
  trial_enabled numeric NOT NULL DEFAULT 0,
  trial_days integer NOT NULL DEFAULT 14 CHECK(trial_days BETWEEN 1 AND 365),
  trial_template_id integer REFERENCES feature_templates(id) ON DELETE RESTRICT);

CREATE TABLE "audit_logs" (`id` integer PRIMARY KEY AUTOINCREMENT,
  `created_at` datetime,
  `admin_id` integer,
  `action` text NOT NULL,
  `resource` text,
  `resource_id` text,
  `ip` text,
  `operator` text,
  `user_agent` text,
  `summary` text,
  `status_code` integer,
  `details` text,
  CONSTRAINT `fk_audit_logs_admin` FOREIGN KEY (`admin_id`) REFERENCES `admins`(`id`) ON DELETE RESTRICT);

CREATE TABLE `client_session_bindings` (`session_id` text,
  `activation_id` integer,
  `generation` text NOT NULL,
  PRIMARY KEY (`session_id`,`activation_id`),
  CONSTRAINT `fk_client_session_bindings_activation` FOREIGN KEY (`activation_id`) REFERENCES `activations`(`id`) ON DELETE RESTRICT,
  CONSTRAINT `fk_client_session_bindings_session` FOREIGN KEY (`session_id`) REFERENCES `client_sessions`(`id`) ON DELETE RESTRICT);

CREATE TABLE `client_sessions` (`id` text,
  `app_id` integer NOT NULL,
  `license_id` integer NOT NULL,
  `token_hash` text NOT NULL,
  `device` text,
  `created_at` datetime,
  `updated_at` datetime,
  `revoked_at` datetime,
  PRIMARY KEY (`id`),
  CONSTRAINT `fk_client_sessions_application` FOREIGN KEY (`app_id`) REFERENCES `applications`(`id`) ON DELETE RESTRICT,
  CONSTRAINT `fk_client_sessions_license` FOREIGN KEY (`license_id`) REFERENCES `licenses`(`id`) ON DELETE RESTRICT);

CREATE TABLE docker_hub_sync_states (id integer PRIMARY KEY AUTOINCREMENT,
  app_id integer NOT NULL UNIQUE REFERENCES applications(id) ON DELETE CASCADE,
  image text NOT NULL,
  last_sync_at datetime,
  last_result text NOT NULL DEFAULT '',
  last_error text NOT NULL DEFAULT '',
  next_sync_at datetime NOT NULL,
  retry_at datetime,
  collected integer NOT NULL DEFAULT 0,
  ignored integer NOT NULL DEFAULT 0,
  failures integer NOT NULL DEFAULT 0,
  tags_json text NOT NULL DEFAULT '{}');

CREATE TABLE `end_users` (`id` integer PRIMARY KEY AUTOINCREMENT,
  `created_at` datetime,
  `updated_at` datetime,
  `name` text NOT NULL,
  `email` text NOT NULL DEFAULT "",
  `note` text,
  `status` text NOT NULL DEFAULT "active",
  `portal_password_hash` text,
  `auth_version` integer NOT NULL DEFAULT 0);

CREATE TABLE feature_templates(id integer PRIMARY KEY AUTOINCREMENT,
  app_id integer NOT NULL REFERENCES applications(id) ON DELETE RESTRICT,
  name text NOT NULL CHECK(length(name) BETWEEN 1 AND 64),
  features text NOT NULL CHECK(json_valid(features) AND json_type(features)='object'),
  default_max_activations integer CHECK(default_max_activations BETWEEN 1 AND 1000000),
  default_days integer CHECK(default_days BETWEEN 1 AND 36500),
  default_maintenance_days integer CHECK(default_maintenance_days BETWEEN 0 AND 36500),
  created_at datetime,
  updated_at datetime,
  UNIQUE(app_id,name));

CREATE TABLE gateway_keys (id text PRIMARY KEY,
  public_key text NOT NULL,
  private_encrypted text NOT NULL,
  created_at datetime NOT NULL,
  expires_at datetime);

CREATE TABLE license_sharing(license_id integer PRIMARY KEY REFERENCES licenses(id) ON DELETE CASCADE,
  countries text NOT NULL DEFAULT '[]' CHECK(json_valid(countries) AND json_type(countries)='array'),
  asns text NOT NULL DEFAULT '[]' CHECK(json_valid(asns) AND json_type(asns)='array'),
  instance_count integer NOT NULL DEFAULT 0 CHECK(instance_count>=0),
  flagged_at datetime,
  last_seen_at datetime,
  ignored_until datetime,
  updated_at datetime NOT NULL);

CREATE TABLE "licenses" (`id` integer PRIMARY KEY AUTOINCREMENT,
  `created_at` datetime,
  `updated_at` datetime,
  `app_id` integer NOT NULL,
  `key` text NOT NULL,
  `batch_id` text,
  `validity_rule` text NOT NULL DEFAULT "perpetual",
  `type` text NOT NULL DEFAULT "standard",
  `status` text NOT NULL DEFAULT "unused",
  `verify_methods` text,
  `match_mode` text NOT NULL DEFAULT "all",
  `max_activations` integer NOT NULL DEFAULT 1,
  `features` text,
  `starts_at` datetime,
  `expires_at` datetime,
  `duration_days` integer,
  `portal_password_hash` text,
  `note` text,
  `metadata` text,
  user_id integer,
  maintenance_until datetime,
  source text NOT NULL DEFAULT '',
  converted_at datetime,
  CONSTRAINT `fk_licenses_application` FOREIGN KEY (`app_id`) REFERENCES `applications`(`id`) ON DELETE RESTRICT,
  CONSTRAINT "fk_licenses_user" FOREIGN KEY ("user_id") REFERENCES "end_users"("id") ON DELETE RESTRICT);

CREATE TABLE `mail_deliveries` (`receipt_key` text,
  `id` integer PRIMARY KEY AUTOINCREMENT,
  `created_at` datetime,
  `updated_at` datetime,
  `recipient` text,
  `subject` text,
  `body` text,
  `status` text NOT NULL DEFAULT "pending",
  `attempts` integer,
  `last_error` text,
  `next_retry_at` datetime,
  `claim_until` datetime,
  `claim_token` text,
  `sent_at` datetime);

CREATE TABLE `notification_receipts` (`key` text,
  `created_at` datetime,
  PRIMARY KEY (`key`));

CREATE TABLE payload_keys(id integer PRIMARY KEY AUTOINCREMENT,
  app_id integer NOT NULL REFERENCES applications(id) ON DELETE RESTRICT,
  key_id text NOT NULL UNIQUE,
  public_key text NOT NULL,
  private_key_encrypted text NOT NULL,
  is_current integer NOT NULL DEFAULT 1 CHECK(is_current IN (0,1)),
  created_at datetime NOT NULL);

CREATE TABLE `schema_migrations` (`version` integer,
  `name` text NOT NULL,
  `applied_at` datetime NOT NULL,
  PRIMARY KEY (`version`));

CREATE TABLE `settings` (`key` text,
  `value` text NOT NULL,
  `updated_at` datetime,
  PRIMARY KEY (`key`));

INSERT INTO settings(key,value,updated_at) VALUES('admin.path','/admin',CURRENT_TIMESTAMP);

CREATE TABLE trial_claims(id integer PRIMARY KEY AUTOINCREMENT,
  app_id integer NOT NULL REFERENCES applications(id) ON DELETE RESTRICT,
  ip_key text NOT NULL,
  instance_id text NOT NULL,
  license_id integer NOT NULL REFERENCES licenses(id) ON DELETE RESTRICT,
  created_at datetime NOT NULL,
  UNIQUE(app_id,instance_id));

CREATE TABLE `verify_logs` (`id` integer PRIMARY KEY AUTOINCREMENT,
  `created_at` datetime,
  `app_id` integer,
  `license_id` integer,
  `activation_id` integer,
  `action` text,
  `code` text,
  `success` numeric,
  `reason` text,
  `ip` text,
  `device` text,
  `client_version` text,
  `duration_ms` integer,
  CONSTRAINT `fk_verify_logs_application` FOREIGN KEY (`app_id`) REFERENCES `applications`(`id`) ON DELETE RESTRICT,
  CONSTRAINT `fk_verify_logs_license` FOREIGN KEY (`license_id`) REFERENCES `licenses`(`id`) ON DELETE RESTRICT,
  CONSTRAINT `fk_verify_logs_activation` FOREIGN KEY (`activation_id`) REFERENCES `activations`(`id`) ON DELETE RESTRICT);

CREATE UNIQUE INDEX `idx_activation_binding` ON `activations`(`license_id`,`kind`,`value`);

CREATE INDEX `idx_activations_last_seen_at` ON `activations`(`last_seen_at`);

CREATE INDEX `idx_activations_lease_expires_at` ON `activations`(`lease_expires_at`);

CREATE INDEX `idx_activations_license_id` ON `activations`(`license_id`);

CREATE INDEX `idx_activations_offline_at` ON `activations`(`offline_at`);

CREATE INDEX `idx_activations_status` ON `activations`(`status`);

CREATE UNIQUE INDEX `idx_activations_token` ON `activations`(`token`);

CREATE INDEX `idx_admin_sessions_admin_id` ON `admin_sessions`(`admin_id`);

CREATE INDEX `idx_admin_sessions_expires_at` ON `admin_sessions`(`expires_at`);

CREATE INDEX `idx_admin_sessions_revoked_at` ON `admin_sessions`(`revoked_at`);

CREATE UNIQUE INDEX `idx_admin_sessions_token_hash` ON `admin_sessions`(`token_hash`);

CREATE UNIQUE INDEX idx_admin_singleton ON admins((1));

CREATE UNIQUE INDEX `idx_admins_username` ON `admins`(`username`);

CREATE INDEX `idx_announcements_app_id` ON `announcements`(`app_id`);

CREATE INDEX `idx_announcements_published_at` ON `announcements`(`published_at`);

CREATE UNIQUE INDEX `idx_app_version` ON `app_versions`(`app_id`,`version`);

CREATE UNIQUE INDEX `idx_applications_app_key` ON `applications`(`app_key`);

CREATE INDEX `idx_applications_status` ON `applications`(`status`);

CREATE INDEX idx_applications_trial_template ON applications(trial_template_id);

CREATE INDEX `idx_audit_logs_action` ON `audit_logs`(`action`);

CREATE INDEX `idx_audit_logs_admin_id` ON `audit_logs`(`admin_id`);

CREATE INDEX `idx_audit_logs_created_at` ON `audit_logs`(`created_at`);

CREATE INDEX `idx_audit_logs_ip` ON `audit_logs`(`ip`);

CREATE INDEX `idx_audit_logs_operator` ON `audit_logs`(`operator`);

CREATE INDEX `idx_audit_logs_resource` ON `audit_logs`(`resource`);

CREATE INDEX `idx_audit_logs_resource_id` ON `audit_logs`(`resource_id`);

CREATE INDEX `idx_audit_logs_status_code` ON `audit_logs`(`status_code`);

CREATE INDEX `idx_client_session_bindings_activation_id` ON `client_session_bindings`(`activation_id`);

CREATE INDEX `idx_client_sessions_app_id` ON `client_sessions`(`app_id`);

CREATE INDEX `idx_client_sessions_license_id` ON `client_sessions`(`license_id`);

CREATE INDEX `idx_client_sessions_revoked_at` ON `client_sessions`(`revoked_at`);

CREATE UNIQUE INDEX `idx_client_sessions_token_hash` ON `client_sessions`(`token_hash`);

CREATE INDEX idx_docker_hub_sync_due ON docker_hub_sync_states(next_sync_at);

CREATE UNIQUE INDEX idx_end_users_email ON end_users(email COLLATE NOCASE) WHERE email <> '';

CREATE INDEX `idx_end_users_status` ON `end_users`(`status`);

CREATE INDEX idx_license_sharing_flagged ON license_sharing(flagged_at,ignored_until);

CREATE INDEX `idx_licenses_app_id` ON `licenses`(`app_id`);

CREATE INDEX `idx_licenses_batch_id` ON `licenses`(`batch_id`);

CREATE INDEX `idx_licenses_expires_at` ON `licenses`(`expires_at`);

CREATE UNIQUE INDEX `idx_licenses_key` ON `licenses`(`key`);

CREATE INDEX `idx_licenses_status` ON `licenses`(`status`);

CREATE INDEX idx_licenses_trial_source ON licenses(source,created_at);

CREATE INDEX `idx_licenses_type` ON `licenses`(`type`);

CREATE INDEX idx_licenses_user_id ON licenses(user_id);

CREATE INDEX `idx_mail_deliveries_claim_until` ON `mail_deliveries`(`claim_until`);

CREATE INDEX `idx_mail_deliveries_next_retry_at` ON `mail_deliveries`(`next_retry_at`);

CREATE INDEX `idx_mail_deliveries_receipt_key` ON `mail_deliveries`(`receipt_key`);

CREATE INDEX `idx_mail_deliveries_status` ON `mail_deliveries`(`status`);

CREATE INDEX idx_payload_keys_app ON payload_keys(app_id);

CREATE UNIQUE INDEX idx_payload_keys_current ON payload_keys(app_id) WHERE is_current=1;

CREATE INDEX idx_trial_claims_ip ON trial_claims(app_id,ip_key,created_at);

CREATE INDEX idx_trial_claims_license ON trial_claims(license_id);

CREATE INDEX `idx_verify_logs_activation_id` ON `verify_logs`(`activation_id`);

CREATE INDEX `idx_verify_logs_app_id` ON `verify_logs`(`app_id`);

CREATE INDEX `idx_verify_logs_code` ON `verify_logs`(`code`);

CREATE INDEX `idx_verify_logs_created_at` ON `verify_logs`(`created_at`);

CREATE INDEX `idx_verify_logs_ip` ON `verify_logs`(`ip`);

CREATE INDEX `idx_verify_logs_license_id` ON `verify_logs`(`license_id`);

CREATE INDEX idx_verify_logs_sharing ON verify_logs(license_id,ip,created_at) WHERE success=1 AND action IN ('activate','verify','heartbeat');

CREATE TRIGGER insert_docker_hub_sync AFTER INSERT ON applications WHEN NEW.docker_image <> '' BEGIN INSERT INTO docker_hub_sync_states(app_id,image,next_sync_at,last_result) VALUES(NEW.id,NEW.docker_image,'1970-01-01 00:00:00+00:00','等待同步'); END;

CREATE TRIGGER reset_docker_hub_sync AFTER UPDATE OF docker_image ON applications WHEN OLD.docker_image <> NEW.docker_image BEGIN DELETE FROM docker_hub_sync_states WHERE app_id=NEW.id; INSERT INTO docker_hub_sync_states(app_id,image,next_sync_at,last_result) SELECT NEW.id,NEW.docker_image,'1970-01-01 00:00:00+00:00','等待同步' WHERE NEW.docker_image<>''; END;
