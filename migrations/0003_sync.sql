-- Sync: per-user version counter plus profile / environment tables with tombstones.
-- sync_counters.version is the monotonic server_version source; it is incremented
-- under a row lock inside the push transaction (see README, Sync API).
CREATE TABLE sync_counters (
  user_id BIGINT NOT NULL,
  version BIGINT NOT NULL DEFAULT 0,
  PRIMARY KEY (user_id),
  CONSTRAINT fk_sync_counter_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE sync_profiles (
  user_id BIGINT NOT NULL,
  id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  label VARCHAR(255) NOT NULL DEFAULT '',
  payload MEDIUMTEXT NULL,
  client_updated_at BIGINT NOT NULL,
  deleted TINYINT(1) NOT NULL DEFAULT 0,
  deleted_at DATETIME(3) NULL,
  server_version BIGINT NOT NULL,
  created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  updated_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  PRIMARY KEY (user_id, id),
  KEY idx_sync_profiles_version (user_id, server_version),
  CONSTRAINT fk_sync_profiles_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE sync_environments (
  user_id BIGINT NOT NULL,
  id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  label VARCHAR(255) NOT NULL DEFAULT '',
  payload MEDIUMTEXT NULL,
  client_updated_at BIGINT NOT NULL,
  deleted TINYINT(1) NOT NULL DEFAULT 0,
  deleted_at DATETIME(3) NULL,
  server_version BIGINT NOT NULL,
  created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  updated_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  PRIMARY KEY (user_id, id),
  KEY idx_sync_environments_version (user_id, server_version),
  CONSTRAINT fk_sync_environments_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
