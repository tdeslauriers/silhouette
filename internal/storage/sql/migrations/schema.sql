CREATE TABLE IF NOT EXISTS profile (
    uuid CHAR(36) PRIMARY KEY,
    username VARCHAR(128) NOT NULL,
    user_index VARCHAR(128) NOT NULL,
    nick_name VARCHAR(128),
    dark_mode BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP NOT NULL DEFAULT UTC_TIMESTAMP
);
CREATE UNIQUE INDEX idx_profile_blind_index ON profile(user_index);

CREATE TABLE IF NOT EXISTS address (
    uuid CHAR(36) PRIMARY KEY,
    address_line_1 VARCHAR(512),
    address_line_2 VARCHAR(255), 
    city VARCHAR(128),
    state VARCHAR(128),
    zip VARCHAR(32),
    country VARCHAR(128),
    is_current BOOLEAN NOT NULL DEFAULT TRUE,
    updated_at TIMESTAMP NOT NULL DEFAULT UTC_TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT UTC_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS phone (
    uuid CHAR(36) PRIMARY KEY,
    country_code VARCHAR(16) ,   -- e.g., "+1", "+44"
    phone_number VARCHAR(32),   -- the actual number
    extension VARCHAR(16) ,
    phone_type VARCHAR(32),
    is_current BOOLEAN NOT NULL DEFAULT TRUE,
    updated_at TIMESTAMP NOT NULL DEFAULT UTC_TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT UTC_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS profile_address (
    id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    profile_uuid CHAR(36) NOT NULL,
    address_uuid CHAR(36) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT UTC_TIMESTAMP,
    CONSTRAINT fk_profile_address_xref FOREIGN KEY (profile_uuid) REFERENCES profile(uuid),
    CONSTRAINT fk_address_profile_xref FOREIGN KEY (address_uuid) REFERENCES address(uuid)
);
CREATE INDEX idx_profile_address_xref ON profile_address(profile_uuid);   
CREATE INDEX idx_address_profile_xref ON profile_address(address_uuid);

CREATE TABLE IF NOT EXISTS profile_phone (
    id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    profile_uuid CHAR(36) NOT NULL,
    phone_uuid CHAR(36) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT UTC_TIMESTAMP,
    CONSTRAINT fk_profile_phone_xref FOREIGN KEY (profile_uuid) REFERENCES profile(uuid),
    CONSTRAINT fk_phone_profile_xref FOREIGN KEY (phone_uuid) REFERENCES phone(uuid)
);
CREATE INDEX idx_profile_phone_xref ON profile_phone(profile_uuid);   
CREATE INDEX idx_phone_profile_xref ON profile_phone(phone_uuid);
