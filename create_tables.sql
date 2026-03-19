-- Chatwork webhook storage schema
-- MySQL 8+

CREATE TABLE IF NOT EXISTS users (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    mention_id VARCHAR(32) NOT NULL,
    user_name VARCHAR(255) NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_users_mention_id (mention_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS messages (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    room_id BIGINT NULL,
    message_id VARCHAR(64) NULL,
    sender_user_id BIGINT UNSIGNED NULL,
    sender_mention_id VARCHAR(32) NULL,
    sender_name VARCHAR(255) NULL,
    webhook_event_type VARCHAR(64) NOT NULL,
    message_body MEDIUMTEXT NOT NULL,
    recipient_targets TEXT NOT NULL COMMENT 'Comma-separated mention IDs and/or toall',
    sent_at DATETIME NULL,
    raw_payload JSON NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_messages_room_message (room_id, message_id),
    KEY idx_messages_sender_user_id (sender_user_id),
    KEY idx_messages_sent_at (sent_at),
    CONSTRAINT fk_messages_sender_user
        FOREIGN KEY (sender_user_id) REFERENCES users(id)
        ON UPDATE CASCADE
        ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
