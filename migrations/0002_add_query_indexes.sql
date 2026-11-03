CREATE INDEX IF NOT EXISTS idx_channels_community_position
  ON channels (community_id, position, name);

CREATE INDEX IF NOT EXISTS idx_sessions_expires_at
  ON sessions (expires_at);

CREATE INDEX IF NOT EXISTS idx_messages_channel_created_id
  ON messages (channel_id, created_at, id);
