-- ── Channel connections (Buzz Connect) ───────────────────────────────────────
-- One row per side of a channel shared with a community on another relay
-- (docs/buzz-connect.md). peer_pubkey, when the row is 'active', is admitted
-- with read access to channel_id only. local_secret_key is plaintext in the
-- prototype and must be encrypted before real use. offer_code_hash stores only
-- SHA-256 of the one-time code. NULLs are distinct, so the unique indexes
-- allow any number of rows without a peer key or code.

CREATE TABLE channel_connections (
    community_id UUID NOT NULL,
    id UUID NOT NULL,
    channel_id UUID NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('offerer', 'acceptor')),
    state TEXT NOT NULL CHECK (state IN ('offered', 'active', 'disconnected')),
    peer_relay_url TEXT,
    peer_community_name TEXT,
    local_pubkey TEXT NOT NULL CHECK (length(local_pubkey) = 64),
    local_secret_key TEXT NOT NULL CHECK (length(local_secret_key) = 64),
    peer_pubkey TEXT CHECK (length(peer_pubkey) = 64),
    offer_code_hash BYTEA CHECK (length(offer_code_hash) = 32),
    offer_expires_at TIMESTAMPTZ,
    cursor_created_at BIGINT NOT NULL DEFAULT 0,
    cursor_event_id BYTEA CHECK (length(cursor_event_id) = 32),
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    disconnected_at TIMESTAMPTZ,
    PRIMARY KEY (community_id, id)
);

CREATE UNIQUE INDEX idx_channel_connections_peer_pubkey ON channel_connections (community_id, peer_pubkey);
CREATE UNIQUE INDEX idx_channel_connections_offer_code ON channel_connections (community_id, offer_code_hash);
CREATE INDEX idx_channel_connections_channel ON channel_connections (community_id, channel_id);
