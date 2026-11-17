-- Buzz Connect (docs/buzz-connect.md): channels shared between communities on
-- two relays. Expand-only: two new tenant-owned tables, no foreign keys,
-- triggers or functions, no data changes. Writers go through community
-- admission; community deletion purges both tables.
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '30s';

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

CREATE TABLE mirrored_events (
    community_id UUID NOT NULL,
    event_id BYTEA NOT NULL CHECK (length(event_id) = 32),
    connection_id UUID NOT NULL,
    origin_relay_url TEXT NOT NULL,
    received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    fanned_out_at TIMESTAMPTZ,
    PRIMARY KEY (community_id, event_id)
);

CREATE INDEX idx_mirrored_events_connection ON mirrored_events (community_id, connection_id, event_id);
