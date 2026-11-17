-- ── Mirrored events (Buzz Connect) ───────────────────────────────────────────
-- One row per event stored through the mirror path, naming the connection
-- that supplied it. Serving a connection omits the events it supplied (no
-- loops); fanned_out_at makes local fan-out run once per mirrored event.

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
