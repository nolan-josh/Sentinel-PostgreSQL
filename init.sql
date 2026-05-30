CREATE TABLE logs(
    timestamp TIMESTAMPTZ,
    event_type text,
    source_ip text,
    destination text,
    username text,
    severity text,
    message text,
    log_id text
);