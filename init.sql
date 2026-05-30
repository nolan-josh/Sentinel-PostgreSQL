CREATE TABLE logs(
    id serial not null,
    timestamp TIMESTAMPTZ,
    event_type text,
    source_ip text,
    destination text,
    username text,
    severity text,
    message text,
    log_id text
);