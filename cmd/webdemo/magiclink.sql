CREATE TABLE magiclink (
    id      VARCHAR UNIQUE,
    email   VARCHAR UNIQUE,
    data    JSONB
)