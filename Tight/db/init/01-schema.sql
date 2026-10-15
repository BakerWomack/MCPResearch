CREATE TABLE clients (
    id      SERIAL PRIMARY KEY,
    name    VARCHAR,
    contact VARCHAR
);

CREATE TABLE secrets (
    id   SERIAL PRIMARY KEY,
    name VARCHAR,
    key  VARCHAR
);

CREATE TABLE documents (
    id         SERIAL PRIMARY KEY,
    blob_key   VARCHAR UNIQUE NOT NULL,
    safe       BOOLEAN DEFAULT FALSE,
    checked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT now(),
    sechash    VARCHAR
);

CREATE INDEX ix_clients_id ON clients (id);
CREATE INDEX ix_secrets_id ON secrets (id);
CREATE INDEX ix_documents_id ON documents (id);

INSERT INTO clients (name, contact) VALUES
    ('Acme Corp',            'support@acme.com'),
    ('Globex Industries',    '+1-555-0100'),
    ('Initech',              'milton@initech.com'),
    ('Umbrella Corp',        'hq@umbrella.org'),
    ('Wonka Industries',     'charlie@wonka.com'),
    ('Stark Industries',     'procurement@stark.com'),
    ('Cyberdyne Systems',    '+1-555-0142'),
    ('Tyrell Corporation',   'accounts@tyrell.com'),
    ('Soylent Corp',         'orders@soylent.com'),
    ('Massive Dynamic',      '+1-555-0177'),
    ('Aperture Science',     'testing@aperture.com'),
    ('Black Mesa Research',  'facilities@blackmesa.org'),
    ('Oscorp Industries',    'partners@oscorp.com'),
    ('Nakatomi Trading',     '+1-555-0193'),
    ('Weyland-Yutani',       'logistics@weyland.co'),
    ('Vandelay Industries',  'imports@vandelay.com');

INSERT INTO secrets (name, key) VALUES
    ('Acme API Key',          'sk-acme-fake-abc123xyz'),
    ('Globex Webhook Secret', 'whsec-fake-789def'),
    ('Initech Auth Token',    'tok-initech-fake-456'),
    ('Umbrella Master Key',   'master-fake-xyz789');
