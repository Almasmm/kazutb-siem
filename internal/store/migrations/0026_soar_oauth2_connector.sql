ALTER TABLE soar_connectors DROP CONSTRAINT IF EXISTS soar_connectors_auth_type_check;
ALTER TABLE soar_connectors ADD CONSTRAINT soar_connectors_auth_type_check CHECK (auth_type IN (
    'NONE',
    'BEARER',
    'HMAC_SHA256',
    'BASIC',
    'API_KEY',
    'OAUTH2_CLIENT_CREDENTIALS'
));
