ALTER TABLE soar_connectors DROP CONSTRAINT IF EXISTS soar_connectors_kind_check;
ALTER TABLE soar_connectors ADD CONSTRAINT soar_connectors_kind_check CHECK (kind IN (
    'WEBHOOK',
    'FIREWALL_REST',
    'ITSM_REST',
    'KCSP_API',
    'THREAT_INTEL_REST',
    'NOTIFICATION_REST',
    'EDR_XDR_REST'
));

ALTER TABLE soar_connectors DROP CONSTRAINT IF EXISTS soar_connectors_auth_type_check;
ALTER TABLE soar_connectors ADD CONSTRAINT soar_connectors_auth_type_check CHECK (auth_type IN (
    'NONE',
    'BEARER',
    'HMAC_SHA256',
    'BASIC',
    'API_KEY'
));
