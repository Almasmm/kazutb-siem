ALTER TABLE soar_connectors DROP CONSTRAINT IF EXISTS soar_connectors_kind_check;
ALTER TABLE soar_connectors ADD CONSTRAINT soar_connectors_kind_check CHECK (kind IN (
    'WEBHOOK',
    'FIREWALL_REST',
    'ITSM_REST',
    'KCSP_API',
    'THREAT_INTEL_REST',
    'NOTIFICATION_REST',
    'EDR_XDR_REST',
    'EMAIL_SMTP',
    'LDAP_DIRECTORY'
));
