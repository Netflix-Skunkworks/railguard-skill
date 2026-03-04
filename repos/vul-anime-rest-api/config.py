"""
Simple configuration file demonstrating hardcoded credentials vulnerability
and proper encrypted secret usage.
"""
# ==========================================
# PROPER ENCRYPTED SECRETS (EXAMPLE FORMAT)
# ==========================================

# How the above credentials SHOULD be stored using a secrets manager:

SECURE_CONFIG = {
    "database": {
        "password": {
            "encrypted": {
                "secret": "MGICAQAwGAYJKoZIhvcNAQkDMQsGCSqGSIb3DQEHATAjBgkqhkiG9w0BCQUxFhYUMjAyNDEyMzAxMjAwMDBaMA0GCSqGSIb3DQEJAAUA"
            }
        }
    },
    "sendgrid": {
        "api_key": {
            "encrypted": {
                "secret": "MGICAQAwGAYJKoZIhvcNAQkDMQsGCSqGSIb3DQEHATAjBgkqhkiG9w0BCQUxFhYUMjAyNDEyMzAxMjAwMDBaMQ0GCSqGSIb3DQEBAQUAA"
            }
        }
    },
    "aws": {
        "secret_access_key": {
            "encrypted": {
                "secret": "MGICAQAwGAYJKoZIhvcNAQkDMQsGCSqGSIb3DQEHATAjBgkqhkiG9w0BCQUxFhYUMjAyNDEyMzAxMjAwMDBaMg0GCSqGSIb3DQEBCQUAA"
            }
        }
    }
}

# ==========================================
# JDBC DATABASE CONNECTION CONFIGURATION
# ==========================================

# Raw JDBC connection string with username specified (password intentionally omitted for demonstration)
JDBC_CONFIG = {
    "spring": {
        "datasource": {
            "url": "jdbc:postgresql://localhost:26257/saul",
            "driver_class_name": "org.postgresql.Driver",
            "username": "root",
            # Note: password intentionally not specified here
            "hikari": {
                "connection_test_query": "SELECT 1"
            }
        }
    }
}

