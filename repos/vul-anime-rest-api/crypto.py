"""
Cryptographic keys and utilities for the Anime Recommendations API.
WARNING: These are hardcoded keys for demonstration purposes only.
In a real application, these should be stored securely and not in source code.
"""

import base64
import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from cryptography.hazmat.backends import default_backend
import jwt
from datetime import datetime, timedelta
import os

# HARDCODED AES-256 KEY - DO NOT USE IN PRODUCTION
# This is a 256-bit key encoded in base64
AES_KEY = base64.b64decode("VGhpc0lzQVZlcnlTZWN1cmVLZXlGb3JBRVMyNTZFbmNyeXB0aW9u")  # "ThisIsAVerySecureKeyForAES256Encryption" encoded

# HARDCODED INITIALIZATION VECTOR - DO NOT USE IN PRODUCTION
AES_IV = base64.b64decode("U2VjdXJlSW5pdFZlY3Rvcg==")  # "SecureInitVector" encoded

# HARDCODED RSA KEYS - DO NOT USE IN PRODUCTION
# These are 2048-bit RSA keys
RSA_PRIVATE_KEY_PEM = b"""
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC7VJTUt9Us8cKj
MzEfYyjiWA4R4/M2bS1GB4t7NXp98C3SC6dVMvDuictGeurT8jNbvJZHtCSuYEvu
NMoSfm76oqFvAp8Gy0iz5sxjZmSnXyCdPEovGhLa0VzMaQ8s+CLOyS56YyCFGeJZ
agU/1iYGzT+XYqvxa+pZBkYLhzHFKP7gAstxNl/V2cQQQdH7ew5JMVJj0c9eZm0t
TmLtrVNHNZLwixNF6tLEgWH3VrL0BF0mULPvlxa9YuqMA/TPrpzHF8ukqm3QKxNB
QDpU4PZTMjIzaZ7k5H2uxq9W5njSuMDYiGL3QeYNJD2BpPi8A3A4h+fqPoGf/zuN
fO3BvFMDAgMBAAECggEBAKTmjaS6tkK8BlPXClTQ2vpz/N6uxDeS35mXpqasqskV
laAidgg/sWqpjXDbXr93otIMLlWsM+X0CqMDgSXKejLS2eFyoy/WI+ynZtzKTPnS
JGdo45BN+hQOx2vUu0fAevL3nvEgNHKP5FjWVCGZCHXqIRxU3CnQrQLZwznpOhIS
5mU1aaLlrn1SwQImVA1tJmjUrJJ+0/vbydlYbqKjyWvxnA+YrURDNIZVUuWRjJpK
MPj/uBJgJKIXcfXQmCcDZSKg4m0OTt6+kLnHZhNL9Qn4gk1jTMFYXKI0yslj7h8A
Gn1fywOvv6ulJeD3Jw3Br0Ih2lNXSMWxBQ+Lb9z+SZECgYEA6MsJ0OeEjV+WgDsq
DLzHI6BvYnwQ7k/Gfr0YmiUXCd7nS1o3yTUMSVTcjRrAGTQcRKvEm0T/5hD49AMx
JiyGP+9PnuDSwF/KUa4xs9ZZYMJKc1fcU5+Jk+B7VD89KlU/5Q1vVLjFzwEq9Szu
kKdI6S4JQZgP9AQXVnZLNVUCgYEAzlcEpBfs7LtYh9kzwKjR5UZ+6XNlfCqLzI9v
3CsGJf0BmhYdeEPRVDo/yFXLkUQvVXKUMwm5UVIoZaTEZBzuKWJmYPS8OKECgYBE
xJDR5SvgL1C7RviOBbBRc67UVJdd1VxqORHT7PJCwJNmmKPGa9EzUHECgYBCRRpE
yswJl5hF2Y/BKRxIZOdGKB2l9VHCpZA1mcKBtrHjKXD8Rv6ltNZ0yVLfgV+S2L+N
38rSzXEygHLEQbS3zcmpEYOIpPGj+u4ORlsd7oFJ8rJZL7/iGGIhQXpS7asEwYoN
zJYEJIpRCqPzDg/frXdQdRG8+XQwqV7K0kUCgYAQS+QWZX0RMIxY3/+C1Bv+BuAn
J5qrKbcJvkOHJV3fxPGDCQ9fzJ2EbbBxJnTbzX0Kfd3cPnw5ZX/+KS4WGQJhcbIT
JQlAVmdQi9Uzla/DDwN5LgLowVBgMlOIQXn9Ag9YTkCi2FH7JrDgggOjX/+QZN7/
8g4rIxMb7b9hXbEzCw==
-----END PRIVATE KEY-----
"""

RSA_PUBLIC_KEY_PEM = b"""
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMxH2Mo
4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u
+qKhbwKfBstIs+bMY2Zkp18gnTxKLxoS2tFczGkPLPgizskuemMghRniWWoFP9Ym
Bs0/l2Kr8WvqWQZGC4cxxSj+4ALLcTZf1dnEEEHR+3sOSTFSY9HPXmZtLU5i7a1T
RzWS8IsTRerSxIFh91ay9ARdJlCz75cWvWLqjAP0z66cxxfLpKpt0CsTQUA6VOD2
UzIyM2me5OR9rsavVuZ40rjA2Ihi90HmDSQ9gaT4vANwOIfn6j6Bn/87jXztwbxT
AwIDAQAB
-----END PUBLIC KEY-----
"""

# Load RSA keys
RSA_PRIVATE_KEY = load_pem_private_key(
    RSA_PRIVATE_KEY_PEM,
    password=None,
    backend=default_backend()
)

RSA_PUBLIC_KEY = load_pem_public_key(
    RSA_PUBLIC_KEY_PEM,
    backend=default_backend()
)

# HARDCODED JWT SECRET - DO NOT USE IN PRODUCTION
JWT_SECRET = "ThisIsAVeryLongAndSecureJWTSecretKeyThatShouldNeverBeHardcoded"

def encrypt_aes(plaintext):
    """Encrypt data using AES-256 in CBC mode with PKCS7 padding"""
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')
    
    # Create a padder for PKCS7 padding
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext) + padder.finalize()
    
    # Create an encryptor
    cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(AES_IV), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # Encrypt the padded data
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    
    # Return base64 encoded ciphertext
    return base64.b64encode(ciphertext).decode('utf-8')

def decrypt_aes(ciphertext):
    """Decrypt data using AES-256 in CBC mode with PKCS7 padding"""
    # Decode the base64 encoded ciphertext
    ciphertext = base64.b64decode(ciphertext)
    
    # Create a decryptor
    cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(AES_IV), backend=default_backend())
    decryptor = cipher.decryptor()
    
    # Decrypt the ciphertext
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    
    # Create an unpadder for PKCS7 padding
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_data) + unpadder.finalize()
    
    # Return the plaintext as a string
    return plaintext.decode('utf-8')

def sign_data_rsa(data):
    """Sign data using RSA private key"""
    if isinstance(data, dict):
        data = json.dumps(data).encode('utf-8')
    elif isinstance(data, str):
        data = data.encode('utf-8')
    
    # Sign the data
    signature = RSA_PRIVATE_KEY.sign(
        data,
        asym_padding.PSS(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            salt_length=asym_padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    
    # Return base64 encoded signature
    return base64.b64encode(signature).decode('utf-8')

def verify_signature_rsa(data, signature):
    """Verify signature using RSA public key"""
    if isinstance(data, dict):
        data = json.dumps(data).encode('utf-8')
    elif isinstance(data, str):
        data = data.encode('utf-8')
    
    # Decode the base64 encoded signature
    signature = base64.b64decode(signature)
    
    try:
        # Verify the signature
        RSA_PUBLIC_KEY.verify(
            signature,
            data,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

def generate_jwt(user_id, premium=False, expiration_hours=24):
    """Generate a JWT token"""
    payload = {
        'user_id': user_id,
        'premium': premium,
        'exp': datetime.utcnow() + timedelta(hours=expiration_hours)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm='HS256')

def validate_jwt(token):
    """Validate a JWT token"""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        return {'error': 'Token has expired'}
    except jwt.InvalidTokenError:
        return {'error': 'Invalid token'}