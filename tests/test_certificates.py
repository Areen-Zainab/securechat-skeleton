"""
Test script for certificate validation.
Tests: self-signed, expired, wrong CN, and valid certificates.
"""

import os
import sys
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from app.crypto.pki import validate_certificate_chain


def create_self_signed_cert():
    """Create a self-signed certificate (not issued by CA)."""
    print("\n[TEST 1] Creating self-signed certificate...")
    
    # Generate key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    
    # Create self-signed certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
        x509.NameAttribute(NameOID.COMMON_NAME, "attacker.local"),
    ])
    
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)  # Self-signed
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=365))
        .sign(private_key, hashes.SHA256())
    )
    
    # Save temporarily
    with open('certs/fake_self_signed.pem', 'wb') as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    
    print("[*] Self-signed certificate created: certs/fake_self_signed.pem")
    return cert


def create_expired_cert():
    """Create an expired certificate signed by CA."""
    print("\n[TEST 2] Creating expired certificate...")
    
    from app.crypto.pki import load_certificate, load_private_key
    
    # Load CA
    ca_cert = load_certificate('certs/ca_cert.pem')
    ca_key = load_private_key('certs/ca_key.pem')
    
    # Generate key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    
    # Create expired certificate
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
        x509.NameAttribute(NameOID.COMMON_NAME, "expired.local"),
    ])
    
    # Expired: valid from 2 years ago to 1 year ago
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow() - timedelta(days=730))  # 2 years ago
        .not_valid_after(datetime.utcnow() - timedelta(days=365))   # 1 year ago (expired)
        .sign(ca_key, hashes.SHA256())
    )
    
    # Save
    with open('certs/fake_expired.pem', 'wb') as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    
    print("[*] Expired certificate created: certs/fake_expired.pem")
    return cert


def create_wrong_cn_cert():
    """Create certificate with wrong Common Name."""
    print("\n[TEST 3] Creating certificate with wrong CN...")
    
    from app.crypto.pki import load_certificate, load_private_key
    
    # Load CA
    ca_cert = load_certificate('certs/ca_cert.pem')
    ca_key = load_private_key('certs/ca_key.pem')
    
    # Generate key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    
    # Create certificate with wrong CN
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
        x509.NameAttribute(NameOID.COMMON_NAME, "wrong.hostname.local"),
    ])
    
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=365))
        .sign(ca_key, hashes.SHA256())
    )
    
    # Save
    with open('certs/fake_wrong_cn.pem', 'wb') as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    
    print("[*] Wrong CN certificate created: certs/fake_wrong_cn.pem")
    return cert


def test_certificate_validation():
    """Test all certificate validation scenarios."""
    print("\n" + "="*60)
    print("CERTIFICATE VALIDATION TEST SUITE")
    print("="*60)
    
    # Test 1: Valid Certificate
    print("\n[TEST 0] Testing VALID certificate...")
    try:
        with open('certs/server_cert.pem', 'rb') as f:
            cert_pem = f.read()
        
        valid, message, cert = validate_certificate_chain(
            cert_pem, 
            'certs/ca_cert.pem',
            'server.local'
        )
        
        if valid:
            print(f"✅ PASS: {message}")
        else:
            print(f"❌ FAIL: Should accept valid cert but got: {message}")
    except Exception as e:
        print(f"❌ ERROR: {e}")
    
    # Test 1: Self-Signed
    print("\n[TEST 1] Testing SELF-SIGNED certificate...")
    create_self_signed_cert()
    
    try:
        with open('certs/fake_self_signed.pem', 'rb') as f:
            cert_pem = f.read()
        
        valid, message, cert = validate_certificate_chain(
            cert_pem,
            'certs/ca_cert.pem'
        )
        
        if not valid and "BAD_CERT" in message:
            print(f"✅ PASS: Correctly rejected - {message}")
        else:
            print(f"❌ FAIL: Should reject self-signed cert")
    except Exception as e:
        print(f"✅ PASS: Exception raised - {e}")
    
    # Test 2: Expired
    print("\n[TEST 2] Testing EXPIRED certificate...")
    create_expired_cert()
    
    try:
        with open('certs/fake_expired.pem', 'rb') as f:
            cert_pem = f.read()
        
        valid, message, cert = validate_certificate_chain(
            cert_pem,
            'certs/ca_cert.pem'
        )
        
        if not valid and "expired" in message.lower():
            print(f"✅ PASS: Correctly rejected - {message}")
        else:
            print(f"❌ FAIL: Should reject expired cert")
    except Exception as e:
        print(f"✅ PASS: Exception raised - {e}")
    
    # Test 3: Wrong CN
    print("\n[TEST 3] Testing WRONG CN certificate...")
    create_wrong_cn_cert()
    
    try:
        with open('certs/fake_wrong_cn.pem', 'rb') as f:
            cert_pem = f.read()
        
        valid, message, cert = validate_certificate_chain(
            cert_pem,
            'certs/ca_cert.pem',
            'server.local'  # Expect server.local, but cert has wrong.hostname.local
        )
        
        if not valid and "CN mismatch" in message:
            print(f"✅ PASS: Correctly rejected - {message}")
        else:
            print(f"❌ FAIL: Should reject wrong CN")
    except Exception as e:
        print(f"✅ PASS: Exception raised - {e}")
    
    print("\n" + "="*60)
    print("CERTIFICATE TESTS COMPLETE")
    print("="*60)
    
    # Cleanup
    import os
    for f in ['certs/fake_self_signed.pem', 'certs/fake_expired.pem', 'certs/fake_wrong_cn.pem']:
        if os.path.exists(f):
            os.remove(f)
            print(f"[*] Cleaned up: {f}")


if __name__ == "__main__":
    test_certificate_validation()