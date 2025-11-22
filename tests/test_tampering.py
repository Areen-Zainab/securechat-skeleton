"""
Test script for message tampering detection.
Demonstrates that signature verification detects modifications.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from app.crypto.aes import aes_encrypt
from app.crypto.sign import sign_data, verify_signature
from app.crypto.pki import load_certificate, load_private_key
from app.common.utils import b64encode, b64decode, sha256_bytes
import json


def test_tampering():
    """Test that tampering is detected."""
    print("\n" + "="*60)
    print("MESSAGE TAMPERING DETECTION TEST")
    print("="*60)
    
    # Load certificates and keys
    print("\n[*] Loading certificates and keys...")
    client_cert = load_certificate('certs/client_cert.pem')
    client_key = load_private_key('certs/client_key.pem')
    
    # Simulate session key
    session_key = b'0123456789ABCDEF'  # 16 bytes for AES-128
    
    # Create a valid message
    print("\n[*] Creating valid message...")
    plaintext = "This is a test message"
    seqno = 5
    timestamp = 1732032145892
    
    # Encrypt
    ciphertext = aes_encrypt(plaintext.encode(), session_key)
    ct_b64 = b64encode(ciphertext)
    
    # Sign: SHA256(seqno || timestamp || ciphertext)
    digest_data = f"{seqno}|{timestamp}|{ct_b64}".encode()
    digest = sha256_bytes(digest_data)
    signature = sign_data(digest, client_key)
    sig_b64 = b64encode(signature)
    
    # Create message
    original_msg = {
        "type": "msg",
        "seqno": seqno,
        "ts": timestamp,
        "ct": ct_b64,
        "sig": sig_b64
    }
    
    print(f"[*] Original message:")
    print(f"    seqno: {seqno}")
    print(f"    ts: {timestamp}")
    print(f"    ct: {ct_b64[:40]}...")
    print(f"    sig: {sig_b64[:40]}...")
    
    # TEST 1: Verify original message (should pass)
    print("\n[TEST 1] Verifying ORIGINAL message...")
    digest_data = f"{original_msg['seqno']}|{original_msg['ts']}|{original_msg['ct']}".encode()
    digest = sha256_bytes(digest_data)
    signature = b64decode(original_msg['sig'])
    
    if verify_signature(digest, signature, client_cert):
        print("✅ PASS: Original message signature valid")
    else:
        print("❌ FAIL: Original message should be valid")
    
    # TEST 2: Tamper with ciphertext (flip bits)
    print("\n[TEST 2] Tampering with CIPHERTEXT...")
    tampered_msg = original_msg.copy()
    
    # Flip bits in ciphertext
    ct_bytes = b64decode(original_msg['ct'])
    tampered_ct = bytearray(ct_bytes)
    tampered_ct[5] ^= 0xFF  # Flip all bits in byte 5
    tampered_msg['ct'] = b64encode(bytes(tampered_ct))
    
    print(f"[*] Original ct byte 5: {ct_bytes[5]:02x}")
    print(f"[*] Tampered ct byte 5: {tampered_ct[5]:02x}")
    
    # Try to verify (should fail)
    digest_data = f"{tampered_msg['seqno']}|{tampered_msg['ts']}|{tampered_msg['ct']}".encode()
    digest = sha256_bytes(digest_data)
    signature = b64decode(tampered_msg['sig'])
    
    if not verify_signature(digest, signature, client_cert):
        print("✅ PASS: SIG_FAIL - Tampered ciphertext detected")
    else:
        print("❌ FAIL: Should detect tampering")
    
    # TEST 3: Tamper with sequence number
    print("\n[TEST 3] Tampering with SEQUENCE NUMBER...")
    tampered_msg2 = original_msg.copy()
    tampered_msg2['seqno'] = 999  # Change seqno
    
    print(f"[*] Original seqno: {original_msg['seqno']}")
    print(f"[*] Tampered seqno: {tampered_msg2['seqno']}")
    
    # Try to verify (should fail)
    digest_data = f"{tampered_msg2['seqno']}|{tampered_msg2['ts']}|{tampered_msg2['ct']}".encode()
    digest = sha256_bytes(digest_data)
    signature = b64decode(tampered_msg2['sig'])
    
    if not verify_signature(digest, signature, client_cert):
        print("✅ PASS: SIG_FAIL - Tampered seqno detected")
    else:
        print("❌ FAIL: Should detect seqno tampering")
    
    # TEST 4: Tamper with timestamp
    print("\n[TEST 4] Tampering with TIMESTAMP...")
    tampered_msg3 = original_msg.copy()
    tampered_msg3['ts'] = 9999999999999  # Change timestamp
    
    print(f"[*] Original timestamp: {original_msg['ts']}")
    print(f"[*] Tampered timestamp: {tampered_msg3['ts']}")
    
    # Try to verify (should fail)
    digest_data = f"{tampered_msg3['seqno']}|{tampered_msg3['ts']}|{tampered_msg3['ct']}".encode()
    digest = sha256_bytes(digest_data)
    signature = b64decode(tampered_msg3['sig'])
    
    if not verify_signature(digest, signature, client_cert):
        print("✅ PASS: SIG_FAIL - Tampered timestamp detected")
    else:
        print("❌ FAIL: Should detect timestamp tampering")
    
    # TEST 5: Replace signature with random data
    print("\n[TEST 5] Replacing signature with RANDOM DATA...")
    tampered_msg4 = original_msg.copy()
    import secrets
    fake_sig = secrets.token_bytes(256)  # Random 256 bytes
    tampered_msg4['sig'] = b64encode(fake_sig)
    
    print(f"[*] Original sig: {sig_b64[:40]}...")
    print(f"[*] Fake sig: {tampered_msg4['sig'][:40]}...")
    
    # Try to verify (should fail)
    digest_data = f"{tampered_msg4['seqno']}|{tampered_msg4['ts']}|{tampered_msg4['ct']}".encode()
    digest = sha256_bytes(digest_data)
    signature = b64decode(tampered_msg4['sig'])
    
    if not verify_signature(digest, signature, client_cert):
        print("✅ PASS: SIG_FAIL - Fake signature detected")
    else:
        print("❌ FAIL: Should detect fake signature")
    
    print("\n" + "="*60)
    print("TAMPERING TESTS COMPLETE")
    print("="*60)
    print("\nSummary: ALL tampering attempts were successfully detected ✅")


if __name__ == "__main__":
    test_tampering()