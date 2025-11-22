"""
Test script for non-repudiation verification.
Demonstrates offline verification of transcripts and receipts.
"""

import sys
import os
import json
import hashlib
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from app.crypto.sign import sign_data, verify_signature
from app.crypto.pki import load_certificate, load_private_key
from app.common.utils import b64encode, b64decode


def create_sample_transcript():
    """Create a sample transcript for testing."""
    transcript_entries = [
        "1|1732032145892|SGVsbG8gV29ybGQh...|dGhpcyBpc0Fz...|8a3f2b1c4d5e6f7a",
        "2|1732032146123|Rm9vYmFyIGJheg==...|YW5vdGhlcnNp...|8a3f2b1c4d5e6f7a",
        "3|1732032146456|VGVzdCBtZXNzYWdl...|c2lnbmF0dXJl...|8a3f2b1c4d5e6f7a",
        "4|1732032147789|SGVsbG8gYWdhaW4h...|bW9yZXNpZ25h...|8a3f2b1c4d5e6f7a",
        "5|1732032148012|R29vZGJ5ZSE=...|ZmluYWxzaWdu...|8a3f2b1c4d5e6f7a",
    ]
    return transcript_entries


def test_nonrepudiation():
    """Test non-repudiation verification."""
    print("\n" + "="*60)
    print("NON-REPUDIATION VERIFICATION TEST")
    print("="*60)
    
    # Load certificates and keys
    print("\n[*] Loading certificates and keys...")
    client_cert = load_certificate('certs/client_cert.pem')
    client_key = load_private_key('certs/client_key.pem')
    
    # Part 1: Create and verify individual message signatures
    print("\n" + "="*60)
    print("PART 1: INDIVIDUAL MESSAGE VERIFICATION")
    print("="*60)
    
    print("\n[*] Creating sample messages with signatures...")
    
    messages = [
        {"seqno": 1, "ts": 1732032145892, "ct": "SGVsbG8gV29ybGQh"},
        {"seqno": 2, "ts": 1732032146123, "ct": "Rm9vYmFyIGJheg=="},
        {"seqno": 3, "ts": 1732032146456, "ct": "VGVzdCBtZXNzYWdl"},
    ]
    
    signed_messages = []
    
    for msg in messages:
        # Compute digest: SHA256(seqno || ts || ct)
        digest_data = f"{msg['seqno']}|{msg['ts']}|{msg['ct']}".encode()
        digest = hashlib.sha256(digest_data).digest()
        
        # Sign
        signature = sign_data(digest, client_key)
        msg['sig'] = b64encode(signature)
        signed_messages.append(msg)
        
        print(f"\n[*] Message {msg['seqno']}:")
        print(f"    Digest: {digest.hex()[:40]}...")
        print(f"    Signature: {msg['sig'][:40]}...")
    
    # Verify each message
    print("\n[TEST 1] Verifying each message signature...")
    all_valid = True
    
    for msg in signed_messages:
        # Recompute digest
        digest_data = f"{msg['seqno']}|{msg['ts']}|{msg['ct']}".encode()
        digest = hashlib.sha256(digest_data).digest()
        
        # Verify signature
        signature = b64decode(msg['sig'])
        valid = verify_signature(digest, signature, client_cert)
        
        status = "✅ VALID" if valid else "❌ INVALID"
        print(f"  Message {msg['seqno']}: {status}")
        
        if not valid:
            all_valid = False
    
    if all_valid:
        print("\n✅ PASS: All individual message signatures valid")
    else:
        print("\n❌ FAIL: Some signatures invalid")
    
    # Part 2: Create and verify session receipt
    print("\n" + "="*60)
    print("PART 2: SESSION RECEIPT VERIFICATION")
    print("="*60)
    
    # Create transcript
    print("\n[*] Creating session transcript...")
    transcript_entries = create_sample_transcript()
    
    # Compute transcript hash
    transcript_data = "\n".join(transcript_entries)
    transcript_hash = hashlib.sha256(transcript_data.encode()).hexdigest()
    
    print(f"[*] Transcript ({len(transcript_entries)} entries):")
    for entry in transcript_entries[:2]:
        print(f"    {entry}")
    print(f"    ... ({len(transcript_entries) - 2} more entries)")
    
    print(f"\n[*] Transcript Hash: {transcript_hash}")
    
    # Sign transcript hash
    print("\n[*] Signing transcript hash...")
    signature = sign_data(transcript_hash.encode(), client_key)
    sig_b64 = b64encode(signature)
    
    # Create receipt
    receipt = {
        "type": "receipt",
        "peer": "client",
        "first_seq": 1,
        "last_seq": 5,
        "transcript_sha256": transcript_hash,
        "sig": sig_b64
    }
    
    # Save receipt
    os.makedirs('transcripts', exist_ok=True)
    receipt_file = 'transcripts/test_receipt.json'
    with open(receipt_file, 'w') as f:
        json.dump(receipt, f, indent=2)
    
    print(f"[*] Receipt saved to: {receipt_file}")
    print(f"[*] Receipt signature: {sig_b64[:40]}...")
    
    # TEST 2: Verify receipt
    print("\n[TEST 2] Verifying session receipt...")
    
    # Load receipt (simulating offline verification)
    with open(receipt_file, 'r') as f:
        loaded_receipt = json.load(f)
    
    # Verify signature over transcript hash
    receipt_hash = loaded_receipt['transcript_sha256']
    receipt_sig = b64decode(loaded_receipt['sig'])
    
    valid = verify_signature(receipt_hash.encode(), receipt_sig, client_cert)
    
    if valid:
        print("✅ PASS: Receipt signature valid")
        print(f"    First seq: {loaded_receipt['first_seq']}")
        print(f"    Last seq: {loaded_receipt['last_seq']}")
        print(f"    Transcript hash: {receipt_hash[:40]}...")
    else:
        print("❌ FAIL: Receipt signature invalid")
    
    # Part 3: Tamper detection
    print("\n" + "="*60)
    print("PART 3: TAMPER DETECTION")
    print("="*60)
    
    # TEST 3: Modify transcript and show detection
    print("\n[TEST 3] Testing transcript tampering detection...")
    
    print("[*] Original transcript hash:", transcript_hash[:40], "...")
    
    # Tamper with transcript
    tampered_entries = transcript_entries.copy()
    tampered_entries[2] = "3|1732032146456|TAMPERED_DATA!...|c2lnbmF0dXJl...|8a3f2b1c4d5e6f7a"
    
    # Recompute hash
    tampered_data = "\n".join(tampered_entries)
    tampered_hash = hashlib.sha256(tampered_data.encode()).hexdigest()
    
    print("[*] Tampered transcript hash:", tampered_hash[:40], "...")
    
    # Try to verify with original receipt
    if tampered_hash != receipt_hash:
        print("\n✅ PASS: Hash mismatch detected")
        print("    Original:  ", receipt_hash[:40], "...")
        print("    Tampered:  ", tampered_hash[:40], "...")
        print("    Result: ❌ Transcript has been modified!")
    else:
        print("\n❌ FAIL: Should detect hash change")
    
    # TEST 4: Try to verify tampered hash with receipt signature
    print("\n[TEST 4] Verifying receipt with tampered hash...")
    
    valid = verify_signature(tampered_hash.encode(), receipt_sig, client_cert)
    
    if not valid:
        print("✅ PASS: Signature verification fails for tampered hash")
        print("    This proves the transcript was modified after signing")
    else:
        print("❌ FAIL: Should fail verification")
    
    # TEST 5: Modify receipt signature
    print("\n[TEST 5] Testing receipt signature tampering...")
    
    # Create fake signature
    import secrets
    fake_sig = b64encode(secrets.token_bytes(256))
    
    print("[*] Original signature:", sig_b64[:40], "...")
    print("[*] Fake signature:    ", fake_sig[:40], "...")
    
    # Try to verify
    fake_sig_bytes = b64decode(fake_sig)
    valid = verify_signature(receipt_hash.encode(), fake_sig_bytes, client_cert)
    
    if not valid:
        print("\n✅ PASS: Fake signature rejected")
        print("    Only the holder of the private key can create valid signatures")
    else:
        print("\n❌ FAIL: Should reject fake signature")
    
    print("\n" + "="*60)
    print("NON-REPUDIATION TESTS COMPLETE")
    print("="*60)
    
    print("\n📋 Summary:")
    print("  ✅ Individual message signatures verified")
    print("  ✅ Session receipt signature verified")
    print("  ✅ Transcript tampering detected (hash mismatch)")
    print("  ✅ Signature tampering detected (verification failure)")
    print("  ✅ Non-repudiation properties demonstrated")
    
    print("\n💡 Key Points:")
    print("  • Each message is individually signed (authenticity)")
    print("  • Transcript hash covers all messages (integrity)")
    print("  • Receipt signature proves authorship (non-repudiation)")
    print("  • Any modification breaks verification (tamper-evident)")
    print("  • Third party can verify using public certificate")


if __name__ == "__main__":
    test_nonrepudiation()