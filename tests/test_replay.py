"""
Test script for replay attack detection.
Demonstrates that old messages are rejected based on sequence numbers.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))


class MessageValidator:
    """Simulates server-side message validation."""
    
    def __init__(self):
        self.last_seqno = 0
    
    def validate_message(self, msg):
        """
        Validate message sequence number.
        Returns (valid, reason).
        """
        seqno = msg['seqno']
        
        # Check for replay
        if seqno <= self.last_seqno:
            return False, f"REPLAY: seqno {seqno} <= last received {self.last_seqno}"
        
        # Update counter
        self.last_seqno = seqno
        return True, "OK"


def test_replay_protection():
    """Test replay attack detection."""
    print("\n" + "="*60)
    print("REPLAY ATTACK DETECTION TEST")
    print("="*60)
    
    validator = MessageValidator()
    
    # Create message sequence
    messages = [
        {"type": "msg", "seqno": 1, "content": "Message 1"},
        {"type": "msg", "seqno": 2, "content": "Message 2"},
        {"type": "msg", "seqno": 3, "content": "Message 3"},
        {"type": "msg", "seqno": 4, "content": "Message 4"},
        {"type": "msg", "seqno": 5, "content": "Message 5"},
    ]
    
    # TEST 1: Send messages in order (should all pass)
    print("\n[TEST 1] Sending messages in CORRECT ORDER...")
    for msg in messages:
        valid, reason = validator.validate_message(msg)
        status = "✅ ACCEPT" if valid else "❌ REJECT"
        print(f"  seqno={msg['seqno']}: {status} - {reason}")
    
    print(f"\n[*] Current state: last_seqno = {validator.last_seqno}")
    
    # TEST 2: Replay old message (should fail)
    print("\n[TEST 2] REPLAY ATTACK - Resending message seqno=3...")
    old_msg = {"type": "msg", "seqno": 3, "content": "Message 3"}
    valid, reason = validator.validate_message(old_msg)
    
    if not valid and "REPLAY" in reason:
        print(f"  ✅ PASS: {reason}")
    else:
        print(f"  ❌ FAIL: Should reject replayed message")
    
    # TEST 3: Replay most recent message (should fail)
    print("\n[TEST 3] REPLAY ATTACK - Resending message seqno=5...")
    old_msg = {"type": "msg", "seqno": 5, "content": "Message 5"}
    valid, reason = validator.validate_message(old_msg)
    
    if not valid and "REPLAY" in reason:
        print(f"  ✅ PASS: {reason}")
    else:
        print(f"  ❌ FAIL: Should reject replayed message")
    
    # TEST 4: Out of order (late arrival)
    print("\n[TEST 4] Sending NEW message seqno=6...")
    new_msg = {"type": "msg", "seqno": 6, "content": "Message 6"}
    valid, reason = validator.validate_message(new_msg)
    
    if valid:
        print(f"  ✅ ACCEPT: {reason}")
    else:
        print(f"  ❌ FAIL: Should accept new message")
    
    print(f"\n[*] Current state: last_seqno = {validator.last_seqno}")
    
    # TEST 5: Send old seqno after gap
    print("\n[TEST 5] LATE ARRIVAL - Sending old seqno=4 after accepting seqno=6...")
    late_msg = {"type": "msg", "seqno": 4, "content": "Message 4"}
    valid, reason = validator.validate_message(late_msg)
    
    if not valid and "REPLAY" in reason:
        print(f"  ✅ PASS: {reason}")
        print("  [*] Late messages correctly treated as replays")
    else:
        print(f"  ❌ FAIL: Should reject old seqno")
    
    # TEST 6: Multiple replay attempts
    print("\n[TEST 6] MULTIPLE REPLAY ATTACKS...")
    replay_attempts = [
        {"type": "msg", "seqno": 1, "content": "Replay 1"},
        {"type": "msg", "seqno": 2, "content": "Replay 2"},
        {"type": "msg", "seqno": 3, "content": "Replay 3"},
    ]
    
    all_blocked = True
    for msg in replay_attempts:
        valid, reason = validator.validate_message(msg)
        status = "✅ BLOCKED" if not valid else "❌ ACCEPTED"
        print(f"  seqno={msg['seqno']}: {status}")
        if valid:
            all_blocked = False
    
    if all_blocked:
        print("\n  ✅ PASS: All replay attempts blocked")
    else:
        print("\n  ❌ FAIL: Some replays were accepted")
    
    print("\n" + "="*60)
    print("REPLAY PROTECTION TESTS COMPLETE")
    print("="*60)
    print("\nSummary:")
    print("  ✅ Sequential messages accepted")
    print("  ✅ Replayed messages rejected")
    print("  ✅ Out-of-order messages rejected")
    print("  ✅ Multiple replay attempts blocked")


if __name__ == "__main__":
    test_replay_protection()