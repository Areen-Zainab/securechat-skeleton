"""
Append-only session transcript for non-repudiation.
"""

import hashlib
from pathlib import Path
from typing import List
from app.common.utils import sha256_hex


class TranscriptManager:
    """Manages append-only session transcript."""
    
    def __init__(self, filepath: str, peer_fingerprint: str):
        """
        Initialize transcript manager.
        
        Args:
            filepath: Path to transcript file
            peer_fingerprint: SHA-256 fingerprint of peer's certificate
        """
        self.filepath = Path(filepath)
        self.peer_fingerprint = peer_fingerprint
        self.entries = []
        
        # Create transcripts directory if needed
        self.filepath.parent.mkdir(parents=True, exist_ok=True)
        
        # Create or append to file
        if not self.filepath.exists():
            with open(self.filepath, 'w') as f:
                f.write(f"# Session Transcript\n")
                f.write(f"# Peer Certificate Fingerprint: {peer_fingerprint}\n")
                f.write(f"# Format: seqno | timestamp | ciphertext | signature | peer_fingerprint\n")
                f.write("-" * 80 + "\n")
    
    def append_message(self, seqno: int, timestamp: int, ciphertext: str, signature: str):
        """
        Append message to transcript.
        
        Args:
            seqno: Sequence number
            timestamp: Unix timestamp in milliseconds
            ciphertext: Base64 encoded ciphertext
            signature: Base64 encoded signature
        """
        entry = f"{seqno}|{timestamp}|{ciphertext}|{signature}|{self.peer_fingerprint}"
        self.entries.append(entry)
        
        # Write to file
        with open(self.filepath, 'a') as f:
            f.write(entry + "\n")
    
    def compute_transcript_hash(self) -> str:
        """
        Compute SHA-256 hash of entire transcript.
        
        Returns:
            Hex digest of transcript hash
        """
        if not self.entries:
            return sha256_hex(b"")
        
        # Concatenate all entries
        transcript_data = "\n".join(self.entries).encode('utf-8')
        return sha256_hex(transcript_data)
    
    def get_sequence_range(self) -> tuple:
        """
        Get first and last sequence numbers.
        
        Returns:
            (first_seq, last_seq) or (0, 0) if empty
        """
        if not self.entries:
            return 0, 0
        
        # Parse sequence numbers from entries
        seqnos = [int(entry.split('|')[0]) for entry in self.entries]
        return min(seqnos), max(seqnos)
    
    def export_receipt(self, signature: str, peer_type: str) -> dict:
        """
        Generate session receipt for non-repudiation.
        
        Args:
            signature: Base64 RSA signature over transcript hash
            peer_type: "client" or "server"
        
        Returns:
            Receipt dictionary
        """
        first_seq, last_seq = self.get_sequence_range()
        transcript_hash = self.compute_transcript_hash()
        
        return {
            "type": "receipt",
            "peer": peer_type,
            "first_seq": first_seq,
            "last_seq": last_seq,
            "transcript_sha256": transcript_hash,
            "sig": signature
        }
    
    def load_from_file(self) -> List[str]:
        """Load transcript entries from file."""
        if not self.filepath.exists():
            return []
        
        entries = []
        with open(self.filepath, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and not line.startswith('-'):
                    entries.append(line)
        
        self.entries = entries
        return entries
    
    @staticmethod
    def verify_receipt(receipt: dict, certificate) -> bool:
        """
        Verify a session receipt (offline verification).
        
        Args:
            receipt: Receipt dictionary
            certificate: Certificate to verify signature
        
        Returns:
            True if receipt signature is valid
        """
        from app.crypto.sign import verify_signature
        from app.common.utils import b64decode
        
        # Extract fields
        transcript_hash = receipt['transcript_sha256']
        signature = b64decode(receipt['sig'])
        
        # Verify signature over transcript hash
        return verify_signature(
            transcript_hash.encode('utf-8'),
            signature,
            certificate
        )