"""
Pydantic models for protocol messages.
"""

from typing import Optional
from pydantic import BaseModel


class HelloMessage(BaseModel):
    """Client hello with certificate and nonce."""
    type: str = "hello"
    client_cert: str  # PEM format
    nonce: str  # base64


class ServerHelloMessage(BaseModel):
    """Server hello response with certificate and nonce."""
    type: str = "server_hello"
    server_cert: str  # PEM format
    nonce: str  # base64


class RegisterMessage(BaseModel):
    """User registration message (encrypted)."""
    type: str = "register"
    email: str
    username: str
    password: str  # Will be hashed before storage


class LoginMessage(BaseModel):
    """User login message (encrypted)."""
    type: str = "login"
    email: str
    password: str
    nonce: str  # base64


class DHClientMessage(BaseModel):
    """Client DH public parameters."""
    type: str = "dh_client"
    g: int
    p: int
    A: int  # Client public key


class DHServerMessage(BaseModel):
    """Server DH public key."""
    type: str = "dh_server"
    B: int  # Server public key


class ChatMessage(BaseModel):
    """Encrypted chat message with signature."""
    type: str = "msg"
    seqno: int
    ts: int  # Unix timestamp in milliseconds
    ct: str  # base64 ciphertext
    sig: str  # base64 RSA signature


class ReceiptMessage(BaseModel):
    """Session receipt for non-repudiation."""
    type: str = "receipt"
    peer: str  # "client" or "server"
    first_seq: int
    last_seq: int
    transcript_sha256: str  # hex
    sig: str  # base64 RSA signature


class ResponseMessage(BaseModel):
    """Generic response message."""
    type: str = "response"
    success: bool
    message: str
    data: Optional[dict] = None


class ErrorMessage(BaseModel):
    """Error message."""
    type: str = "error"
    code: str  # BAD_CERT, SIG_FAIL, REPLAY, etc.
    message: str