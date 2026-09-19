from datetime import timedelta
import pytest
from app.core.security import (
    get_password_hash,
    verify_password,
    create_access_token,
    decode_access_token,
)


def test_password_hashing():
    raw_password = "SuperSecretPassword123!"
    hashed = get_password_hash(raw_password)

    # Hash must not contain plaintext
    assert raw_password not in hashed
    assert hashed.startswith("$2b$") or hashed.startswith("$2a$")

    # Verification must succeed for correct password
    assert verify_password(raw_password, hashed) is True

    # Verification must fail for incorrect password
    assert verify_password("WrongPassword123!", hashed) is False
    assert verify_password("", hashed) is False


def test_jwt_token_generation_and_decoding():
    subject = "sarah.connor"
    roles = ["Security Analyst"]
    user_id = "123e4567-e89b-12d3-a456-426614174000"

    token = create_access_token(
        subject=subject,
        roles=roles,
        user_id=user_id,
        expires_delta=timedelta(minutes=30)
    )
    assert isinstance(token, str)

    payload = decode_access_token(token)
    assert payload is not None
    assert payload["sub"] == subject
    assert payload["roles"] == roles
    assert payload["user_id"] == user_id


def test_jwt_token_tampering_rejection():
    token = create_access_token(
        subject="admin",
        roles=["Security Admin"],
        user_id="123e4567-e89b-12d3-a456-426614174000"
    )

    # Tamper with the token string
    tampered_token = token[:-4] + "ABCD"
    assert decode_access_token(tampered_token) is None
    assert decode_access_token("invalid.jwt.token") is None
