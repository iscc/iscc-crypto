"""Full test coverage for the iscc_crypto.resolve module."""

import pytest

from iscc_crypto.resolve import resolve_did_key, InvalidURIError


@pytest.mark.asyncio
async def test_resolve_did_key_valid(did_key, did_key_doc):
    """Test resolving a valid did:key returns correct DID document."""
    result = await resolve_did_key(did_key)

    # Check basic structure
    assert result["@context"] == [
        "https://www.w3.org/ns/did/v1",
        "https://w3id.org/security/suites/ed25519-2020/v1",
    ]
    assert result["id"] == did_key

    # Check verificationMethod
    assert len(result["verificationMethod"]) == 1
    vm = result["verificationMethod"][0]
    assert vm["id"] == f"{did_key}#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
    assert vm["type"] == "Multikey"
    assert vm["controller"] == did_key
    assert vm["publicKeyMultibase"] == "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"

    # Check capability references
    expected_ref = f"{did_key}#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
    assert result["authentication"] == [expected_ref]
    assert result["assertionMethod"] == [expected_ref]
    assert result["capabilityDelegation"] == [expected_ref]
    assert result["capabilityInvocation"] == [expected_ref]

    assert result == did_key_doc


@pytest.mark.asyncio
async def test_resolve_did_key_invalid_prefix():
    """Test resolving invalid did:key prefix raises InvalidURIError."""
    with pytest.raises(InvalidURIError, match="Invalid did:key format"):
        await resolve_did_key("did:web:example.com")


@pytest.mark.asyncio
async def test_resolve_did_key_no_prefix():
    """Test resolving URI without did:key prefix raises InvalidURIError."""
    with pytest.raises(InvalidURIError, match="Invalid did:key format"):
        await resolve_did_key("z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK")


@pytest.mark.asyncio
async def test_resolve_did_key_invalid_multikey_prefix():
    """Test resolving did:key with invalid multikey prefix raises InvalidURIError."""
    with pytest.raises(InvalidURIError, match="Invalid multikey"):
        await resolve_did_key("did:key:x6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK")


@pytest.mark.asyncio
async def test_resolve_did_key_invalid_base58():
    """Test resolving did:key with invalid base58 encoding raises InvalidURIError."""
    with pytest.raises(InvalidURIError, match="Invalid multikey"):
        await resolve_did_key("did:key:z0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ!")


@pytest.mark.asyncio
async def test_resolve_did_key_invalid_key_prefix():
    """Test resolving did:key with wrong key prefix raises InvalidURIError."""
    # Valid base58 but wrong key type prefix (this would be for a different key type)
    with pytest.raises(InvalidURIError, match="Invalid multikey"):
        await resolve_did_key(
            "did:key:z2J9gaYxrKVpdoG9A4gRnmpnRCcxU6agDtFVVBVdn1JedouoZN7SzcyREXXzWVUmw5Cz"
        )
