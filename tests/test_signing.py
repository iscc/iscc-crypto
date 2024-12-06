import iscc_crypto as icr

TESTKEY = icr.KeyPair(
    public_key="z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2",
    secret_key="z3u2en7t5LR2WtQH5PfFqMqwVHBeXouLzo6haApm8XHqvjxq",
)


def test_spec_vector_signing():
    """Test vectors from https://www.w3.org/TR/vc-di-eddsa/#representation-eddsa-jcs-2022"""
    payload = bytes.fromhex(
        "c46b3487ab7087c4f426b546c449094ff57b8fefa6fd85e83f1b31e24c230da859b7cb6251b8991add1"
        "ce0bc83107e3db9dbbab5bd2c28f687db1a03abc92f19"
    )
    expected_signature = (
        "zboydVv31kj6jP37GMBZwYyjbvrqr9MWeY9NCEfYUwLcKwkdqAcB44dqEcqaMi8mfdvT2Vbnvdrv6XRaYzgpuPWn"
    )

    assert icr.sign_data(payload, TESTKEY) == expected_signature
