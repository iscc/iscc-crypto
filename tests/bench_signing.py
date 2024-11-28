"""
Benchmark signature performance for different algorithms.

Reports:
    - signatures per second
    - verifications per second

Tests algorithms:
    - Ed25519 (EdDSA)
    - ECDSA with NIST P-256 curve (ES256)
    - ECDSA with secp256k1 curve (ES256K)

Uses jwcrypto library
"""

import time
import json
from jwcrypto import jwk, jws


def generate_test_data(n=1000, alg="EdDSA"):
    # type: (int, str) -> tuple[jwk.JWK, list[bytes], list[str]]
    """
    Generate test key and signatures for benchmarking.

    :param n: Number of test signatures to generate
    :param alg: Signature algorithm (EdDSA, ES256, or ES256K)
    :return: Tuple of (key, test_data, signatures)
    """
    if alg == "EdDSA":
        key = jwk.JWK.generate(kty="OKP", crv="Ed25519")
    elif alg == "ES256":
        key = jwk.JWK.generate(kty="EC", crv="P-256")
    elif alg == "ES256K":
        key = jwk.JWK.generate(kty="EC", crv="secp256k1")
    else:
        raise ValueError(f"Unsupported algorithm: {alg}")
    test_data = [json.dumps({"test": f"data{i}"}).encode() for i in range(n)]
    signatures = []

    for data in test_data:
        token = jws.JWS(data)
        token.add_signature(key, None, {"alg": alg})
        signatures.append(token.serialize())

    return key, test_data, signatures


def benchmark_verify(key, signatures, iterations=3):
    # type: (jwk.JWK, list[str], int) -> float
    """
    Benchmark signature verification speed.

    :param key: Public key for verification
    :param signatures: List of JWS signatures to verify
    :param iterations: Number of benchmark iterations
    :return: Average verifications per second
    """
    times = []
    for _ in range(iterations):
        start = time.time()
        for signature in signatures:
            token = jws.JWS()
            token.deserialize(signature)
            token.verify(key)
        elapsed = time.time() - start
        times.append(len(signatures) / elapsed)
    return sum(times) / len(times)


def benchmark_sign(n=1000, iterations=3, alg="EdDSA"):
    # type: (int, int, str) -> float
    """
    Benchmark signing speed for different algorithms.

    :param n: Number of test signatures to generate
    :param iterations: Number of benchmark iterations
    :param alg: Signature algorithm (EdDSA, ES256, or ES256K)
    :return: Average signatures per second
    """
    if alg == "EdDSA":
        key = jwk.JWK.generate(kty="OKP", crv="Ed25519")
    elif alg == "ES256":
        key = jwk.JWK.generate(kty="EC", crv="P-256")
    elif alg == "ES256K":
        key = jwk.JWK.generate(kty="EC", crv="secp256k1")
    else:
        raise ValueError(f"Unsupported algorithm: {alg}")
    test_data = [json.dumps({"test": f"data{i}"}).encode() for i in range(n)]
    times = []

    for _ in range(iterations):
        start = time.time()
        for data in test_data:
            token = jws.JWS(data)
            token.add_signature(key, None, {"alg": alg})
            token.serialize()
        elapsed = time.time() - start
        times.append(n / elapsed)
    return sum(times) / len(times)


def main():
    # type: () -> None
    """Run signature benchmarks for all algorithms."""
    n = 1000
    iterations = 3
    algorithms = ["EdDSA", "ES256", "ES256K"]

    for alg in algorithms:
        print(f"\nBenchmarking {alg} signatures with n={n}, iterations={iterations}")
        print("-" * 60)

        # Benchmark signing
        signs_per_second = benchmark_sign(n, iterations, alg)
        print(f"Signatures per second: {signs_per_second:.2f}")

        # Benchmark verification
        key, data, signatures = generate_test_data(n, alg)
        verifies_per_second = benchmark_verify(key, signatures, iterations)
        print(f"Verifications per second: {verifies_per_second:.2f}")


if __name__ == "__main__":
    main()
