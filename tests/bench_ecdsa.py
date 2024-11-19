# -*- coding: utf-8 -*-
import time
import json
from jwcrypto import jwk
from iscc_crypto.signing import sign, verify
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec


def generate_test_data(n=1000):
    # type: (int) -> tuple[list, jwk.JWK]
    """
    Generate test signatures and key.

    :param n: Number of test signatures to generate
    :return: Tuple of (signatures, key)
    """
    key = jwk.JWK.generate(kty="EC", crv="secp256k1")
    test_data = {"test": "data"}
    signatures = []
    for _ in range(n):
        signatures.append(sign(test_data, key))
    return signatures, key


def benchmark_verify(signatures, iterations=3):
    # type: (list, int) -> float
    """
    Measure signature verification performance.

    :param signatures: List of signatures to verify
    :param iterations: Number of benchmark iterations
    :return: Average verifications per second
    """
    times = []
    for _ in range(iterations):
        start = time.perf_counter()
        for sig in signatures:
            verify(sig)
        elapsed = time.perf_counter() - start
        times.append(len(signatures) / elapsed)
    return sum(times) / len(times)


def benchmark_ecdsa_sign(n=1000, iterations=3):
    # type: (int, int) -> float
    """
    Measure ECDSA signing performance using cryptography library.

    :param n: Number of signatures per iteration
    :param iterations: Number of benchmark iterations
    :return: Average signatures per second
    """
    private_key = ec.generate_private_key(ec.SECP256K1())
    test_data = json.dumps({"test": "data"}).encode()
    times = []

    for _ in range(iterations):
        start = time.perf_counter()
        for _ in range(n):
            signature = private_key.sign(test_data, ec.ECDSA(hashes.SHA256()))
        elapsed = time.perf_counter() - start
        times.append(n / elapsed)
    return sum(times) / len(times)


def main():
    # type: () -> None
    """Run ECDSA benchmarks."""
    n_sigs = 1000

    # JWCrypto verification benchmark
    print(f"\nGenerating {n_sigs} JWCrypto test signatures...")
    signatures, _ = generate_test_data(n_sigs)
    print("Running JWCrypto verification benchmark...")
    verifs_per_sec = benchmark_verify(signatures)
    print(f"JWCrypto verifications per second: {verifs_per_sec:.0f}")

    # ECDSA signing benchmark
    print("\nRunning ECDSA signing benchmark...")
    signs_per_sec = benchmark_ecdsa_sign(n_sigs)
    print(f"ECDSA signatures per second: {signs_per_sec:.0f}")


if __name__ == "__main__":
    main()
