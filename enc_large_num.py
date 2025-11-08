#!/usr/bin/env python3
"""
BFV + CRT exact integer multiplication example using TenSEAL.

Requirements:
    pip install tenseal sympy

This script:
  - finds batching-friendly primes t (t % (2*N) == 1),
  - for each t: creates a BFV context with plain_modulus = t,
                encrypts (number % t), multiplies by scalar,
                decrypts residue;
  - reconstructs full integer via CRT.

Warning: creating many TenSEAL contexts and large poly_modulus_degree uses memory.
Tune poly_modulus_degree and per_modulus_bits to your environment.
"""

import tenseal as ts
import sympy
from math import prod
from typing import List, Tuple

# ---------- math helpers ----------
def egcd(a: int, b: int) -> Tuple[int,int,int]:
    if b == 0:
        return (a, 1, 0)
    g, x1, y1 = egcd(b, a % b)
    return (g, y1, x1 - (a // b) * y1)

def inv_mod(a: int, m: int) -> int:
    g, x, _ = egcd(a, m)
    if g != 1:
        raise ValueError("Inverse does not exist")
    return x % m

def crt_reconstruct(residues: List[int], moduli: List[int]) -> Tuple[int, int]:
    """Reconstruct x mod M, where M = product(moduli). Returns (x, M)."""
    M = 1
    for m in moduli:
        M *= m
    x = 0
    for (r_i, m_i) in zip(residues, moduli):
        M_i = M // m_i
        inv = inv_mod(M_i, m_i)
        x = (x + (r_i * M_i % M) * inv) % M
    return x, M

# ---------- find batching-friendly prime ----------
def find_batching_prime(poly_modulus_degree: int, bits: int, start_k: int = 1, max_tries: int = 5_000_000) -> int:
    """
    Find a prime t with ~bits bits such that:
        t % (2 * poly_modulus_degree) == 1
    Search t = 1 + k*(2*N) starting from start_k.
    """
    N2 = 2 * poly_modulus_degree
    # choose starting k near 2^(bits-1) / N2 to get candidate of ~bits bits
    if bits > 10:
        k = max(start_k, (1 << (bits - 1)) // N2)
    else:
        k = max(start_k, 1)
    tries = 0
    while tries < max_tries:
        candidate = 1 + k * N2
        # check approximate size (allow a little drift)
        if candidate.bit_length() >= bits - 2:
            if sympy.isprime(candidate):
                return candidate
        k += 1
        tries += 1
    raise RuntimeError("No batching prime found in max tries; try increasing max_tries or bits")

# ---------- choose moduli until product > target ----------
def choose_moduli_for_target(target_value: int,
                             poly_modulus_degree: int = 8192,
                             per_modulus_bits: int = 40) -> List[int]:
    moduli = []
    product = 1
    start_k = 1
    round_no = 0
    while product <= target_value:
        round_no += 1
        print(f"[moduli] Round {round_no}: current product bits={product.bit_length()} target bits={target_value.bit_length()}")
        p = find_batching_prime(poly_modulus_degree, per_modulus_bits, start_k=start_k)
        print(f"[moduli] found prime, bitlen={p.bit_length()}")
        moduli.append(p)
        product *= p
        # move start_k forward to avoid repeated small searches (heuristic)
        start_k += 1000
        # if still far, increase per_modulus_bits slightly to reduce future count
        if product.bit_length() < target_value.bit_length() // 2:
            per_modulus_bits += 1
    print(f"[moduli] selected {len(moduli)} moduli, total product bits={product.bit_length()}")
    return moduli

# ---------- main flow ----------
def encrypt_multiply_crt(number: int, multiplier: int,
                         poly_modulus_degree: int = 8192,
                         per_modulus_bits: int = 40):
    expected = number * multiplier
    print("Expected product bitlength:", expected.bit_length())

    # choose moduli
    moduli = choose_moduli_for_target(expected, poly_modulus_degree, per_modulus_bits)
    M = prod(moduli)
    print("Final modulus product M bitlength:", M.bit_length())
    if M <= expected:
        raise RuntimeError("Moduli product not large enough. Adjust parameters.")

    residues = [number % m for m in moduli]
    dec_residues = []

    for i, m in enumerate(moduli):
        print(f"\n[CTX {i+1}/{len(moduli)}] modulus bitlen={m.bit_length()}")
        # create context for this modulus
        # Note: larger plain_modulus may need larger poly_modulus_degree in practice.
        context = ts.context(ts.SCHEME_TYPE.BFV, poly_modulus_degree=poly_modulus_degree, plain_modulus=m)
        context.generate_galois_keys()
        context.generate_relin_keys()

        # encrypt residue (single-slot BFVVector)
        enc = ts.bfv_vector(context, [residues[i]])
        # homomorphic multiply by plaintext scalar
        enc_prod = enc * multiplier
        # decrypt
        dec = enc_prod.decrypt()
        r = int(dec[0] % m)
        print(f"  residue={residues[i]} -> decrypted prod residue={r}")
        dec_residues.append(r)

    # reconstruct via CRT
    reconstructed, M = crt_reconstruct(dec_residues, moduli)
    print("\nReconstruction completed.")
    ok = (reconstructed == expected)
    print("Reconstructed equals expected ?", ok)
    if not ok:
        print("Expected:", expected)
        print("Reconstructed:", reconstructed)
    else:
        print("Exact match achieved.")
    return ok, reconstructed, expected

# ---------- example usage ----------
if __name__ == "__main__":
    # CHANGE these as needed (your large integer and multiplier)
    number = 96419820023653965779435520
    multiplier = 7

    # tune these according to your machine (memory/time)
    poly_mod_degree = 8192        # 8192 or 16384 recommended
    per_mod_bits = 40             # ~40-48 bits per modulus is common; raise to reduce count of moduli

    print("Starting BFV + CRT exact integer multiplication demo")
    ok, recon, exp = encrypt_multiply_crt(number, multiplier, poly_mod_degree, per_mod_bits)
    if ok:
        print("\nSUCCESS: reconstructed == expected")
    else:
        print("\nFAIL: reconstruction mismatch")
