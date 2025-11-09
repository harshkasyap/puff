#!/usr/bin/env python3
# bfv_crt_exact_fixed.py
# BFV + CRT exact integer multiplication example (robusted).
#
# Requirements:
#   pip install tenseal sympy
#
# Notes:
# - Finding batching primes (sympy.isprime) can take time.
# - Each modulus creates a TenSEAL context; memory use grows with number of moduli.
# - Tune poly_mod_degree and per_mod_bits as needed.

import tenseal as ts
import sympy
from math import prod, gcd
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

def moduli_pairwise_coprime(moduli: List[int]) -> Tuple[bool, Tuple[int,int,int] or None]:
    n = len(moduli)
    for i in range(n):
        for j in range(i+1, n):
            g = gcd(moduli[i], moduli[j])
            if g != 1:
                return False, (i, j, g)
    return True, None

# ---------- find batching-friendly prime ----------
def find_batching_prime(poly_modulus_degree: int, bits: int, start_k: int = 1, max_tries: int = 5_000_000) -> int:
    """
    Find a prime t with ~bits bits such that:
        t % (2 * poly_modulus_degree) == 1
    Search t = 1 + k*(2*N) starting from start_k.
    """
    N2 = 2 * poly_modulus_degree
    if bits > 10:
        k = max(start_k, (1 << (bits - 1)) // N2)
    else:
        k = max(start_k, 1)
    tries = 0
    while tries < max_tries:
        candidate = 1 + k * N2
        if candidate.bit_length() >= bits - 2:
            if sympy.isprime(candidate):
                return candidate
        k += 1
        tries += 1
    raise RuntimeError("No batching prime found in max tries; try increasing max_tries or bits")

# ---------- choose moduli until product > target ----------
def choose_moduli_for_target(target_value: int,
                             poly_modulus_degree: int = 8192,
                             per_modulus_bits: int = 40,
                             max_moduli: int = 8) -> List[int]:
    """
    Pick batching-safe primes until product exceeds target_value.
    Ensures uniqueness and pairwise coprime property.
    """
    moduli = []
    product = 1
    start_k = 1
    round_no = 0
    while product <= target_value:
        round_no += 1
        if len(moduli) >= max_moduli:
            raise RuntimeError("Reached max_moduli limit; increase per_modulus_bits or max_moduli.")
        print(f"[moduli] Round {round_no}: product bits={product.bit_length()} target bits={target_value.bit_length()}")
        p = find_batching_prime(poly_modulus_degree, per_modulus_bits, start_k=start_k)
        start_k += 1_000  # heuristic bump to avoid same region
        # ensure uniqueness & coprime to previous
        rejected = False
        for prev in moduli:
            if prev == p or gcd(prev, p) != 1:
                print(f"[moduli] rejected candidate (duplicate/non-coprime): prev={prev}, candidate={p}, gcd={gcd(prev,p)}")
                rejected = True
                break
        if rejected:
            continue
        moduli.append(p)
        product *= p
        print(f"[moduli] accepted prime (bitlen {p.bit_length()}); moduli count={len(moduli)}")
        # heuristic: if still far from target, make next primes slightly bigger
        if product.bit_length() < target_value.bit_length() // 2:
            per_modulus_bits += 1
    print(f"[moduli] selected {len(moduli)} moduli; total product bits={product.bit_length()}")
    return moduli

# ---------- main flow ----------
def encrypt_multiply_crt(number: int, multiplier: int,
                         poly_modulus_degree: int = 8192,
                         per_modulus_bits: int = 40,
                         max_moduli: int = 8):
    expected = number * multiplier
    print("Expected full product bitlength:", expected.bit_length())

    # choose moduli
    moduli = choose_moduli_for_target(expected, poly_modulus_degree, per_modulus_bits, max_moduli)
    ok, bad = moduli_pairwise_coprime(moduli)
    if not ok:
        i,j,g = bad
        raise RuntimeError(f"Selected moduli not pairwise coprime: moduli[{i}],moduli[{j}] share gcd {g}")

    M = prod(moduli)
    print("Total modulus product M bitlength:", M.bit_length())
    if M <= expected:
        raise RuntimeError("Chosen moduli product not large enough!")

    residues = [number % m for m in moduli]
    dec_residues = []

    # process each modulus
    for i, m in enumerate(moduli):
        print(f"\n[CTX {i+1}/{len(moduli)}] modulus bitlen={m.bit_length()}")
        try:
            context = ts.context(ts.SCHEME_TYPE.BFV, poly_modulus_degree=poly_modulus_degree, plain_modulus=m)
            context.generate_galois_keys()
            context.generate_relin_keys()
        except Exception as e:
            print("Error creating TenSEAL context for modulus:", m)
            raise

        try:
            enc = ts.bfv_vector(context, [residues[i]])
        except Exception as e:
            print("Error creating BFVVector for modulus:", m, " — skipping this modulus.")
            raise

        # multiply by scalar (plaintext)
        enc_prod = enc * multiplier

        # decrypt and reduce modulo m (IMPORTANT)
        dec = enc_prod.decrypt()
        raw = int(dec[0])
        r = raw % m
        print(f"  residue={residues[i]} -> decrypted raw={raw} -> reduced residue={r}")
        dec_residues.append(r)

    # final CRT reconstruct
    reconstructed, M = crt_reconstruct(dec_residues, moduli)
    print("\nCRT reconstruction done. reconstructed bitlen:", reconstructed.bit_length())
    ok = (reconstructed == expected)
    print("Reconstructed equals expected? ", ok)
    if not ok:
        print("Expected:", expected)
        print("Reconstructed:", reconstructed)
    return ok, reconstructed, expected

# ---------- example usage ----------
if __name__ == "__main__":
    # change these inputs as needed
    number = 96419820023653965779435520
    multiplier = 96419820023653965779435520

    # tune these parameters for your environment:
    poly_mod_degree = 8192    # try 8192 or 16384
    per_mod_bits = 40         # ~40-48 bits per modulus reduces number of moduli
    max_moduli = 8            # safety cap to avoid runaway memory usage

    print("Starting fixed BFV + CRT example")
    ok, recon, exp = encrypt_multiply_crt(number, multiplier, poly_mod_degree, per_mod_bits, max_moduli)
    if ok:
        print("\nSUCCESS: reconstructed == expected")
    else:
        print("\nFAIL: reconstruction mismatch")
