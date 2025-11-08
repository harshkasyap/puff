# crt_tenseal_example.py
import tenseal as ts
from math import prod

# --- small utility: extended gcd for inverse ---
def egcd(a, b):
    if b == 0:
        return (a, 1, 0)
    g, x1, y1 = egcd(b, a % b)
    return (g, y1, x1 - (a // b) * y1)

def inv_mod(a, m):
    g, x, _ = egcd(a, m)
    if g != 1:
        raise ValueError("Inverse does not exist")
    return x % m

# --- CRT combine (given residues r[i] modulo m[i], pairwise coprime) ---
def crt_reconstruct(residues, moduli):
    # Computes x mod M, where M = product(moduli)
    M = 1
    for m in moduli:
        M *= m

    x = 0
    for (r_i, m_i) in zip(residues, moduli):
        M_i = M // m_i
        inv = inv_mod(M_i, m_i)    # (M_i)^{-1} mod m_i
        x = (x + (r_i * M_i % M) * inv) % M
    return x, M

# --- helper: pick moduli list (example: powers of two primes or large ints) ---
def choose_moduli_for_target(target_value, per_modulus_bits=50):
    # pick moduli = simple large integers (here 2^B - k). In practice use primes.
    moduli = []
    current_product = 1
    k = 0
    while current_product <= target_value:
        # pick modulus roughly 2^B (keep it odd)
        B = per_modulus_bits
        m = (1 << B) - (2 * k + 1)  # simple odd near 2^B; replace with random primes in practice
        moduli.append(m)
        current_product *= m
        k += 1
        if k > 8:
            break
    return moduli

# --- main demo ---
def main():
    # very large number and multiplier (example from your input)
    number = 96419820023653965779435520
    multiplier = 7
    expected = number * multiplier

    print("Expected full product size (approx):", expected)

    # choose moduli whose product > expected
    moduli = choose_moduli_for_target(expected, per_modulus_bits=48)
    print("Selected moduli ({}):".format(len(moduli)))
    for m in moduli:
        print("  modulus ~", m.bit_length(), "bits")

    M = prod(moduli)
    print("Product of moduli M bitlength:", M.bit_length())
    if M <= expected:
        raise SystemExit("Moduli product not large enough; increase number/size of moduli")

    # compute residues
    residues = [number % m for m in moduli]
    print("Residues (first few):", residues[:min(5, len(residues))])

    # For each modulus, create a BFV context with plain_modulus = m,
    # encrypt residue as bfv_vector(context, [residue]), multiply by scalar, decrypt.
    # Keep decrypted residue results in dec_residues.
    dec_residues = []
    for i, m in enumerate(moduli):
        print(f"\n-- modulus {i+1}/{len(moduli)} (bitlen {m.bit_length()}) --")
        # Choose a poly_modulus_degree suitable for this plain_modulus.
        # Larger plain_modulus may need larger poly_modulus_degree. Adjust as needed.
        # Using 16384 here to be safe in many cases; lower values may fail.
        context = ts.context(ts.SCHEME_TYPE.BFV, poly_modulus_degree=16384, plain_modulus=m)
        context.generate_galois_keys()
        context.generate_relin_keys()

        # encrypt residue (single-slot BFV vector)
        enc = ts.bfv_vector(context, [residues[i]])
        # homomorphic multiply by plaintext scalar (supported)
        enc_prod = enc * multiplier

        # decrypt
        dec = enc_prod.decrypt()    # returns a list; single-slot at index 0
        r = int(dec[0] % m)         # ensure reduced residue
        print("decrypted residue mod m:", r)
        dec_residues.append(r)

    # Now reconstruct using CRT
    reconstructed, M = crt_reconstruct(dec_residues, moduli)
    print("\nCRT reconstructed value (mod M):")
    # reconstructed is modulo M; since M > expected it should equal expected exactly
    print("reconstructed == expected ?", reconstructed == expected)
    if reconstructed != expected:
        print("Mismatch! But CRT reconstructed mod M. Values:")
        print("reconstructed:", reconstructed)
        print("expected     :", expected)
    else:
        print("Success! exact reconstruction recovered the full product.")

if __name__ == "__main__":
    main()
