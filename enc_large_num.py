import tenseal as ts

context = ts.context(
    ts.SCHEME_TYPE.BFV,
    poly_modulus_degree=8192,    # typical size for moderate computation
    plain_modulus=1032193        # must be prime; affects value range
)
context.generate_galois_keys()
context.generate_relin_keys()

number = 12345678901234567890
print("Original number:", number)

# Step 3: Encrypt using BFV (scalar encoding)
enc_num = ts.bfv_encoder(context).encode_int(number)
enc_val = ts.bfv_vector(context, [number])  # vector form for ops
print("Encrypted value created.")

# Step 4: Multiply by a plaintext scalar
multiplier = 12
print("Multiplier:", multiplier)
enc_product = enc_val * multiplier

# Step 5: Decrypt
decrypted_result = enc_product.decrypt()
print("Decrypted result:", decrypted_result[0])

# Step 6: Verify correctness
expected = number * multiplier
print("Expected result:", expected)
print("Match:", decrypted_result[0] == expected)
