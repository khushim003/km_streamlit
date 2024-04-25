def sign(message, private_key):
    """ Sign a message using the private key. """
    d, n = private_key
    # Convert the message into an integer for signing
    m = int.from_bytes(message.encode('utf-8'), 'big')
    signature = pow(m, d, n)
    return signature

def verify(message, signature, public_key):
    """ Verify a signature using the public key. """
    e, n = public_key
    # Compute the message from the signature
    m_ver = pow(signature, e, n)
    # Convert original message into the same integer format
    m_orig = int.from_bytes(message.encode('utf-8'), 'big')
    return m_ver == m_orig


import streamlit as st
import random
import time

# Include all previous definitions and new functions for signing and verifying

def modinv(a, m):
    m0, x0, x1 = m, 0, 1
    if m == 1:
        return 0
    while a > 1:
        # q is quotient
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    if x1 < 0:
        x1 += m0
    return x1

def is_prime_mr(n, k=5):
    if n <= 1:
        return False
    if n <= 3:
        return True

    # Write n as d*2^r + 1
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    # Witness loop
    for _ in range(k):
        a = random.randint(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def generate_prime_mr(bits):
    while True:
        p = random.getrandbits(bits)
        if is_prime_mr(p):
            return p

def generate_rsa_key(bit_length):
    start_time = time.time()
    e = 65537
    p = generate_prime_mr(bit_length // 2)
    q = generate_prime_mr(bit_length // 2)
    n = p * q
    phi = (p - 1) * (q - 1)
    d = modinv(e, phi)
    end_time = time.time()
    generation_time = end_time - start_time
    return (e, n), (d, n), generation_time

def encrypt(plaintext, public_key):
    e, n = public_key
    # Convert plaintext to a number (simple conversion for demonstration)
    m = int.from_bytes(plaintext.encode('utf-8'), 'big')
    c = pow(m, e, n)
    return c

def decrypt(ciphertext, private_key):
    d, n = private_key
    m = pow(ciphertext, d, n)
    # Convert number back to plaintext
    plaintext = m.to_bytes((m.bit_length() + 7) // 8, 'big').decode('utf-8')
    return plaintext

# Streamlit interface setup
st.title('RSA Encryption, Decryption, and Digital Signature')

# Key size input
bit_length = st.number_input('Enter the bit length for the key:', min_value=128, max_value=4096, value=1024, step=64)

# Key generation
key_generation_button = st.button('Generate Keys')
if key_generation_button:
    public_key, private_key, generation_time = generate_rsa_key(bit_length)
    st.write("Public Key (e, n):", public_key)
    st.write("Private Key (d, n):", private_key)
    st.write("Key Generation Time:", generation_time, "seconds")

# Text input for plaintext
plaintext = st.text_input('Enter a plaintext message:')

# Encryption
encryption_button = st.button('Encrypt Message')
if encryption_button and plaintext and 'public_key' in locals():
    ciphertext = encrypt(plaintext, public_key)
    st.write("Encrypted message:", ciphertext)

# Decryption
decryption_button = st.button('Decrypt Message')
if decryption_button and 'ciphertext' in locals() and 'private_key' in locals():
    decrypted_message = decrypt(ciphertext, private_key)
    st.write("Decrypted message:", decrypted_message)

# Signing
signing_button = st.button('Sign Message')
if signing_button and plaintext and 'private_key' in locals():
    signature = sign(plaintext, private_key)
    st.write("Signature:", signature)

# Signature verification
verification_button = st.button('Verify Signature')
if verification_button and plaintext and 'signature' in locals() and 'public_key' in locals():
    is_valid = verify(plaintext, signature, public_key)
    if is_valid:
        st.success("Signature is valid.")
    else:
        st.error("Signature is invalid.")

# Option to modify encrypted key digits
modify_encrypted_key_checkbox = st.checkbox('Modify Encrypted Key')
if modify_encrypted_key_checkbox:
    modified_ciphertext = st.text_input('Enter modified encrypted key:')
    if modified_ciphertext:
        if modified_ciphertext != str(ciphertext):
            st.error("Decryption failed! The modified encrypted key is not valid.")
        else:
            st.success("Decryption succeeded! The modified encrypted key is valid.")
    else:
        st.warning("Enter the modified encrypted key.")
