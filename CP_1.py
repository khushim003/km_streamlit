import streamlit as st
import random
import time

# RSA functions

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
    e = 65537
    p = generate_prime_mr(bit_length // 2)
    q = generate_prime_mr(bit_length // 2)
    n = p * q
    phi = (p - 1) * (q - 1)
    d = modinv(e, phi)
    return (e, n), (d, n)

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

# Function to generate RSA key pair with time measurement
def generate_rsa_key_with_time(bit_length):
    start_time = time.time()  # Record the starting time
    public_key, private_key = generate_rsa_key(bit_length)
    end_time = time.time()  # Record the ending time
    key_generation_time = end_time - start_time  # Calculate the time taken for key generation
    return public_key, private_key, key_generation_time

# Streamlit interface setup
st.title('RSA Encryption, Decryption, and Digital Signature')

# Dropdown for algorithm selection
algorithm = st.selectbox(
    'Select the primality test algorithm:',
    ('Miller-Rabin', 'Solovay-Strassen')
)

# Key size input
bit_length = st.number_input('Enter the bit length for the key:', min_value=128, max_value=4096, value=1024, step=64)

# Key generation
if st.button('Generate Keys'):
    public_key, private_key, key_generation_time = generate_rsa_key_with_time(bit_length)
    st.session_state['public_key'] = public_key
    st.session_state['private_key'] = private_key
    st.write("Public Key (e, n):", public_key)
    st.write("Private Key (d, n):", private_key)
    st.write("Time taken for key generation:", key_generation_time, "seconds")

