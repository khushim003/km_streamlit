import streamlit as st
import random
import time

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

def encrypt_with_time(plaintext, public_key):
    e, n = public_key
    # Generate current timestamp as part of the plaintext
    timestamp = str(int(time.time()))
    plaintext_with_time = plaintext + "|" + timestamp
    # Convert plaintext to a number (simple conversion for demonstration)
    m = int.from_bytes(plaintext_with_time.encode('utf-8'), 'big')
    c = pow(m, e, n)
    return c, timestamp

def decrypt_and_verify_with_time(ciphertext, private_key):
    d, n = private_key
    m = pow(ciphertext, d, n)
    # Convert number back to plaintext
    plaintext_with_time = m.to_bytes((m.bit_length() + 7) // 8, 'big').decode('utf-8')
    # Separate the plaintext and timestamp
    plaintext, timestamp = plaintext_with_time.split("|")
    # Verify the timestamp
    current_time = int(time.time())
    if abs(current_time - int(timestamp)) > MAX_TIME_DIFFERENCE:
        return None, False
    else:
        return plaintext, True

# Streamlit interface setup
st.title('RSA Encryption, Decryption, and Digital Signature')
MAX_TIME_DIFFERENCE = 60  # Maximum time difference allowed in seconds

# Dropdown for algorithm selection
algorithm = st.selectbox(
    'Select the primality test algorithm:',
    ('Miller-Rabin', 'Solovay-Strassen')
)

# Key size input
bit_length = st.number_input('Enter the bit length for the key:', min_value=128, max_value=4096, value=1024, step=64)

# Key generation
if st.button('Generate Keys'):
    public_key, private_key = generate_rsa_key(bit_length)
    st.session_state['public_key'] = public_key
    st.session_state['private_key'] = private_key
    st.write("Public Key (e, n):", public_key)
    st.write("Private Key (d, n):", private_key)

# Text input for plaintext
plaintext = st.text_input('Enter a plaintext message:')

# Encryption with timestamp
if st.button('Encrypt Message with Time') and plaintext and 'public_key' in st.session_state:
    ciphertext, timestamp = encrypt_with_time(plaintext, st.session_state['public_key'])
    st.session_state['ciphertext'] = ciphertext
    st.session_state['timestamp'] = timestamp
    st.write("Encrypted message:", ciphertext)
    st.write("Timestamp:", timestamp)

# Decryption and verification with timestamp
if st.button('Decrypt and Verify Message with Time') and 'ciphertext' in st.session_state and 'private_key' in st.session_state:
    decrypted_message, is_valid = decrypt_and_verify_with_time(st.session_state['ciphertext'], st.session_state['private_key'])
    if is_valid:
        st.write("Decrypted message:", decrypted_message)
        st.success("Message is valid within the time limit.")
    else:
        st.error("Message is invalid or expired.")

