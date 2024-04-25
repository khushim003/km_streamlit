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
    start_time = time.time()  # Measure start time
    e = 65537
    p = generate_prime_mr(bit_length // 2)
    q = generate_prime_mr(bit_length // 2)
    n = p * q
    phi = (p - 1) * (q - 1)
    d = modinv(e, phi)
    end_time = time.time()  # Measure end time
    time_taken = end_time - start_time  # Calculate time taken
    return (e, n), (d, n), time_taken

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

# Dropdown for algorithm selection
algorithm = st.selectbox(
    'Select the primality test algorithm:',
    ('Miller-Rabin', 'Solovay-Strassen')
)

# Key size input
bit_length = st.number_input('Enter the bit length for the key:', min_value=128, max_value=4096, value=1024, step=64)

# Key generation
if st.button('Generate Keys'):
    public_key, private_key, time_taken = generate_rsa_key(bit_length)
    st.session_state['public_key'] = public_key
    st.session_state['private_key'] = private_key
    st.write("Public Key (e, n):", public_key)
    st.write("Private Key (d, n):", private_key)
    st.write("Time taken to generate key:", time_taken, "seconds")

# Text input for plaintext
plaintext = st.text_input('Enter a plaintext message:')

# Encryption
if st.button('Encrypt Message') and plaintext and 'public_key' in st.session_state:
    ciphertext = encrypt(plaintext, st.session_state['public_key'])
    st.session_state['ciphertext'] = ciphertext
    st.write("Encrypted message:", ciphertext)

# Decryption
if st.button('Decrypt Message') and 'ciphertext' in st.session_state and 'private_key' in st.session_state:
    decrypted_message = decrypt(st.session_state['ciphertext'], st.session_state['private_key'])
    st.write("Decrypted message:", decrypted_message)

# Signing
if st.button('Sign Message') and plaintext and 'private_key' in st.session_state:
    signature = sign(plaintext, st.session_state['private_key'])
    st.session_state['signature'] = signature
    st.write("Signature:", signature)

# Signature verification
if st.button('Verify Signature') and plaintext and 'signature' in st.session_state and 'public_key' in st.session_state:
    is_valid = verify(plaintext, st.session_state['signature'], st.session_state['public_key'])
    if is_valid:
        st.success("Signature is valid.")
    else:
        st.error("Signature is invalid.")

# Option to modify encrypted key digits
if st.checkbox('Modify Encrypted Key'):
    modified_ciphertext = st.text_input('Enter modified encrypted key:')
    st.write("Original Encrypted Key:", st.session_state.get('ciphertext', "Encrypt a message first."))
    if modified_ciphertext:
        if modified_ciphertext != st.session_state.get('ciphertext'):
            st.error("Decryption failed! The modified encrypted key is not valid.")
        else:
            st.success("Decryption succeeded! The modified encrypted key is valid.")

