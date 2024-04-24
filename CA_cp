import streamlit as st
import random
import time

# Include your primality tests and RSA key generation functions here
# Miller-Rabin primality test
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

# Generate a prime number using Miller-Rabin algorithm
def generate_prime_mr(bits):
    while True:
        p = random.getrandbits(bits)
        if is_prime_mr(p):
            return p

# Generate RSA key using Miller-Rabin algorithm
def generate_rsa_key_mr(bit_length):
    start_time = time.time()
    p = generate_prime_mr(bit_length // 2)
    q = generate_prime_mr(bit_length // 2)
    n = p * q
    end_time = time.time()
    key_gen_time = end_time - start_time
    return p, q, n, key_gen_time

# Solovay-Strassen primality test
def jacobi(a, n):
    if a == 0:
        return 0
    if a == 1:
        return 1
    if a == 2:
        if n % 8 == 1 or n % 8 == 7:
            return 1
        elif n % 8 == 3 or n % 8 == 5:
            return -1
    if a % 2 == 0:
        return jacobi(2, n) * jacobi(a // 2, n)
    if a >= n:
        return jacobi(a % n, n)
    if a % 4 == 3 and n % 4 == 3:
        return -jacobi(n, a)
    else:
        return jacobi(n, a)

def is_prime_ss(n, k=5):
    if n == 2 or n == 3:
        return True
    if n <= 1 or n % 2 == 0:
        return False

    for _ in range(k):
        a = random.randint(2, n - 1)
        x = pow(a, (n - 1) // 2, n)
        j = jacobi(a, n)
        if x != j % n:
            return False
    return True

def generate_prime_ss(bits):
    while True:
        p = random.getrandbits(bits)
        if is_prime_ss(p):
            return p

def generate_rsa_key_ss(bit_length):
    start_time = time.time()
    p = generate_prime_ss(bit_length // 2)
    q = generate_prime_ss(bit_length // 2)
    n = p * q
    end_time = time.time()
    key_gen_time = end_time - start_time
    return p, q, n, key_gen_time


# Streamlit interface
st.title('RSA Key Generator')

# Dropdown menu to choose the algorithm
algorithm = st.selectbox(
    'Select the primality test algorithm:',
    ('Miller-Rabin', 'Solovay-Strassen')
)

# Input for key size
bit_length = st.number_input('Enter the bit length for the key:', min_value=128, max_value=4096, value=1024, step=64)

# Button to generate keys
if st.button('Generate Keys'):
    if algorithm == 'Miller-Rabin':
        p, q, n, key_gen_time = generate_rsa_key_mr(bit_length)
    else:
        p, q, n, key_gen_time = generate_rsa_key_ss(bit_length)

    # Display the results
    st.write("Key generated using the {} algorithm:".format(algorithm))
    st.write("p:", p)
    st.write("q:", q)
    st.write("n:", n)
    st.write("Time taken for key generation:", key_gen_time, "seconds")
