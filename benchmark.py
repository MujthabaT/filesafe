import os
import time
import secrets
import statistics

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


# =========================
# CONFIG
# =========================
FILE_SIZES_MB = [1, 5, 10, 25]   # change if needed
RUNS = 5                         # repetitions for averaging
RECIPIENTS_TEST = [1, 5, 10, 20]


# =========================
# AES-GCM
# =========================
def aes_encrypt(data):
    key = secrets.token_bytes(32)
    nonce = secrets.token_bytes(12)

    start = time.perf_counter()
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(nonce),
        backend=default_backend()
    ).encryptor()

    ciphertext = encryptor.update(data) + encryptor.finalize()
    enc_time = (time.perf_counter() - start) * 1000

    return ciphertext, key, nonce, encryptor.tag, enc_time


def aes_decrypt(ciphertext, key, nonce, tag):
    start = time.perf_counter()
    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(nonce, tag),
        backend=default_backend()
    ).decryptor()

    decryptor.update(ciphertext) + decryptor.finalize()
    dec_time = (time.perf_counter() - start) * 1000
    return dec_time


# =========================
# RSA
# =========================
def generate_rsa():
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )


def rsa_wrap(pub, key):
    start = time.perf_counter()
    enc = pub.encrypt(
        key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    t = (time.perf_counter() - start) * 1000
    return enc, t


def rsa_unwrap(priv, enc):
    start = time.perf_counter()
    priv.decrypt(
        enc,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    t = (time.perf_counter() - start) * 1000
    return t


# =========================
# MAIN BENCHMARK
# =========================
print("\n=== FILESAFE CRYPTO BENCHMARK ===\n")

private_key = generate_rsa()
public_key = private_key.public_key()

# ---------------------------------
# FILE SIZE TESTS
# ---------------------------------
print("Upload / Download Cost\n")

for size in FILE_SIZES_MB:
    aes_enc_times = []
    rsa_wrap_times = []
    aes_dec_times = []
    rsa_unwrap_times = []

    for _ in range(RUNS):
        data = os.urandom(size * 1024 * 1024)

        ciphertext, aes_key, nonce, tag, t_enc = aes_encrypt(data)
        enc_key, t_wrap = rsa_wrap(public_key, aes_key)

        t_unwrap = rsa_unwrap(private_key, enc_key)
        t_dec = aes_decrypt(ciphertext, aes_key, nonce, tag)

        aes_enc_times.append(t_enc)
        rsa_wrap_times.append(t_wrap)
        aes_dec_times.append(t_dec)
        rsa_unwrap_times.append(t_unwrap)

    print(f"File: {size} MB")
    print(f" AES Encrypt avg: {statistics.mean(aes_enc_times):.2f} ms")
    print(f" RSA Wrap avg : {statistics.mean(rsa_wrap_times):.2f} ms")
    print(f" AES Decrypt avg: {statistics.mean(aes_dec_times):.2f} ms")
    print(f" RSA Unwrap avg : {statistics.mean(rsa_unwrap_times):.2f} ms")
    print("-" * 40)


# ---------------------------------
# MULTI USER SCALABILITY
# ---------------------------------
print("\nRSA Scalability Simulation\n")

aes_key = secrets.token_bytes(32)

for r in RECIPIENTS_TEST:
    pubs = [generate_rsa().public_key() for _ in range(r)]

    times = []
    for pub in pubs:
        _, t = rsa_wrap(pub, aes_key)
        times.append(t)

    print(f"Recipients: {r}  Total wrap time: {sum(times):.2f} ms")


# ---------------------------------
# STORAGE OVERHEAD
# ---------------------------------
print("\nStorage Overhead\n")

data = os.urandom(1 * 1024 * 1024)
ciphertext, key, nonce, tag, _ = aes_encrypt(data)

increase = len(ciphertext) + len(nonce) + len(tag) - len(data)

print(f"Plaintext: {len(data)} bytes")
print(f"Ciphertext: {len(ciphertext)} bytes")
print(f"Nonce: {len(nonce)} bytes")
print(f"Tag: {len(tag)} bytes")
print(f"Increase: {increase} bytes")
