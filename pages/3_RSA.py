import streamlit as st
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, PKCS1_v1_5
from Crypto.Random import get_random_bytes
from base64 import b64decode, b64encode


# Helper functions
def generate_rsa_keys(key_size=2048):
    key = RSA.generate(key_size)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key


def rsa_encrypt(message, public_key, padding_scheme):
    try:
        public_key = RSA.import_key(public_key)
        if padding_scheme == "PKCS1_OAEP":
            cipher = PKCS1_OAEP.new(public_key)
        elif padding_scheme == "PKCS1_v1_5":
            cipher = PKCS1_v1_5.new(public_key)
        else:
            raise ValueError("Unsupported padding scheme.")

        ciphertext = cipher.encrypt(message.encode())
        return b64encode(ciphertext).decode()
    except Exception as e:
        raise ValueError(f"Encryption error: {e}")


def rsa_decrypt(ciphertext, private_key, padding_scheme):
    try:
        private_key = RSA.import_key(private_key)
        if padding_scheme == "PKCS1_OAEP":
            cipher = PKCS1_OAEP.new(private_key)
            plaintext = cipher.decrypt(b64decode(ciphertext))
        elif padding_scheme == "PKCS1_v1_5":
            cipher = PKCS1_v1_5.new(private_key)
            plaintext = cipher.decrypt(b64decode(ciphertext), None)
            if plaintext is None:
                raise ValueError("Decryption failed. Possible padding mismatch.")
        else:
            raise ValueError("Unsupported padding scheme.")

        return plaintext.decode()
    except Exception as e:
        raise ValueError(f"Decryption error: {e}")


# Streamlit app
st.title("RSA Encryption/Decryption")

key_size = st.selectbox("RSA Key Size (bits)", (1024, 2048, 3072, 4096))
method = st.selectbox("Method", ("Encrypt", "Decrypt"))
padding_scheme = st.selectbox("Padding Scheme", ("PKCS1_OAEP", "PKCS1_v1_5"))

# Key handling
if st.checkbox("Generate RSA Keys"):
    private_key, public_key = generate_rsa_keys(key_size)
    st.text_area("Generated Private Key", private_key.decode(), height=200)
    st.text_area("Generated Public Key", public_key.decode(), height=200)

# Input for public or private keys
if method == "Encrypt":
    public_key = st.text_area("Enter the Public Key (PEM format):", height=200)
    message = st.text_area("Enter the message to encrypt:")
elif method == "Decrypt":
    private_key = st.text_area("Enter the Private Key (PEM format):", height=200)
    ciphertext = st.text_area("Enter the ciphertext (Base64 encoded):")

if st.button("Submit"):
    try:
        if method == "Encrypt":
            if not public_key or not message:
                st.error("Public key and message are required for encryption.")
            else:
                result = rsa_encrypt(message, public_key, padding_scheme)
                st.success(f"Ciphertext (Base64): {result}")
        elif method == "Decrypt":
            if not private_key or not ciphertext:
                st.error("Private key and ciphertext are required for decryption.")
            else:
                result = rsa_decrypt(ciphertext, private_key, padding_scheme)
                st.success(f"Decrypted Message: {result}")
    except Exception as e:
        st.error(f"Error: {e}")
