import streamlit as st
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
from base64 import b64decode, b64encode


# Helper functions
def parse_key(key_input, format_type):
    try:
        if format_type == "Plaintext":
            key = key_input.encode()
        elif format_type == "Hex":
            key = bytes.fromhex(key_input)
        elif format_type == "Base64":
            key = b64decode(key_input)
        else:
            raise ValueError("Unsupported key format")

        if len(key) < 8:
            raise ValueError("Key must be at least 8 bytes (DES block size)")

        # Truncate or pad the key to fit DES block size (8 bytes)
        key = key[:8] if len(key) > 8 else pad(key, 8)
        return key
    except Exception as e:
        raise ValueError(f"Invalid key: {e}")


def parse_iv(iv_input, format_type):
    try:
        if iv_input:
            if format_type == "Plaintext" and len(iv_input) == 8:
                iv = iv_input.encode()
            else:
                iv = parse_key(iv_input, format_type)
            if len(iv) != 8:
                raise ValueError(f"IV must be 8 bytes, got {len(iv)}")
            return iv
        else:
            return None  # Return None if IV is not provided
    except Exception as e:
        raise ValueError(f"Invalid IV: {e}")


def des_encrypt(message, key, mode, iv=None, padding=True):
    if mode == "ECB":
        cipher = DES.new(key, DES.MODE_ECB)
    else:
        cipher = DES.new(key, DES.MODE_CBC, iv=iv or b"\x00" * 8)

    if padding:
        message = pad(message.encode(), DES.block_size)
    else:
        message = message.encode()
    ciphertext = cipher.encrypt(message)
    return b64encode(ciphertext).decode()


def des_decrypt(ciphertext, key, mode, iv=None, padding=True):
    if mode == "ECB":
        cipher = DES.new(key, DES.MODE_ECB)
    else:
        cipher = DES.new(key, DES.MODE_CBC, iv=iv or b"\x00" * 8)

    plaintext = cipher.decrypt(b64decode(ciphertext))
    if padding:
        plaintext = unpad(plaintext, DES.block_size)
    return plaintext.decode()


# Streamlit app
st.title("DES Encryption/Decryption")

method = st.selectbox("Method", ("Encrypt", "Decrypt"))
encryption_type = st.selectbox("Type", ("DES",))

if encryption_type == "DES":
    key_format = st.radio("Key Format", ("Plaintext", "Hex", "Base64"))
    key_input = st.text_input("Enter the DES key (minimum 8 bytes):")

    mode = st.selectbox("Cipher Mode", ("ECB", "CBC"))
    padding = st.radio("Padding", ("PKCS7 Padding", "No Padding")) == "PKCS7 Padding"

    if method == "Encrypt":
        message = st.text_area("Enter the message:")
    else:
        ciphertext = st.text_area("Enter the ciphertext (in Base64):")

    iv = None
    if mode == "CBC":
        iv_format = st.radio("IV Format", ("Plaintext", "Hex", "Base64"))
        iv = st.text_input("Enter the IV (optional):")

        # IV length validation
        if iv:
            if iv_format == "Plaintext":
                iv_length = len(iv)
            elif iv_format == "Hex":
                iv_length = len(iv) // 2
            elif iv_format == "Base64":
                iv_length = len(b64decode(iv, validate=True)) if iv else 0
            else:
                iv_length = 0

            st.write(f"IV Length: {iv_length}/8 bytes")
            if iv_length < 8:
                st.warning(f"IV is too short. Add {8 - iv_length} more bytes.")
            elif iv_length > 8:
                st.error(f"IV is too long. Reduce it by {iv_length - 8} bytes.")

if st.button("Submit"):
    try:
        key_bytes = parse_key(key_input, key_format)
        iv_bytes = parse_iv(iv, iv_format) if iv else None

        if method == "Encrypt":
            result = des_encrypt(message, key_bytes, mode, iv_bytes, padding)
            st.success(f"Ciphertext: {result}")
        else:
            result = des_decrypt(ciphertext, key_bytes, mode, iv_bytes, padding)
            st.success(f"Plaintext: {result}")
    except Exception as e:
        st.error(f"Error: {e}")
