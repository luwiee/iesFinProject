import streamlit as st
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from base64 import b64decode, b64encode

# Helper functions
# Helper functions
def parse_key(key_input, format_type, expected_length=None):
    try:
        if format_type == "Plaintext":
            key = key_input.encode()
        elif format_type == "Hex":
            key = bytes.fromhex(key_input)
        elif format_type == "Base64":
            key = b64decode(key_input)
        else:
            raise ValueError("Unsupported key format")

        if expected_length and len(key) != expected_length:
            raise ValueError(f"Key length must be {expected_length} bytes")

        return key
    except Exception as e:
        raise ValueError(f"Invalid key: {e}")


def parse_iv(iv_input, format_type, block_size=16):
    try:
        if iv_input:
            if format_type == "Plaintext" and len(iv_input) == block_size:
                iv = iv_input.encode()
            else:
                iv = parse_key(iv_input, format_type, block_size)
            if len(iv) != block_size:
                raise ValueError(f"IV must be {block_size} bytes, got {len(iv)}")
            return iv
        else:
            return None  # Return None if IV is not provided
    except Exception as e:
        raise ValueError(f"Invalid IV: {e}")


def aes_encrypt(message, key, mode, iv=None, padding=True):
    if mode == "ECB":
        cipher = AES.new(key, AES.MODE_ECB)
    else:
        cipher = AES.new(key, getattr(AES, f"MODE_{mode}"), iv=iv or b"\x00" * 16)

    if padding:
        message = pad(message.encode(), AES.block_size)
    else:
        message = message.encode()
    ciphertext = cipher.encrypt(message)
    return b64encode(ciphertext).decode()


def aes_decrypt(ciphertext, key, mode, iv=None, padding=True):
    if mode == "ECB":
        cipher = AES.new(key, AES.MODE_ECB)
    else:
        cipher = AES.new(key, getattr(AES, f"MODE_{mode}"), iv=iv or b"\x00" * 16)

    plaintext = cipher.decrypt(b64decode(ciphertext))
    if padding:
        plaintext = unpad(plaintext, AES.block_size)
    return plaintext.decode()


# Streamlit app
st.title("AES Encryption/Decryption")

method = st.selectbox("Method", ("Encrypt", "Decrypt"))
encryption_type = st.selectbox("Type", ("AES",))

if encryption_type == "AES":
    aes_key_size = st.selectbox("AES Key Size (bits)", (128, 192, 256))
    key_format = st.radio("Key Format", ("Plaintext", "Hex", "Base64"))
    key_input = st.text_input(f"Enter the AES-{aes_key_size} key:")

    # Key length validation
    expected_key_length = aes_key_size // 8
    if key_format == "Plaintext":
        current_length = len(key_input)
    elif key_format == "Hex":
        current_length = len(key_input) // 2
    elif key_format == "Base64":
        current_length = len(b64decode(key_input, validate=True)) if key_input else 0
    else:
        current_length = 0

    st.write(f"Key Length: {current_length}/{expected_key_length} bytes")
    if current_length < expected_key_length:
        st.warning(f"Key is too short. Add {expected_key_length - current_length} more bytes.")
    elif current_length > expected_key_length:
        st.error(f"Key is too long. Reduce it by {current_length - expected_key_length} bytes.")

    mode = st.selectbox("Cipher Mode", ("ECB", "CBC", "CFB", "OFB"))
    padding = st.radio("Padding", ("PKCS7 Padding", "No Padding")) == "PKCS7 Padding"

    if method == "Encrypt":
        message = st.text_area("Enter the message:")
    else:
        ciphertext = st.text_area("Enter the ciphertext (in Base64):")

    iv = None
    if mode != "ECB":
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

            st.write(f"IV Length: {iv_length}/16 bytes")
            if iv_length < 16:
                st.warning(f"IV is too short. Add {16 - iv_length} more bytes.")
            elif iv_length > 16:
                st.error(f"IV is too long. Reduce it by {iv_length - 16} bytes.")

if st.button("Submit"):
    try:
        key_bytes = parse_key(key_input, key_format, expected_length=expected_key_length)
        iv_bytes = parse_iv(iv, iv_format) if iv else None

        if method == "Encrypt":
            result = aes_encrypt(message, key_bytes, mode, iv_bytes, padding)
            st.success(f"Ciphertext: {result}")
        else:
            result = aes_decrypt(ciphertext, key_bytes, mode, iv_bytes, padding)
            st.success(f"Plaintext: {result}")
    except Exception as e:
        st.error(f"Error: {e}")
