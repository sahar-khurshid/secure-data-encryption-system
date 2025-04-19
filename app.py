import streamlit as st
import hashlib
from cryptography.fernet import Fernet # type: ignore

# Generate and store encryption key
KEY = Fernet.generate_key()
cipher = Fernet(KEY)

# In-memory data storage
stored_data = {}  # Format: {"encrypted_text": {"encrypted_text": str, "passkey": hashed_passkey}}
if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0
if 'reauthorized' not in st.session_state:
    st.session_state.reauthorized = False

# --- Function to hash passkey ---
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# --- Function to encrypt data ---
def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

# --- Function to decrypt data ---
def decrypt_data(encrypted_text, passkey):
    hashed_passkey = hash_passkey(passkey)
    for key, value in stored_data.items():
        if key == encrypted_text and value["passkey"] == hashed_passkey:
            st.session_state.failed_attempts = 0
            return cipher.decrypt(encrypted_text.encode()).decode()
    
    st.session_state.failed_attempts += 1
    return None

# --- Streamlit App ---
st.set_page_config(page_title="🔒 Secure Data Encryption System", layout="centered")
st.title("🔐 Secure Data Encryption System")

# Navigation Menu
menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("📁 Menu", menu)

# --- HOME PAGE ---
if choice == "Home":
    st.subheader("🏠 Welcome")
    st.write("""
        This is a **secure data storage** app using **Fernet encryption**.
        
        👉 You can **store and encrypt** sensitive information with a unique passkey.  
        👉 Retrieve the data later using the **same passkey**.  
        ❗ Three incorrect passkey attempts require **login reauthorization**.
    """)

# --- STORE DATA PAGE ---
elif choice == "Store Data":
    st.subheader("📂 Store New Data")
    user_data = st.text_area("Enter the data to encrypt:")
    passkey = st.text_input("Enter a secret passkey:", type="password")

    if st.button("Encrypt & Save"):
        if user_data and passkey:
            encrypted_text = encrypt_data(user_data)
            hashed_passkey = hash_passkey(passkey)
            stored_data[encrypted_text] = {
                "encrypted_text": encrypted_text,
                "passkey": hashed_passkey
            }
            st.success("✅ Data encrypted and securely!")
            st.code(encrypted_text, language="text")
        else:
            st.warning("⚠️ Both data and passkey are required!")

# --- RETRIEVE DATA PAGE ---
elif choice == "Retrieve Data":
    if st.session_state.failed_attempts >= 3 and not st.session_state.reauthorized:
        st.warning("🔒 Too many failed attempts! Please reauthorize first.")
        st.stop()

    st.subheader("🔍 Retrieve Encrypted Data")
    encrypted_text = st.text_area("Paste your encrypted data:")
    passkey = st.text_input("Enter your passkey:", type="password")

    if st.button("Decrypt"):
        if encrypted_text and passkey:
            result = decrypt_data(encrypted_text, passkey)
            if result:
                st.success("✅ Decryption successful!")
                st.text_area("Your decrypted data:", result, height=150)
            else:
                remaining = 3 - st.session_state.failed_attempts
                st.error(f"❌ Incorrect passkey! Attempts remaining: {remaining}")
                if st.session_state.failed_attempts >= 3:
                    st.warning("🔒 Redirecting to Login Page due to failed attempts...")
                    st.experimental_rerun()
        else:
            st.warning("⚠️ Both fields are required!")

# --- LOGIN PAGE ---
elif choice == "Login":
    st.subheader("🔑 Reauthorization Required")
    login_pass = st.text_input("Enter Admin Password:", type="password")

    if st.button("Login"):
        if login_pass == "admin123":
            st.session_state.failed_attempts = 0
            st.session_state.reauthorized = True
            st.success("✅ Logged in successfully! You can now retry decryption.")
        else:
            st.error("❌ Incorrect login password.")
            
