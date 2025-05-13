import streamlit as st
from cryptography.fernet import Fernet
import hashlib

# Initialize encryption key and cipher
if "ENCRYPTION_KEY" not in st.session_state:
    st.session_state.ENCRYPTION_KEY = Fernet.generate_key()

cipher = Fernet(st.session_state.ENCRYPTION_KEY)

# In-memory storage
if 'stored_data' not in st.session_state:
    st.session_state.stored_data = {}

failed_attempts = {}
authorized_users = {"admin": "admin123"}  # Simple login creds
session_state = st.session_state

# Initialize session state
if "logged_in" not in session_state:
    session_state.logged_in = True
if "reauth_required" not in session_state:
    session_state.reauth_required = False
if "failed_count" not in session_state:
    session_state.failed_count = 0
if "username" not in session_state:
    session_state.username = "admin"

# Hashing function
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# Home page
def home():
    st.title("🔐 Secure Data Encryption System")
    st.write("Choose an action below:")
    if st.button("➕ Store New Data"):
        session_state.page = "store"
    if st.button("🔓 Retrieve Data"):
        session_state.page = "retrieve"

# Insert data page
def store_data():
    st.title("➕ Store Encrypted Data")
    data = st.text_area("Enter your data:")
    passkey = st.text_input("Set a passkey:", type="password")
    key_name = st.text_input("Enter a key name (e.g., 'user1_data'):")

    if st.button("Encrypt & Save"):
        if not data or not passkey or not key_name:
            st.error("All fields are required!")
        else:
            encrypted = cipher.encrypt(data.encode()).decode()
            st.session_state.stored_data[key_name] = {
                "encrypted_text": encrypted,
                "passkey": hash_passkey(passkey),
            }
            st.success(f"Data stored securely as '{key_name}'")
            st.write(f"Current stored data: {st.session_state.stored_data}")  # Debugging line

    if st.button("⬅️ Back to Home"):
        session_state.page = "home"

# Retrieve data page
def retrieve_data():
    st.title("🔓 Retrieve Decrypted Data")

    key_name = st.text_input("Enter the key name:")
    passkey = st.text_input("Enter the passkey:", type="password")

    if st.button("Decrypt"):
        if key_name not in st.session_state.stored_data:
            st.error("Key not found!")
            st.write(f"Stored keys: {list(st.session_state.stored_data.keys())}")  # Debugging line
            return

        hashed_input = hash_passkey(passkey)
        saved_hash = st.session_state.stored_data[key_name]["passkey"]

        if hashed_input == saved_hash:
            session_state.failed_count = 0  # Reset on success
            try:
                decrypted = cipher.decrypt(st.session_state.stored_data[key_name]["encrypted_text"].encode()).decode()
                st.success("Data decrypted successfully:")
                st.code(decrypted)
            except Exception as e:
                st.error(f"Error decrypting data: {str(e)}")
        else:
            session_state.failed_count += 1
            st.error(f"Incorrect passkey! Attempts: {session_state.failed_count}/3")

            if session_state.failed_count >= 3:
                session_state.reauth_required = True
                session_state.page = "login"

    if st.button("⬅️ Back to Home"):
        session_state.page = "home"

# Login page
def login_page():
    st.title("🔐 Reauthentication Required")

    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        if username in authorized_users and authorized_users[username] == password:
            session_state.reauth_required = False
            session_state.failed_count = 0
            session_state.page = "retrieve"
            st.success("Reauthorized! Redirecting...")
        else:
            st.error("Invalid credentials.")

# Page routing
def main():
    if "page" not in session_state:
        session_state.page = "home"

    if session_state.reauth_required:
        login_page()
    elif session_state.page == "home":
        home()
    elif session_state.page == "store":
        store_data()
    elif session_state.page == "retrieve":
        retrieve_data()

if __name__ == "__main__":
    main()
