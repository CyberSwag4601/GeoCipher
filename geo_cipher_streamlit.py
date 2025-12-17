"""
Geo Cipher - Streamlit Demo App

Single-file Streamlit app implementing a simple location-based encryption (Geo Cipher).
Pages:
 - Login
 - Encrypt Message
 - Decrypt Message
 - About / Deployment Notes

How it works (simple, secure-ish demo):
 - A key is deterministically derived from (latitude, longitude, optional passphrase) using SHA-256.
 - That digest is base64-encoded to produce a Fernet key for symmetric encryption (from cryptography.fernet).
 - The same lat/lon + passphrase must be used to decrypt.

Run locally:
 1. Create virtualenv (recommended): python -m venv venv && source venv/bin/activate (or venv\Scripts\activate on Windows)
 2. Install: pip install streamlit cryptography qrcode pillow
 3. Run: streamlit run geo_cipher_streamlit.py

NOTES:
 - This is a demo for learning + class showcase of deploying Python web apps with Streamlit. For production, use proper user auth, secure key management, and non-deterministic salts.
 - The "location" is user-provided lat/lon. You can extend to capture browser geolocation via JS + streamlit.components if you want.

"""

import streamlit as st
from cryptography.fernet import Fernet, InvalidToken
import hashlib
import base64
import qrcode
from io import BytesIO
from PIL import Image

# ----------------------- Utility functions -----------------------

def derive_fernet_key(lat: float, lon: float, passphrase: str = "") -> bytes:
    """Derive a deterministic Fernet key from latitude, longitude and optional passphrase.
    NOTE: Deterministic so same inputs -> same key (convenient for demo)."""
    payload = f"{lat:.6f},{lon:.6f},{passphrase}".encode("utf-8")
    digest = hashlib.sha256(payload).digest()  # 32 bytes
    return base64.urlsafe_b64encode(digest)  # Fernet expects urlsafe base64-encoded 32-byte key


def encrypt_message(message: str, lat: float, lon: float, passphrase: str = "") -> str:
    key = derive_fernet_key(lat, lon, passphrase)
    f = Fernet(key)
    token = f.encrypt(message.encode("utf-8"))
    return token.decode("utf-8")


def decrypt_message(token: str, lat: float, lon: float, passphrase: str = "") -> str:
    key = derive_fernet_key(lat, lon, passphrase)
    f = Fernet(key)
    plaintext = f.decrypt(token.encode("utf-8"))
    return plaintext.decode("utf-8")


def generate_qr(data: str) -> Image.Image:
    qr = qrcode.QRCode(box_size=6, border=2)
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    return img


# ----------------------- Simple in-memory demo auth -----------------------

# Demo credentials (only for class demo). Replace with real auth in production.
DEMO_USERS = {
    "student": "password123",
    "demo": "demo"
}


def login(username: str, password: str) -> bool:
    return DEMO_USERS.get(username) == password


# ----------------------- Streamlit App -----------------------

st.set_page_config(page_title="Geo Cipher (Streamlit)", layout="centered")

if "logged_in" not in st.session_state:
    st.session_state["logged_in"] = False

if "username" not in st.session_state:
    st.session_state["username"] = ""

# Sidebar navigation
st.sidebar.title("Geo Cipher — Demo")
if not st.session_state["logged_in"]:
    page = st.sidebar.radio("Go to", ("Login", "About / Deployment Notes"))
else:
    page = st.sidebar.radio("Go to", ("Encrypt Message", "Decrypt Message", "About / Deployment Notes", "Logout"))

# ---------- PAGE: LOGIN ----------
if page == "Login":
    st.title("Login — Geo Cipher Demo")
    st.write("Use demo credentials (shown below) to log in for the class demo.")
    col1, col2 = st.columns(2)
    with col1:
        username = st.text_input("Username")
    with col2:
        password = st.text_input("Password", type="password")

    if st.button("Log in"):
        if login(username.strip(), password):
            st.session_state["logged_in"] = True
            st.session_state["username"] = username.strip()
            st.success(f"Logged in as {st.session_state['username']}")
            st.experimental_rerun()
        else:
            st.error("Invalid credentials — try 'student' / 'password123' or 'demo' / 'demo'")

    st.markdown("---")
    st.subheader("Demo credentials")
    st.write("- Username: **student**  Password: **password123**")
    st.write("- Username: **demo**  Password: **demo**")

# ---------- PAGE: ENCRYPT MESSAGE ----------
elif page == "Encrypt Message":
    st.title("Encrypt Message — Geo Cipher")
    st.write("Enter the message, location coordinates (latitude & longitude) and an optional passphrase to create an encrypted token. The same coordinates + passphrase are required to decrypt.")

    m = st.text_area("Plaintext message", height=150)
    col1, col2 = st.columns(2)
    with col1:
        lat = st.number_input("Latitude", format="%.6f", value=12.971598)
    with col2:
        lon = st.number_input("Longitude", format="%.6f", value=77.594566)
    passphrase = st.text_input("Optional passphrase (adds secrecy)")

    if st.button("Encrypt"):
        if not m.strip():
            st.error("Please enter a message to encrypt.")
        else:
            try:
                token = encrypt_message(m, float(lat), float(lon), passphrase)
                st.success("Message encrypted successfully — share this token and the location+passphrase with recipient.")
                st.code(token, language="text")

                st.markdown("**QR code (optional):**")
                img = generate_qr(token)
                buf = BytesIO()
                img.save(buf, format="PNG")
                st.image(buf)

                with st.expander("Show derived key (for learning only)"):
                    key = derive_fernet_key(float(lat), float(lon), passphrase)
                    st.text(key.decode())
            except Exception as e:
                st.error(f"Encryption failed: {e}")

# ---------- PAGE: DECRYPT MESSAGE ----------
elif page == "Decrypt Message":
    st.title("Decrypt Message — Geo Cipher")
    st.write("Paste the encrypted token (or scan QR code externally) and provide the same coordinates + passphrase used to encrypt.")

    token = st.text_area("Encrypted token", height=150)
    col1, col2 = st.columns(2)
    with col1:
        lat = st.number_input("Latitude", format="%.6f", value=12.971598, key="dec_lat")
    with col2:
        lon = st.number_input("Longitude", format="%.6f", value=77.594566, key="dec_lon")
    passphrase = st.text_input("Optional passphrase (must match encryption)", key="dec_pass")

    if st.button("Decrypt"):
        if not token.strip():
            st.error("Please paste an encrypted token to decrypt.")
        else:
            try:
                plaintext = decrypt_message(token.strip(), float(lat), float(lon), passphrase)
                st.success("Decryption successful — plaintext below:")
                st.text_area("Plaintext message", value=plaintext, height=150)
            except InvalidToken:
                st.error("Failed to decrypt — token, coordinates, or passphrase may be incorrect.")
            except Exception as e:
                st.error(f"Decryption error: {e}")

# ---------- PAGE: ABOUT / DEPLOYMENT NOTES ----------
elif page == "About / Deployment Notes":
    st.title("About Geo Cipher (Demo)")
    st.markdown(
        """
- This demo shows a *location-based encryption* concept where the key is derived from latitude, longitude and an optional passphrase.
- It's meant for classroom demonstration of building and deploying a Python web app (Streamlit) and showing secure symmetric encryption in practice.

**Deployment (quick):**
1. Ensure code dependencies are installed: `pip install streamlit cryptography qrcode pillow`.
2. Run locally: `streamlit run geo_cipher_streamlit.py`.
3. To deploy for demo: use Streamlit Community Cloud (share via GitHub) or containerize with Docker and deploy to any cloud provider (Heroku, AWS Elastic Beanstalk, Azure Web Apps, Railway, etc.).

**Security notes (important):**
- The deterministic key derivation here is for demo convenience. In production you should use per-message random salts and authenticated key exchange protocols.
- Protect coordinates and passphrases — leaking them lets attackers decrypt.

"""
    )

    st.markdown("---")
    st.subheader("Class demo checklist")
    st.write("1. Show the Login page and enter demo credentials.")
    st.write("2. Go to Encrypt, type a message and coordinates, encrypt and show the token + QR code.")
    st.write("3. Copy token and go to Decrypt; use same coordinates & passphrase to recover message.")
    st.write("4. Explain how the key is derived and where you would improve security for production.")

    st.markdown("---")
    st.write("If you want, I can also:")
    st.write("- Create a `requirements.txt` snippet you can add to your repo.")
    st.write("- Convert this into a small Dockerfile for containerized deployment.")

# ---------- PAGE: LOGOUT ----------
elif page == "Logout":
    st.session_state["logged_in"] = False
    st.session_state["username"] = ""
    st.success("Logged out — you can close the tab or log in again.")
    st.experimental_rerun()

# ----------------------- End of app -----------------------

# Helpful: show footer note only when not in login
if st.session_state.get("logged_in"):
    st.caption("Geo Cipher demo — built with Streamlit. For class/demo use only.")
