import base64
import io
import json
import os
import time
import hmac
import hashlib
import requests
import streamlit as st
from dotenv import load_dotenv

load_dotenv()

VULN = os.environ.get("VULN_BASE_URL", "http://localhost:8001")
HARD = os.environ.get("HARD_BASE_URL", "http://localhost:8000")
SECRET = os.environ.get("SECRET_KEY", "change-me")

st.set_page_config(page_title="Secure File Upload Demo", page_icon="🛡️", layout="centered")
st.title("Secure File Upload Demo")
st.write("Compare vulnerable vs hardened upload services.")

tab1, tab2 = st.tabs(["Vulnerable Service", "Hardened Service"]) 

with tab1:
    st.subheader("Upload to vulnerable-service")
    file = st.file_uploader("Choose a file", key="v_file")
    upid = st.text_input("Uploader ID (optional)", key="v_uid")
    if st.button("Upload (vulnerable)"):
        if not file:
            st.warning("No file selected")
        else:
            files = {"file": (file.name, file.getvalue(), file.type or "application/octet-stream")}
            data = {"uploader_id": upid}
            r = requests.post(f"{VULN}/upload", files=files, data=data, timeout=30)
            st.code(r.text)
            if r.ok:
                url = (r.json().get("url"))
                if url:
                    st.success("Uploaded. Direct link:")
                    st.write(f"{VULN}{url}")

with tab2:
    st.subheader("Upload to hardened-service")
    file2 = st.file_uploader("Choose a file", key="h_file")
    upid2 = st.text_input("Uploader ID (optional)", key="h_uid")
    if st.button("Upload (hardened)"):
        if not file2:
            st.warning("No file selected")
        else:
            files = {"file": (file2.name, file2.getvalue(), file2.type or "application/octet-stream")}
            data = {"uploader_id": upid2}
            r = requests.post(f"{HARD}/upload", files=files, data=data, timeout=60)
            st.code(r.text)
            if r.status_code == 200:
                file_id = r.json().get("id")
                if file_id:
                    st.session_state["last_file_id"] = file_id
                    st.success(f"Uploaded with id: {file_id}")

    st.divider()
    st.subheader("Generate signed download URL")
    file_id_input = st.text_input("File ID", value=st.session_state.get("last_file_id", ""))
    exp_secs = st.number_input("Expiry seconds", value=300, min_value=60, max_value=3600, step=60)

    def sign_token(file_id: str, exp_seconds: int) -> str:
        payload = {"file_id": file_id, "exp": int(time.time()) + int(exp_seconds)}
        msg = json.dumps(payload, separators=(",", ":")).encode()
        sig = hmac.new(SECRET.encode(), msg, hashlib.sha256).digest()
        token = base64.urlsafe_b64encode(msg + b"." + sig).decode().rstrip("=")
        return token

    if st.button("Generate & Download"):
        if not file_id_input:
            st.warning("Provide a file id")
        else:
            token = sign_token(file_id_input, int(exp_secs))
            url = f"{HARD}/download/{file_id_input}?token={token}"
            st.code(url)
            try:
                dr = requests.get(url, timeout=60)
                if dr.status_code == 200:
                    st.success("Downloaded successfully")
                    st.download_button(
                        label="Save file",
                        data=dr.content,
                        file_name=file_id_input,
                        mime=dr.headers.get("Content-Type", "application/octet-stream"),
                    )
                else:
                    st.error(f"Failed: {dr.status_code} {dr.text}")
            except Exception as e:
                st.error(str(e))

st.caption("Set SECRET_KEY in .env so UI can sign tokens to download from hardened-service.")


