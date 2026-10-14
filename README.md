# VitaDairy protected report launcher

Dedicated report accounts are configured by the report owner. The application opens an authenticated AES-256-GCM encrypted snapshot only after login.

No plaintext report or credentials are stored in this repository. Encryption keys and account password hashes belong only in Streamlit Secrets.

Entry point: `bootstrap.py` | Python 3.13.
