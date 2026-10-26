# Secure Login System

Ek secure login web app (Python + Flask + SQLite).

## Features
- **User registration & login** with bcrypt-hashed passwords (cost factor 12, per-user salt)
- **Input validation** (username, email, password strength) + **parameterized SQL queries** → SQL injection se protection
- **Session management**: HttpOnly + SameSite cookies, 30 min timeout, session reset on login (session fixation protection), **logout**
- **CSRF protection** on every POST form
- **Brute-force protection**: 5 galat attempts ke baad 5 minute ka lockout
- **Optional 2FA (TOTP)**: Google Authenticator / Authy se, QR code ke saath
- Security headers (CSP, X-Frame-Options, nosniff, no-store)
- Generic error messages (username enumeration se bachne ke liye)

## Setup & Run
```bash
cd secure-login-system
python -m venv venv
venv\Scripts\activate        # Windows
# source venv/bin/activate   # Linux / Mac
pip install -r requirements.txt
python app.py
```
Browser me kholo: http://127.0.0.1:5000

## Project Structure
```
secure-login-system/
├── app.py               # Flask app (routes, auth, validation, 2FA)
├── requirements.txt
├── users.db             # SQLite DB (auto-create hota hai)
├── templates/           # HTML pages
└── static/style.css
```

## Security Notes
- Production me `HTTPS=1` environment variable set karo (Secure cookie flag ke liye) aur `SECRET_KEY` env var me strong key do.
- Password kabhi plain text me store nahi hota, sirf bcrypt hash.
- Saari SQL queries `?` placeholders use karti hain.
