# Zero Trust Security Architecture – Flask Demo

A local educational web application that demonstrates core Zero Trust security concepts:

- Identity verification with securely hashed passwords
- Simulated one-time password (OTP) multi-factor authentication (MFA)
- Trusted-browser registration
- Role-based access control (RBAC)
- Least-privilege resource policies
- Access decision and audit logging
- Administrator dashboard

## Technology stack

- Python 3
- Flask
- SQLite
- HTML, Jinja templates, Bootstrap 5

## Requirements

- Python 3.9 or newer
- pip

## Run on Windows

```powershell
py -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

## Run on Linux / Kali Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Open http://127.0.0.1:5000 in your browser.

## Demo accounts

| Role | Username | Password |
|---|---|---|
| Administrator | `admin` | `Admin@12345` |
| Employee | `employee` | `Employee@12345` |

After entering a password, the app prints a six-digit demo MFA code in the terminal running Flask. Enter that code in the browser. Select **Trust this browser for 30 days** to register the current browser. Protected resources require a registered browser.

## Demonstration workflow

1. Sign in as `employee` and complete the OTP challenge.
2. Select the option to trust the browser.
3. Open **General Company Documents** to see an allowed access decision.
4. Try to open **Payroll Records** as an employee; the role policy denies access.
5. Sign out and sign in as `admin`.
6. Open the **Admin Dashboard** to review registered users and recent access logs.
7. Sign in without trusting the browser and observe that protected resource access is denied.

## Project structure

```text
zero-trust-security-flask/
├── app.py
├── requirements.txt
├── README.md
├── .gitignore
└── templates/
    ├── base.html
    ├── index.html
    ├── login.html
    ├── register.html
    ├── verify_otp.html
    ├── dashboard.html
    ├── resource.html
    ├── admin.html
    └── error.html
```

## Security notes and limitations

**This project is an educational simulation and is not production-ready.**

- The OTP is printed to the server terminal. This demonstrates the MFA flow but is not a secure delivery channel. Use a real authenticator app (TOTP) or a verified messaging provider in a real deployment.
- The seeded demo credentials are public and must only be used in this local demonstration.
- Set a strong, random `FLASK_SECRET_KEY` before deployment.
- Use HTTPS, secure cookie settings, rate limiting, account lockout, managed secrets, database backups, and centralized monitoring before production use.
- Device trust is represented by a random browser cookie whose hash is stored in SQLite. This is not a real endpoint posture or health assessment.
- The app binds to `127.0.0.1` by default. Do not expose this demonstration directly to the public internet.
- The app uses SQLite for a simple local demonstration; production systems should use an appropriately managed database and operational controls.

## Environment variables

| Variable | Purpose |
|---|---|
| `FLASK_SECRET_KEY` | Secret used to sign Flask sessions |
| `DATABASE_PATH` | Optional SQLite database file path |
| `COOKIE_SECURE` | Set to `1` when running behind HTTPS to mark cookies Secure |

## Learning outcomes

This project illustrates the Zero Trust principle **“Never Trust, Always Verify”** by checking identity, a registered device, and the user's role before granting access to protected resources. It is intended for classroom demonstrations and safe local testing.
