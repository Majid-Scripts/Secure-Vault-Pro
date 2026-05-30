# 🔐 SecureVault Pro

A secure, offline desktop password manager built with Python and Tkinter.  
All passwords are encrypted locally using **AES-256-GCM** — your data never leaves your machine.

---

## 📸 Features

- 🔒 **AES-256-GCM Encryption** — industry-standard authenticated encryption for every stored password
- 🧂 **Argon2id Master Password Hashing** — memory-hard hashing resistant to brute-force attacks
- 🗝️ **Recovery Key System** — 8-word recovery key generated on setup to regain vault access
- 🛡️ **Breach Detection** — checks passwords against the HaveIBeenPwned database (k-anonymity, your password is never sent)
- 🔑 **Password Generator** — cryptographically secure passwords with configurable length and character sets
- 📊 **Strength Analyzer** — real-time password strength scoring with visual feedback
- 📂 **Categories** — organize passwords by Work, Personal, Finance, Social, and more
- 📈 **Vault Statistics** — overview of total passwords, weak passwords, and average strength
- 💾 **Encrypted Export** — backup your vault to a JSON file with a file picker
- 🌓 **Dark / Light Theme** — toggle between dark (darkly) and light (flatly) themes
- ⏱️ **Auto-Lock** — vault automatically locks after 5 minutes of inactivity
- 🔁 **Session Security** — master password cleared from memory on every lock/logout
- 🚫 **Persistent Lockout** — failed login attempts persist across restarts

---

## 🗂️ Project Structure

```
SecureVault-Pro/
│
├── gui.py                  # Main UI — all screens and dashboard logic
├── encrypt.py              # Cryptographic core (AES-256-GCM, Argon2id, HKDF)
├── password_generator.py   # Secure password and passphrase generation
├── requirements.txt        # Python dependencies
├── README.md               # This file
├── .gitignore              # Excludes data/ and cache files
│
└── data/                   # Auto-created on first run (git-ignored)
    ├── vault.txt           # Encrypted vault entries (JSONL format)
    ├── master.key          # Argon2id hash of master password
    ├── recovery.key        # PBKDF2 hash of recovery key
    ├── vault.salt          # 32-byte vault salt for AES key derivation
    ├── lockout.json        # Persistent failed-attempt counter
    └── theme.pref          # Saved theme preference
```

> ⚠️ The `data/` folder is excluded from git via `.gitignore`. It contains your encrypted vault and should **never** be committed.

---

## ⚙️ Installation

### Prerequisites
- Python **3.10** or higher
- pip

### 1. Clone the repository
```bash
git clone https://github.com/Majid-Scripts/SecureVault-Pro.git
cd SecureVault-Pro
```

### 2. (Optional but recommended) Create a virtual environment
```bash
python -m venv venv

# Windows
venv\Scripts\activate

# Linux / macOS
source venv/bin/activate
```

### 3. Install dependencies
```bash
pip install -r requirements.txt
```

Or manually:
```bash
pip install cryptography argon2-cffi ttkbootstrap requests
```

### 4. Run the app
```bash
python gui.py
```

---

## 🚀 First-Time Setup

1. On first launch you will be prompted to **create a master password**
   - Minimum 8 characters
   - Use uppercase, lowercase, numbers, and symbols for best strength
2. A **recovery key** (8 random words) will be generated — **write it down and store it safely**
   - This is the only way to recover your vault if you forget your master password
   - It will not be shown again
3. You are now inside your vault — start adding passwords!

---

## 🔐 Security Design

| Layer | Implementation |
|---|---|
| Master password storage | Argon2id (time=3, mem=64MB, p=2) with PBKDF2-SHA256 fallback |
| Vault encryption | AES-256-GCM with random 96-bit nonce per entry |
| Key derivation | HKDF-SHA256 from session password + per-vault 32-byte salt |
| Recovery key storage | PBKDF2-HMAC-SHA256 (100,000 iterations) with random salt |
| Breach check | k-anonymity via HaveIBeenPwned API (only first 5 SHA1 chars sent) |
| Session password | In-memory only, wiped on lock/logout via `clear_session_password()` |
| Clipboard | Auto-cleared 15 seconds after copying a password |
| Vault writes | Atomic (write to temp file → `os.replace()`) — crash-safe |
| Notes | Encrypted with the same AES-256-GCM as passwords |
| Lockout | Persists across restarts (stored in `lockout.json`) |
| Auto-lock | Triggers after 5 minutes of inactivity |

---

## 📦 Dependencies

| Package | Version | Purpose |
|---|---|---|
| `cryptography` | ≥ 41.0 | AES-256-GCM encryption, HKDF key derivation |
| `argon2-cffi` | ≥ 21.0 | Argon2id master password hashing |
| `ttkbootstrap` | ≥ 1.10 | Themed Tkinter widgets (UI framework) |
| `requests` | ≥ 2.28 | HaveIBeenPwned breach check API |

All other imports (`tkinter`, `hashlib`, `secrets`, `json`, `os`, `re`, `time`, `tempfile`, `shutil`) are part of the Python standard library.

---

## 🖥️ Usage Guide

### Adding a Password
1. Click **Vault** in the sidebar
2. Click **+ Add New**
3. Fill in Website, Username, Password (required), Category, and Notes
4. Click **Check Breach Status** to verify against known breaches
5. Click **SAVE PASSWORD**

### Copying a Password
1. Select an entry in the vault list
2. Click **Copy** — the password is copied to clipboard
3. It auto-clears from clipboard after **15 seconds**

### Revealing a Password
1. Select an entry and click **Reveal**
2. The password displays for **10 seconds** then re-hides automatically

### Changing Master Password
1. Click **Change Master** in the sidebar
2. Enter your old password and new password
3. All vault entries are automatically re-encrypted with the new key

### Exporting Your Vault
1. Click **Export** in the sidebar
2. Enter your master password to confirm
3. Choose a save location — exports as an encrypted JSON backup

---

## ⚠️ Important Notes

- **Never share your `data/` folder** — it contains your encrypted vault
- **Never commit `data/` to git** — the `.gitignore` prevents this by default
- **Your master password is not recoverable** without the recovery key — store it safely
- The app is **fully offline** — the only network request is the optional HaveIBeenPwned breach check
- Exporting the vault produces **encrypted** JSON — the master password is still required to decrypt it

---

## 🛠️ Built With

- [Python](https://python.org) — core language
- [Tkinter](https://docs.python.org/3/library/tkinter.html) — GUI framework
- [ttkbootstrap](https://ttkbootstrap.readthedocs.io) — modern themed widgets
- [cryptography](https://cryptography.io) — AES-256-GCM and HKDF
- [argon2-cffi](https://argon2-cffi.readthedocs.io) — Argon2id password hashing
- [HaveIBeenPwned API](https://haveibeenpwned.com/API/v3) — breach detection

---

## 👨‍💻 Author

**Abdul Majid**
- 🎓 Cyber Security Student — HITEC University
- 🗓️ Batch 2024
- 🐙 GitHub: [Majid-Scripts](https://github.com/Majid-Scripts)

---

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
