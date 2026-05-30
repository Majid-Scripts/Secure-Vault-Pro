import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import ttkbootstrap as ttkb
from ttkbootstrap.constants import *
import os
import re
import json
import time
import hashlib
import requests
import secrets
import tempfile
from datetime import datetime

from encrypt import (
    encrypt_message, decrypt_message,
    hash_master_password, verify_master_password,
    set_session_password, rotate_vault_salt,
    clear_session_password
)
from password_generator import generate_password

# ================= THEME CONSTANTS =================
THEME = "darkly"
ALT_THEME = "flatly"

# ================= FILES =================
import sys

def get_base_dir():
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))

BASE_DIR = get_base_dir()
DATA_DIR = os.path.join(BASE_DIR, "data")
os.makedirs(DATA_DIR, exist_ok=True)

VAULT_FILE    = os.path.join(DATA_DIR, "vault.txt")
MASTER_FILE   = os.path.join(DATA_DIR, "master.key")
RECOVERY_FILE = os.path.join(DATA_DIR, "recovery.key")
THEME_FILE    = os.path.join(DATA_DIR, "theme.pref")
LOCKOUT_FILE  = os.path.join(DATA_DIR, "lockout.json")

# ================= LOGIN SECURITY =================
MAX_ATTEMPTS   = 5
LOCKOUT_TIME   = 300
IDLE_TIMEOUT   = 300

# ──────────────────────────────────────────────────
# Persistent lockout state
# ──────────────────────────────────────────────────
def _load_lockout():
    if os.path.exists(LOCKOUT_FILE):
        try:
            with open(LOCKOUT_FILE) as f:
                d = json.load(f)
            return d.get("attempts", 0), d.get("until", 0)
        except Exception:
            pass
    return 0, 0

def _save_lockout(attempts, until):
    with open(LOCKOUT_FILE, "w") as f:
        json.dump({"attempts": attempts, "until": until}, f)
    try:
        os.chmod(LOCKOUT_FILE, 0o600)
    except Exception:
        pass

_failed_attempts, _lockout_until = _load_lockout()

# ──────────────────────────────────────────────────
# Idle-lock state
# ──────────────────────────────────────────────────
_idle_job        = None
_lock_callback   = None
_idle_bound      = False

def reset_idle_timer(root):
    global _idle_job
    if _idle_job is not None:
        root.after_cancel(_idle_job)
    if _lock_callback is not None:
        _idle_job = root.after(IDLE_TIMEOUT * 1000, _fire_idle_lock)

def _fire_idle_lock():
    if _lock_callback is not None:
        _lock_callback()

def bind_idle_reset(root):
    global _idle_bound
    if _idle_bound:
        return
    _idle_bound = True
    for event in ("<Motion>", "<KeyPress>", "<ButtonPress>"):
        root.bind(event, lambda e: reset_idle_timer(root), add="+")


# ================= THEME =================
def save_theme(theme_name):
    with open(THEME_FILE, "w") as f:
        f.write(theme_name)

def load_theme():
    if os.path.exists(THEME_FILE):
        with open(THEME_FILE) as f:
            return f.read().strip()
    return THEME

# ================= MASTER PASSWORD =================
def get_master():
    if os.path.exists(MASTER_FILE):
        with open(MASTER_FILE) as f:
            return f.read().strip()
    return None

def save_master(p):
    hashed = hash_master_password(p)
    with open(MASTER_FILE, "w") as f:
        f.write(hashed)
    try:
        os.chmod(MASTER_FILE, 0o600)
    except Exception:
        pass

# ================= RECOVERY KEY =================
def generate_recovery_key():
    words = [
        "alpha","bravo","charlie","delta","echo","foxtrot",
        "golf","hotel","india","juliet","kilo","lima",
        "mike","november","oscar","papa","quebec","romeo",
        "sierra","tango","uniform","victor","whiskey","xray",
        "yankee","zulu","apple","banana","cherry","dragon"
    ]
    return "-".join(secrets.choice(words) for _ in range(8))

def hash_recovery_key(key):
    salt = secrets.token_bytes(16)
    h    = hashlib.pbkdf2_hmac('sha256', key.encode(), salt, 100_000)
    return f"{salt.hex()}:{h.hex()}"

def verify_recovery_key(key, stored):
    try:
        salt_hex, hash_hex = stored.strip().split(":")
        salt          = bytes.fromhex(salt_hex)
        expected_hash = bytes.fromhex(hash_hex)
        test_hash     = hashlib.pbkdf2_hmac('sha256', key.encode(), salt, 100_000)
        return secrets.compare_digest(test_hash, expected_hash)
    except Exception:
        return False

def save_recovery_key(key):
    with open(RECOVERY_FILE, "w") as f:
        f.write(hash_recovery_key(key))
    try:
        os.chmod(RECOVERY_FILE, 0o600)
    except Exception:
        pass

def get_recovery():
    if os.path.exists(RECOVERY_FILE):
        with open(RECOVERY_FILE) as f:
            return f.read().strip()
    return None

# ================= PASSWORD STRENGTH =================
def check_strength(p):
    if not p:
        return 0
    s = 0
    if len(p) >= 8:  s += 1
    if len(p) >= 12: s += 1
    if re.search(r"[A-Z]", p): s += 1
    if re.search(r"[a-z]", p): s += 1
    if re.search(r"[0-9]", p): s += 1
    if re.search(r"[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]", p): s += 1
    return min(s, 6)

# ================= BREACH CHECK =================
def check_breach(password):
    try:
        sha1   = hashlib.sha1(password.encode()).hexdigest().upper()
        prefix, suffix = sha1[:5], sha1[5:]
        r      = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}", timeout=5)
        for line in r.text.splitlines():
            h, count = line.split(":")
            if h == suffix:
                return int(count)
        return 0
    except Exception:
        return -1

# ──────────────────────────────────────────────────
# Atomic vault write helper
# ──────────────────────────────────────────────────
def atomic_write_vault(entries_dicts):
    fd, tmp_path = tempfile.mkstemp(dir=DATA_DIR, suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            for d in entries_dicts:
                f.write(json.dumps(d) + "\n")
        os.replace(tmp_path, VAULT_FILE)
    except Exception:
        try:
            os.unlink(tmp_path)
        except Exception:
            pass
        raise

# ================= GLOBAL ROOT & CONTAINER =================
_root = None
_container = None

def _clear_container():
    global _container
    if _container is not None:
        for w in _container.winfo_children():
            w.destroy()

def _set_geometry(w, h, resizable=False):
    global _root
    if _root is None:
        return
    _root.geometry(f"{w}x{h}")
    _root.resizable(resizable, resizable)
    _root.update_idletasks()

# ================= START =================
def start_app():
    global _root, _container
    current_theme = load_theme()
    _root = ttkb.Window(themename=current_theme)
    _root.title("SecureVault Pro")
    _root.geometry("520x320")
    _root.resizable(False, False)

    _container = ttkb.Frame(_root)
    _container.pack(fill=BOTH, expand=True)

    if not get_master():
        create_master()
    else:
        login()
    _root.mainloop()

# ================= CREATE MASTER =================
def create_master():
    global _root
    _clear_container()
    _set_geometry(560, 640, False)

    card = ttkb.Frame(_container, padding=30)
    card.pack(expand=True, fill=BOTH)

    ttkb.Label(card, text="SECUREVAULT PRO", font=("Segoe UI", 11, "bold"), bootstyle="info").pack()
    ttkb.Label(card, text="Create Master Password", font=("Segoe UI", 22, "bold")).pack(pady=(4, 6))
    ttkb.Label(card, text="This is the only password you'll need to remember.",
               font=("Segoe UI", 9), wraplength=480, bootstyle="secondary").pack(pady=(0, 20))

    form = ttkb.Frame(card)
    form.pack(fill=X)

    ttkb.Label(form, text="Master Password", font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(0, 4))
    pwd_frame = ttkb.Frame(form)
    pwd_frame.pack(fill=X, pady=(0, 14))
    pwd = ttkb.Entry(pwd_frame, show="*", font=("Segoe UI", 11), bootstyle="primary")
    pwd.pack(side=LEFT, fill=X, expand=True)

    def toggle_pwd():
        pwd.config(show="" if pwd.cget("show") == "*" else "*")
    ttkb.Button(pwd_frame, text="Show", width=6, command=toggle_pwd, bootstyle="secondary").pack(side=LEFT, padx=(6, 0))

    ttkb.Label(form, text="Confirm Password", font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(0, 4))
    conf_frame = ttkb.Frame(form)
    conf_frame.pack(fill=X, pady=(0, 10))
    conf = ttkb.Entry(conf_frame, show="*", font=("Segoe UI", 11), bootstyle="primary")
    conf.pack(side=LEFT, fill=X, expand=True)

    def toggle_conf():
        conf.config(show="" if conf.cget("show") == "*" else "*")
    ttkb.Button(conf_frame, text="Show", width=6, command=toggle_conf, bootstyle="secondary").pack(side=LEFT, padx=(6, 0))

    meter_frame = ttkb.Frame(form)
    meter_frame.pack(fill=X, pady=(6, 6))
    strength_bar = ttkb.Progressbar(meter_frame, maximum=6, length=480, bootstyle="info")
    strength_bar.pack(fill=X)
    strength_lbl = ttkb.Label(meter_frame, text="Enter a password...", font=("Segoe UI", 9), bootstyle="secondary")
    strength_lbl.pack(anchor="e", pady=(4, 0))

    def update_meter(ev=None):
        s = check_strength(pwd.get())
        strength_bar["value"] = s
        if s <= 2:
            strength_bar.configure(bootstyle="danger");  strength_lbl.configure(text=f"Weak ({s}/6)",   bootstyle="danger")
        elif s <= 4:
            strength_bar.configure(bootstyle="warning"); strength_lbl.configure(text=f"Medium ({s}/6)", bootstyle="warning")
        else:
            strength_bar.configure(bootstyle="success"); strength_lbl.configure(text=f"Strong ({s}/6)", bootstyle="success")

    pwd.bind("<KeyRelease>", update_meter)

    ttkb.Separator(card, orient="horizontal").pack(fill=X, pady=14)
    ttkb.Label(card, text="Minimum 8 characters. Use uppercase, lowercase, numbers, and symbols for best security.",
               font=("Segoe UI", 9), wraplength=480, bootstyle="secondary").pack(anchor="w", pady=(0, 10))

    def save():
        p = pwd.get()
        if len(p) < 8:
            messagebox.showerror("Weak Password", "Minimum 8 characters required.")
            return
        if p != conf.get():
            messagebox.showerror("Mismatch", "Passwords do not match.")
            return
        recovery = generate_recovery_key()
        save_master(p)
        save_recovery_key(recovery)
        show_recovery(recovery, next_fn=login)

    ttkb.Button(card, text="Create Vault & Continue", command=save,
                bootstyle="success", padding=14).pack(fill=X, pady=(10, 0))


def show_recovery(recovery, next_fn=None):
    global _root
    dlg = tk.Toplevel(_root)
    dlg.title("Recovery Key Generated")
    dlg.geometry("580x460")
    dlg.resizable(False, False)
    dlg.transient(_root)
    dlg.grab_set()
    dlg.protocol("WM_DELETE_WINDOW", lambda: None)

    frame = ttkb.Frame(dlg, padding=25)
    frame.pack(fill=BOTH, expand=True)

    ttkb.Label(frame, text="Save This Recovery Key!", font=("Segoe UI", 18, "bold"), bootstyle="danger").pack(pady=(0, 8))
    ttkb.Label(frame, text="If you forget your master password, this is the ONLY way to recover your vault.",
               font=("Segoe UI", 9), wraplength=500, bootstyle="secondary").pack()

    key_frame = ttkb.Frame(frame, bootstyle="info", padding=12)
    key_frame.pack(fill=X, pady=14)
    ttkb.Label(key_frame, text=recovery, font=("Courier", 13, "bold"),
               bootstyle="inverse-info", wraplength=500).pack()

    def copy_key():
        _root.clipboard_clear()
        _root.clipboard_append(recovery)
        toast("Recovery key copied!")

    ttkb.Button(frame, text="Copy to Clipboard", command=copy_key, bootstyle="primary").pack(pady=4)
    ttkb.Label(frame, text="Write this down and store it safely. It will not be shown again.",
               font=("Segoe UI", 9), bootstyle="warning", wraplength=500).pack(pady=(8, 0))

    def proceed():
        dlg.destroy()
        if next_fn:
            next_fn()

    ttkb.Button(frame, text="I Have Saved It — Continue", command=proceed,
                bootstyle="success", padding=10).pack(fill=X, pady=(14, 0), side=BOTTOM)


# ================= LOGIN =================
def login():
    global _root, _lock_callback, _idle_job, _failed_attempts, _lockout_until
    _lock_callback = None
    if _idle_job is not None:
        _root.after_cancel(_idle_job)
        _idle_job = None

    clear_session_password()
    _clear_container()
    _set_geometry(520, 580, False)

    card = ttkb.Frame(_container, padding=30)
    card.pack(expand=True, fill=BOTH)

    ttkb.Label(card, text="SECUREVAULT PRO", font=("Segoe UI", 11, "bold"), bootstyle="info").pack()
    ttkb.Label(card, text="Welcome Back", font=("Segoe UI", 22, "bold")).pack(pady=(4, 6))
    ttkb.Label(card, text="Enter your master password to unlock your vault",
               font=("Segoe UI", 9), wraplength=440, bootstyle="secondary").pack(pady=(0, 20))

    _failed_attempts, _lockout_until = _load_lockout()
    if time.time() >= _lockout_until and _lockout_until > 0:
        _failed_attempts = 0
        _lockout_until = 0
        _save_lockout(0, 0)

    if time.time() < _lockout_until:
        mins = int((_lockout_until - time.time()) / 60) + 1
        banner = ttkb.Frame(card, bootstyle="danger", padding=10)
        banner.pack(fill=X, pady=(0, 15))
        ttkb.Label(banner, text=f"Locked due to failed attempts. Try again in {mins} min.",
                   font=("Segoe UI", 9, "bold"), bootstyle="inverse-danger").pack()
    else:
        ttkb.Frame(card, height=10).pack()

    ttkb.Label(card, text="Master Password", font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(0, 4))
    pwd_frame = ttkb.Frame(card)
    pwd_frame.pack(fill=X, pady=(0, 20))
    e = ttkb.Entry(pwd_frame, show="*", font=("Segoe UI", 11), bootstyle="primary")
    e.pack(side=LEFT, fill=X, expand=True)

    def toggle_login():
        e.config(show="" if e.cget("show") == "*" else "*")
    ttkb.Button(pwd_frame, text="Show", width=6, command=toggle_login, bootstyle="secondary").pack(side=LEFT, padx=(6, 0))
    e.focus()

    def check(event=None):
        global _failed_attempts, _lockout_until

        _failed_attempts, _lockout_until = _load_lockout()
        if time.time() >= _lockout_until and _lockout_until > 0:
            _failed_attempts = 0
            _lockout_until = 0
            _save_lockout(0, 0)

        if time.time() < _lockout_until:
            mins = int((_lockout_until - time.time()) / 60) + 1
            messagebox.showerror("Locked", f"Too many failed attempts. Wait {mins} minutes.")
            return

        stored = get_master()
        pwd    = e.get()

        if stored and verify_master_password(pwd, stored):
            _failed_attempts = 0
            _save_lockout(0, 0)
            set_session_password(pwd)
            dashboard(pwd)
        else:
            _failed_attempts += 1
            remaining = MAX_ATTEMPTS - _failed_attempts

            if _failed_attempts >= MAX_ATTEMPTS:
                _lockout_until = time.time() + LOCKOUT_TIME
                _save_lockout(_failed_attempts, _lockout_until)
                messagebox.showerror("Locked", "Too many failed attempts. Locked for 5 minutes.")
                _root.after(50, login)
            else:
                _save_lockout(_failed_attempts, _lockout_until)
                messagebox.showerror("Access Denied", f"Incorrect password. {remaining} attempts remaining.")
                e.delete(0, tk.END)

    ttkb.Button(card, text="Unlock Vault", command=check, bootstyle="primary", padding=14).pack(fill=X, pady=(0, 5))
    _root.bind("<Return>", check)

    ttkb.Separator(card, orient="horizontal").pack(fill=X, pady=20)
    ttkb.Label(card, text="Can't access your vault?", font=("Segoe UI", 10, "bold"), bootstyle="secondary").pack(anchor="w")
    ttkb.Label(card, text="If you forgot your master password, use your recovery key to regain access.",
               font=("Segoe UI", 9), wraplength=440, bootstyle="secondary").pack(anchor="w", pady=(2, 10))

    ttkb.Button(card, text="Use Recovery Key", command=recovery_login, bootstyle="warning outline").pack(fill=X)
    ttkb.Label(card, text="Without the recovery key, a forgotten password means permanent vault loss.",
               font=("Segoe UI", 8), wraplength=440, bootstyle="muted").pack(pady=(12, 0))


# ================= RECOVERY LOGIN =================
def recovery_login():
    global _root
    _clear_container()
    _set_geometry(520, 440, False)

    card = ttkb.Frame(_container, padding=30)
    card.pack(expand=True, fill=BOTH)

    ttkb.Label(card, text="SECUREVAULT PRO", font=("Segoe UI", 11, "bold"), bootstyle="info").pack()
    ttkb.Label(card, text="Recovery Key Login", font=("Segoe UI", 22, "bold"), bootstyle="warning").pack(pady=(4, 6))
    ttkb.Label(card, text="Enter your 8-word recovery key to reset your master password",
               font=("Segoe UI", 9), wraplength=440, bootstyle="secondary").pack(pady=(0, 20))

    ttkb.Label(card, text="Recovery Key", font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(0, 4))
    key_frame = ttkb.Frame(card)
    key_frame.pack(fill=X, pady=(0, 8))
    e = ttkb.Entry(key_frame, font=("Segoe UI", 11), show="*", bootstyle="primary")
    e.pack(side=LEFT, fill=X, expand=True)
    e.focus()

    def toggle_key():
        e.config(show="" if e.cget("show") == "*" else "*")
    ttkb.Button(key_frame, text="Show", width=6, command=toggle_key, bootstyle="secondary").pack(side=LEFT, padx=(6, 0))

    ttkb.Label(card, text="Format: 8 lowercase words separated by hyphens (e.g., alpha-bravo-charlie-...)",
               font=("Segoe UI", 9), wraplength=440, bootstyle="secondary").pack(anchor="w", pady=(0, 18))

    def check_recovery():
        stored  = get_recovery()
        raw_key = e.get().strip().lower()
        key     = re.sub(r"\s*-\s*", "-", raw_key)
        if stored and verify_recovery_key(key, stored):
            reset_with_recovery()
        else:
            messagebox.showerror("Invalid Key",
                "Recovery key does not match.\n\nMake sure you entered all 8 words with hyphens exactly as shown.")

    ttkb.Button(card, text="Verify & Reset Password", command=check_recovery, bootstyle="warning", padding=14).pack(fill=X, pady=(0, 10))
    ttkb.Button(card, text="Back to Login", command=login, bootstyle="secondary outline").pack(fill=X)


def reset_with_recovery():
    global _root
    _clear_container()
    _set_geometry(520, 560, False)

    card = ttkb.Frame(_container, padding=30)
    card.pack(expand=True, fill=BOTH)

    ttkb.Label(card, text="SECUREVAULT PRO", font=("Segoe UI", 11, "bold"), bootstyle="info").pack()
    ttkb.Label(card, text="Set New Master Password", font=("Segoe UI", 22, "bold"), bootstyle="success").pack(pady=(4, 6))
    ttkb.Label(card, text="Your vault will be re-encrypted with this new password.",
               font=("Segoe UI", 9), wraplength=440, bootstyle="secondary").pack(pady=(0, 20))

    ttkb.Label(card, text="New Password", font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(0, 4))
    new_frame = ttkb.Frame(card)
    new_frame.pack(fill=X, pady=(0, 12))
    new = ttkb.Entry(new_frame, show="*", font=("Segoe UI", 11), bootstyle="primary")
    new.pack(side=LEFT, fill=X, expand=True)
    ttkb.Button(new_frame, text="Show", width=6, command=lambda: new.config(show="" if new.cget("show") == "*" else "*"),
                bootstyle="secondary").pack(side=LEFT, padx=(6, 0))

    ttkb.Label(card, text="Confirm Password", font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(0, 4))
    conf_frame = ttkb.Frame(card)
    conf_frame.pack(fill=X, pady=(0, 15))
    conf = ttkb.Entry(conf_frame, show="*", font=("Segoe UI", 11), bootstyle="primary")
    conf.pack(side=LEFT, fill=X, expand=True)
    ttkb.Button(conf_frame, text="Show", width=6, command=lambda: conf.config(show="" if conf.cget("show") == "*" else "*"),
                bootstyle="secondary").pack(side=LEFT, padx=(6, 0))

    meter_frame = ttkb.Frame(card)
    meter_frame.pack(fill=X, pady=(0, 15))
    strength_bar = ttkb.Progressbar(meter_frame, maximum=6, length=440, bootstyle="info")
    strength_bar.pack(fill=X)
    strength_lbl = ttkb.Label(meter_frame, text="Enter a password...", font=("Segoe UI", 9), bootstyle="secondary")
    strength_lbl.pack(anchor="e", pady=(4, 0))

    def update_meter(ev=None):
        s = check_strength(new.get())
        strength_bar["value"] = s
        if s <= 2:
            strength_bar.configure(bootstyle="danger");  strength_lbl.configure(text=f"Weak ({s}/6)",   bootstyle="danger")
        elif s <= 4:
            strength_bar.configure(bootstyle="warning"); strength_lbl.configure(text=f"Medium ({s}/6)", bootstyle="warning")
        else:
            strength_bar.configure(bootstyle="success"); strength_lbl.configure(text=f"Strong ({s}/6)", bootstyle="success")

    new.bind("<KeyRelease>", update_meter)

    def save_new():
        p = new.get()
        if len(p) < 8:
            messagebox.showerror("Error", "Minimum 8 characters"); return
        if p != conf.get():
            messagebox.showerror("Error", "Passwords do not match"); return

        entries = []
        if os.path.exists(VAULT_FILE):
            with open(VAULT_FILE) as f:
                for line in f:
                    line = line.strip()
                    if not line: continue
                    try:
                        data = json.loads(line)
                        data["password"] = decrypt_message(data["password"])
                        if data.get("notes"):
                            try:
                                data["notes"] = decrypt_message(data["notes"])
                            except Exception:
                                pass
                        entries.append(data)
                    except Exception as ex:
                        messagebox.showerror("Error", f"Vault read failed: {ex}"); return

        save_master(p)
        rotate_vault_salt()
        set_session_password(p)

        now = datetime.now().strftime("%Y-%m-%d %H:%M")
        for d in entries:
            d["password"] = encrypt_message(d["password"])
            if d.get("notes"):
                d["notes"] = encrypt_message(d["notes"])
            d["modified"] = now

        atomic_write_vault(entries)

        messagebox.showinfo("Success", "Master password reset! All entries re-encrypted.")
        login()

    ttkb.Button(card, text="Reset Password", command=save_new, bootstyle="success", padding=14).pack(fill=X, pady=(5, 0))


# ================= DASHBOARD =================
def dashboard(session_password):
    global _root, _lock_callback, _idle_job

    _clear_container()
    _set_geometry(1200, 750, True)

    def do_idle_lock():
        try:
            _root.clipboard_clear()
        except Exception:
            pass
        toast("Session locked due to inactivity.")
        _root.after(1500, login)

    _lock_callback = do_idle_lock
    bind_idle_reset(_root)
    reset_idle_timer(_root)

    sidebar = ttkb.Frame(_container, width=220, bootstyle="secondary")
    sidebar.pack(side=LEFT, fill=Y)
    sidebar.pack_propagate(False)

    main = ttkb.Frame(_container, padding=15)
    main.pack(side=RIGHT, fill=BOTH, expand=True)

    ttkb.Label(sidebar, text="SecureVault", font=("Segoe UI", 14, "bold"), bootstyle="inverse-secondary").pack(pady=20)

    content = ttkb.Frame(main)
    content.pack(fill=BOTH, expand=True)

    def clear_content():
        for w in content.winfo_children():
            w.destroy()

    # ──────────────────────────────────────────────────
    # Re-authentication helper
    # ──────────────────────────────────────────────────
    def require_password(action_label, on_success):
        dlg = tk.Toplevel(_root)
        dlg.title("Confirm Identity")
        dlg.geometry("400x220")
        dlg.resizable(False, False)
        dlg.transient(_root)
        dlg.grab_set()

        frame = ttkb.Frame(dlg, padding=25)
        frame.pack(fill=BOTH, expand=True)

        ttkb.Label(frame, text=f"Confirm: {action_label}", font=("Segoe UI", 13, "bold")).pack(pady=(0, 12))
        ttkb.Label(frame, text="Enter your master password to continue:", font=("Segoe UI", 9)).pack(anchor="w")

        pf = ttkb.Frame(frame)
        pf.pack(fill=X, pady=6)
        pe = ttkb.Entry(pf, show="*", font=("Segoe UI", 11), bootstyle="primary")
        pe.pack(side=LEFT, fill=X, expand=True)
        ttkb.Button(pf, text="Show", width=6, command=lambda: pe.config(show="" if pe.cget("show") == "*" else "*"),
                    bootstyle="secondary").pack(side=LEFT, padx=(4, 0))
        pe.focus()

        def verify(event=None):
            stored = get_master()
            if stored and verify_master_password(pe.get(), stored):
                dlg.destroy()
                on_success()
            else:
                messagebox.showerror("Wrong Password", "Master password incorrect.", parent=dlg)
                pe.delete(0, tk.END)

        ttkb.Button(frame, text="Confirm", command=verify, bootstyle="warning", padding=10).pack(fill=X, pady=(8, 0))
        dlg.bind("<Return>", verify)

    # ================= VAULT =================
    def vault():
        clear_content()

        header = ttkb.Frame(content)
        header.pack(fill=X, pady=(0, 10))
        ttkb.Label(header, text="Password Vault", font=("Segoe UI", 20, "bold")).pack(side=LEFT)

        controls = ttkb.Frame(content)
        controls.pack(fill=X, pady=(0, 10))

        search_var = tk.StringVar()
        search = ttkb.Entry(controls, textvariable=search_var, font=("Segoe UI", 10), width=30)
        search.pack(side=LEFT, padx=(0, 10))
        search.insert(0, "Search...")

        def on_search_focus(event):
            if search.get() == "Search...":
                search.delete(0, tk.END)
        def on_search_blur(event):
            if search.get() == "":
                search.insert(0, "Search...")

        search.bind("<FocusIn>", on_search_focus)
        search.bind("<FocusOut>", on_search_blur)

        cat_var = tk.StringVar(value="All")
        cat_box = ttkb.Combobox(controls, textvariable=cat_var,
                                values=["All", "Work", "Personal", "Finance", "Social", "Other"],
                                width=12, state="readonly")
        cat_box.pack(side=LEFT, padx=5)

        ttkb.Button(controls, text="+ Add New", command=lambda: add_dialog(), bootstyle="success").pack(side=RIGHT)

        cols = ("Site", "Username", "Password", "Category", "Modified")
        tree = ttk.Treeview(content, columns=cols, show="headings", height=20)
        for c in cols:
            tree.heading(c, text=c)
        tree.column("Site",     width=250)
        tree.column("Username", width=200)
        tree.column("Password", width=200)
        tree.column("Category", width=100)
        tree.column("Modified", width=150)
        tree.pack(fill=BOTH, expand=True, pady=10)

        style = ttk.Style()
        style.configure("Treeview", font=("Segoe UI", 10), rowheight=25)
        style.configure("Treeview.Heading", font=("Segoe UI", 10, "bold"))

        revealed_items = set()

        actions = ttkb.Frame(content)
        actions.pack(fill=X, pady=5)

        def copy_pwd():
            sel = tree.selection()
            if not sel:
                return
            tags  = tree.item(sel[0])["tags"]
            actual = tags[0] if tags else "********"
            _root.clipboard_clear()
            _root.clipboard_append(actual)
            toast("Password copied! Clears in 15s")
            _root.after(15000, _root.clipboard_clear)

        def del_entry():
            sel = tree.selection()
            if not sel:
                return
            vals = tree.item(sel[0])["values"]
            if not vals:
                return
            site, username = vals[0], vals[1]
            if not messagebox.askyesno("Confirm", f"Delete password for {site}?"):
                return

            new_entries = []
            deleted = False
            if os.path.exists(VAULT_FILE):
                with open(VAULT_FILE) as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            data = json.loads(line)
                            if not deleted and data["site"] == site and data["username"] == username:
                                deleted = True
                                continue
                            new_entries.append(data)
                        except Exception:
                            continue
            atomic_write_vault(new_entries)
            load()

        def reveal_selected():
            sel = tree.selection()
            if not sel:
                return
            iid  = sel[0]
            item = tree.item(iid)
            vals = list(item["values"])
            tags = list(item["tags"])
            if not tags:
                return

            actual_pwd = tags[0]
            vals[2]    = actual_pwd
            tree.item(iid, values=tuple(vals))
            revealed_items.add(iid)

            def rehide():
                try:
                    current_vals    = list(tree.item(iid)["values"])
                    current_vals[2] = "********"
                    tree.item(iid, values=tuple(current_vals))
                    revealed_items.discard(iid)
                except Exception:
                    pass

            _root.after(10_000, rehide)

        ttkb.Button(actions, text="Copy",   command=copy_pwd,        bootstyle="primary outline").pack(side=LEFT, padx=2)
        ttkb.Button(actions, text="Delete", command=del_entry,        bootstyle="danger outline").pack(side=LEFT, padx=2)
        ttkb.Button(actions, text="Reveal", command=reveal_selected,  bootstyle="warning outline").pack(side=LEFT, padx=2)

        load_errors = []

        def load():
            for item in tree.get_children():
                tree.delete(item)
            revealed_items.clear()
            load_errors.clear()

            term       = search_var.get().lower().strip()
            if term == "search...":
                term = ""
            cat_filter = cat_var.get()

            count = 0
            if os.path.exists(VAULT_FILE):
                with open(VAULT_FILE) as f:
                    for lineno, line in enumerate(f, 1):
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            data = json.loads(line)
                            dec  = decrypt_message(data["password"])
                            entry_cat = data.get("category", "Other")
                            mod  = data.get("modified", "Unknown")

                            if cat_filter != "All" and entry_cat != cat_filter:
                                continue
                            if term and term not in data["site"].lower() and term not in data["username"].lower():
                                continue

                            s = check_strength(dec)
                            tag = "weak" if s <= 2 else ("medium" if s <= 4 else "strong")

                            tree.insert("", tk.END,
                                        values=(data["site"], data["username"], "********", entry_cat, mod),
                                        tags=(dec, tag))
                            count += 1
                        except Exception as e:
                            load_errors.append(f"Line {lineno}: {e}")

            tree.tag_configure("weak",   foreground="#ef4444")
            tree.tag_configure("medium", foreground="#f59e0b")
            tree.tag_configure("strong", foreground="#22c55e")

            if load_errors:
                err_msg = "\n".join(load_errors[:5])
                if len(load_errors) > 5:
                    err_msg += f"\n... and {len(load_errors)-5} more."
                toast(f"{len(load_errors)} entry/entries failed to load — vault may be partially corrupt.")
                print(f"Load errors:\n{err_msg}")

        # ================= ADD DIALOG (FIXED - SCROLLABLE) =================
        def add_dialog():
            dlg = tk.Toplevel(_root)
            dlg.title("Add Password")
            dlg.geometry("560x640")
            dlg.resizable(False, False)
            dlg.transient(_root)
            dlg.grab_set()

            # Scrollable canvas wrapper
            canvas = tk.Canvas(dlg, highlightthickness=0)
            scrollbar = ttk.Scrollbar(dlg, orient="vertical", command=canvas.yview)
            scroll_frame = ttkb.Frame(canvas, padding=25)

            scroll_frame.bind(
                "<Configure>",
                lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
            )

            canvas.create_window((0, 0), window=scroll_frame, anchor="nw", width=540)
            canvas.configure(yscrollcommand=scrollbar.set)

            scrollbar.pack(side=RIGHT, fill=Y)
            canvas.pack(side=LEFT, fill=BOTH, expand=True)

            # Mouse wheel scrolling
            def on_mousewheel(event):
                canvas.yview_scroll(int(-1*(event.delta/120)), "units")
            canvas.bind_all("<MouseWheel>", on_mousewheel)

            # Cleanup binding on close
            def on_close():
                canvas.unbind_all("<MouseWheel>")
                dlg.destroy()
            dlg.protocol("WM_DELETE_WINDOW", on_close)

            form = scroll_frame

            ttkb.Label(form, text="Add New Password", font=("Segoe UI", 18, "bold")).pack(pady=(0, 18))

            ttkb.Label(form, text="Website *", font=("Segoe UI", 10, "bold")).pack(anchor="w")
            site = ttkb.Entry(form, font=("Segoe UI", 11), bootstyle="primary")
            site.pack(fill=X, pady=(0, 10))

            ttkb.Label(form, text="Username *", font=("Segoe UI", 10, "bold")).pack(anchor="w")
            user = ttkb.Entry(form, font=("Segoe UI", 11), bootstyle="primary")
            user.pack(fill=X, pady=(0, 10))

            ttkb.Label(form, text="Password *", font=("Segoe UI", 10, "bold")).pack(anchor="w")
            pwd_frame = ttkb.Frame(form)
            pwd_frame.pack(fill=X, pady=(0, 8))
            pwd = ttkb.Entry(pwd_frame, font=("Segoe UI", 11), show="*", bootstyle="primary")
            pwd.pack(side=LEFT, fill=X, expand=True)
            ttkb.Button(pwd_frame, text="Show", width=6,
                        command=lambda: pwd.config(show="" if pwd.cget("show") == "*" else "*"),
                        bootstyle="secondary").pack(side=LEFT, padx=(6, 0))

            breach_lbl = ttkb.Label(form, text="", font=("Segoe UI", 9))
            breach_lbl.pack(anchor="w", pady=(0, 5))

            def check_pwd_breach():
                p = pwd.get()
                if len(p) < 6:
                    breach_lbl.config(text="Enter password to check breaches", bootstyle="secondary"); return
                breach_lbl.config(text="Checking...", bootstyle="info")
                _root.update()
                count = check_breach(p)
                if count > 0:
                    breach_lbl.config(text=f"Found in {count:,} breaches! Change immediately!", bootstyle="danger")
                elif count == 0:
                    breach_lbl.config(text="Not found in any known breaches", bootstyle="success")
                else:
                    breach_lbl.config(text="Could not check breaches (offline)", bootstyle="warning")

            ttkb.Button(form, text="Check Breach Status", command=check_pwd_breach, bootstyle="info outline").pack(fill=X, pady=(0, 10))

            ttkb.Label(form, text="Category", font=("Segoe UI", 10, "bold")).pack(anchor="w")
            cat_box = ttkb.Combobox(form, values=["Work","Personal","Finance","Social","Other"],
                                    state="readonly", font=("Segoe UI", 10))
            cat_box.set("Personal")
            cat_box.pack(fill=X, pady=(0, 10))

            ttkb.Label(form, text="Notes (encrypted)", font=("Segoe UI", 10, "bold")).pack(anchor="w")
            notes = ttkb.Entry(form, font=("Segoe UI", 11), show="*", bootstyle="primary")
            notes.pack(fill=X, pady=(0, 5))
            ttkb.Button(form, text="Show Notes", width=14,
                        command=lambda: notes.config(show="" if notes.cget("show") == "*" else "*"),
                        bootstyle="secondary").pack(anchor="w", pady=(0, 10))

            def save():
                s = site.get().strip()
                u = user.get().strip()
                p = pwd.get()
                if not all([s, u, p]):
                    messagebox.showerror("Error", "Website, Username and Password are required.", parent=dlg); return

                if os.path.exists(VAULT_FILE):
                    with open(VAULT_FILE) as f:
                        for line in f:
                            line = line.strip()
                            if not line:
                                continue
                            try:
                                data = json.loads(line)
                                if data["site"] == s and data["username"] == u:
                                    if not messagebox.askyesno(
                                            "Duplicate Entry",
                                            f"An entry for {s} / {u} already exists.\nAdd anyway?",
                                            parent=dlg):
                                        return
                                    break
                            except Exception:
                                continue

                try:
                    n_plain = notes.get()
                    entry = {
                        "site":     s,
                        "username": u,
                        "password": encrypt_message(p),
                        "category": cat_box.get(),
                        "notes":    encrypt_message(n_plain) if n_plain else "",
                        "modified": datetime.now().strftime("%Y-%m-%d %H:%M")
                    }
                    with open(VAULT_FILE, "a") as file:
                        file.write(json.dumps(entry) + "\n")
                        file.flush()
                        os.fsync(file.fileno())

                    dlg.destroy()
                    _root.after(200, load)
                    toast("Password saved successfully!")
                except Exception as e:
                    messagebox.showerror("Save Error", f"Failed to save: {e}", parent=dlg)

            ttkb.Button(form, text="SAVE PASSWORD", command=save, bootstyle="success", padding=14).pack(fill=X, pady=(10, 0))
            ttkb.Label(form, text="Fill all required fields and click Save", font=("Segoe UI", 8), bootstyle="muted").pack(pady=(8, 0))

        search.bind("<KeyRelease>", lambda e: load())
        cat_box.bind("<<ComboboxSelected>>", lambda e: load())
        load()

    # ================= GENERATOR =================
    def generator():
        clear_content()
        ttkb.Label(content, text="Password Generator", font=("Segoe UI", 20, "bold")).pack(pady=10)

        frame = ttkb.Frame(content)
        frame.pack(pady=20)

        ttkb.Label(frame, text="Length", font=("Segoe UI", 11)).pack()
        length = ttkb.Scale(frame, from_=12, to=32, orient=HORIZONTAL, length=300)
        length.set(16)
        length.pack(pady=5)

        val_label = ttkb.Label(frame, text="16", font=("Segoe UI", 12, "bold"))
        val_label.pack()
        length.bind("<Motion>", lambda e: val_label.config(text=int(length.get())))

        result = ttkb.Entry(content, font=("Segoe UI", 14, "bold"), justify="center", width=40)
        result.pack(pady=20)

        breach_lbl = ttkb.Label(content, text="", font=("Segoe UI", 10))
        breach_lbl.pack(pady=5)

        def gen():
            result.delete(0, tk.END)
            pwd = generate_password(length=int(length.get()))
            result.insert(0, pwd)
            breach_lbl.config(text="Generated password is unique and secure", bootstyle="success")

        def copy_gen():
            if result.get():
                _root.clipboard_clear()
                _root.clipboard_append(result.get())
                toast("Generated password copied!")
                _root.after(15000, _root.clipboard_clear)

        btn_frame = ttkb.Frame(content)
        btn_frame.pack()
        ttkb.Button(btn_frame, text="Generate", command=gen, bootstyle="primary", width=15).pack(side=LEFT, padx=5)
        ttkb.Button(btn_frame, text="Copy",     command=copy_gen, bootstyle="success outline", width=15).pack(side=LEFT, padx=5)

    # ================= STRENGTH =================
    def strength():
        clear_content()
        ttkb.Label(content, text="Password Strength Analyzer", font=("Segoe UI", 20, "bold")).pack(pady=10)

        frame = ttkb.Frame(content, padding=20)
        frame.pack(pady=20)

        e = ttkb.Entry(frame, font=("Segoe UI", 12), width=40, show="*")
        e.pack(pady=10)

        meter_frame = ttkb.Frame(frame)
        meter_frame.pack(pady=10)
        
        meter_bar = ttkb.Progressbar(meter_frame, maximum=6, length=200, bootstyle="info", orient=HORIZONTAL)
        meter_bar.pack()
        
        meter_lbl = ttkb.Label(meter_frame, text="0 / 6", font=("Segoe UI", 16, "bold"))
        meter_lbl.pack(pady=5)

        feedback     = ttkb.Label(frame, text="Enter a password to analyze", font=("Segoe UI", 11))
        feedback.pack(pady=5)
        breach_result = ttkb.Label(frame, text="", font=("Segoe UI", 10))
        breach_result.pack(pady=5)

        ttkb.Button(frame, text="Show / Hide",
                    command=lambda: e.config(show="" if e.cget("show") == "*" else "*"),
                    bootstyle="secondary outline").pack(pady=5)

        def analyze(event=None):
            p = e.get()
            s = check_strength(p)
            meter_bar["value"] = s
            meter_lbl.config(text=f"{s} / 6")

            count = check_breach(p)
            if count > 0:
                breach_result.config(text=f"Found in {count:,} breaches!", bootstyle="danger")
            elif count == 0:
                breach_result.config(text="Not found in breaches", bootstyle="success")
            else:
                breach_result.config(text="Offline — breach check unavailable", bootstyle="warning")

            if s <= 2:
                meter_bar.configure(bootstyle="danger");  feedback.config(text="Weak — easily cracked",             bootstyle="danger")
            elif s <= 4:
                meter_bar.configure(bootstyle="warning"); feedback.config(text="Medium — acceptable but improvable", bootstyle="warning")
            else:
                meter_bar.configure(bootstyle="success"); feedback.config(text="Strong — excellent password",        bootstyle="success")

        e.bind("<KeyRelease>", analyze)

    # ================= STATS =================
    def stats():
        clear_content()
        ttkb.Label(content, text="Vault Statistics", font=("Segoe UI", 20, "bold")).pack(pady=10)

        total      = 0
        categories = {}
        strengths  = {0: 0, 1: 0, 2: 0, 3: 0, 4: 0, 5: 0, 6: 0}
        weak_count = 0

        if os.path.exists(VAULT_FILE):
            with open(VAULT_FILE) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                        total += 1
                        cat   = data.get("category", "Other")
                        categories[cat] = categories.get(cat, 0) + 1
                        dec = decrypt_message(data["password"])
                        s   = check_strength(dec)
                        strengths[s] = strengths.get(s, 0) + 1
                        if s <= 2:
                            weak_count += 1
                    except Exception:
                        continue

        cards = ttkb.Frame(content)
        cards.pack(fill=X, pady=20)

        card1 = ttkb.Frame(cards, bootstyle="info", padding=15)
        card1.pack(side=LEFT, expand=True, fill=BOTH, padx=5)
        ttkb.Label(card1, text=str(total), font=("Segoe UI", 28, "bold"), bootstyle="inverse-info").pack()
        ttkb.Label(card1, text="Total Passwords", font=("Segoe UI", 10), bootstyle="inverse-info").pack()

        style2 = "danger" if weak_count > 0 else "success"
        card2  = ttkb.Frame(cards, bootstyle=style2, padding=15)
        card2.pack(side=LEFT, expand=True, fill=BOTH, padx=5)
        ttkb.Label(card2, text=str(weak_count), font=("Segoe UI", 28, "bold"), bootstyle=f"inverse-{style2}").pack()
        ttkb.Label(card2, text="Weak Passwords", font=("Segoe UI", 10), bootstyle=f"inverse-{style2}").pack()

        avg   = sum(k*v for k,v in strengths.items()) / total if total > 0 else 0
        card3 = ttkb.Frame(cards, bootstyle="primary", padding=15)
        card3.pack(side=LEFT, expand=True, fill=BOTH, padx=5)
        ttkb.Label(card3, text=f"{avg:.1f}/6", font=("Segoe UI", 28, "bold"), bootstyle="inverse-primary").pack()
        ttkb.Label(card3, text="Avg Strength", font=("Segoe UI", 10), bootstyle="inverse-primary").pack()

        if categories:
            ttkb.Label(content, text="By Category", font=("Segoe UI", 14, "bold")).pack(anchor="w", pady=(20, 10))
            cat_frame = ttkb.Frame(content)
            cat_frame.pack(fill=X)
            for cat, count in sorted(categories.items()):
                row = ttkb.Frame(cat_frame)
                row.pack(fill=X, pady=2)
                ttkb.Label(row, text=cat, font=("Segoe UI", 11), width=15).pack(side=LEFT)
                ttkb.Progressbar(row, maximum=total, value=count, length=300, bootstyle="info").pack(side=LEFT, padx=10)
                ttkb.Label(row, text=str(count), font=("Segoe UI", 11)).pack(side=LEFT)

    # ================= EXPORT =================
    def export_vault():
        def do_export():
            clear_content()
            ttkb.Label(content, text="Export Vault", font=("Segoe UI", 20, "bold")).pack(pady=10)

            frame = ttkb.Frame(content, padding=20)
            frame.pack(pady=20)

            ttkb.Label(frame, text="Export your encrypted vault to a JSON backup file.", font=("Segoe UI", 10)).pack(pady=5)
            ttkb.Label(frame,
                       text="Note: Exported file contains encrypted passwords only. Your master password is required to decrypt.",
                       font=("Segoe UI", 9), bootstyle="muted").pack(pady=5)

            def run_export():
                if not os.path.exists(VAULT_FILE):
                    messagebox.showerror("Error", "No vault data to export."); return
                entries = []
                with open(VAULT_FILE) as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            try: entries.append(json.loads(line))
                            except Exception: pass

                default_name = f"vault_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                path = filedialog.asksaveasfilename(
                    defaultextension=".json",
                    filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
                    initialfile=default_name,
                    title="Save Vault Backup"
                )
                if not path:
                    return

                with open(path, "w") as f:
                    json.dump(entries, f, indent=2)
                toast(f"Exported to {os.path.basename(path)}")

            ttkb.Button(frame, text="Choose Location & Export", command=run_export,
                        bootstyle="info", width=28).pack(pady=20)

        require_password("Export Vault", do_export)

    # ================= CHANGE MASTER =================
    def change_master():
        clear_content()

        container = ttkb.Frame(content)
        container.pack(expand=True)

        ttkb.Label(container, text="Change Master Password", font=("Segoe UI", 22, "bold")).pack(pady=(0, 25))

        form = ttkb.Frame(container, padding=10)
        form.pack()

        ttkb.Label(form, text="Old Password", font=("Segoe UI", 10)).pack(anchor="w", pady=(10, 0))
        old_frame = ttkb.Frame(form)
        old_frame.pack(fill=X, pady=(0, 10))
        old = ttkb.Entry(old_frame, show="*", font=("Segoe UI", 11), width=32)
        old.pack(side=LEFT, fill=X, expand=True)
        ttkb.Button(old_frame, text="Show", width=6,
                    command=lambda: old.config(show="" if old.cget("show") == "*" else "*"),
                    bootstyle="secondary").pack(side=LEFT, padx=2)

        ttkb.Label(form, text="New Password", font=("Segoe UI", 10)).pack(anchor="w")
        new_frame = ttkb.Frame(form)
        new_frame.pack(fill=X, pady=(0, 10))
        new = ttkb.Entry(new_frame, show="*", font=("Segoe UI", 11), width=32)
        new.pack(side=LEFT, fill=X, expand=True)
        ttkb.Button(new_frame, text="Show", width=6,
                    command=lambda: new.config(show="" if new.cget("show") == "*" else "*"),
                    bootstyle="secondary").pack(side=LEFT, padx=2)

        ttkb.Label(form, text="Confirm New Password", font=("Segoe UI", 10)).pack(anchor="w")
        conf_frame = ttkb.Frame(form)
        conf_frame.pack(fill=X, pady=(0, 15))
        conf = ttkb.Entry(conf_frame, show="*", font=("Segoe UI", 11), width=32)
        conf.pack(side=LEFT, fill=X, expand=True)
        ttkb.Button(conf_frame, text="Show", width=6,
                    command=lambda: conf.config(show="" if conf.cget("show") == "*" else "*"),
                    bootstyle="secondary").pack(side=LEFT, padx=2)

        meter_frame  = ttkb.Frame(form)
        meter_frame.pack(fill=X, pady=(0, 15))
        strength_bar = ttkb.Progressbar(meter_frame, maximum=6, length=300, bootstyle="info")
        strength_bar.pack(fill=X)

        strength_lbl = ttkb.Label(meter_frame, text="Enter a password...", font=("Segoe UI", 9), bootstyle="secondary")
        strength_lbl.pack(anchor="e", pady=(3, 0))

        def update_meter(ev=None):
            s = check_strength(new.get())
            strength_bar["value"] = s
            if s <= 2:
                strength_bar.configure(bootstyle="danger");  strength_lbl.configure(text=f"Weak ({s}/6)",   bootstyle="danger")
            elif s <= 4:
                strength_bar.configure(bootstyle="warning"); strength_lbl.configure(text=f"Medium ({s}/6)", bootstyle="warning")
            else:
                strength_bar.configure(bootstyle="success"); strength_lbl.configure(text=f"Strong ({s}/6)", bootstyle="success")

        new.bind("<KeyRelease>", update_meter)

        def update():
            nonlocal session_password
            stored = get_master()
            if not verify_master_password(old.get(), stored):
                messagebox.showerror("Error", "Wrong old password"); return
            if new.get() != conf.get():
                messagebox.showerror("Error", "Passwords do not match"); return
            if len(new.get()) < 8:
                messagebox.showerror("Error", "Minimum 8 characters"); return

            entries = []
            if os.path.exists(VAULT_FILE):
                with open(VAULT_FILE) as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            data = json.loads(line)
                            data["password"] = decrypt_message(data["password"])
                            if data.get("notes"):
                                try:
                                    data["notes"] = decrypt_message(data["notes"])
                                except Exception:
                                    pass
                            entries.append(data)
                        except Exception as ex:
                            messagebox.showerror("Error", f"Vault read failed: {ex}"); return

            save_master(new.get())
            rotate_vault_salt()
            set_session_password(new.get())

            now = datetime.now().strftime("%Y-%m-%d %H:%M")
            for d in entries:
                d["password"] = encrypt_message(d["password"])
                if d.get("notes"):
                    d["notes"] = encrypt_message(d["notes"])
                d["modified"] = now

            atomic_write_vault(entries)
            session_password = new.get()
            messagebox.showinfo("Success", "Master password updated. All entries re-encrypted.")

        ttkb.Button(form, text="Update Master Password", command=update, bootstyle="warning", width=30).pack(pady=10)

    # ================= REGENERATE RECOVERY KEY =================
    def regenerate_recovery():
        clear_content()

        container = ttkb.Frame(content)
        container.pack(expand=True)

        ttkb.Label(container, text="Regenerate Recovery Key", font=("Segoe UI", 22, "bold"), bootstyle="warning").pack(pady=(0, 15))
        ttkb.Label(container,
                   text="Verify your master password to generate a new recovery key. Your old recovery key will become invalid.",
                   font=("Segoe UI", 9), wraplength=500, bootstyle="secondary").pack(pady=(0, 25))

        form = ttkb.Frame(container, padding=10)
        form.pack()

        ttkb.Label(form, text="Master Password", font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(0, 6))
        pwd_frame  = ttkb.Frame(form)
        pwd_frame.pack(fill=X, pady=(0, 20))
        verify_pwd = ttkb.Entry(pwd_frame, show="*", font=("Segoe UI", 11), bootstyle="primary")
        verify_pwd.pack(side=LEFT, fill=X, expand=True)
        ttkb.Button(pwd_frame, text="Show", width=6,
                    command=lambda: verify_pwd.config(show="" if verify_pwd.cget("show") == "*" else "*"),
                    bootstyle="secondary").pack(side=LEFT, padx=(6, 0))

        def do_regenerate():
            stored = get_master()
            if not verify_master_password(verify_pwd.get(), stored):
                messagebox.showerror("Error", "Incorrect master password"); return
            new_recovery = generate_recovery_key()
            save_recovery_key(new_recovery)
            show_recovery(new_recovery)

        ttkb.Button(form, text="Generate New Recovery Key", command=do_regenerate,
                    bootstyle="warning", padding=14).pack(fill=X, pady=(10, 0))

        ttkb.Label(container,
                   text="Warning: This will invalidate your old recovery key. Make sure to save the new one immediately.",
                   font=("Segoe UI", 9), bootstyle="danger", wraplength=500).pack(pady=(25, 0))

    # ================= THEME TOGGLE =================
    def toggle_theme():
        current   = _root.style.theme.name
        new_theme = ALT_THEME if current == THEME else THEME
        _root.style.theme_use(new_theme)
        save_theme(new_theme)
        toast(f"Switched to {'Light' if new_theme == 'flatly' else 'Dark'} theme")

    # ================= SIDEBAR NAV =================
    def nav(text, cmd):
        btn = ttkb.Button(sidebar, text=text, command=cmd, bootstyle="secondary-link", width=20)
        btn.pack(fill=X, pady=2, padx=10)

    nav("Vault",         vault)
    nav("Generator",     generator)
    nav("Strength",      strength)
    nav("Statistics",    stats)
    nav("Export",        export_vault)
    nav("Change Master", change_master)
    nav("Recovery Key",  regenerate_recovery)

    ttkb.Separator(sidebar, orient="horizontal").pack(fill=X, pady=15, padx=10)
    ttkb.Button(sidebar, text="Toggle Theme", command=toggle_theme, bootstyle="secondary-link", width=20).pack(fill=X, pady=2, padx=10)
    ttkb.Separator(sidebar, orient="horizontal").pack(fill=X, pady=15, padx=10)

    def lock_now():
        try:
            _root.clipboard_clear()
        except Exception:
            pass
        messagebox.showinfo("Locked", "Session locked.")
        login()

    ttkb.Button(sidebar, text="Lock Now", command=lock_now, bootstyle="danger outline").pack(fill=X, padx=10, pady=5)

    vault()


# ================= TOAST NOTIFICATION =================
def toast(msg):
    global _root
    tw = tk.Toplevel(_root)
    tw.overrideredirect(True)
    tw.attributes("-topmost", True)
    tw.configure(bg="#1e293b")
    lbl = tk.Label(tw, text=msg, bg="#1e293b", fg="white", font=("Segoe UI", 10), padx=15, pady=8)
    lbl.pack()
    tw.update_idletasks()
    x = _root.winfo_x() + _root.winfo_width()  - tw.winfo_width()  - 20
    y = _root.winfo_y() + _root.winfo_height() - tw.winfo_height() - 20
    tw.geometry(f"+{x}+{y}")
    tw.after(2500, tw.destroy)