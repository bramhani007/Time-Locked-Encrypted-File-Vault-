from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from functools import wraps
from io import BytesIO
from pathlib import Path
from zoneinfo import ZoneInfo

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import click

from flask import (
    Flask, abort, flash, g, redirect, render_template, request,
    send_file, session, url_for
)
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

from anomaly_detector import detect_anomalies

BASE_DIR = Path(__file__).resolve().parent
INSTANCE_DIR = BASE_DIR / "instance"
STORAGE_DIR = BASE_DIR / "storage"
DB_PATH = INSTANCE_DIR / "vault.sqlite3"
PRIVATE_KEY_PATH = INSTANCE_DIR / "rsa_private_key.pem"
PUBLIC_KEY_PATH = INSTANCE_DIR / "rsa_public_key.pem"

INSTANCE_DIR.mkdir(exist_ok=True)
STORAGE_DIR.mkdir(exist_ok=True)

MAX_UPLOAD_MB = max(1, int(os.environ.get("MAX_UPLOAD_MB", "100")))

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("FLASK_SECRET_KEY", "dev-only-change-this-before-deployment"),
    MAX_UPLOAD_MB=MAX_UPLOAD_MB,
    MAX_CONTENT_LENGTH=MAX_UPLOAD_MB * 1024 * 1024,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "0") == "1",
    APP_TIMEZONE=os.environ.get("APP_TIMEZONE", "Asia/Kolkata"),
    TEMPLATES_AUTO_RELOAD=True,
)
csrf = CSRFProtect(app)
LOCAL_TZ = ZoneInfo(app.config["APP_TIMEZONE"])


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def utc_iso(value: datetime | None = None) -> str:
    return (value or utc_now()).astimezone(timezone.utc).isoformat(timespec="seconds")


def parse_local_datetime(value: str) -> datetime:
    """Parse a datetime-local field in APP_TIMEZONE and return aware UTC time."""
    local_value = datetime.fromisoformat(value)
    if local_value.tzinfo is None:
        local_value = local_value.replace(tzinfo=LOCAL_TZ)
    return local_value.astimezone(timezone.utc)


def display_time(value: str | None) -> str:
    if not value:
        return "—"
    try:
        dt = datetime.fromisoformat(value)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(LOCAL_TZ).strftime("%d %b %Y, %I:%M %p")
    except ValueError:
        return value


app.jinja_env.filters["datetime_display"] = display_time


def from_json_filter(value: str | None):
    try:
        return json.loads(value or "[]")
    except (TypeError, json.JSONDecodeError):
        return []


app.jinja_env.filters["from_json"] = from_json_filter


def local_input_time(value: str | None) -> str:
    if not value:
        return ""
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(LOCAL_TZ).strftime("%Y-%m-%dT%H:%M")


def is_expired(value: str | None) -> bool:
    if not value:
        return False
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt <= utc_now()


app.jinja_env.filters["local_input"] = local_input_time
app.jinja_env.filters["is_expired"] = is_expired


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(_error=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DB_PATH)
    db.execute("PRAGMA foreign_keys = ON")
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE COLLATE NOCASE,
            password_hash TEXT NOT NULL,
            is_admin INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS files (
            id TEXT PRIMARY KEY,
            owner_id INTEGER NOT NULL,
            original_filename TEXT NOT NULL,
            stored_filename TEXT NOT NULL,
            content_type TEXT,
            nonce_b64 TEXT NOT NULL,
            wrapped_key_b64 TEXT NOT NULL,
            size_bytes INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            FOREIGN KEY(owner_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS shares (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_id TEXT NOT NULL,
            token_hash TEXT NOT NULL UNIQUE,
            password_hash TEXT,
            token_enc_b64 TEXT NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            revoked_at TEXT,
            FOREIGN KEY(file_id) REFERENCES files(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS access_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_id TEXT,
            share_id INTEGER,
            event TEXT NOT NULL,
            result TEXT NOT NULL,
            details TEXT,
            created_at TEXT NOT NULL,
            actor_user_id INTEGER,
            actor_key TEXT,
            ip_hash TEXT,
            FOREIGN KEY(file_id) REFERENCES files(id) ON DELETE SET NULL,
            FOREIGN KEY(share_id) REFERENCES shares(id) ON DELETE SET NULL
        );

        CREATE TABLE IF NOT EXISTS anomaly_analyses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            performed_by INTEGER,
            range_days INTEGER NOT NULL,
            activity_count INTEGER NOT NULL DEFAULT 0,
            window_count INTEGER NOT NULL DEFAULT 0,
            flagged_count INTEGER NOT NULL DEFAULT 0,
            model_trained INTEGER NOT NULL DEFAULT 0,
            model_message TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            FOREIGN KEY(performed_by) REFERENCES users(id) ON DELETE SET NULL
        );

        CREATE TABLE IF NOT EXISTS anomaly_detections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            analysis_id INTEGER NOT NULL,
            actor_key TEXT NOT NULL,
            actor_user_id INTEGER,
            actor_label TEXT NOT NULL,
            window_start TEXT NOT NULL,
            window_end TEXT NOT NULL,
            event_count INTEGER NOT NULL,
            failed_logins INTEGER NOT NULL,
            downloads INTEGER NOT NULL,
            denied_events INTEGER NOT NULL,
            unique_files INTEGER NOT NULL,
            anomaly_score REAL NOT NULL,
            detection_source TEXT NOT NULL,
            category TEXT NOT NULL,
            severity TEXT NOT NULL,
            summary TEXT NOT NULL,
            evidence_json TEXT NOT NULL,
            review_status TEXT NOT NULL DEFAULT 'Pending',
            reviewed_by INTEGER,
            reviewed_at TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY(analysis_id) REFERENCES anomaly_analyses(id) ON DELETE CASCADE,
            FOREIGN KEY(actor_user_id) REFERENCES users(id) ON DELETE SET NULL,
            FOREIGN KEY(reviewed_by) REFERENCES users(id) ON DELETE SET NULL
        );

        CREATE INDEX IF NOT EXISTS idx_files_owner ON files(owner_id);
        CREATE INDEX IF NOT EXISTS idx_shares_file ON shares(file_id);
        CREATE INDEX IF NOT EXISTS idx_logs_created ON access_logs(created_at);
        CREATE INDEX IF NOT EXISTS idx_anomaly_analysis ON anomaly_detections(analysis_id);
        """
    )

    # Safe, additive migration for existing File Vault databases.
    existing_columns = {row[1] for row in db.execute("PRAGMA table_info(access_logs)").fetchall()}
    for column, sql_type in (
        ("actor_user_id", "INTEGER"),
        ("actor_key", "TEXT"),
        ("ip_hash", "TEXT"),
    ):
        if column not in existing_columns:
            db.execute(f"ALTER TABLE access_logs ADD COLUMN {column} {sql_type}")

    # Give historical authenticated file events an owner identity where possible.
    db.execute(
        """UPDATE access_logs
           SET actor_user_id = (SELECT owner_id FROM files WHERE files.id = access_logs.file_id)
           WHERE actor_user_id IS NULL AND file_id IS NOT NULL
             AND event IN ('ENCRYPT', 'OWNER_DOWNLOAD', 'LINK_CREATED', 'LINK_REVOKED', 'LINK_HISTORY_DELETED')"""
    )
    db.execute(
        "UPDATE access_logs SET actor_key = 'user:' || actor_user_id WHERE actor_key IS NULL AND actor_user_id IS NOT NULL"
    )
    # Keep legacy events separate when the historical application did not
    # record actor fingerprints; do not merge every old visitor into one actor.
    db.execute(
        "UPDATE access_logs SET actor_key = 'legacy:event:' || id WHERE actor_key IS NULL"
    )
    db.execute("CREATE INDEX IF NOT EXISTS idx_logs_actor ON access_logs(actor_key, created_at)")
    db.commit()
    db.close()


def load_or_create_rsa_keys():
    if PRIVATE_KEY_PATH.exists() and PUBLIC_KEY_PATH.exists():
        return
    if PUBLIC_KEY_PATH.exists() and not PRIVATE_KEY_PATH.exists():
        raise RuntimeError(
            "The RSA private key is missing. Restore instance/rsa_private_key.pem from a secure backup; "
            "generating a new key would make existing encrypted files unrecoverable."
        )
    if PRIVATE_KEY_PATH.exists() and not PUBLIC_KEY_PATH.exists():
        private_key = serialization.load_pem_private_key(PRIVATE_KEY_PATH.read_bytes(), password=None)
        public_bytes = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        PUBLIC_KEY_PATH.write_bytes(public_bytes)
        return
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    PRIVATE_KEY_PATH.write_bytes(private_bytes)
    PUBLIC_KEY_PATH.write_bytes(public_bytes)
    try:
        os.chmod(PRIVATE_KEY_PATH, 0o600)
    except OSError:
        pass


def get_private_key():
    load_or_create_rsa_keys()
    return serialization.load_pem_private_key(PRIVATE_KEY_PATH.read_bytes(), password=None)


def get_public_key():
    load_or_create_rsa_keys()
    return serialization.load_pem_public_key(PUBLIC_KEY_PATH.read_bytes())


init_db()
load_or_create_rsa_keys()


def _privacy_fingerprint(value: str) -> str:
    secret = str(app.config["SECRET_KEY"]).encode("utf-8")
    return hmac.new(secret, value.encode("utf-8"), hashlib.sha256).hexdigest()


def log_event(
    file_id: str | None,
    share_id: int | None,
    event: str,
    result: str,
    details: str = "",
    *,
    actor_user_id: int | None = None,
    actor_key: str | None = None,
    anonymous: bool = False,
):
    """Write an event plus privacy-preserving actor/network fingerprints."""
    db = get_db()
    if actor_user_id is None and not anonymous:
        actor_user_id = session.get("user_id")
    remote_addr = request.remote_addr or "unknown"
    ip_hash = _privacy_fingerprint("ip:" + remote_addr)
    if actor_key is None:
        if actor_user_id is not None:
            actor_key = f"user:{actor_user_id}"
        else:
            actor_key = f"ip:{ip_hash}"
    db.execute(
        """INSERT INTO access_logs
           (file_id, share_id, event, result, details, created_at, actor_user_id, actor_key, ip_hash)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (file_id, share_id, event, result, details[:250], utc_iso(), actor_user_id, actor_key, ip_hash),
    )
    db.commit()


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please log in to continue.", "info")
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapped


def admin_required(view):
    @wraps(view)
    @login_required
    def wrapped(*args, **kwargs):
        user = get_db().execute("SELECT is_admin FROM users WHERE id = ?", (session["user_id"],)).fetchone()
        if not user or not user["is_admin"]:
            abort(403)
        return view(*args, **kwargs)
    return wrapped


@app.before_request
def load_current_user():
    g.user = None
    if session.get("user_id"):
        g.user = get_db().execute(
            "SELECT id, name, email, is_admin FROM users WHERE id = ?", (session["user_id"],)
        ).fetchone()
        if g.user is None:
            session.clear()


@app.context_processor
def inject_globals():
    return {"app_timezone": app.config["APP_TIMEZONE"], "current_year": datetime.now().year, "is_admin": bool(g.user and g.user["is_admin"])}


def file_for_owner(file_id: str):
    row = get_db().execute(
        "SELECT * FROM files WHERE id = ? AND owner_id = ?",
        (file_id, session["user_id"]),
    ).fetchone()
    if not row:
        abort(404)
    return row


def decrypt_file(file_row) -> bytes:
    encrypted_path = STORAGE_DIR / file_row["stored_filename"]
    if not encrypted_path.is_file():
        raise FileNotFoundError("Encrypted file is missing from storage.")
    wrapped_key = base64.b64decode(file_row["wrapped_key_b64"])
    nonce = base64.b64decode(file_row["nonce_b64"])
    private_key = get_private_key()
    aes_key = private_key.decrypt(
        wrapped_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    ciphertext = encrypted_path.read_bytes()
    return AESGCM(aes_key).decrypt(nonce, ciphertext, None)


def make_token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def encrypt_share_token(token: str) -> str:
    wrapped = get_public_key().encrypt(
        token.encode("utf-8"),
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    return base64.b64encode(wrapped).decode("ascii")


def decrypt_share_token(token_enc_b64: str) -> str:
    wrapped = base64.b64decode(token_enc_b64)
    token_bytes = get_private_key().decrypt(
        wrapped,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    return token_bytes.decode("utf-8")


def lookup_share(token: str):
    return get_db().execute(
        """SELECT s.*, f.original_filename, f.owner_id, f.stored_filename, f.content_type,
                  f.nonce_b64, f.wrapped_key_b64, f.size_bytes, f.expires_at AS file_expires_at
           FROM shares s JOIN files f ON f.id = s.file_id WHERE s.token_hash = ?""",
        (make_token_hash(token),),
    ).fetchone()


def share_state(share):
    if share["revoked_at"]:
        return "revoked"
    now = utc_now()
    share_expiry = datetime.fromisoformat(share["expires_at"])
    file_expiry = datetime.fromisoformat(share["file_expires_at"])
    if share_expiry <= now or file_expiry <= now:
        return "expired"
    return "active"


def share_access_allowed(share, token: str, require_password: bool = True) -> bool:
    state = share_state(share)
    if state != "active":
        log_event(share["file_id"], share["id"], "ACCESS", "DENIED", f"Link {state}", anonymous=True)
        return False
    if require_password and share["password_hash"]:
        authorized = session.get("authorized_share_hashes", [])
        if make_token_hash(token) not in authorized:
            return False
    return True


def set_share_authorized(token: str):
    hashes_list = session.get("authorized_share_hashes", [])
    token_hash = make_token_hash(token)
    if token_hash not in hashes_list:
        hashes_list.append(token_hash)
    session["authorized_share_hashes"] = hashes_list[-20:]


@app.route("/")
def home():
    if g.user:
        return redirect(url_for("dashboard"))
    return render_template("home.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        if not name or not email or len(password) < 8:
            flash("Enter your name and email, and use a password with at least 8 characters.", "error")
            return render_template("register.html")
        try:
            db = get_db()
            db.execute(
                "INSERT INTO users (name, email, password_hash, created_at) VALUES (?, ?, ?, ?)",
                (name, email, generate_password_hash(password), utc_iso()),
            )
            db.commit()
            user = db.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
            session.clear()
            session["user_id"] = user["id"]
            log_event(None, None, "REGISTER", "SUCCESS", "New account registered")
            flash("Account created. Welcome to File Vault!", "success")
            return redirect(url_for("dashboard"))
        except sqlite3.IntegrityError:
            flash("An account with that email already exists.", "error")
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        user = get_db().execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            log_event(None, None, "LOGIN_SUCCESS", "SUCCESS", "Successful login")
            flash("You are now logged in.", "success")
            next_url = request.args.get("next")
            if next_url and next_url.startswith("/") and not next_url.startswith("//"):
                return redirect(next_url)
            return redirect(url_for("dashboard"))
        remote_addr = request.remote_addr or "unknown"
        login_actor = "ip:" + _privacy_fingerprint("ip:" + remote_addr)
        log_event(None, None, "LOGIN_FAILED", "DENIED", "Invalid login credentials", actor_key=login_actor, anonymous=True)
        flash("Email or password is incorrect.", "error")
    return render_template("login.html")


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    log_event(None, None, "LOGOUT", "SUCCESS", "User logged out")
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("home"))


@app.route("/dashboard")
@login_required
def dashboard():
    db = get_db()
    files = db.execute("SELECT * FROM files WHERE owner_id = ? ORDER BY created_at DESC", (session["user_id"],)).fetchall()
    total_files = len(files)
    shared_count = db.execute(
        "SELECT COUNT(*) FROM shares s JOIN files f ON s.file_id = f.id WHERE f.owner_id = ? AND s.revoked_at IS NULL",
        (session["user_id"],),
    ).fetchone()[0]
    active_links = db.execute(
        "SELECT COUNT(*) FROM shares s JOIN files f ON s.file_id = f.id WHERE f.owner_id = ? AND s.revoked_at IS NULL AND s.expires_at > ? AND f.expires_at > ?",
        (session["user_id"], utc_iso(), utc_iso()),
    ).fetchone()[0]
    expired_files = sum(1 for f in files if datetime.fromisoformat(f["expires_at"]) <= utc_now())
    return render_template(
        "dashboard.html", total_files=total_files, shared_count=shared_count,
        active_links=active_links, expired_files=expired_files, recent_files=files[:5]
    )


@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload():
    if request.method == "POST":
        uploaded = request.files.get("file")
        expiry_value = request.form.get("expires_at", "")
        if not uploaded or not uploaded.filename:
            flash("Choose a file to upload.", "error")
            return render_template("upload.html")
        if not expiry_value:
            flash("Choose an expiry date and time.", "error")
            return render_template("upload.html")
        try:
            expiry = parse_local_datetime(expiry_value)
        except (ValueError, TypeError):
            flash("Enter a valid expiry date and time.", "error")
            return render_template("upload.html")
        if expiry <= utc_now():
            flash("Expiry must be in the future.", "error")
            return render_template("upload.html")

        original_name = secure_filename(uploaded.filename) or "uploaded-file"
        plaintext = uploaded.read()
        if not plaintext:
            flash("The selected file is empty.", "error")
            return render_template("upload.html")
        file_id = secrets.token_urlsafe(18)
        stored_filename = f"{file_id}.vault"
        aes_key = AESGCM.generate_key(bit_length=256)
        nonce = os.urandom(12)
        ciphertext = AESGCM(aes_key).encrypt(nonce, plaintext, None)
        wrapped_key = get_public_key().encrypt(
            aes_key,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
        )
        (STORAGE_DIR / stored_filename).write_bytes(ciphertext)
        db = get_db()
        db.execute(
            """INSERT INTO files (id, owner_id, original_filename, stored_filename, content_type,
               nonce_b64, wrapped_key_b64, size_bytes, created_at, expires_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (file_id, session["user_id"], original_name, stored_filename,
             uploaded.mimetype or "application/octet-stream",
             base64.b64encode(nonce).decode(), base64.b64encode(wrapped_key).decode(),
             len(plaintext), utc_iso(), utc_iso(expiry)),
        )
        db.commit()
        log_event(file_id, None, "ENCRYPT", "SUCCESS", "File encrypted and stored")
        flash("File encrypted and stored successfully. Create a secure sharing link next.", "success")
        return redirect(url_for("file_detail", file_id=file_id))
    return render_template("upload.html")


@app.route("/files")
@login_required
def my_files():
    files = get_db().execute(
        "SELECT * FROM files WHERE owner_id = ? ORDER BY created_at DESC",
        (session["user_id"],),
    ).fetchall()
    return render_template("my_files.html", files=files)


@app.route("/files/<file_id>")
@login_required
def file_detail(file_id):
    file_row = file_for_owner(file_id)
    raw_links = get_db().execute("SELECT * FROM shares WHERE file_id = ? ORDER BY created_at DESC", (file_id,)).fetchall()
    links = []
    for link in raw_links:
        item = dict(link)
        item["state"] = "revoked" if link["revoked_at"] else ("expired" if is_expired(link["expires_at"]) else "active")
        links.append(item)
    return render_template("file_detail.html", file=file_row, links=links)


@app.route("/files/<file_id>/share", methods=["POST"])
@login_required
def create_share(file_id):
    file_row = file_for_owner(file_id)
    try:
        file_expiry = datetime.fromisoformat(file_row["expires_at"])
        requested_expiry_value = request.form.get("expires_at", "")
        requested_expiry = parse_local_datetime(requested_expiry_value) if requested_expiry_value else file_expiry
    except (ValueError, TypeError):
        flash("Enter a valid link expiry date and time.", "error")
        return redirect(url_for("file_detail", file_id=file_id))
    if requested_expiry <= utc_now():
        flash("Link expiry must be in the future.", "error")
        return redirect(url_for("file_detail", file_id=file_id))
    if requested_expiry > file_expiry:
        flash("A sharing link cannot outlive the encrypted file's expiry time.", "error")
        return redirect(url_for("file_detail", file_id=file_id))

    password = request.form.get("link_password", "").strip()
    if password and len(password) < 6:
        flash("Link password must contain at least 6 characters.", "error")
        return redirect(url_for("file_detail", file_id=file_id))
    token = secrets.token_urlsafe(32)
    token_hash = make_token_hash(token)
    password_hash = generate_password_hash(password) if password else None
    db = get_db()
    token_enc_b64 = encrypt_share_token(token)
    cursor = db.execute(
        "INSERT INTO shares (file_id, token_hash, password_hash, token_enc_b64, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)",
        (file_id, token_hash, password_hash, token_enc_b64, utc_iso(), utc_iso(requested_expiry)),
    )
    db.commit()
    log_event(file_id, cursor.lastrowid, "LINK_CREATED", "SUCCESS", "Secure sharing link created")
    share_url = url_for("public_share", token=token, _external=True)
    return render_template("link_generated.html", file=file_row, share_url=share_url, expires_at=utc_iso(requested_expiry), has_password=bool(password))


@app.route("/shared")
@login_required
def shared_links():
    rows = get_db().execute(
        """SELECT s.*, f.original_filename, f.expires_at AS file_expires_at
           FROM shares s JOIN files f ON f.id = s.file_id
           WHERE f.owner_id = ? ORDER BY s.created_at DESC""",
        (session["user_id"],),
    ).fetchall()
    links = []
    for row in rows:
        data = dict(row)
        data["state"] = share_state(row)
        data["share_url"] = url_for("public_share", token=decrypt_share_token(row["token_enc_b64"]), _external=True)
        links.append(data)
    return render_template("shared_links.html", links=links)


@app.route("/shares/<int:share_id>/revoke", methods=["POST"])
@login_required
def revoke_share(share_id):
    db = get_db()
    share = db.execute(
        """SELECT s.*, f.owner_id FROM shares s JOIN files f ON f.id = s.file_id
           WHERE s.id = ? AND f.owner_id = ?""",
        (share_id, session["user_id"]),
    ).fetchone()
    if not share:
        abort(404)
    if not share["revoked_at"]:
        db.execute("UPDATE shares SET revoked_at = ? WHERE id = ?", (utc_iso(), share_id))
        db.commit()
        log_event(share["file_id"], share_id, "LINK_REVOKED", "SUCCESS", "Owner revoked the link")
        flash("Sharing link revoked.", "success")
    return redirect(request.referrer if request.referrer and request.referrer.startswith("/") else url_for("shared_links"))


@app.route("/shares/<int:share_id>/delete", methods=["POST"])
@login_required
def delete_share_record(share_id):
    """Permanently remove one link from the owner's sharing history.

    Deleting an active record also invalidates its URL immediately. Related
    audit events remain available; their share_id is set to NULL by SQLite.
    """
    db = get_db()
    share = db.execute(
        """SELECT s.id, s.file_id, f.owner_id FROM shares s
           JOIN files f ON f.id = s.file_id
           WHERE s.id = ? AND f.owner_id = ?""",
        (share_id, session["user_id"]),
    ).fetchone()
    if not share:
        abort(404)
    log_event(share["file_id"], share_id, "LINK_HISTORY_DELETED", "SUCCESS", "Owner deleted the sharing-link history record")
    db.execute("DELETE FROM shares WHERE id = ?", (share_id,))
    db.commit()
    flash("Sharing-link record deleted. Its URL can no longer be used.", "success")
    return redirect(url_for("shared_links"))


@app.route("/share/<token>", methods=["GET", "POST"])
def public_share(token):
    share = lookup_share(token)
    if not share:
        return render_template("share_unavailable.html", state="invalid"), 404
    state = share_state(share)
    if state != "active":
        log_event(share["file_id"], share["id"], "ACCESS", "DENIED", f"Link {state}", anonymous=True)
        return render_template("share_unavailable.html", state=state), 410

    if share["password_hash"]:
        authorized = make_token_hash(token) in session.get("authorized_share_hashes", [])
        if not authorized:
            if request.method == "POST":
                entered = request.form.get("link_password", "")
                if check_password_hash(share["password_hash"], entered):
                    set_share_authorized(token)
                    log_event(share["file_id"], share["id"], "PASSWORD_CHECK", "SUCCESS", "Recipient passed link password", anonymous=True)
                    return redirect(url_for("public_share", token=token))
                log_event(share["file_id"], share["id"], "PASSWORD_CHECK", "DENIED", "Incorrect link password", anonymous=True)
                flash("That password is incorrect.", "error")
            return render_template("share_password.html")

    log_event(share["file_id"], share["id"], "VIEW", "SUCCESS", "Sharing page opened", anonymous=True)
    owner = get_db().execute("SELECT name FROM users WHERE id = ?", (share["owner_id"],)).fetchone()
    return render_template("recipient_view.html", share=share, owner_name=owner["name"] if owner else "File Vault user", token=token)


@app.route("/share/<token>/download", methods=["POST"])
def public_download(token):
    share = lookup_share(token)
    if not share:
        return render_template("share_unavailable.html", state="invalid"), 404
    if not share_access_allowed(share, token):
        if share_state(share) == "active":
            flash("Open the sharing link and complete its password check first.", "error")
            return redirect(url_for("public_share", token=token))
        return render_template("share_unavailable.html", state=share_state(share)), 410
    try:
        plaintext = decrypt_file(share)
    except Exception:
        log_event(share["file_id"], share["id"], "DOWNLOAD", "FAILED", "Decryption failed", anonymous=True)
        abort(500)
    log_event(share["file_id"], share["id"], "DOWNLOAD", "SUCCESS", "Recipient downloaded and decrypted file", anonymous=True)
    return send_file(
        BytesIO(plaintext), as_attachment=True,
        download_name=share["original_filename"],
        mimetype=share["content_type"] or "application/octet-stream",
    )


@app.route("/files/<file_id>/download", methods=["POST"])
@login_required
def owner_download(file_id):
    file_row = file_for_owner(file_id)
    try:
        if datetime.fromisoformat(file_row["expires_at"]) <= utc_now():
            log_event(file_id, None, "OWNER_DOWNLOAD", "DENIED", "File expired")
            flash("This file has expired and cannot be downloaded.", "error")
            return redirect(url_for("file_detail", file_id=file_id))
        plaintext = decrypt_file(file_row)
    except Exception:
        log_event(file_id, None, "OWNER_DOWNLOAD", "FAILED", "Decryption failed")
        abort(500)
    log_event(file_id, None, "OWNER_DOWNLOAD", "SUCCESS", "Owner downloaded file")
    return send_file(BytesIO(plaintext), as_attachment=True, download_name=file_row["original_filename"], mimetype=file_row["content_type"] or "application/octet-stream")


@app.route("/logs")
@login_required
def access_logs():
    rows = get_db().execute(
        """SELECT l.*, f.original_filename FROM access_logs l
           LEFT JOIN files f ON l.file_id = f.id
           WHERE f.owner_id = ? OR l.actor_user_id = ?
           ORDER BY l.created_at DESC LIMIT 200""",
        (session["user_id"], session["user_id"]),
    ).fetchall()
    # A null file_id log would be global; this app only creates file-scoped logs.
    return render_template("access_logs.html", logs=rows)


@app.route("/logs/<int:log_id>/delete", methods=["POST"])
@login_required
def delete_access_log(log_id):
    db = get_db()
    row = db.execute(
        """SELECT l.id FROM access_logs l
           LEFT JOIN files f ON f.id = l.file_id
           WHERE l.id = ? AND (f.owner_id = ? OR l.actor_user_id = ?)""",
        (log_id, session["user_id"], session["user_id"]),
    ).fetchone()
    if not row:
        abort(404)
    db.execute("DELETE FROM access_logs WHERE id = ?", (log_id,))
    db.commit()
    flash("Activity entry deleted.", "success")
    return redirect(url_for("access_logs"))


@app.route("/logs/clear", methods=["POST"])
@login_required
def clear_access_logs():
    db = get_db()
    db.execute(
        """DELETE FROM access_logs
           WHERE actor_user_id = ?
              OR file_id IN (SELECT id FROM files WHERE owner_id = ?)""",
        (session["user_id"], session["user_id"]),
    )
    db.commit()
    flash("Your access history has been cleared.", "success")
    return redirect(url_for("access_logs"))


@app.route("/admin/logs/<int:log_id>/delete", methods=["POST"])
@admin_required
def admin_delete_access_log(log_id):
    db = get_db()
    cursor = db.execute("DELETE FROM access_logs WHERE id = ?", (log_id,))
    if cursor.rowcount == 0:
        abort(404)
    db.commit()
    flash("Security activity entry deleted.", "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/logs/clear", methods=["POST"])
@admin_required
def admin_clear_access_logs():
    db = get_db()
    db.execute("DELETE FROM access_logs")
    db.execute("DELETE FROM anomaly_analyses")
    db.commit()
    flash("All security activity history has been cleared.", "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin")
@admin_required
def admin_dashboard():
    db = get_db()
    metrics = {
        "users": db.execute("SELECT COUNT(*) FROM users").fetchone()[0],
        "files": db.execute("SELECT COUNT(*) FROM files").fetchone()[0],
        "active_links": db.execute("SELECT COUNT(*) FROM shares s JOIN files f ON s.file_id=f.id WHERE s.revoked_at IS NULL AND s.expires_at > ? AND f.expires_at > ?", (utc_iso(), utc_iso())).fetchone()[0],
        "denied": db.execute("SELECT COUNT(*) FROM access_logs WHERE result = 'DENIED'").fetchone()[0],
    }
    logs = db.execute(
        "SELECT l.*, f.original_filename FROM access_logs l LEFT JOIN files f ON l.file_id=f.id ORDER BY l.created_at DESC LIMIT 12"
    ).fetchall()
    return render_template("admin.html", metrics=metrics, logs=logs)


def run_anomaly_analysis_pipeline(range_days: int = 7, user_id: int | None = None):
    """Execute anomaly detection for the given time range and synchronize tables.

    Admin users are excluded from anomaly detection — their activity is trusted
    and should not generate false-positive alerts.
    """
    db = get_db()
    # Collect all admin user IDs so their logs can be excluded below.
    admin_ids = {
        row["id"]
        for row in db.execute("SELECT id FROM users WHERE is_admin = 1").fetchall()
    }

    if range_days > 0:
        cutoff = utc_iso(utc_now() - timedelta(days=range_days))
        rows = [dict(row) for row in db.execute(
            """SELECT id, file_id, actor_user_id, actor_key, ip_hash, created_at, event, result, details
               FROM access_logs WHERE created_at >= ? ORDER BY created_at ASC""",
            (cutoff,),
        ).fetchall()]
    else:
        rows = [dict(row) for row in db.execute(
            """SELECT id, file_id, actor_user_id, actor_key, ip_hash, created_at, event, result, details
               FROM access_logs ORDER BY created_at ASC"""
        ).fetchall()]

    # Remove logs that belong to admin accounts before running the ML model.
    rows = [r for r in rows if r.get("actor_user_id") not in admin_ids]

    analysis = detect_anomalies(rows, contamination=0.10)
    now = utc_iso()
    cursor = db.execute(
        """INSERT INTO anomaly_analyses
           (performed_by, range_days, activity_count, window_count, flagged_count,
            model_trained, model_message, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (user_id, range_days, len(rows), analysis["windows"],
         len(analysis["results"]), int(analysis["model_trained"]), analysis["model_message"], now),
    )
    analysis_id = cursor.lastrowid

    user_ids = {item.get("actor_user_id") for item in analysis["results"] if item.get("actor_user_id")}
    user_labels = {}
    if user_ids:
        placeholders = ",".join("?" for _ in user_ids)
        user_labels = {
            row["id"]: f"{row['name']} · {row['email']}"
            for row in db.execute(
                f"SELECT id, name, email FROM users WHERE id IN ({placeholders})",
                tuple(user_ids),
            ).fetchall()
        }

    for item in analysis["results"]:
        actor_label = user_labels.get(item.get("actor_user_id"), item["actor_label"])
        db.execute(
            """INSERT INTO anomaly_detections
               (analysis_id, actor_key, actor_user_id, actor_label, window_start, window_end,
                event_count, failed_logins, downloads, denied_events, unique_files,
                anomaly_score, detection_source, category, severity, summary, evidence_json, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (analysis_id, item["actor_key"], item.get("actor_user_id"), actor_label,
             item["window_start"], item["window_end"], item["event_count"],
             item["failed_logins"], item["downloads"], item["denied_events"],
             item["unique_files"], item["anomaly_score"], item["source"],
             item["category"], item["severity"], item["summary"],
             json.dumps(item["evidence"]), now),
        )
    db.commit()

    latest = db.execute("SELECT * FROM anomaly_analyses WHERE id = ?", (analysis_id,)).fetchone()
    detections = db.execute(
        """SELECT d.*, u.name AS user_name, u.email AS user_email
           FROM anomaly_detections d
           LEFT JOIN users u ON u.id = d.actor_user_id
           WHERE d.analysis_id = ?
           ORDER BY CASE d.severity WHEN 'Critical' THEN 4 WHEN 'High' THEN 3 WHEN 'Medium' THEN 2 ELSE 1 END DESC,
                    d.anomaly_score DESC, d.created_at DESC""",
        (analysis_id,),
    ).fetchall()
    return latest, detections, analysis


@app.route("/admin/anomaly-detection")
@admin_required
def anomaly_detection():
    db = get_db()
    latest = db.execute(
        "SELECT * FROM anomaly_analyses ORDER BY id DESC LIMIT 1"
    ).fetchone()

    req_range = request.args.get("range_days")
    if req_range is not None and req_range in {"0", "1", "7", "30"}:
        range_days = int(req_range)
    elif latest:
        range_days = latest["range_days"]
    else:
        range_days = 7

    cleared = request.args.get("cleared") == "1"
    refresh_requested = request.args.get("refresh") == "1"

    if range_days > 0:
        cutoff = utc_iso(utc_now() - timedelta(days=range_days))
        count_now = db.execute("SELECT COUNT(*) FROM access_logs WHERE created_at >= ?", (cutoff,)).fetchone()[0]
        max_log = db.execute("SELECT MAX(created_at) FROM access_logs WHERE created_at >= ?", (cutoff,)).fetchone()[0]
    else:
        count_now = db.execute("SELECT COUNT(*) FROM access_logs").fetchone()[0]
        max_log = db.execute("SELECT MAX(created_at) FROM access_logs").fetchone()[0]

    needs_update = False
    if not cleared:
        if latest is None or refresh_requested:
            needs_update = True
        elif latest["range_days"] != range_days:
            needs_update = True
        elif count_now != latest["activity_count"] or (max_log and max_log > latest["created_at"]):
            needs_update = True

    if needs_update:
        latest, detections, _ = run_anomaly_analysis_pipeline(range_days, session.get("user_id"))
        flagged_count_current = len(detections)
    elif latest:
        detections = db.execute(
            """SELECT d.*, u.name AS user_name, u.email AS user_email
               FROM anomaly_detections d
               LEFT JOIN users u ON u.id = d.actor_user_id
               WHERE d.analysis_id = ?
               ORDER BY CASE d.severity WHEN 'Critical' THEN 4 WHEN 'High' THEN 3 WHEN 'Medium' THEN 2 ELSE 1 END DESC,
                        d.anomaly_score DESC, d.created_at DESC""",
            (latest["id"],),
        ).fetchall()
        flagged_count_current = len(detections)
    else:
        detections = []
        flagged_count_current = 0

    if range_days > 0:
        since = utc_iso(utc_now() - timedelta(days=range_days))
        totals = db.execute(
            """SELECT
                 COUNT(*) AS total,
                 SUM(CASE WHEN (event IN ('LOGIN_FAILED', 'PASSWORD_CHECK') AND result IN ('DENIED', 'FAILED')) OR result IN ('DENIED', 'FAILED') THEN 1 ELSE 0 END) AS failed_auth_or_denied,
                 SUM(CASE WHEN event = 'LOGIN_FAILED' AND result IN ('DENIED', 'FAILED') THEN 1 ELSE 0 END) AS failed_logins,
                 SUM(CASE WHEN event IN ('DOWNLOAD', 'OWNER_DOWNLOAD') AND result = 'SUCCESS' THEN 1 ELSE 0 END) AS downloads,
                 SUM(CASE WHEN result IN ('DENIED', 'FAILED') THEN 1 ELSE 0 END) AS denied
               FROM access_logs WHERE created_at >= ?""",
            (since,),
        ).fetchone()
    else:
        totals = db.execute(
            """SELECT
                 COUNT(*) AS total,
                 SUM(CASE WHEN (event IN ('LOGIN_FAILED', 'PASSWORD_CHECK') AND result IN ('DENIED', 'FAILED')) OR result IN ('DENIED', 'FAILED') THEN 1 ELSE 0 END) AS failed_auth_or_denied,
                 SUM(CASE WHEN event = 'LOGIN_FAILED' AND result IN ('DENIED', 'FAILED') THEN 1 ELSE 0 END) AS failed_logins,
                 SUM(CASE WHEN event IN ('DOWNLOAD', 'OWNER_DOWNLOAD') AND result = 'SUCCESS' THEN 1 ELSE 0 END) AS downloads,
                 SUM(CASE WHEN result IN ('DENIED', 'FAILED') THEN 1 ELSE 0 END) AS denied
               FROM access_logs"""
        ).fetchone()

    return render_template(
        "anomaly_detection.html",
        latest=latest,
        detections=detections,
        totals=totals,
        range_days=range_days,
        flagged_count_current=flagged_count_current,
    )


@app.route("/admin/anomaly-detection/run", methods=["POST"])
@admin_required
def run_anomaly_detection():
    requested_days = request.form.get("range_days", "7")
    if requested_days not in {"0", "1", "7", "30"}:
        flash("Choose a valid analysis period.", "error")
        return redirect(url_for("anomaly_detection"))
    range_days = int(requested_days)
    latest, detections, analysis = run_anomaly_analysis_pipeline(range_days, session.get("user_id"))

    if latest["activity_count"] == 0:
        flash("No activity logs were found in the selected period. Generate activity first, then run the analysis.", "info")
    elif analysis["model_trained"]:
        flash(f"Isolation Forest analysed {latest['activity_count']} events across {analysis['windows']} activity windows and flagged {len(analysis['results'])} suspicious windows.", "success")
    else:
        flash(f"Analysed {latest['activity_count']} events. {analysis['model_message']}", "info")
    return redirect(url_for("anomaly_detection", range_days=range_days))


@app.route("/admin/anomaly-detection/<int:detection_id>/review", methods=["POST"])
@admin_required
def review_anomaly_detection(detection_id):
    status = request.form.get("review_status", "")
    if status not in {"Reviewed", "False Positive"}:
        abort(400)
    db = get_db()
    cursor = db.execute(
        """UPDATE anomaly_detections
           SET review_status = ?, reviewed_by = ?, reviewed_at = ?
           WHERE id = ?""",
        (status, session["user_id"], utc_iso(), detection_id),
    )
    if not cursor.rowcount:
        abort(404)
    db.commit()
    log_event(None, None, "ANOMALY_REVIEW", "SUCCESS", f"Anomaly finding {detection_id} marked as {status}")
    flash(f"Alert marked as {status.lower()}.", "success")
    return redirect(url_for("anomaly_detection"))


@app.route("/admin/anomaly-detection/<int:detection_id>/delete", methods=["POST"])
@admin_required
def delete_anomaly_detection(detection_id):
    db = get_db()
    cursor = db.execute("DELETE FROM anomaly_detections WHERE id = ?", (detection_id,))
    if not cursor.rowcount:
        abort(404)
    db.commit()
    flash("Suspicious activity record deleted.", "success")
    return redirect(url_for("anomaly_detection"))


@app.route("/admin/anomaly-detection/clear", methods=["POST"])
@admin_required
def clear_anomaly_history():
    db = get_db()
    db.execute("DELETE FROM anomaly_analyses")
    db.commit()
    flash("Anomaly detection history cleared. Original access logs were kept.", "success")
    return redirect(url_for("anomaly_detection", cleared="1"))


@app.errorhandler(403)
def forbidden(_error):
    return render_template("error.html", code=403, message="You do not have permission to view this page."), 403


@app.errorhandler(404)
def not_found(_error):
    return render_template("error.html", code=404, message="The page or file could not be found."), 404


@app.errorhandler(413)
def too_large(_error):
    return render_template(
        "error.html",
        code=413,
        message=f"File is too large. The current upload limit is {app.config['MAX_UPLOAD_MB']} MB.",
    ), 413


@app.cli.command("create-admin")
@click.option("--email", required=True, help="Email address of the account to make an administrator")
def create_admin(email):
    db = sqlite3.connect(DB_PATH)
    cursor = db.execute("UPDATE users SET is_admin = 1 WHERE email = ? COLLATE NOCASE", (email.strip(),))
    db.commit()
    db.close()
    if cursor.rowcount:
        click.echo(f"Administrator role enabled for {email}.")
    else:
        click.echo("No account found. Register that email first, then run this command again.")
