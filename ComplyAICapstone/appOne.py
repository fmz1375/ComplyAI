
# Eventlet monkey-patching must be first
import eventlet
eventlet.monkey_patch()

from flask import Flask, render_template, redirect, request, session, url_for, jsonify
import json
import sqlite3
import re
import os
import uuid
import secrets
import threading
from datetime import datetime, timedelta
from enum import Enum
from pydantic import BaseModel
from werkzeug.exceptions import HTTPException
from werkzeug.security import generate_password_hash, check_password_hash

# Auth0 imports
from auth0.authentication import GetToken
from auth0.management import Auth0
from jose import jwt

# Import Key Management System for document encryption
from key_management_system import KeyManagementSystem

# Initialize KMS instance for document encryption
kms = KeyManagementSystem()

# Custom JSON encoder for datetime, enum, and Pydantic objects
class CustomJSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        if isinstance(obj, Enum):
            return obj.value
        if isinstance(obj, BaseModel):
            return obj.model_dump() if hasattr(obj, "model_dump") else obj.dict()
        return super().default(obj)


def model_to_dict(model_obj):
    return model_obj.model_dump() if hasattr(model_obj, "model_dump") else model_obj.dict()

app = Flask(__name__)


@app.errorhandler(HTTPException)
def handle_http_exception(err):
    if request.path.startswith("/api/"):
        return jsonify({
            "error": err.description or "HTTP error",
            "status": err.code,
            "type": err.name,
        }), err.code
    return err


@app.errorhandler(Exception)
def handle_unexpected_exception(err):
    if request.path.startswith("/api/"):
        return jsonify({
            "error": "Internal server error",
            "details": str(err)
        }), 500
    raise err

# Register custom Jinja2 filter for JSON parsing
@app.template_filter('from_json')
def from_json_filter(s):
    return json.loads(s) if s else []

# ============================================
# SECURITY CONFIGURATION
# ============================================

# Generate a secure secret key (use env var in production)
app.secret_key = os.environ.get('FLASK_SECRET_KEY') or secrets.token_hex(32)

# Session security settings
app.config.update(
    SESSION_COOKIE_SECURE=os.environ.get('FLASK_ENV') == 'production',  # HTTPS only in production
    SESSION_COOKIE_HTTPONLY=True,  # Prevent JavaScript access to session cookie
    SESSION_COOKIE_SAMESITE='Lax',  # CSRF protection
    PERMANENT_SESSION_LIFETIME=timedelta(hours=2),  # Session timeout
)

# ============================================
# AUTH0 CONFIGURATION
# ============================================

AUTH0_DOMAIN = os.environ.get('AUTH0_DOMAIN')
AUTH0_CLIENT_ID = os.environ.get('AUTH0_CLIENT_ID')
AUTH0_CLIENT_SECRET = os.environ.get('AUTH0_CLIENT_SECRET')
AUTH0_CALLBACK_URL = os.environ.get('AUTH0_CALLBACK_URL', 'http://localhost:5000/callback')
AUTH0_AUDIENCE = os.environ.get('AUTH0_AUDIENCE')
AUTH0_MOCK_MODE = os.environ.get('AUTH0_MOCK_MODE', 'true').lower() in ('1', 'true', 'yes')

# Mock SSO special users (demo credentials)
MOCK_AUTH0_USERS = {
    'bobby@example.com': {
        'password': 'bobby',
        'sub': 'auth0|mock:bobby@example.com',
        'full_name': 'Bobby Demo',
        'role': 'user'
    },
    'admin@example.com': {
        'password': 'admin123',
        'sub': 'auth0|mock:admin@example.com',
        'full_name': 'Admin Demo',
        'role': 'admin'
    }
}

# Auth0 SDK instances
auth0 = Auth0(AUTH0_DOMAIN, AUTH0_CLIENT_ID, AUTH0_CLIENT_SECRET) if AUTH0_DOMAIN and not AUTH0_MOCK_MODE else None
token_getter = GetToken(AUTH0_DOMAIN, AUTH0_CLIENT_ID, AUTH0_CLIENT_SECRET) if AUTH0_DOMAIN and not AUTH0_MOCK_MODE else None


# Security headers middleware
@app.after_request
def add_security_headers(response):
    """Add security headers to all responses."""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    # Content Security Policy - adjust as needed for your app
    if not request.path.startswith('/api/'):
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    return response


# ============================================
# KEY MANAGEMENT SYSTEM UTILITIES
# ============================================

def encrypt_sensitive_data(tenant_id, data):
    """
    Encrypt sensitive data using the KMS envelope encryption pattern.
    
    Args:
        tenant_id: Tenant identifier for key isolation
        data: String or bytes to encrypt
    
    Returns:
        dict with encrypted_data and encryption metadata
    """
    try:
        # Generate a data encryption key (DEK)
        dek = kms.generate_dek()
        
        # Encrypt the DEK with the tenant's master key
        encrypted_dek_data = kms.encrypt_dek(tenant_id, dek)
        
        # Encrypt the actual data with the DEK
        encrypted_content = kms.encrypt_document(dek, data)
        
        return {
            'success': True,
            'encrypted_content': encrypted_content,
            'encrypted_dek': encrypted_dek_data
        }
    except Exception as e:
        return {'success': False, 'error': str(e)}


def decrypt_sensitive_data(tenant_id, encrypted_package):
    """
    Decrypt sensitive data using the KMS.
    
    Args:
        tenant_id: Tenant identifier
        encrypted_package: Dict containing encrypted_content and encrypted_dek
    
    Returns:
        Decrypted data as bytes
    """
    try:
        # Decrypt the DEK using the tenant's master key
        dek = kms.decrypt_dek(tenant_id, encrypted_package['encrypted_dek'])
        
        # Decrypt the content using the DEK
        decrypted_data = kms.decrypt_document(dek, encrypted_package['encrypted_content'])
        
        return {'success': True, 'data': decrypted_data}
    except Exception as e:
        return {'success': False, 'error': str(e)}


def check_key_rotation_needed(tenant_id, max_age_days=90):
    """Check if encryption keys need rotation for a tenant."""
    return kms.should_rotate_keys(tenant_id, max_age_days)


def rotate_tenant_keys(tenant_id):
    """Rotate encryption keys for a tenant."""
    try:
        new_version = kms.rotate_keys(tenant_id)
        return {'success': True, 'new_version': new_version}
    except Exception as e:
        return {'success': False, 'error': str(e)}


# API endpoint for key management (admin only)
@app.route("/api/security/key-status", methods=["GET"])
def key_status():
    """Get encryption key status for the current user's tenant."""
    if not session.get("user_id"):
        return jsonify({"error": "Authentication required"}), 401
    
    # Use user_id as tenant identifier (or implement your own tenant logic)
    tenant_id = f"user_{session.get('user_id')}"
    
    needs_rotation = check_key_rotation_needed(tenant_id)
    return jsonify({
        "tenant_id": tenant_id,
        "needs_rotation": needs_rotation,
        "rotation_recommended_days": 90
    })


@app.route("/api/security/rotate-keys", methods=["POST"])
def api_rotate_keys():
    """Rotate encryption keys (admin only)."""
    if session.get("role") != "admin":
        return jsonify({"error": "Admin access required"}), 403
    
    tenant_id = request.json.get("tenant_id") if request.is_json else None
    if not tenant_id:
        tenant_id = f"user_{session.get('user_id')}"
    
    result = rotate_tenant_keys(tenant_id)
    if result['success']:
        return jsonify({"status": "success", "new_version": result['new_version']})
    return jsonify({"error": result['error']}), 500


def _random_id(length=12):
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    return "".join(__import__("random").choice(alphabet) for _ in range(length))


def _safe_archive_filename(original_name: str, suffix: str) -> str:
    base, ext = os.path.splitext(original_name or "document.pdf")
    sanitized_base = re.sub(r"[^a-zA-Z0-9._-]", "_", base) or "document"
    return f"{sanitized_base}_{suffix}{ext or '.pdf'}"


def _archive_file_if_exists(filename: str) -> str:
    """Archive an existing uploaded file and return archived filename, else empty string."""
    if not filename:
        return ""

    current_path = os.path.join(UPLOAD_FOLDER, filename)
    if not os.path.exists(current_path):
        return ""

    ts = datetime.now().strftime("%Y%m%d%H%M%S")
    archived_name = _safe_archive_filename(filename, f"archived_{ts}")
    archived_path = os.path.join(UPLOAD_FOLDER, archived_name)
    os.rename(current_path, archived_path)
    return archived_name

# --- Upload route for dashboard button ---
@app.route("/upload", methods=["GET", "POST"])
def upload():
    if request.method == "POST":
        if not session.get("user_id"):
            if request.is_json:
                return jsonify({"error": "Not authenticated"}), 401
            return redirect(url_for("login"))

        user_id = session.get("user_id")
        full_name = session.get("full_name")
        payload = request.get_json(silent=True) if request.is_json else request.form
        create_result = _create_document_metadata_version(payload, user_id, full_name)

        if not create_result["ok"]:
            # Log failed upload
            AuditLogger.log("document_upload", "document", payload.get("document_name", "unknown"),
                           f"Failed to upload document: {create_result['error']}", "failure")
            if request.is_json:
                return jsonify({"error": create_result["error"]}), 400
            return create_result["error"], 400

        # Log successful upload
        AuditLogger.log("document_upload", "document", create_result["document_id"],
                       f"Uploaded document: {payload.get('document_name', 'unknown')}", "success")

        if request.is_json:
            return jsonify({
                "success": True,
                "document_id": create_result["document_id"],
                "unique_id": create_result["unique_id"],
                "version_group_id": create_result["version_group_id"],
                "deactivated_previous_document_id": create_result["previous_document_id"],
            })

        return redirect(url_for("upload_document"))

    previous_document_id = request.args.get("previous_document_id", type=int)
    previous_document = None
    if previous_document_id and session.get("user_id"):
        db = get_db_connection()
        try:
            if session.get("role") == "admin":
                row = db.execute("SELECT * FROM documents WHERE id = ?", (previous_document_id,)).fetchone()
            else:
                row = db.execute(
                    "SELECT * FROM documents WHERE id = ? AND user_id = ?",
                    (previous_document_id, session.get("user_id")),
                ).fetchone()
            previous_document = dict(row) if row else None
        finally:
            db.close()

    return render_template(
        "naming.html",
        role=session.get("role"),
        full_name=session.get("full_name"),
        user_id=session.get("user_id"),
        previous_document=previous_document,
    )

# --- Upload Analysis Route ---
@app.route("/upload-document")
def upload_document():
    return render_template("index.html")


@app.route("/pdf-viewer")
def pdf_viewer():
    return render_template("pdf_viewer_clean.html")

# --- Legacy Index Route ---
@app.route("/index")
def index():
    return redirect(url_for("upload_document"))

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "project.db")

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _get_latest_document_compliance_score(db, document_id, user_id=None):
    details = _get_latest_document_compliance_score_details(db, document_id, user_id)
    return details["score"]


def _get_latest_document_compliance_score_details(db, document_id, user_id=None):
    """Return the latest compliance percentage for a document version.

    Lookup order:
    1. report.compliance_summary.compliance_percentage
    2. compliance_results.results_json.compliance_summary.compliance_percentage
    3. legacy compliance.compliance_score
    """
    report_query = (
        "SELECT compliance_summary FROM report WHERE document_id = ? ORDER BY created_at DESC, id DESC LIMIT 1"
    )
    report_params = (document_id,)
    if user_id is not None:
        report_query = (
            "SELECT compliance_summary FROM report WHERE document_id = ? AND user_id = ? ORDER BY created_at DESC, id DESC LIMIT 1"
        )
        report_params = (document_id, user_id)

    row = db.execute(report_query, report_params).fetchone()
    if row and row["compliance_summary"]:
        try:
            parsed = json.loads(row["compliance_summary"])
            score = parsed.get("compliance_percentage")
            if score is not None:
                return {"score": float(score), "source": "report"}
        except Exception:
            pass

    results_query = (
        "SELECT results_json FROM compliance_results WHERE document_id = ? ORDER BY created_at DESC, id DESC LIMIT 1"
    )
    results_params = (document_id,)
    if user_id is not None:
        results_query = (
            "SELECT results_json FROM compliance_results WHERE document_id = ? AND user_id = ? ORDER BY created_at DESC, id DESC LIMIT 1"
        )
        results_params = (document_id, user_id)

    row = db.execute(results_query, results_params).fetchone()
    if row and row["results_json"]:
        try:
            parsed = json.loads(row["results_json"])
            if isinstance(parsed, dict):
                summary = parsed.get("compliance_summary") or {}
                score = summary.get("compliance_percentage")
                if score is not None:
                    return {"score": float(score), "source": "compliance_results"}
        except Exception:
            pass

    compliance_query = (
        "SELECT compliance_score FROM compliance WHERE document_id = ? ORDER BY id DESC LIMIT 1"
    )
    row = db.execute(compliance_query, (document_id,)).fetchone()
    if row and row["compliance_score"] is not None:
        try:
            return {"score": float(row["compliance_score"]), "source": "legacy_compliance"}
        except Exception:
            pass

    return {"score": None, "source": None}


def ensure_documents_versioning_schema():
    """Ensure documents table has soft-versioning columns for historical tracking."""
    conn = get_db_connection()
    try:
        table = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='documents'"
        ).fetchone()
        if not table:
            return

        cols = conn.execute("PRAGMA table_info(documents)").fetchall()
        existing = {c[1] for c in cols}

        if "is_active" not in existing:
            conn.execute("ALTER TABLE documents ADD COLUMN is_active INTEGER DEFAULT 1")
        if "version_group_id" not in existing:
            conn.execute("ALTER TABLE documents ADD COLUMN version_group_id TEXT")
        if "deactivated_at" not in existing:
            conn.execute("ALTER TABLE documents ADD COLUMN deactivated_at TEXT")
        if "fileName" not in existing:
            conn.execute("ALTER TABLE documents ADD COLUMN fileName TEXT")

        # Backfill existing rows into their own groups and mark as active by default.
        conn.execute("UPDATE documents SET is_active = COALESCE(is_active, 1)")
        conn.execute(
            "UPDATE documents SET version_group_id = COALESCE(version_group_id, 'vg_' || unique_id, 'vg_' || id)"
        )
        conn.commit()
    finally:
        conn.close()


def init_db():
    """Create collaboration tables if they don't exist."""
    conn = get_db_connection()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS collaborators (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            document_id INTEGER NOT NULL,
            owner_id INTEGER NOT NULL,
            viewer_id INTEGER,
            viewer_email TEXT NOT NULL,
            status TEXT DEFAULT 'active',
            invited_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(document_id) REFERENCES documents(id),
            FOREIGN KEY(owner_id) REFERENCES users(id)
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS share_links (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            token TEXT UNIQUE NOT NULL,
            owner_id INTEGER NOT NULL,
            document_id INTEGER NOT NULL,
            section TEXT NOT NULL,
            expires_at TEXT,
            revoked INTEGER DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(owner_id) REFERENCES users(id),
            FOREIGN KEY(document_id) REFERENCES documents(id)
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS share_link_access_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            share_link_id INTEGER NOT NULL,
            accessor_ip TEXT,
            accessor_user_id INTEGER,
            accessed_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(share_link_id) REFERENCES share_links(id)
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS chat_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            document_id INTEGER NOT NULL,
            sender_id INTEGER NOT NULL,
            sender_name TEXT NOT NULL,
            sender_role TEXT DEFAULT 'viewer',
            content TEXT NOT NULL,
            message_type TEXT DEFAULT 'user',
            attachment_url TEXT,
            attachment_type TEXT,
            attachment_name TEXT,
            is_deleted INTEGER DEFAULT 0,
            deleted_at TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(document_id) REFERENCES documents(id),
            FOREIGN KEY(sender_id) REFERENCES users(id)
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS finding_feedback (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            finding_key TEXT NOT NULL,
            session_id TEXT,
            user_id INTEGER NOT NULL DEFAULT 0,
            control_id TEXT,
            confidence REAL,
            source_quote TEXT,
            action TEXT NOT NULL CHECK(action IN ('verified','dismissed')),
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(user_id, finding_key)
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS gap_feedback (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            framework_version TEXT,
            control_id TEXT,
            chunk_text TEXT NOT NULL,
            embedding_blob BLOB NOT NULL,
            embedding_dim INTEGER NOT NULL,
            user_id INTEGER NOT NULL DEFAULT 0,
            reason TEXT,
            dismissed_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_gap_feedback_control ON gap_feedback(control_id)
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_gap_feedback_framework ON gap_feedback(framework_version)
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS report_edit_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            report_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            user_name TEXT NOT NULL,
            edit_type TEXT NOT NULL,
            field_changed TEXT,
            old_value TEXT,
            new_value TEXT,
            summary TEXT,
            edited_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(report_id) REFERENCES report(id),
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_report_edit_history_report ON report_edit_history(report_id)
    """)
    
    # Create audit_logs table for comprehensive user action logging
    conn.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            username TEXT,
            action TEXT NOT NULL,
            resource_type TEXT,
            resource_id TEXT,
            details TEXT,
            status TEXT DEFAULT 'success',
            ip_address TEXT,
            user_agent TEXT,
            timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_audit_logs_user ON audit_logs(user_id)
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp)
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action)
    """)
    conn.commit()
    conn.close()


def ensure_default_admin_user():
    """Ensure default admin account exists with known credentials."""
    conn = get_db_connection()
    try:
        users_table = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='users'"
        ).fetchone()
        if not users_table:
            return

        # Hash the default admin password securely
        hashed_admin_password = generate_password_hash("admin123")

        existing_admin = conn.execute(
            "SELECT id, role, password FROM users WHERE email = ?",
            ("admin@example.com",)
        ).fetchone()
        if existing_admin:
            # Only update if password isn't already hashed
            if not existing_admin["password"].startswith(('pbkdf2:', 'scrypt:')):
                conn.execute(
                    "UPDATE users SET password = ?, role = ? WHERE id = ?",
                    (hashed_admin_password, "admin", existing_admin["id"])
                )
                conn.commit()
                print("[INFO] Migrated admin password to secure hash for admin@example.com")
            return

        username = "admin"
        suffix = 1
        while conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone():
            username = f"admin_{suffix}"
            suffix += 1

        conn.execute(
            "INSERT INTO users (username, full_name, email, password, role) VALUES (?, ?, ?, ?, ?)",
            (username, "System Admin", "admin@example.com", hashed_admin_password, "admin")
        )
        conn.commit()
        print("[INFO] Seeded default admin user: admin@example.com")
    finally:
        conn.close()


init_db()
ensure_documents_versioning_schema()
ensure_default_admin_user()
# -*- coding: utf-8 -*-
"""
ComplyAI Flask Backend for PDF Upload and Advanced RAG Analysis

This Flask server handles:
1. PDF file uploads from the frontend
2. Triggering the Advanced RAG pipeline for NIST compliance gap analysis
3. Serving progress updates as batches are processed
4. Returning consolidated compliance findings

ARCHITECTURE:
- Frontend sends PDF → Backend saves file → RAG engine analyzes → Results returned to frontend
- Uses batch-based processing for better context and progress tracking
- Hybrid retrieval combines FAISS (dense vectors) + BM25 (keyword matching)
"""

import os
import logging
import time
import uuid
from flask import Flask, request, jsonify, send_from_directory, copy_current_request_context
from flask_cors import CORS
from werkzeug.utils import secure_filename
from rag.advanced_rag import AdvancedRAGEngine
from rag_chatbot import RAGChatbot

# Import new services
from services.questionnaire_engine import QuestionnaireEngine
from services.llm_service import LLMService
from services.report_exporter import ReportExporter
from services.risk_heatmap_service import RiskHeatMapService
from services.framework_service import FrameworkService
from models.report_models import (
    OrganizationInfo, QuestionAnswer, NISTFunction,
    FinalReport, QuestionType,
    RiskAppetiteProfile, HeatMapItem, RiskApproach, MaxAcceptableRisk,
    ImpactType, RiskTreatment, MitigationTimeline
)


# Ensure framework DB/table exists (migration)
try:
    from migrations.create_framework_table import run as _run_migration
    _run_migration()
except Exception:
    pass

# Initialize framework service (creates folders)
FrameworkService.init()

# ============================================
# CONFIGURATION
# ============================================

# Get the directory where this script is located (project root)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Define where uploaded PDFs are stored
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")

# Only allow PDF files to be uploaded for security
ALLOWED_EXTENSIONS = {"pdf"}


CORS(app)  # Allow Cross-Origin requests from the frontend

from flask_socketio import SocketIO, emit, join_room
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="eventlet")

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# ============================================
# IN-MEMORY STATUS TRACKING
# ============================================

# Dictionary to track analysis progress for each uploaded file
# Format: {filename: {status, processed_batches, total_batches, timestamp, error, etc}}
# This allows the frontend to poll /progress to see real-time analysis updates
ANALYSIS_STATUS = {}
ANALYSIS_STATUS_LOCK = threading.Lock()
ANALYSIS_TASK_THREADS = {}
ANALYSIS_CANCEL_EVENTS = {}
LATEST_ANALYSIS_BY_FILENAME = {}

# Dictionary to track report generation progress per questionnaire session
# Format: {session_id: {status, processed_steps, total_steps, stage, error, etc}}
REPORT_STATUS = {}

# ============================================
# INITIALIZE RAG ENGINE
# ============================================

# Initialize the Advanced RAG Engine instance
# Uses dynamic framework config when available, falls back to defaults
rag = AdvancedRAGEngine()

# Initialize standalone policy chatbot (separate from audit-agent chat)
chatbot = RAGChatbot()

# Initialize new services for questionnaire pipeline
questionnaire_engine = QuestionnaireEngine()
llm_service = LLMService()
report_exporter = ReportExporter()
heatmap_service = RiskHeatMapService()

logger = logging.getLogger(__name__)


# ============================================
# AUDIT LOGGING SYSTEM
# ============================================

class AuditLogger:
    """Comprehensive audit logging for user actions and system events."""
    
    @staticmethod
    def log(action: str, resource_type: str = None, resource_id: str = None, 
            details: str = None, status: str = "success", user_id: int = None, 
            username: str = None):
        """
        Log a user action to the audit_logs table.
        
        Args:
            action: Type of action (login, logout, create_report, delete_document, etc.)
            resource_type: Type of resource affected (report, document, user, framework, etc.)
            resource_id: ID of the resource affected
            details: Additional details in JSON format
            status: success/failure
            user_id: ID of user performing action (defaults to session user_id)
            username: Username of user performing action (defaults to session username)
        """
        try:
            # Get user info from session if not provided
            if user_id is None:
                user_id = session.get("user_id")
            
            if username is None:
                username = session.get("username", session.get("full_name", "unknown"))
            
            # Get IP address and user agent
            ip_address = request.remote_addr if request else None
            user_agent = request.headers.get('User-Agent')[:255] if request else None
            
            conn = get_db_connection()
            conn.execute("""
                INSERT INTO audit_logs 
                (user_id, username, action, resource_type, resource_id, details, status, ip_address, user_agent)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (user_id, username, action, resource_type, resource_id, details, status, ip_address, user_agent))
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"Error logging audit action '{action}': {str(e)}")
    
    @staticmethod
    def get_logs(limit: int = 100, user_id: int = None, action: str = None):
        """Retrieve audit logs with optional filtering."""
        try:
            conn = get_db_connection()
            query = "SELECT * FROM audit_logs WHERE 1=1"
            params = []
            
            if user_id:
                query += " AND user_id = ?"
                params.append(user_id)
            
            if action:
                query += " AND action = ?"
                params.append(action)
            
            query += " ORDER BY timestamp DESC LIMIT ?"
            params.append(limit)
            
            rows = conn.execute(query, params).fetchall()
            conn.close()
            return [dict(r) for r in rows]
        except Exception as e:
            logger.error(f"Error retrieving audit logs: {str(e)}")
            return []


# In-memory storage for reports and questionnaire sessions
REPORTS = {}
QUESTIONNAIRE_SESSIONS = {}
HEATMAP_REPORTS = {}  # Storage for heat-map reports


# ============================================
# HELPER FUNCTIONS
# ============================================

def allowed_file(filename):
    """
    Validate that uploaded file has a .pdf extension.

    Security: Prevents malicious file uploads (only PDFs allowed)
    """
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route("/frameworks", methods=["GET"])
def frameworks_ui():
    if "role" in session and session.get("role") not in ("owner", "admin"):
        return redirect(url_for("dashboard"))
    cfg = FrameworkService.get_config()
    return render_template("framework_management_admin.html", config=cfg, role=session.get("role"))


@app.route("/api/framework/status", methods=["GET"])
def framework_status():
    cfg = FrameworkService.get_config()
    if not cfg:
        return jsonify({"error": "no configuration"}), 404
    return jsonify({k: cfg[k] for k in cfg.keys()})


@app.route("/api/framework/upload", methods=["POST"])
def framework_upload():
    # Role check: in production enforce owner/admin only
    if "role" in session and session.get("role") not in ("owner", "admin"):
        return jsonify({"error": "forbidden"}), 403

    files = request.files.getlist("files")
    source_url = request.form.get("source_url")
    source_json_raw = request.form.get("source_json")

    source_json = None
    if source_json_raw:
        try:
            source_json = json.loads(source_json_raw)
        except Exception:
            return jsonify({"error": "source_json must be valid JSON"}), 400

    if not files and not source_url and source_json is None:
        return jsonify({"error": "provide files, source_url, or source_json"}), 400

    MAX_SIZE = 25 * 1024 * 1024  # 25MB per file
    for f in files:
        if not allowed_file(f.filename):
            return jsonify({"error": "only PDF allowed for file uploads"}), 400
        f.seek(0, os.SEEK_END)
        size = f.tell()
        f.seek(0)
        if size > MAX_SIZE:
            return jsonify({"error": f"file too large: {f.filename}"}), 400

    tmp_root = os.path.join(app.config.get("UPLOAD_FOLDER"), "framework_uploads")
    os.makedirs(tmp_root, exist_ok=True)
    saved = []
    for f in files:
        filename = secure_filename(f.filename)
        dest = os.path.join(tmp_root, f"{uuid.uuid4().hex}_{filename}")
        f.save(dest)
        saved.append(dest)

    name = request.form.get("name", "custom-framework")
    version = request.form.get("version", "latest")
    version_id = request.form.get("version_id") or None
    description = request.form.get("description", "Uploaded by admin")
    embedding_model = request.form.get("embedding_model", "qwen3-embedding")
    user = session.get("full_name") or session.get("user_id") or "unknown"

    try:
        job_id = FrameworkService.start_shadow_rebuild(
            name=name,
            version_label=version,
            version_id=version_id,
            description=description,
            embedding_model=embedding_model,
            user=user,
            uploaded_files=saved if saved else None,
            source_url=source_url,
            source_json=source_json,
        )
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 409
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    return jsonify({"job_id": job_id, "status": "started"})


@app.route("/api/framework/versions", methods=["GET"])
def framework_versions():
    cfg = FrameworkService.get_config()
    active_version_id = cfg["version_id"] if cfg and "version_id" in cfg.keys() else None

    conn = get_db_connection()
    rows = conn.execute(
        """
        SELECT version_id, framework_name, version_label, description, embedding_model,
               vector_store_path, created_at, created_by, source_type, source_ref,
               chunk_count, status, is_active
        FROM framework_versions
        ORDER BY datetime(created_at) DESC
        """
    ).fetchall()
    conn.close()

    result = []
    for row in rows:
        d = dict(row)
        if active_version_id and d.get("version_id") == active_version_id:
            d["is_active"] = 1
        result.append(d)

    return jsonify({
        "active_version_id": active_version_id,
        "versions": result,
    })


@app.route("/api/framework/activate", methods=["POST"])
def framework_activate():
    if "role" in session and session.get("role") not in ("owner", "admin"):
        return jsonify({"error": "forbidden"}), 403

    data = request.get_json(silent=True) or {}
    version_id = data.get("version_id")
    if not version_id:
        return jsonify({"error": "version_id is required"}), 400

    row = FrameworkService.get_framework_version(version_id)
    if not row:
        return jsonify({"error": "framework version not found"}), 404

    user = session.get("full_name") or session.get("user_id") or "unknown"
    now = datetime.utcnow().isoformat()

    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("UPDATE framework_versions SET is_active = 0")
        cur.execute("UPDATE framework_versions SET is_active = 1 WHERE version_id = ?", (version_id,))
        cur.execute(
            """
            UPDATE framework_config
            SET name = ?, version = ?, version_id = ?, description = ?, embedding_model = ?,
                vector_store_path = ?, last_updated_at = ?, status = 'ready', updated_by = ?
            WHERE id = 1
            """,
            (
                row["framework_name"],
                row["version_label"],
                row["version_id"],
                row["description"],
                row["embedding_model"],
                row["vector_store_path"],
                now,
                user,
            ),
        )
        conn.commit()
    finally:
        conn.close()

    FrameworkService.audit(
        "manual_activate",
        f"Activated framework version {version_id}",
        performed_by=str(user),
    )

    return jsonify({"status": "ready", "active_version_id": version_id})


@app.route("/api/framework/audit_logs", methods=["GET"])
def framework_audit_logs():
    # Return recent audit log entries (most recent first)
    try:
        limit = int(request.args.get('limit', 50))
    except Exception:
        limit = 50

    conn = get_db_connection()
    rows = conn.execute(
        "SELECT id, event_type, message, created_at FROM framework_audit_log ORDER BY created_at DESC LIMIT ?",
        (limit,)
    ).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


# --- User Action Audit Logs ---
@app.route("/api/audit-logs", methods=["GET"])
def get_audit_logs():
    """Get audit logs for user actions. Admin can see all, users see only their own."""
    if not session.get("user_id"):
        return jsonify({"error": "Authentication required"}), 401
    
    try:
        limit = int(request.args.get('limit', 100))
        limit = min(limit, 1000)  # Cap at 1000
    except Exception:
        limit = 100
    
    role = session.get("role")
    user_id = session.get("user_id")
    
    if role not in ("admin", "owner"):
        # Regular users can only see their own logs
        logs = AuditLogger.get_logs(limit=limit, user_id=user_id)
    else:
        # Admins can see all logs or filter by user
        filter_user = request.args.get('user_id', type=int)
        logs = AuditLogger.get_logs(limit=limit, user_id=filter_user)
    
    return jsonify(logs)


@app.route("/api/audit-logs/summary", methods=["GET"])
def get_audit_logs_summary():
    """Get summary statistics of audit logs (admin only)."""
    if session.get("role") not in ("admin", "owner"):
        return jsonify({"error": "Admin access required"}), 403
    
    conn = get_db_connection()
    
    # Get action breakdown
    actions = conn.execute("""
        SELECT action, COUNT(*) as count FROM audit_logs GROUP BY action ORDER BY count DESC
    """).fetchall()
    
    # Get failure count
    failures = conn.execute("SELECT COUNT(*) as count FROM audit_logs WHERE status = 'failure'").fetchone()
    
    # Get today's activity
    today_activity = conn.execute("""
        SELECT COUNT(*) as count FROM audit_logs 
        WHERE date(timestamp) = date('now')
    """).fetchone()
    
    # Get by user (top 10)
    by_user = conn.execute("""
        SELECT username, COUNT(*) as count FROM audit_logs 
        GROUP BY username ORDER BY count DESC LIMIT 10
    """).fetchall()
    
    conn.close()
    
    return jsonify({
        "actions": [dict(r) for r in actions],
        "total_failures": failures["count"],
        "today_activity": today_activity["count"],
        "top_users": [dict(r) for r in by_user]
    })


@app.route("/api/audit-logs/<int:log_id>", methods=["GET"])
def get_audit_log_detail(log_id):
    """Get details of a specific audit log entry (admin only or own entry)."""
    if not session.get("user_id"):
        return jsonify({"error": "Authentication required"}), 401
    
    conn = get_db_connection()
    log = conn.execute("SELECT * FROM audit_logs WHERE id = ?", (log_id,)).fetchone()
    conn.close()
    
    if not log:
        return jsonify({"error": "Log entry not found"}), 404
    
    # Check authorization
    if session.get("role") not in ("admin", "owner") and log["user_id"] != session.get("user_id"):
        return jsonify({"error": "Not authorized"}), 403
    
    return jsonify(dict(log))


# --- Home ---
@app.route("/")
def home():
    return redirect(url_for("login"))

# --- Login ---
@app.route("/login", methods=["GET", "POST"])
def login():
    # GET: Auth0 SSO redirect if configured and not mock mode, otherwise render local login page
    if request.method == "GET":
        if AUTH0_DOMAIN and not AUTH0_MOCK_MODE:
            return redirect(f"https://{AUTH0_DOMAIN}/authorize?response_type=code&client_id={AUTH0_CLIENT_ID}&redirect_uri={AUTH0_CALLBACK_URL}&scope=openid profile email&audience={AUTH0_AUDIENCE or ''}")
        error = request.args.get("error")
        return render_template("login.html", error=error, auth0_mock_mode=AUTH0_MOCK_MODE)

    # POST: Local login or mock Auth0 demo login
    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")

    if not email or not password:
        AuditLogger.log("login_attempt", "user", email or "unknown", "Missing credentials", "failure")
        return redirect(url_for("login", error="Email and password are required."))

    # First check real DB users
    conn = get_db_connection()
    user = conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()

    if user and check_password_hash(user["password"], password):
        session["user_id"] = user["id"]
        session["role"] = user["role"]
        session["full_name"] = user["full_name"]
        session["auth0_id"] = user.get("auth0_id") if "auth0_id" in user.keys() else None
        session.permanent = True
        conn.close()
        
        # Log successful login
        AuditLogger.log("login", "user", user["id"], f"User {user['full_name']} logged in", "success", 
                       user_id=user["id"], username=email)
        return redirect(url_for("dashboard"))

    # If Auth0 mock mode is on, allow demo accounts
    if AUTH0_MOCK_MODE and email in MOCK_AUTH0_USERS and MOCK_AUTH0_USERS[email]["password"] == password:
        demo_user = MOCK_AUTH0_USERS[email]
        # Ensure demo user exists in local DB (for session/user mapping)
        if not user:
            conn.execute(
                "INSERT INTO users (username, full_name, email, password, role) VALUES (?, ?, ?, ?, ?)",
                (email.split("@")[0], demo_user["full_name"], email, generate_password_hash(password), demo_user["role"])
            )
            conn.commit()
            user = conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()

        conn.close()
        session["user_id"] = user["id"]
        session["role"] = demo_user["role"]
        session["full_name"] = demo_user["full_name"]
        session["auth0_id"] = demo_user["sub"]
        session.permanent = True
        
        # Log successful demo login
        AuditLogger.log("login", "user", user["id"], f"Demo user {demo_user['full_name']} logged in", "success",
                       user_id=user["id"], username=email)
        return redirect(url_for("dashboard"))

    conn.close()
    
    # Log failed login attempt
    AuditLogger.log("login_attempt", "user", email, "Invalid credentials", "failure")
    return redirect(url_for("login", error="Invalid username or password. Please try again."))

# --- Auth0 Callback ---
@app.route("/callback")
def callback():
    if not AUTH0_DOMAIN:
        return redirect(url_for("login", error="Auth0 not configured"))

    code = request.args.get("code")
    if not code:
        return redirect(url_for("login", error="Authorization code missing"))

    try:
        # Exchange code for tokens
        token_response = token_getter.authorization_code(
            code=code,
            redirect_uri=AUTH0_CALLBACK_URL
        )

        # Decode ID token to get user info
        id_token = token_response['id_token']
        payload = jwt.get_unverified_claims(id_token)

        # Extract user information
        user_id = payload.get('sub')
        email = payload.get('email')
        full_name = payload.get('name', payload.get('nickname', email))

        # Check if user exists in local database, create if not
        conn = get_db_connection()
        user = conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()

        if not user:
            # Create new user from Auth0 profile
            conn.execute("""
                INSERT INTO users (full_name, email, role)
                VALUES (?, ?, 'user')
            """, (full_name, email))
            conn.commit()
            user = conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()

        conn.close()

        # Set session
        session["user_id"] = user["id"]
        session["role"] = user["role"]
        session["full_name"] = user["full_name"]
        session["auth0_id"] = user_id
        session.permanent = True

        # Log Auth0 login
        AuditLogger.log("login_auth0", "user", user["id"], f"Auth0 user {full_name} logged in", "success",
                       user_id=user["id"], username=email)

        return redirect(url_for("dashboard"))

    except Exception as e:
        print(f"Auth0 callback error: {e}")
        return redirect(url_for("login", error="Authentication failed"))

# --- Logout ---
@app.route("/logout")
def logout():
    # Log logout before clearing session
    user_id = session.get("user_id")
    username = session.get("full_name", "unknown")
    AuditLogger.log("logout", "user", user_id, f"User {username} logged out", "success",
                   user_id=user_id, username=username)
    
    session.clear()
    if AUTH0_DOMAIN:
        # Redirect to Auth0 logout
        logout_url = f"https://{AUTH0_DOMAIN}/v2/logout?client_id={AUTH0_CLIENT_ID}&returnTo={url_for('login', _external=True)}"
        return redirect(logout_url)
    return redirect(url_for("login"))

# --- Readme / About ---
@app.route("/readme")
def readme():
    user_id = session.get("user_id")
    if not user_id:
        return redirect(url_for("login"))
    
    db = get_db_connection()
    user = db.execute("SELECT full_name, role FROM users WHERE id = ?", (user_id,)).fetchone()
    db.close()
    
    return render_template("readme.html", 
                           full_name=user["full_name"] if user else "User",
                           role=user["role"] if user else "user",
                           user_id=user_id)

# --- Dashboard ---
@app.route("/dashboard")
def dashboard():
    user_id = session.get("user_id")
    role = session.get("role")
    is_admin = role == "admin"

    db = get_db_connection()

    # --- Fetch recent documents ---
    if is_admin:
        recent_documents = db.execute("""
            SELECT d.id, d.documentTitle, d.uploadDate, d.dueDate, d.user_id, u.full_name as user_name, 
                   json_extract(r.compliance_summary, '$.compliance_percentage') as compliance_score, d.Review as review
            FROM documents d
            LEFT JOIN report r ON d.id = r.document_id
            LEFT JOIN users u ON d.user_id = u.id
            ORDER BY d.uploadDate DESC
            LIMIT 10
        """).fetchall()

        all_docs = db.execute("""
            SELECT d.id, d.documentTitle, d.dueDate, d.user_id, u.full_name as user_name, 
                   json_extract(r.compliance_summary, '$.compliance_percentage') as compliance_score, d.Review as review
            FROM documents d
            LEFT JOIN report r ON d.id = r.document_id
            LEFT JOIN users u ON d.user_id = u.id
        """).fetchall()
    else:
        recent_documents = db.execute("""
            SELECT d.id, d.documentTitle, d.uploadDate, d.dueDate, 
                   json_extract(r.compliance_summary, '$.compliance_percentage') as compliance_score, d.Review as review
            FROM documents d
            LEFT JOIN report r ON d.id = r.document_id AND r.user_id = ?
            WHERE d.user_id = ?
            ORDER BY d.uploadDate DESC
            LIMIT 10
        """, (user_id, user_id)).fetchall()

        all_docs = db.execute("""
            SELECT d.id, d.documentTitle, d.dueDate, 
                   json_extract(r.compliance_summary, '$.compliance_percentage') as compliance_score, d.Review as review
            FROM documents d
            LEFT JOIN report r ON d.id = r.document_id AND r.user_id = ?
            WHERE d.user_id = ?
        """, (user_id, user_id)).fetchall()

    # --- Filter critical documents: due in <= 5 days ---
    critical_documents = []
    today = datetime.now()
    for doc in all_docs:
        if doc['dueDate']:
            due_date = datetime.strptime(doc['dueDate'], "%Y-%m-%d")
            days_left = (due_date - today).days
            if days_left <= 5:
                critical_documents.append(doc)

    # Sort critical docs by nearest due date
    critical_documents.sort(key=lambda x: datetime.strptime(x['dueDate'], "%Y-%m-%d"))

    # --- Counts ---
    if is_admin:
        total_documents = db.execute("SELECT COUNT(*) FROM documents").fetchone()[0]
        under_review_documents = db.execute("SELECT COUNT(*) FROM documents WHERE Review='Under Review'").fetchone()[0]
        compliant_documents = db.execute("SELECT COUNT(*) FROM documents WHERE Review='Compliant'").fetchone()[0]
    else:
        total_documents = db.execute("SELECT COUNT(*) FROM documents WHERE user_id=?", (user_id,)).fetchone()[0]
        under_review_documents = db.execute("""
            SELECT COUNT(*) 
            FROM documents 
            WHERE user_id=? AND Review='Under Review'
        """, (user_id,)).fetchone()[0]
        compliant_documents = db.execute("""
            SELECT COUNT(*) 
            FROM documents 
            WHERE user_id=? AND Review='Compliant'
        """, (user_id,)).fetchone()[0]

    # --- Notifications ---
    notifications = db.execute("""
        SELECT id, message, created_at, document_id, read
        FROM notifications
        WHERE user_id=? AND read=0
        ORDER BY created_at DESC
        LIMIT 20
    """, (user_id,)).fetchall()

    unread_count = db.execute("""
        SELECT COUNT(*) 
        FROM notifications 
        WHERE user_id=? AND read=0
    """, (user_id,)).fetchone()[0]

    db.close()

    # --- Template ---
    template_name = "dashboardAdmin.html" if is_admin else "dashboard.html"

    return render_template(
        template_name,
        full_name=session.get("full_name"),
        total_documents=total_documents,
        under_review_documents=under_review_documents,
        compliant_documents=compliant_documents,
        recent_documents=recent_documents,
        critical_documents=critical_documents,
        notifications=notifications,
        unread_count=unread_count,
        role=role,
        user_id=user_id
    )


# --- Chat Page ---
@app.route("/chat")
def chat_page():
    user_id = session.get("user_id")
    if not user_id:
        return redirect(url_for("login"))
    return render_template(
        "chat.html",
        full_name=session.get("full_name"),
        role=session.get("role"),
        user_id=user_id
    )


# --- Shared Documents Page ---
@app.route("/shared-documents")
def shared_documents_page():
    user_id = session.get("user_id")
    if not user_id:
        return redirect(url_for("login"))
    return render_template(
        "shared_documents.html",
        full_name=session.get("full_name"),
        role=session.get("role"),
        user_id=user_id
    )


# --- Mark Notification as Read ---
@app.route("/notifications/mark_read/<int:notification_id>", methods=["POST"])
def mark_notification_read(notification_id):
    user_id = session.get("user_id")
    db = get_db_connection()
    db.execute("UPDATE notifications SET read=1 WHERE id=? AND user_id=?", (notification_id, user_id))
    db.commit()
    db.close()
    return '', 204


@app.route("/notifications/clear_read", methods=["POST"])
def clear_read_notifications():
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401

    db = get_db_connection()
    db.execute("DELETE FROM notifications WHERE user_id=? AND read=1", (user_id,))
    db.commit()
    db.close()
    return '', 204


@app.route("/api/assessments/<assessment_id>/compliance-summary", methods=["GET"])
def get_assessment_compliance_summary(assessment_id):
    """
    Returns per-function compliance percentages (Govern, Identify, Protect) and overall for
    a questionnaire session id or a saved report id.
    """
    try:
        # Try questionnaire session
        if assessment_id in QUESTIONNAIRE_SESSIONS:
            session = QUESTIONNAIRE_SESSIONS[assessment_id]
            answers = session.get("answers", [])
            summary = questionnaire_engine.compute_compliance_by_function(answers)
            return jsonify(summary)

        # Try stored report
        if assessment_id in REPORTS:
            report = REPORTS[assessment_id]["report"]
            answers = getattr(report, "questionnaire_answers", []) or []
            summary = questionnaire_engine.compute_compliance_by_function(answers)
            return jsonify(summary)

        # Fall back to DB lookup: try to find report row by numeric id
        try:
            db = get_db_connection()
            rid = int(assessment_id)
            row = db.execute("SELECT compliance_summary, gap_analysis FROM report WHERE id = ?", (rid,)).fetchone()
        except Exception:
            row = None

        if row:
            # Try to compute compliance per function from gap_analysis (gaps grouped by nist_function)
            import json as _json
            try:
                gap_analysis = _json.loads(row["gap_analysis"]) if row["gap_analysis"] else []
            except Exception:
                try:
                    gap_analysis = _json.loads(row[0]) if row[0] else []
                except Exception:
                    gap_analysis = []

            # Count gaps per function — all 6 NIST functions
            gaps_count = {"Govern": 0, "Identify": 0, "Protect": 0, "Detect": 0, "Respond": 0, "Recover": 0}
            for g in gap_analysis:
                try:
                    func = g.get("nist_function") if isinstance(g, dict) else None
                    if not func:
                        func = g.get("nist_function", None) if isinstance(g, dict) else None
                    if func and func in gaps_count:
                        gaps_count[func] += 1
                except Exception:
                    continue

            # Determine total questions per function from questionnaire engine — all 6 functions
            totals = {}
            for f in [NISTFunction.GOVERN, NISTFunction.IDENTIFY, NISTFunction.PROTECT, NISTFunction.DETECT, NISTFunction.RESPOND, NISTFunction.RECOVER]:
                try:
                    totals[f.value] = questionnaire_engine.get_function_summary(f)["total_questions"]
                except Exception:
                    totals[f.value] = 0

            results = {}
            total_gaps = 0
            total_qs = 0
            for fname in ["Govern", "Identify", "Protect", "Detect", "Respond", "Recover"]:
                tq = totals.get(fname, 0) or 0
                gc = gaps_count.get(fname, 0)
                total_gaps += gc
                total_qs += tq
                if tq == 0:
                    pct = 0.0
                else:
                    pct = round(max(0.0, 100.0 * (1.0 - (gc / tq))), 1)
                results[fname.lower()] = pct

            if total_qs == 0:
                results["overall"] = 0.0
            else:
                results["overall"] = round(100.0 * (1.0 - (total_gaps / total_qs)), 1)

            db.close()
            return jsonify(results)

        return jsonify({"error": "Assessment not found"}), 404
    except Exception as e:
        return jsonify({"error": f"Failed to compute compliance summary: {str(e)}"}), 500

# --- Documents page ---
@app.route("/documents")
def documents():
    user_id = session.get("user_id")
    is_admin = session.get("role") == "admin"

    # Get filter parameters
    due_date_from = request.args.get("due_date_from", "")
    due_date_to = request.args.get("due_date_to", "")
    review_status = request.args.get("review_status", "")
    show_inactive = request.args.get("show_inactive", "0") == "1"

    db = get_db_connection()
    
    # Build query with filters
    base_query = "SELECT * FROM documents WHERE 1=1"
    params = []

    # Default to active versions only unless explicitly toggled.
    if not show_inactive:
        base_query += " AND COALESCE(is_active, 1) = 1"
    
    # Apply user filter for non-admin
    if not is_admin:
        base_query += " AND user_id = ?"
        params.append(user_id)
    
    # Apply due date range filter
    if due_date_from:
        base_query += " AND dueDate >= ?"
        params.append(due_date_from)
    if due_date_to:
        base_query += " AND dueDate <= ?"
        params.append(due_date_to)
    
    # Apply review status filter
    if review_status:
        base_query += " AND Review = ?"
        params.append(review_status)
    
    # Show most recent documents first
    base_query += " ORDER BY uploadDate DESC, id DESC"
    
    docs = db.execute(base_query, params).fetchall()

    import json
    documents_with_compliance = []
    for doc in docs:
        doc_dict = dict(doc)
        # Fetch only compliance_results for this user and document
        if is_admin:
            compliance_results = db.execute(
                "SELECT * FROM compliance_results WHERE document_id = ? ORDER BY created_at DESC",
                (doc_dict["id"],)
            ).fetchall()
            report_rows = db.execute(
                "SELECT * FROM report WHERE document_id = ? ORDER BY created_at DESC",
                (doc_dict["id"],)
            ).fetchall()
        else:
            compliance_results = db.execute(
                "SELECT * FROM compliance_results WHERE document_id = ? AND user_id = ? ORDER BY created_at DESC",
                (doc_dict["id"], user_id)
            ).fetchall()
            report_rows = db.execute(
                "SELECT * FROM report WHERE document_id = ? AND user_id = ? ORDER BY created_at DESC",
                (doc_dict["id"], user_id)
            ).fetchall()
        compliance_results_list = []
        for r in compliance_results:
            r_dict = dict(r)
            try:
                parsed_json = json.loads(r_dict["results_json"])
                if isinstance(parsed_json, list):
                    r_dict["results_json"] = {"compliance_gaps": parsed_json}
                else:
                    r_dict["results_json"] = parsed_json
            except Exception:
                r_dict["results_json"] = {"compliance_gaps": []}
            compliance_results_list.append(r_dict)
        # Fetch compliance rows (legacy/dummy)
        compliance_rows = db.execute("SELECT * FROM compliance WHERE document_id = ?", (doc_dict["id"],)).fetchall()
        compliance_list = [dict(c) for c in compliance_rows]
        # Parse report table rows
        report_cards = []
        for rep in report_rows:
            rep_dict = _parse_report_row(rep, db=db)
            report_cards.append(rep_dict)

        history_versions = []
        version_group_id = doc_dict.get("version_group_id")
        if version_group_id:
            if is_admin:
                history_rows = db.execute(
                    """
                    SELECT * FROM documents
                    WHERE version_group_id = ?
                      AND id != ?
                      AND COALESCE(is_active, 1) = 0
                    ORDER BY COALESCE(deactivated_at, uploadDate) DESC, id DESC
                    """,
                    (version_group_id, doc_dict["id"]),
                ).fetchall()
            else:
                history_rows = db.execute(
                    """
                    SELECT * FROM documents
                    WHERE version_group_id = ?
                      AND id != ?
                      AND user_id = ?
                      AND COALESCE(is_active, 1) = 0
                    ORDER BY COALESCE(deactivated_at, uploadDate) DESC, id DESC
                    """,
                    (version_group_id, doc_dict["id"], user_id),
                ).fetchall()

            for h in history_rows:
                h_dict = dict(h)
                history_score = _get_latest_document_compliance_score(
                    db,
                    h_dict["id"],
                    None if is_admin else user_id,
                )
                h_dict["latest_compliance_score"] = history_score
                history_versions.append(h_dict)

        documents_with_compliance.append({
            "doc": doc_dict,
            "compliance": compliance_list,
            "compliance_results": compliance_results_list,
            "report_cards": report_cards,
            "history_versions": history_versions,
        })
    db.close()

    # Fetch documents shared with this user (viewer role)
    db2 = get_db_connection()
    user_row = db2.execute("SELECT email FROM users WHERE id=?", (user_id,)).fetchone()
    viewer_email = user_row["email"].lower() if user_row else ""
    shared_rows = db2.execute(
        "SELECT d.id, d.documentTitle, d.uploadDate, d.dueDate, d.Review, "
        "u.full_name AS owner_name, c.invited_at "
        "FROM collaborators c "
        "JOIN documents d ON c.document_id = d.id "
        "JOIN users u ON c.owner_id = u.id "
        "WHERE (c.viewer_id=? OR c.viewer_email=?) AND c.status='active' "
        "ORDER BY c.invited_at DESC",
        (user_id, viewer_email),
    ).fetchall()
    shared_documents = [dict(r) for r in shared_rows]
    db2.close()

    return render_template(
        "documents.html",
        documents=documents_with_compliance,
        shared_documents=shared_documents,
        is_admin=is_admin,
        role=session.get("role"),
        full_name=session.get("full_name"),
        user_id=user_id,
        show_inactive=show_inactive,
    )


@app.route("/documents/<int:doc_id>/download", methods=["GET"])
def download_document_version(doc_id):
    """Download a specific document version file (active or inactive)."""
    user_id = session.get("user_id")
    if not user_id:
        return redirect(url_for("login"))

    user_email = (session.get("email") or "").lower()
    role = session.get("role")

    db = get_db_connection()
    try:
        doc = db.execute("SELECT * FROM documents WHERE id = ?", (doc_id,)).fetchone()
        if not doc:
            return "Document not found", 404

        owner_id = doc["user_id"]
        has_access = role == "admin" or owner_id == user_id
        if not has_access:
            if not user_email:
                row = db.execute("SELECT email FROM users WHERE id = ?", (user_id,)).fetchone()
                user_email = (row["email"] if row else "").lower()

            collab = db.execute(
                """
                SELECT id FROM collaborators
                WHERE document_id = ?
                  AND status = 'active'
                  AND (viewer_id = ? OR lower(viewer_email) = ?)
                LIMIT 1
                """,
                (doc_id, user_id, user_email),
            ).fetchone()
            has_access = collab is not None

        if not has_access:
            return "Unauthorized", 403

        filename = doc["fileName"]
        if not filename:
            return "No file available for this version", 404

        file_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        if not os.path.exists(file_path):
            return "File not found on disk", 404

        return send_from_directory(app.config["UPLOAD_FOLDER"], filename, as_attachment=True)
    finally:
        db.close()


@app.route("/api/documents/compare-scores", methods=["GET"])
def compare_document_scores():
    """Compare latest compliance scores between active and historical document versions."""
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"error": "Not authenticated"}), 401

    active_document_id = request.args.get("active_document_id", type=int)
    historical_document_id = request.args.get("historical_document_id", type=int)
    if not active_document_id or not historical_document_id:
        return jsonify({"error": "active_document_id and historical_document_id are required"}), 400

    db = get_db_connection()
    try:
        if session.get("role") == "admin":
            active_doc = db.execute("SELECT * FROM documents WHERE id = ?", (active_document_id,)).fetchone()
            historical_doc = db.execute("SELECT * FROM documents WHERE id = ?", (historical_document_id,)).fetchone()
        else:
            active_doc = db.execute(
                "SELECT * FROM documents WHERE id = ? AND user_id = ?",
                (active_document_id, user_id),
            ).fetchone()
            historical_doc = db.execute(
                "SELECT * FROM documents WHERE id = ? AND user_id = ?",
                (historical_document_id, user_id),
            ).fetchone()

        if not active_doc or not historical_doc:
            return jsonify({"error": "One or both documents not found or unauthorized"}), 404

        score_user_id = None if session.get("role") == "admin" else user_id
        active_score_details = _get_latest_document_compliance_score_details(db, active_document_id, score_user_id)
        historical_score_details = _get_latest_document_compliance_score_details(db, historical_document_id, score_user_id)
        active_score = active_score_details["score"]
        historical_score = historical_score_details["score"]

        delta = None
        if active_score is not None and historical_score is not None:
            try:
                delta = round(float(active_score) - float(historical_score), 2)
            except Exception:
                delta = None

        return jsonify({
            "active_document_id": active_document_id,
            "historical_document_id": historical_document_id,
            "active_score": active_score,
            "historical_score": historical_score,
            "delta": delta,
            "active_score_source": active_score_details["source"],
            "historical_score_source": historical_score_details["source"],
            "note": "A score of 0 means that version has a persisted compliance percentage of 0.0 in saved report or analysis data; it does not necessarily mean the compare feature failed.",
        })
    finally:
        db.close()


@app.route("/documents/<int:doc_id>/reactivate", methods=["POST"])
def reactivate_document_version(doc_id):
    """Promote an inactive historical version back to the active document version."""
    user_id = session.get("user_id")
    if not user_id:
        return redirect(url_for("login"))

    db = get_db_connection()
    try:
        if session.get("role") == "admin":
            target_doc = db.execute("SELECT * FROM documents WHERE id = ?", (doc_id,)).fetchone()
        else:
            target_doc = db.execute(
                "SELECT * FROM documents WHERE id = ? AND user_id = ?",
                (doc_id, user_id),
            ).fetchone()

        if not target_doc:
            return "Document not found or unauthorized", 404

        target_doc = dict(target_doc)
        version_group_id = target_doc.get("version_group_id") or f"vg_{target_doc.get('unique_id') or target_doc.get('id')}"
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        current_active = db.execute(
            """
            SELECT id FROM documents
            WHERE version_group_id = ?
              AND id != ?
              AND COALESCE(is_active, 1) = 1
            ORDER BY id DESC
            LIMIT 1
            """,
            (version_group_id, doc_id),
        ).fetchone()

        if current_active:
            db.execute(
                "UPDATE documents SET is_active = 0, deactivated_at = ? WHERE id = ?",
                (now_str, current_active["id"]),
            )

        db.execute(
            "UPDATE documents SET is_active = 1, deactivated_at = NULL WHERE id = ?",
            (doc_id,),
        )
        db.commit()
    finally:
        db.close()

    return redirect(request.referrer or url_for("documents"))

# --- Update review ---
@app.route("/update_review", methods=["POST"])
def update_review():
    if session.get("role") != "admin":
        return "Unauthorized", 403

    document_id = request.form.get("document_id")
    new_status = request.form.get("new_status")

    db = get_db_connection()
    doc = db.execute("""
        SELECT id, user_id
        FROM documents
        WHERE id = ?
    """, (document_id,)).fetchone()

    if doc:
        db.execute("UPDATE documents SET Review = ? WHERE id = ?", (new_status, document_id))
        db.execute(
            "INSERT INTO notifications (user_id, message, document_id, read) VALUES (?, ?, ?, 0)",
            (doc["user_id"], f"Your document review status changed to {new_status}", doc["id"])
        )

    db.commit()
    db.close()
    return redirect(url_for("documents"))

# --- Calendar page ---
@app.route("/calendar")
def calendar():
    user_id = session.get("user_id")
    is_admin = session.get("role") == "admin"
    full_name = session.get("full_name", "User")
    
    db = get_db_connection()
    
    # Admin sees all documents, user sees only their own
    if is_admin:
        docs = db.execute("SELECT id, documentTitle, dueDate, Review FROM documents WHERE dueDate IS NOT NULL AND dueDate != ''").fetchall()
    else:
        docs = db.execute("SELECT id, documentTitle, dueDate, Review FROM documents WHERE user_id = ? AND dueDate IS NOT NULL AND dueDate != ''", (user_id,)).fetchall()
    
    documents = [dict(doc) for doc in docs]
    db.close()
    
    return render_template(
        "calender.html",
        documents=documents,
        full_name=full_name,
        role=session.get("role"),
        user_id=user_id
    )

# --- Notes CRUD Routes ---
@app.route("/notes", methods=["GET"])
def get_notes():
    """Get all notes for the current user"""
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401
    
    db = get_db_connection()
    notes = db.execute(
        "SELECT id, note_date, title, content, created_at, updated_at FROM notes WHERE user_id = ? ORDER BY note_date",
        (user_id,)
    ).fetchall()
    db.close()
    
    return jsonify([dict(note) for note in notes])

@app.route("/notes", methods=["POST"])
def create_note():
    """Create a new note"""
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401
    
    data = request.get_json()
    note_date = data.get("note_date")
    title = data.get("title")
    content = data.get("content", "")
    
    if not note_date or not title:
        return jsonify({"error": "Date and title are required"}), 400
    
    db = get_db_connection()
    cursor = db.execute(
        "INSERT INTO notes (user_id, note_date, title, content) VALUES (?, ?, ?, ?)",
        (user_id, note_date, title, content)
    )
    db.commit()
    note_id = cursor.lastrowid
    db.close()
    
    return jsonify({"success": True, "id": note_id})

@app.route("/notes/<int:note_id>", methods=["PUT"])
def update_note(note_id):
    """Update an existing note"""
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401
    
    data = request.get_json()
    title = data.get("title")
    content = data.get("content", "")
    note_date = data.get("note_date")
    
    if not title:
        return jsonify({"error": "Title is required"}), 400
    
    db = get_db_connection()
    # Verify ownership
    note = db.execute("SELECT user_id FROM notes WHERE id = ?", (note_id,)).fetchone()
    if not note or note["user_id"] != user_id:
        db.close()
        return jsonify({"error": "Note not found or unauthorized"}), 404
    
    db.execute(
        "UPDATE notes SET title = ?, content = ?, note_date = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
        (title, content, note_date, note_id)
    )
    db.commit()
    db.close()
    
    return jsonify({"success": True})

@app.route("/notes/<int:note_id>", methods=["DELETE"])
def delete_note(note_id):
    """Delete a note"""
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401
    
    db = get_db_connection()
    # Verify ownership
    note = db.execute("SELECT user_id FROM notes WHERE id = ?", (note_id,)).fetchone()
    if not note or note["user_id"] != user_id:
        db.close()
        return jsonify({"error": "Note not found or unauthorized"}), 404
    
    db.execute("DELETE FROM notes WHERE id = ?", (note_id,))
    db.commit()
    db.close()
    
    return jsonify({"success": True})


@app.route("/dashboard/admin")
def dashboardAdmin():
    if session.get("role") != "admin":
        return "Unauthorized", 403  # Or redirect to /dashboard
    return dashboard()


# --- Admin Users Page ---
@app.route("/admin/users")
def admin_users():
    if session.get("role") != "admin":
        return "Unauthorized", 403

    db = get_db_connection()
    users = db.execute("SELECT id, full_name, email, role FROM users").fetchall()
    db.close()

    return render_template(
        "admin_users.html",
        full_name=session.get("full_name"),
        role=session.get("role"),
        users=users
    )

# --- Delete User ---
@app.route("/admin/users/delete/<int:user_id>", methods=["POST","GET"])
def delete_user(user_id):
    if session.get("role") != "admin":
        return "Unauthorized", 403
    db = get_db_connection()
    db.execute("DELETE FROM users WHERE id = ?", (user_id,))
    db.commit()
    db.close()
    return jsonify({"success": True})



###add user
# --- Add user (admin) with notifications ---
@app.route("/admin/users/add", methods=["POST"])
def add_user():
    if session.get("role") != "admin":
        return "Unauthorized", 403

    username = request.form.get("username")
    full_name = request.form.get("full_name")
    email = request.form.get("email")
    role = request.form.get("role")
    password = request.form.get("password")

    if not all([full_name, email, role, password]):
        AuditLogger.log("user_create", "user", email, "Failed: Missing required fields", "failure")
        return jsonify({"success": False, "error": "All fields are required"})

    # Hash password securely before storing
    hashed_password = generate_password_hash(password)

    # Use email as username if not provided
    if not username:
        username = email

    db = get_db_connection()
    try:
        # Check if username or email already exists
        existing = db.execute(
            "SELECT * FROM users WHERE username=? OR email=?",
            (username, email)
        ).fetchone()
        if existing:
            AuditLogger.log("user_create", "user", email, "Failed: User already exists", "failure")
            return jsonify({"success": False, "error": "Username or Email already exists"})

        # Insert new user with hashed password
        db.execute(
            "INSERT INTO users (username, full_name, email, role, password) VALUES (?, ?, ?, ?, ?)",
            (username, full_name, email, "user", hashed_password)  # role is automatically 'user'
        )
        db.commit()

        # Get the new user's ID
        new_user = db.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
        new_user_id = new_user["id"] if new_user else None

        # Notify all admins
        admins = db.execute("SELECT id FROM users WHERE role='admin'").fetchall()
        for admin in admins:
            db.execute(
                "INSERT INTO notifications (user_id, message, document_id, read) VALUES (?, ?, ?, 0)",
                (admin["id"], f"New user '{full_name}' created with role 'user'", None)
            )
        db.commit()

        # Log successful user creation
        AuditLogger.log("user_create", "user", new_user_id, f"Created new user: {full_name} ({email})", "success")

    except sqlite3.IntegrityError as e:
        AuditLogger.log("user_create", "user", email, f"Failed: {str(e)}", "failure")
        return jsonify({"success": False, "error": str(e)})

    finally:
        db.close()

    return jsonify({"success": True})




# --- User Management Page ---
@app.route("/management")
def management():
    user_id = session.get("user_id")
    role = session.get("role")

    # Only allow admins to access this page
    if role != "admin":
        return "Access denied", 403

    db = get_db_connection()
    users = db.execute("SELECT id, username, full_name, email, role FROM users ORDER BY id ASC").fetchall()
    db.close()

    return render_template(
        "management.html",
        users=users,
        full_name=session.get("full_name"),
        role=role,
        user_id=user_id
    )

from datetime import datetime


def _create_document_metadata_version(payload, user_id, full_name):
    """
    Create a new active document version.

    If previous_document_id is provided, the previous version is soft-deactivated and
    its uploaded PDF is archived with a timestamped filename.
    """
    title = (payload.get("title") or "").strip()
    document_type = payload.get("document_type")
    framework = payload.get("framework")
    due_date = payload.get("due_date")
    importance = payload.get("importance")
    description = payload.get("description")
    previous_document_id = payload.get("previous_document_id")

    if not title:
        return {"ok": False, "error": "Document title is required"}

    previous_document_id_int = None
    if previous_document_id not in (None, "", "null"):
        try:
            previous_document_id_int = int(previous_document_id)
        except (TypeError, ValueError):
            return {"ok": False, "error": "previous_document_id must be an integer"}

    unique_id = _random_id(12)
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    db = get_db_connection()

    try:
        version_group_id = f"vg_{unique_id}"
        previous_doc = None

        if previous_document_id_int:
            if session.get("role") == "admin":
                previous_doc = db.execute(
                    "SELECT * FROM documents WHERE id = ?",
                    (previous_document_id_int,),
                ).fetchone()
            else:
                previous_doc = db.execute(
                    "SELECT * FROM documents WHERE id = ? AND user_id = ?",
                    (previous_document_id_int, user_id),
                ).fetchone()

            if not previous_doc:
                return {"ok": False, "error": "Previous document not found or unauthorized"}

            previous_doc_dict = dict(previous_doc)
            version_group_id = previous_doc_dict.get("version_group_id") or f"vg_{previous_doc_dict.get('unique_id') or previous_doc_dict.get('id')}"

            # Keep existing metadata if form values are omitted during update workflow.
            document_type = document_type or previous_doc_dict.get("documentType")
            framework = framework or previous_doc_dict.get("complianceFramework")
            due_date = due_date or previous_doc_dict.get("dueDate")
            importance = importance or previous_doc_dict.get("importanceLevel")
            description = description or previous_doc_dict.get("description")

            archived_name = ""
            old_file_name = previous_doc_dict.get("fileName")
            if old_file_name:
                try:
                    archived_name = _archive_file_if_exists(old_file_name)
                except Exception as archive_err:
                    print(f"[WARNING] Failed to archive old document file '{old_file_name}': {archive_err}")

            db.execute(
                """
                UPDATE documents
                SET is_active = 0,
                    deactivated_at = ?,
                    fileName = COALESCE(?, fileName)
                WHERE id = ?
                """,
                (now_str, archived_name or None, previous_document_id_int),
            )

        cursor = db.execute(
            """
            INSERT INTO documents (
                user_id,
                unique_id,
                documentTitle,
                documentType,
                complianceFramework,
                dueDate,
                importanceLevel,
                description,
                uploadDate,
                Review,
                is_active,
                version_group_id,
                deactivated_at,
                fileName
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                user_id,
                unique_id,
                title,
                document_type,
                framework,
                due_date,
                importance,
                description,
                now_str,
                "Under Review",
                1,
                version_group_id,
                None,
                None,
            ),
        )
        document_id = cursor.lastrowid

        admins = db.execute("SELECT id FROM users WHERE role='admin'").fetchall()
        for admin in admins:
            admin_id = admin["id"] if isinstance(admin, sqlite3.Row) else admin[0]
            db.execute(
                "INSERT INTO notifications (user_id, message, document_id, read) VALUES (?, ?, ?, 0)",
                (admin_id, f"New document '{title}' added by {full_name}", document_id),
            )

        db.commit()

        session["pending_doc_id"] = unique_id
        session["previous_document_id"] = previous_document_id_int

        return {
            "ok": True,
            "document_id": document_id,
            "unique_id": unique_id,
            "version_group_id": version_group_id,
            "previous_document_id": previous_document_id_int,
        }
    finally:
        db.close()


# --- Backward-compatible endpoint used by naming form ---
@app.route("/save_metadata", methods=["POST"])
def save_metadata():
    if not session.get("user_id"):
        return redirect(url_for("login"))

    user_id = session.get("user_id")
    full_name = session.get("full_name")
    create_result = _create_document_metadata_version(request.form, user_id, full_name)
    if not create_result["ok"]:
        return create_result["error"], 400

    return redirect(url_for("upload_document"))


    # ---------------- DUMMY GAP ANALYSIS ----------------
    dummy_gaps = """
    The document partially satisfies framework requirements.
    Some security controls lack implementation evidence.
    Risk mitigation procedures require enhancement.
    Monitoring controls are insufficiently documented.
    Additional policy clarification is recommended.
    """

    # ---------------- INSERT INTO COMPLIANCE ----------------
    db.execute("""
        INSERT INTO compliance (
            document_id,
            user_id,
            gaps,
            risk_report,
            compliance_score,
            Review
        )
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        document_id,
        user_id,
        dummy_gaps,
        65,                 # dummy risk score
        72.5,               # dummy compliance %
        "Under Review"
    ))

    db.commit()
    db.close()

    return redirect(url_for("documents"))

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not all([full_name, username, email, password, confirm_password]):
            return "All fields are required.", 400

        if password != confirm_password:
            return "Passwords do not match.", 400

        # Hash password securely before storing
        hashed_password = generate_password_hash(password)

        conn = get_db_connection()
        try:
            # Check if username or email already exists
            existing_user = conn.execute(
                "SELECT * FROM users WHERE username=? OR email=?",
                (username, email)
            ).fetchone()
            if existing_user:
                return "Username or email already exists.", 400

            # Insert new user with hashed password
            conn.execute(
                "INSERT INTO users (username, full_name, email, password, role) VALUES (?, ?, ?, ?, ?)",
                (username, full_name, email, hashed_password, "user")
            )
            conn.commit()

            # Fetch the newly created user for session
            user = conn.execute(
                "SELECT * FROM users WHERE username=?",
                (username,)
            ).fetchone()

            # Notify all admins (document_id=None signals non-document notification)
            admins = conn.execute("SELECT id FROM users WHERE role='admin'").fetchall()
            for admin in admins:
                conn.execute(
                    "INSERT INTO notifications (user_id, message, document_id, read) VALUES (?, ?, ?, 0)",
                    (admin["id"], f"New user '{full_name}' signed up", None)
                )
            conn.commit()

            # Set session for new user
            session["user_id"] = user["id"]
            session["role"] = user["role"]
            session["full_name"] = user["full_name"]

        finally:
            conn.close()

        return redirect(url_for("dashboard"))

    return render_template("signup.html")





# --- Delete Document (Owner only) ---
@app.route("/documents/delete/<int:doc_id>", methods=["POST"])
def delete_document(doc_id):
    try:
        if not session.get("user_id"):
            return redirect(url_for("login"))

        user_id = session.get("user_id")
        db = get_db_connection()

        # Make sure document belongs to logged-in user
        document = db.execute(
            "SELECT * FROM documents WHERE id=? AND user_id=?",
            (doc_id, user_id)
        ).fetchone()

        if not document:
            db.close()
            return "Document not found or unauthorized", 404

        doc_dict = dict(document)
        file_name = doc_dict.get("fileName") or doc_dict.get("documentTitle") or "Unknown File"

        # Delete related compliance records first
        db.execute("DELETE FROM compliance WHERE document_id=?", (doc_id,))
        db.execute("DELETE FROM compliance_results WHERE document_id=? AND user_id=?", (doc_id, user_id))

        # Delete the document
        db.execute("DELETE FROM documents WHERE id=?", (doc_id,))

        # ---------------- NOTIFY ADMINS ----------------
        admins = db.execute("SELECT id FROM users WHERE role='admin'").fetchall()
        for admin in admins:
            admin_id = admin["id"] if isinstance(admin, sqlite3.Row) else admin[0]
            db.execute(
                "INSERT INTO notifications (user_id, message, document_id, read) VALUES (?, ?, ?, 0)",
                (admin_id, f"User '{session.get('full_name')}' deleted document '{file_name}'", None)
            )

        db.commit()
        db.close()
        return redirect(url_for("documents"))
    except Exception as e:
        import traceback
        error_msg = f"Delete failed: {str(e)}\n{traceback.format_exc()}"
        return error_msg, 500



# --- Account Settings ---
@app.route("/account", methods=["GET", "POST"])
def account():
    if not session.get("user_id"):
        return redirect(url_for("login"))

    user_id = session.get("user_id")
    db = get_db_connection()

    error = None
    success = None

    if request.method == "POST":
        full_name = request.form.get("full_name")
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")

        if not all([full_name, username, email]):
            error = "All fields except password are required."
        else:
            # Check if username/email exists for another user
            existing = db.execute(
                """
                SELECT id FROM users 
                WHERE (username=? OR email=?) AND id!=?
                """,
                (username, email, user_id)
            ).fetchone()

            if existing:
                error = "Username or Email already exists."
            else:
                if password:
                    db.execute(
                        """
                        UPDATE users 
                        SET full_name=?, username=?, email=?, password=? 
                        WHERE id=?
                        """,
                        (full_name, username, email, password, user_id)
                    )
                else:
                    db.execute(
                        """
                        UPDATE users 
                        SET full_name=?, username=?, email=? 
                        WHERE id=?
                        """,
                        (full_name, username, email, user_id)
                    )

                db.commit()
                success = "Account updated successfully!"

                # Update session values
                session["full_name"] = full_name

    # Fetch updated user data
    user = db.execute(
        "SELECT * FROM users WHERE id=?",
        (user_id,)
    ).fetchone()

    db.close()

    return render_template(
        "account.html",
        user=user,
        role=session.get("role"),
        full_name=session.get("full_name"),
        error=error,
        success=success,
        user_id=user_id
    )



######################################################




@app.route("/analyze", methods=["POST"])
def analyze_file():
    data = request.get_json(silent=True) or {}
    filename = data.get("filename")
    requested_framework_version_id = data.get("framework_version_id") or data.get("version_id")

    if not filename:
        return jsonify({"error": "No filename provided"}), 400

    with ANALYSIS_STATUS_LOCK:
        running_task_id = LATEST_ANALYSIS_BY_FILENAME.get(filename)
        if running_task_id and ANALYSIS_STATUS.get(running_task_id, {}).get("status") == "running":
            return jsonify({"error": "Analysis already running", "task_id": running_task_id}), 409

        task_id = str(uuid.uuid4())
        LATEST_ANALYSIS_BY_FILENAME[filename] = task_id
        ANALYSIS_STATUS[task_id] = {
            "task_id": task_id,
            "filename": filename,
            "status": "running",
            "processed_batches": 0,
            "total_batches": 0,
            "started_at": time.time(),
            "finished_at": None,
            "error": None,
            "has_results": False,
            "results_count": 0,
            "cancel_requested": False,
            "gaps_found": [],
            "final_results": [],
        }

    pdf_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    cancel_event = threading.Event()

    def cancel_check():
        with ANALYSIS_STATUS_LOCK:
            return bool(ANALYSIS_STATUS.get(task_id, {}).get("cancel_requested"))

    def progress_callback(processed, total, current_gaps=None):
        with ANALYSIS_STATUS_LOCK:
            status = ANALYSIS_STATUS.get(task_id)
            if not status:
                return

            status["processed_batches"] = int(processed or 0)
            status["total_batches"] = int(total or 0)

            if current_gaps:
                status["gaps_found"].extend(current_gaps)
                status["results_count"] = len(status["gaps_found"])
                status["has_results"] = status["results_count"] > 0

    @copy_current_request_context
    def run_analysis_task():
        try:
            findings = rag.analyze_policy_pdf(
                pdf_path,
                progress_callback=progress_callback,
                framework_version_id=requested_framework_version_id,
                cancel_check=cancel_check,
                cancel_event=cancel_event,
            )
            results = findings if isinstance(findings, list) else []

            with ANALYSIS_STATUS_LOCK:
                status = ANALYSIS_STATUS.get(task_id)
                if not status:
                    return
                if status.get("cancel_requested"):
                    status["status"] = "cancelled"
                else:
                    status["status"] = "done"
                    status["final_results"] = results
                    status["gaps_found"] = results
                    status["results_count"] = len(results)
                    status["has_results"] = len(results) > 0
                status["finished_at"] = time.time()
        except Exception as e:
            with ANALYSIS_STATUS_LOCK:
                status = ANALYSIS_STATUS.get(task_id)
                if status:
                    if status.get("cancel_requested") or "cancel" in str(e).lower():
                        status["status"] = "cancelled"
                        status["error"] = "Analysis cancelled"
                    else:
                        status["status"] = "error"
                        status["error"] = str(e)
                    status["finished_at"] = time.time()
        finally:
            with ANALYSIS_STATUS_LOCK:
                ANALYSIS_TASK_THREADS.pop(task_id, None)
                ANALYSIS_CANCEL_EVENTS.pop(task_id, None)

    worker = threading.Thread(target=run_analysis_task, name=f"analysis-{task_id}", daemon=True)
    with ANALYSIS_STATUS_LOCK:
        ANALYSIS_TASK_THREADS[task_id] = worker
        ANALYSIS_CANCEL_EVENTS[task_id] = cancel_event
    worker.start()

    return jsonify({
        "task_id": task_id,
        "status": "accepted",
        "message": "Analysis started in background",
    }), 202


@app.route("/progress", methods=["GET"])
def progress():
    task_id = request.args.get("task_id")
    filename = request.args.get("filename")

    if not task_id and filename:
        with ANALYSIS_STATUS_LOCK:
            task_id = LATEST_ANALYSIS_BY_FILENAME.get(filename)

    if not task_id:
        return jsonify({"error": "task_id or filename is required"}), 400

    with ANALYSIS_STATUS_LOCK:
        status = ANALYSIS_STATUS.get(task_id)

    if not status:
        return jsonify({"status": "unknown", "task_id": task_id})

    total_batches = int(status.get("total_batches") or 0)
    processed_batches = int(status.get("processed_batches") or 0)
    percentage = int(100 * processed_batches / total_batches) if total_batches > 0 else 0

    findings_so_far = status.get("gaps_found", [])
    final_results = status.get("final_results", [])
    status_text = status.get("status")
    if status_text == "running" and status.get("cancel_requested"):
        status_text = "cancelling"
    if status.get("status") == "done" and final_results:
        findings_so_far = final_results

    return jsonify({
        "task_id": task_id,
        "filename": status.get("filename"),
        "status": status_text,
        "processed_batches": processed_batches,
        "total_batches": total_batches,
        "percentage": percentage,
        "has_results": bool(status.get("has_results")),
        "results_count": int(status.get("results_count") or 0),
        "findings_so_far": findings_so_far,
        "results_with_sources": findings_so_far,
        "current_gaps": findings_so_far[-10:],
        "cancel_requested": bool(status.get("cancel_requested")),
        "error": status.get("error"),
    })


@app.route("/cancel", methods=["POST"])
def cancel_analysis():
    data = request.get_json(silent=True) or {}
    task_id = data.get("task_id")
    filename = data.get("filename")

    if not task_id and filename:
        with ANALYSIS_STATUS_LOCK:
            task_id = LATEST_ANALYSIS_BY_FILENAME.get(filename)

    if not task_id:
        return jsonify({"error": "task_id or filename is required"}), 400

    with ANALYSIS_STATUS_LOCK:
        status = ANALYSIS_STATUS.get(task_id)
        if not status:
            return jsonify({"error": "Task not found", "task_id": task_id}), 404

        if status.get("status") in {"done", "error", "cancelled"}:
            return jsonify({"task_id": task_id, "status": status.get("status")})

        status["cancel_requested"] = True
        status["status"] = "cancelling"
        status["error"] = "Cancellation requested by user"
        cancel_event = ANALYSIS_CANCEL_EVENTS.get(task_id)
        if cancel_event:
            cancel_event.set()

    return jsonify({"task_id": task_id, "status": "cancelling"})


@app.route("/api/findings/feedback", methods=["POST"])
def submit_finding_feedback():
    """
    Capture human-in-the-loop validation feedback for model findings.

    Expected payload:
    {
      "finding_key": "...",
      "session_id": "...",
      "control_id": "AC-2(1)",
      "confidence": 0.85,
      "source_quote": "...",
      "action": "verified" | "dismissed"
    }
    """
    data = request.get_json(silent=True) or {}

    finding_key = (data.get("finding_key") or "").strip()
    action = (data.get("action") or "").strip().lower()

    if not finding_key:
        return jsonify({"error": "finding_key is required"}), 400
    if action not in ("verified", "dismissed"):
        return jsonify({"error": "action must be 'verified' or 'dismissed'"}), 400

    user_id = int(session.get("user_id") or 0)
    session_id = data.get("session_id")
    control_id = data.get("control_id")
    source_quote = data.get("source_quote")

    confidence = data.get("confidence")
    try:
        confidence = float(confidence) if confidence is not None else None
    except (TypeError, ValueError):
        confidence = None

    db = get_db_connection()
    try:
        db.execute(
            """
            INSERT INTO finding_feedback (
                finding_key, session_id, user_id, control_id, confidence, source_quote, action
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(user_id, finding_key) DO UPDATE SET
                session_id=excluded.session_id,
                control_id=excluded.control_id,
                confidence=excluded.confidence,
                source_quote=excluded.source_quote,
                action=excluded.action,
                updated_at=CURRENT_TIMESTAMP
            """,
            (finding_key, session_id, user_id, control_id, confidence, source_quote, action),
        )

        # Persist hard negatives for dismissed findings so retrieval/prompting can learn.
        if action == "dismissed":
            chunk_text = (data.get("chunk_text") or source_quote or "").strip()
            reason = (data.get("reason") or data.get("dismiss_reason") or "Dismissed by auditor").strip()
            framework_version = (
                (data.get("framework_version") or data.get("framework_version_id") or "").strip() or None
            )

            if chunk_text and getattr(rag, "embeddings", None):
                try:
                    import numpy as np

                    vector = rag.embeddings.embed_query(chunk_text)
                    vector_arr = np.asarray(vector, dtype=np.float32)
                    db.execute(
                        """
                        INSERT INTO gap_feedback (
                            framework_version, control_id, chunk_text, embedding_blob, embedding_dim, user_id, reason
                        ) VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            framework_version,
                            control_id,
                            chunk_text,
                            sqlite3.Binary(vector_arr.tobytes()),
                            int(vector_arr.shape[0]),
                            user_id,
                            reason,
                        ),
                    )
                except Exception as emb_error:
                    print(f"[WARNING] Failed to persist gap_feedback embedding: {emb_error}")

        db.commit()
    finally:
        db.close()

    return jsonify({"ok": True, "action": action})


@app.route("/api/dismiss-gap", methods=["POST"])
def dismiss_gap():
    """
    Lightweight endpoint dedicated to dismissed-gap learning.

    Payload:
    {
      "chunk_text": "...",
      "control_id": "PR.AC-1",
      "reason": "...",
      "framework_version": "..."
    }
    """
    data = request.get_json(silent=True) or {}
    chunk_text = (data.get("chunk_text") or data.get("source_quote") or "").strip()
    control_id = (data.get("control_id") or "").strip() or None
    reason = (data.get("reason") or "Dismissed by auditor").strip()
    framework_version = (data.get("framework_version") or data.get("framework_version_id") or "").strip() or None

    if not chunk_text:
        return jsonify({"error": "chunk_text is required"}), 400

    if not getattr(rag, "embeddings", None):
        return jsonify({"error": "Embedding model unavailable"}), 503

    try:
        import numpy as np

        vector = rag.embeddings.embed_query(chunk_text)
        vector_arr = np.asarray(vector, dtype=np.float32)
        user_id = int(session.get("user_id") or 0)

        db = get_db_connection()
        db.execute(
            """
            INSERT INTO gap_feedback (
                framework_version, control_id, chunk_text, embedding_blob, embedding_dim, user_id, reason
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                framework_version,
                control_id,
                chunk_text,
                sqlite3.Binary(vector_arr.tobytes()),
                int(vector_arr.shape[0]),
                user_id,
                reason,
            ),
        )
        db.commit()
        db.close()

        return jsonify({"status": "learned", "control_id": control_id})
    except Exception as e:
        return jsonify({"error": f"Failed to store dismissal feedback: {e}"}), 500


@app.route("/api/findings/calibration", methods=["GET"])
def get_finding_calibration():
    """
    Return simple confidence calibration stats from human feedback.
    """
    db = get_db_connection()

    total_row = db.execute(
        "SELECT COUNT(*) AS total, SUM(CASE WHEN action='verified' THEN 1 ELSE 0 END) AS verified FROM finding_feedback"
    ).fetchone()

    bins = db.execute(
        """
        SELECT
            CAST(confidence * 10 AS INTEGER) / 10.0 AS confidence_bin,
            COUNT(*) AS total,
            SUM(CASE WHEN action='verified' THEN 1 ELSE 0 END) AS verified
        FROM finding_feedback
        WHERE confidence IS NOT NULL
        GROUP BY confidence_bin
        ORDER BY confidence_bin DESC
        """
    ).fetchall()

    db.close()

    total = int(total_row["total"] or 0)
    verified = int(total_row["verified"] or 0)
    overall_accuracy = round((verified / total), 4) if total > 0 else None

    by_bin = []
    for row in bins:
        bin_total = int(row["total"] or 0)
        bin_verified = int(row["verified"] or 0)
        bin_accuracy = round((bin_verified / bin_total), 4) if bin_total > 0 else None
        by_bin.append(
            {
                "confidence_bin": float(row["confidence_bin"]),
                "total": bin_total,
                "verified": bin_verified,
                "accuracy": bin_accuracy,
            }
        )

    return jsonify(
        {
            "total_feedback": total,
            "verified_feedback": verified,
            "overall_accuracy": overall_accuracy,
            "by_bin": by_bin,
        }
    )


@app.route("/api/findings/feedback/status", methods=["POST"])
def get_finding_feedback_status():
    """
    Bulk fetch current user's feedback action by finding key.

    Payload:
    {
      "finding_keys": ["key1", "key2", ...]
    }
    """
    data = request.get_json(silent=True) or {}
    finding_keys = data.get("finding_keys") or []

    if not isinstance(finding_keys, list):
        return jsonify({"error": "finding_keys must be a list"}), 400

    finding_keys = [str(k).strip() for k in finding_keys if str(k).strip()]
    if not finding_keys:
        return jsonify({"statuses": {}})

    user_id = int(session.get("user_id") or 0)

    placeholders = ",".join(["?"] * len(finding_keys))
    query = f"""
        SELECT finding_key, action
        FROM finding_feedback
        WHERE user_id = ? AND finding_key IN ({placeholders})
    """

    db = get_db_connection()
    rows = db.execute(query, [user_id, *finding_keys]).fetchall()
    db.close()

    statuses = {row["finding_key"]: row["action"] for row in rows}
    return jsonify({"statuses": statuses})


@app.route("/api/report-progress", methods=["GET"])
def report_progress():
    """
    ENDPOINT: GET /api/report-progress?session_id=xyz

    Provide real-time progress updates during report generation.

    Returns: {status, processed_steps, total_steps, percentage, stage, error}
    """
    session_id = request.args.get("session_id")

    if not session_id:
        return jsonify({"error": "Session ID required"}), 400

    status = REPORT_STATUS.get(session_id)
    if not status:
        return jsonify({"status": "unknown"})

    if status["total_steps"] > 0:
        percentage = int(100 * status["processed_steps"] / status["total_steps"])
    else:
        percentage = 0

    return jsonify({
        "status": status["status"],
        "processed_steps": status["processed_steps"],
        "total_steps": status["total_steps"],
        "percentage": percentage,
        "stage": status.get("stage"),
        "error": status.get("error")
    })


@app.route("/uploads/<path:filename>")
def uploaded_file(filename):
    """
    ENDPOINT: GET /uploads/filename.pdf

    Serve uploaded files (for PDF display in iframe).

    This allows the frontend to display the uploaded PDF in an <iframe>
    so user can review policy alongside the compliance findings.
    """
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)


@app.route("/download-report/<int:report_id>")
def download_report_pdf(report_id):
    """
    ENDPOINT: GET /download-report/<report_id>
    
    Generate and download a PDF report card for the given report ID.
    """
    try:
        db = get_db_connection()
        report_row = db.execute("SELECT * FROM report WHERE id = ?", (report_id,)).fetchone()
        
        if not report_row:
            db.close()
            return "Report not found", 404
        
        report_dict = dict(report_row)
        
        # Parse JSON fields
        try:
            compliance_summary = json.loads(report_dict["compliance_summary"]) if report_dict["compliance_summary"] else {}
        except:
            compliance_summary = {}
        
        try:
            gap_analysis = json.loads(report_dict["gap_analysis"]) if report_dict["gap_analysis"] else []
        except:
            gap_analysis = []
        
        try:
            risk_assessment = json.loads(report_dict["risk_assessment"]) if report_dict["risk_assessment"] else []
        except:
            risk_assessment = []
        
        try:
            recommendations = json.loads(report_dict["recommendations"]) if report_dict["recommendations"] else []
        except:
            recommendations = []
        
        try:
            heatmap = json.loads(report_dict["risk_heat_map"]) if report_dict["risk_heat_map"] else None
        except:
            heatmap = None

        # Apply human feedback filters for this report (dismissed findings should not be exported)
        feedback_actions_by_key = {}
        dismissed_control_ids = set()
        dismissed_gap_ids = set()
        try:
            current_user_id = int(session.get("user_id") or 0)
            if current_user_id > 0:
                feedback_rows = db.execute(
                    """
                    SELECT finding_key, control_id, action
                    FROM finding_feedback
                    WHERE user_id = ?
                      AND (finding_key LIKE ? OR finding_key LIKE ?)
                    """,
                    (current_user_id, f"%report{report_id}%", f"%legacy{report_id}%"),
                ).fetchall()

                for row in feedback_rows:
                    finding_key = (row["finding_key"] or "").strip()
                    action = (row["action"] or "").strip().lower()
                    control_id = (row["control_id"] or "").strip()
                    if not finding_key or action not in ("verified", "dismissed"):
                        continue
                    feedback_actions_by_key[finding_key] = action
                    if action == "dismissed":
                        if control_id:
                            dismissed_control_ids.add(control_id)
                        if "_gap_" in finding_key:
                            dismissed_gap_ids.add(finding_key.split("_gap_", 1)[1])
        except Exception:
            feedback_actions_by_key = {}
            dismissed_control_ids = set()
            dismissed_gap_ids = set()

        filtered_gap_analysis = []
        for g in gap_analysis or []:
            if not isinstance(g, dict):
                continue
            gap_id = str(g.get("gap_id", "") or "")
            control_id = str(g.get("control_id", "") or "")
            if gap_id and gap_id in dismissed_gap_ids:
                continue
            if control_id and control_id in dismissed_control_ids:
                continue
            filtered_gap_analysis.append(g)
        
        db.close()
        
        # Build organization info
        org_info = OrganizationInfo(
            organization_name=report_dict.get("organization_name", "Organization"),
            industry=report_dict.get("industry", ""),
            size=report_dict.get("size", ""),
            contact_person="",
            contact_email="",
            scope=report_dict.get("scope", "")
        )
        
        # Build ComplianceSummary from stored data
        from models.report_models import ComplianceSummary, ComplianceGap, NISTFunction, RiskLevel
        
        summary = ComplianceSummary(
            total_gaps=compliance_summary.get("total_gaps", 0),
            gaps_by_function=compliance_summary.get("gaps_by_function", {}),
            gaps_by_risk_level=compliance_summary.get("gaps_by_risk_level", {}),
            overall_risk_score=compliance_summary.get("overall_risk_score", 0.0),
            compliance_percentage=compliance_summary.get("compliance_percentage", 0.0),
            critical_findings=compliance_summary.get("critical_findings", 0),
            high_priority_recommendations=compliance_summary.get("high_priority_recommendations", 0)
        )
        
        # Convert gap_analysis back to ComplianceGap objects
        compliance_gaps = []
        for gap_dict in filtered_gap_analysis:
            try:
                gap_id = str(gap_dict.get("gap_id", f"gap_{len(compliance_gaps)}"))
                control_id = str(gap_dict.get("control_id", "") or "")

                # Exclude dismissed findings from exported reports
                if gap_id in dismissed_gap_ids:
                    continue
                if control_id and control_id in dismissed_control_ids:
                    continue

                # Map risk_level string to enum
                risk_level_str = gap_dict.get("risk_level", "Medium")
                if isinstance(risk_level_str, str):
                    risk_level_str = risk_level_str.capitalize()
                    if risk_level_str not in ["Low", "Medium", "High", "Critical"]:
                        risk_level_str = "Medium"
                    risk_level = RiskLevel(risk_level_str)
                else:
                    risk_level = RiskLevel.MEDIUM
                
                # Map nist_function string to enum
                nist_func_str = gap_dict.get("nist_function", "Protect")
                try:
                    nist_func = NISTFunction(nist_func_str)
                except:
                    nist_func = NISTFunction.PROTECT
                
                gap = ComplianceGap(
                    gap_id=gap_id,
                    control_id=control_id,
                    control_title=gap_dict.get("control_title", ""),
                    nist_function=nist_func,
                    category=gap_dict.get("category", ""),
                    subcategory=gap_dict.get("subcategory", ""),
                    description=gap_dict.get("description", ""),
                    reasoning=gap_dict.get("reasoning", ""),
                    risk_level=risk_level,
                    affected_assets=gap_dict.get("affected_assets", []),
                    evidence_sources=gap_dict.get("evidence_sources", []),
                    source_metadata=gap_dict.get("source_metadata", gap_dict.get("source_references", [])),
                    related_questions=gap_dict.get("related_questions", []),
                    confidence_score=gap_dict.get("confidence_score", 0.8)
                )
                compliance_gaps.append(gap)
            except Exception as e:
                print(f"[WARNING] Failed to convert gap: {e}")
        
        # Build FinalReport
        # Compute aggregate AI confidence from stored gap analysis
        try:
            conf_vals = []
            for g in filtered_gap_analysis or []:
                v = g.get('confidence_score') if isinstance(g, dict) else None
                if v is None:
                    v = g.get('confidence') if isinstance(g, dict) else None
                if isinstance(v, (int, float)):
                    conf_vals.append(float(v))
            ai_confidence = (sum(conf_vals) / len(conf_vals)) if conf_vals else None
        except Exception:
            ai_confidence = None

        compliance_by_function = {}
        try:
            gaps_count = {"Govern": 0, "Identify": 0, "Protect": 0, "Detect": 0, "Respond": 0, "Recover": 0}
            for g in filtered_gap_analysis or []:
                if isinstance(g, dict):
                    fn = g.get("nist_function")
                    if fn in gaps_count:
                        gaps_count[fn] += 1

            for function in [NISTFunction.GOVERN, NISTFunction.IDENTIFY, NISTFunction.PROTECT, NISTFunction.DETECT, NISTFunction.RESPOND, NISTFunction.RECOVER]:
                try:
                    total_questions = questionnaire_engine.get_function_summary(function).get("total_questions", 0) or 0
                except Exception:
                    total_questions = 0

                gap_count = gaps_count.get(function.value, 0)
                if total_questions == 0:
                    pct = 0.0
                else:
                    pct = round(max(0.0, 100.0 * (1.0 - (gap_count / total_questions))), 1)
                compliance_by_function[function.value.lower()] = pct
        except Exception:
            compliance_by_function = {}

        report = FinalReport(
            report_id=f"report_{report_id}",
            organization_info=org_info,
            compliance_summary=summary,
            questionnaire_answers=[],
            compliance_gaps=compliance_gaps,
            risk_assessment=risk_assessment,
            recommendations=recommendations,
            heatmap=heatmap,
            document_analysis={},
            metadata={
                "framework_name": report_dict.get("framework_name"),
                "framework_version_id": report_dict.get("framework_version_id"),
                "framework_version_label": report_dict.get("framework_version_label"),
                "framework_used_at": report_dict.get("framework_used_at"),
                "gap_analysis": filtered_gap_analysis,
                "compliance_by_function": compliance_by_function,
                "feedback_actions_by_key": feedback_actions_by_key,
                "dismissed_control_ids": sorted(list(dismissed_control_ids)),
                "dismissed_gap_ids": sorted(list(dismissed_gap_ids)),
            },
            ai_confidence_score=ai_confidence,
        )
        
        # Accept optional query params: report_type (executive,detailed,improvement_plan,risk_register) and format (pdf,docx)
        report_type = request.args.get('report_type', 'detailed')
        out_format = request.args.get('format', 'pdf').lower()

        # Generate filename
        safe_org_name = "".join(c for c in org_info.organization_name if c.isalnum() or c in " -_")[:30]
        base_filename = f"{safe_org_name}_Report_{report_id}_{datetime.now().strftime('%Y%m%d')}"

        try:
            if out_format == 'docx' or out_format == 'word':
                filename = f"{base_filename}.docx"
                file_path = report_exporter.export_report_word(report, report_type=report_type, heatmap_report=heatmap, filename=filename)
            else:
                filename = f"{base_filename}.pdf"
                file_path = report_exporter.export_report_pdf(report, report_type=report_type, heatmap_report=heatmap, filename=filename)

            # Serve the file for download
            return send_from_directory(
                directory=os.path.dirname(file_path),
                path=os.path.basename(file_path),
                as_attachment=True,
                download_name=os.path.basename(file_path)
            )
        except Exception as e:
            print(f"[ERROR] Failed to generate report: {e}")
            import traceback
            traceback.print_exc()
            return f"Failed to generate report: {str(e)}", 500
        
    except Exception as e:
        print(f"[ERROR] Failed to generate PDF: {e}")
        import traceback
        traceback.print_exc()
        return f"Failed to generate PDF: {str(e)}", 500


@app.route("/exports/<path:filename>")
def serve_export(filename):
    """Serve files from exports directory (heatmap images, etc.)."""
    return send_from_directory(os.path.join(BASE_DIR, "exports"), filename)


@app.route("/api/audit-chat", methods=["POST"])
def audit_chat():
    """
    ENDPOINT: POST /api/audit-chat

    Handle contextual RAG chatbot queries with optional finding context.

    FLOW:
    1. Frontend sends JSON: {query: "...", finding_id: "...", history: [...]}
    2. Backend calls AdvancedRAGEngine.audit_agent_chat()
    3. Engine processes query with 3 modes: Validator, Remediation Coach, Cross-Document Expert
    4. Returns JSON: {response: "...", history: [...]}

    FEATURES:
    - Contextual intelligence: Uses finding_id to ground responses in specific gap details
    - Conversation memory: Maintains chat_history for follow-up questions
    - Master system prompt: Enables 3 operation modes based on user needs
    - Hybrid retrieval: Uses existing _hybrid_retrieve method for NIST controls

    Returns:
        JSON object with bot response and updated conversation history
    """
    # Parse JSON request data
    data = request.json
    query = data.get("query", "")
    finding_id = data.get("finding_id")
    history = data.get("history", [])

    # Validate query provided
    if not query.strip():
        return jsonify({"error": "No query provided"}), 400

    try:
        # Call the Advanced RAG Engine's audit agent chat method
        # This handles all the sophisticated logic:
        # - Grounding context from finding_id
        # - Hybrid retrieval of NIST controls
        # - Master system prompt with 3 modes
        # - Conversation memory management
        result = rag.audit_agent_chat(
            query=query,
            finding_id=finding_id,
            history=history
        )

        # Return the response and updated history
        return jsonify({
            "response": result["response"],
            "history": result["history"]
        })

    except Exception as e:
        # Handle any errors from the RAG engine
        return jsonify({
            "error": f"Error processing chat request: {str(e)}",
            "response": "I encountered an error while processing your request. Please try again.",
            "history": history
        }), 500


@app.route("/chatbot-widget")
def chatbot_widget():
    """Serve the embedded policy chatbot widget."""
    return send_from_directory(BASE_DIR, "chatbot_widget_fixed.html")


@app.route("/api/chatbot/upload", methods=["POST"])
def chatbot_upload_file():
    """Upload and index a policy document for the standalone chatbot."""
    if "file" not in request.files:
        return jsonify({"error": "No file part"}), 400

    file = request.files["file"]

    if file.filename == "":
        return jsonify({"error": "No selected file"}), 400

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        os.makedirs(UPLOAD_FOLDER, exist_ok=True)
        save_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)

        db = get_db_connection()
        try:
            pending_doc_unique_id = session.get("pending_doc_id")
            previous_document_id = session.get("previous_document_id")

            current_doc_id = None
            if pending_doc_unique_id:
                row = db.execute("SELECT id FROM documents WHERE unique_id = ?", (pending_doc_unique_id,)).fetchone()
                current_doc_id = row["id"] if row else None

            # If this is an update workflow, make sure old version keeps an archived physical file.
            if previous_document_id:
                prev_row = db.execute(
                    "SELECT id, fileName FROM documents WHERE id = ?",
                    (previous_document_id,),
                ).fetchone()
                if prev_row and prev_row["fileName"]:
                    prev_file_name = prev_row["fileName"]
                    prev_file_path = os.path.join(app.config["UPLOAD_FOLDER"], prev_file_name)
                    if os.path.exists(prev_file_path) and prev_file_name == filename:
                        ts = datetime.now().strftime("%Y%m%d%H%M%S")
                        archived_name = _safe_archive_filename(filename, f"v{previous_document_id}_{ts}")
                        os.rename(prev_file_path, os.path.join(app.config["UPLOAD_FOLDER"], archived_name))
                        db.execute(
                            "UPDATE documents SET fileName = ? WHERE id = ?",
                            (archived_name, previous_document_id),
                        )

            # If a same-name file still exists, archive it so current upload always wins.
            if os.path.exists(save_path):
                ts = datetime.now().strftime("%Y%m%d%H%M%S")
                archived_conflict = _safe_archive_filename(filename, f"stale_{ts}")
                os.rename(save_path, os.path.join(app.config["UPLOAD_FOLDER"], archived_conflict))

            file.save(save_path)

            if current_doc_id:
                db.execute(
                    "UPDATE documents SET fileName = ? WHERE id = ?",
                    (filename, current_doc_id),
                )
            db.commit()
        finally:
            db.close()

        success = chatbot.load_policy_document(save_path)

        if success:
            session.pop("previous_document_id", None)
            return jsonify({
                "filename": filename,
                "message": "Document uploaded and indexed successfully"
            })

        return jsonify({"error": "Failed to index document"}), 500

    return jsonify({"error": "Invalid file"}), 400


@app.route("/api/chatbot/chat", methods=["POST"])
def chatbot_chat():
    """Handle standalone chatbot messages."""
    data = request.json
    message = (data or {}).get("message", "").strip()

    if not message:
        return jsonify({"error": "No message provided"}), 400

    try:
        response = chatbot.chat(message)
        return jsonify({
            "response": response,
            "history": chatbot.get_history()
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/chatbot/clear", methods=["POST"])
def chatbot_clear_history():
    """Clear standalone chatbot conversation history."""
    chatbot.clear_history()
    return jsonify({"message": "History cleared"})


@app.route("/api/chatbot/history", methods=["GET"])
def chatbot_get_history():
    """Get standalone chatbot conversation history."""
    return jsonify({"history": chatbot.get_history()})


@app.route("/api/smoke-report", methods=["POST"])
def smoke_report():
    """Generate a minimal report to validate the LLM pipeline quickly."""
    try:
        org_info = OrganizationInfo(
            organization_name="Smoke Test Org",
            industry="Technology",
            size="small",
            contact_person="Test User",
            contact_email="test@example.com",
            scope="Minimal pipeline validation"
        )

        answers = [
            QuestionAnswer(
                question_id="SMOKE_001",
                question_text="Do you maintain an inventory of assets?",
                question_type=QuestionType.YES_NO,
                nist_function=NISTFunction.IDENTIFY,
                category="Asset Management",
                subcategory="Hardware Assets",
                answer="Yes",
                confidence=0.9,
                evidence="Asset inventory exists in CMDB"
            ),
            QuestionAnswer(
                question_id="SMOKE_002",
                question_text="Do you provide security awareness training?",
                question_type=QuestionType.YES_NO,
                nist_function=NISTFunction.PROTECT,
                category="Awareness and Training",
                subcategory="Security Awareness",
                answer="No",
                confidence=0.8,
                evidence="Training program not yet implemented"
            )
        ]

        report = llm_service.generate_compliance_report(
            document_text="",
            questionnaire_answers=answers,
            organization_info=org_info
        )

        return jsonify({
            "report_id": report.report_id,
            "total_gaps": report.compliance_summary.total_gaps,
            "compliance_percentage": report.compliance_summary.compliance_percentage,
            "message": "Smoke report generated successfully"
        })
    except Exception as e:
        return jsonify({"error": f"Smoke report failed: {str(e)}"}), 500


@app.route("/api/smoke-llm", methods=["POST"])
def smoke_llm():
    """Ping the LLM with a tiny prompt to confirm responsiveness."""
    try:
        response_text = llm_service._call_llm(
            "Return a JSON object with a single key 'ok' and value true."
        )
        return jsonify({"raw": response_text})
    except Exception as e:
        return jsonify({"error": f"Smoke LLM failed: {str(e)}"}), 500


# ============================================
# NIST CSF QUESTIONNAIRE PIPELINE ENDPOINTS
# ============================================

@app.route("/api/nist-functions", methods=["GET"])
def get_nist_functions():
    """
    ENDPOINT: GET /api/nist-functions

    Get available NIST CSF functions with question counts.

    Returns:
        List of available NIST functions with metadata
    """
    try:
        functions = questionnaire_engine.get_available_functions()
        function_summaries = []

        for function in functions:
            summary = questionnaire_engine.get_function_summary(function)
            function_summaries.append(summary)

        return jsonify({
            "functions": function_summaries,
            "total_available": len(functions)
        })

    except Exception as e:
        return jsonify({"error": f"Failed to get NIST functions: {str(e)}"}), 500


@app.route("/api/generate-questions", methods=["POST"])
def generate_questions():
    """
    ENDPOINT: POST /api/generate-questions

    Generate questionnaire questions for selected NIST functions.

    Request body:
    {
        "selected_functions": ["Identify", "Protect", ...],
        "organization_info": {
            "organization_name": "...",
            "industry": "...",
            "size": "...",
            "contact_person": "...",
            "contact_email": "...",
            "scope": "..."
        }
    }

    Returns:
        Session ID and generated questions
    """
    try:
        data = request.json
        selected_functions_data = data.get("selected_functions", [])
        organization_data = data.get("organization_info", {})

        # Convert string function names to NISTFunction enum
        selected_functions = []
        for func_name in selected_functions_data:
            try:
                func_enum = NISTFunction(func_name)
                selected_functions.append(func_enum)
            except ValueError:
                return jsonify({"error": f"Invalid NIST function: {func_name}"}), 400

        if not selected_functions:
            return jsonify({"error": "No NIST functions selected"}), 400

        # Generate session ID
        session_id = f"session_{uuid.uuid4().hex[:12]}"

        # Get questions for selected functions
        questions = questionnaire_engine.get_questions_for_functions(selected_functions)

        # Create organization info
        organization_info = OrganizationInfo(**organization_data)

        # Store session data
        QUESTIONNAIRE_SESSIONS[session_id] = {
            "organization_info": organization_info,
            "selected_functions": selected_functions,
            "questions": questions,
            "answers": [],
            "created_at": time.time(),
            "status": "questions_generated"
        }

        return jsonify({
            "session_id": session_id,
            "questions": questions,
            "total_questions": len(questions),
            "estimated_time_minutes": len(questions) * 2
        })

    except Exception as e:
        return jsonify({"error": f"Failed to generate questions: {str(e)}"}), 500


@app.route("/api/submit-answers", methods=["POST"])
def submit_answers():
    """
    ENDPOINT: POST /api/submit-answers

    Submit questionnaire answers and generate compliance report.

    Request body:
    {
        "session_id": "...",
        "answers": [
            {
                "question_id": "...",
                "answer": "...",
                "evidence": "...",
                "confidence": 0.8
            }
        ],
        "filename": "uploaded_document.pdf"  // Optional
    }

    Returns:
        Generated compliance report
    """
    session_id = None
    try:
        data = request.get_json(silent=True) or {}
        session_id = data.get("session_id")
        answers_data = data.get("answers", [])
        filename = data.get("filename")

        if not session_id:
            return jsonify({"error": "Session ID required"}), 400

        if session_id not in QUESTIONNAIRE_SESSIONS:
            return jsonify({"error": "Invalid session ID"}), 404

        if not answers_data:
            return jsonify({"error": "No answers provided"}), 400

        # Initialize report generation status for progress polling
        REPORT_STATUS[session_id] = {
            "status": "running",
            "processed_steps": 0,
            "total_steps": 4,
            "stage": "Starting",
            "started_at": time.time(),
            "finished_at": None,
            "error": None
        }

        def update_report_status(step, stage):
            REPORT_STATUS[session_id]["processed_steps"] = step
            REPORT_STATUS[session_id]["stage"] = stage

        # Get session data
        questionnaire_session = QUESTIONNAIRE_SESSIONS[session_id]
        organization_info = questionnaire_session["organization_info"]

        # Process answers
        update_report_status(1, "Processing answers")
        processed_answers = questionnaire_engine.process_answers(answers_data)

        # Extract document text if filename provided
        document_text = ""
        if filename:
            pdf_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            if os.path.exists(pdf_path):
                # Extract text from PDF using existing RAG engine
                try:
                    # Use RAG engine to extract text
                    from langchain_community.document_loaders import PyPDFLoader
                    loader = PyPDFLoader(pdf_path)
                    documents = loader.load()
                    document_text = " ".join([doc.page_content for doc in documents])
                except Exception as e:
                    print(f"Warning: Could not extract text from PDF: {str(e)}")
                    document_text = ""

        # Update session status
        questionnaire_session["answers"] = processed_answers
        questionnaire_session["status"] = "answers_submitted"
        questionnaire_session["document_text"] = document_text

        # Generate compliance report
        update_report_status(2, "Generating report")
        report = llm_service.generate_compliance_report(
            document_text=document_text,
            questionnaire_answers=processed_answers,
            organization_info=organization_info
        )

        # Merge RAG analysis findings with LLM-generated gaps.
        # ANALYSIS_STATUS is keyed by task_id in async mode.
        rag_findings = []

        with ANALYSIS_STATUS_LOCK:
            # Strategy 1: resolve latest task by filename
            if filename:
                task_id_for_file = LATEST_ANALYSIS_BY_FILENAME.get(filename)
                status_for_file = ANALYSIS_STATUS.get(task_id_for_file) if task_id_for_file else None
                if status_for_file and status_for_file.get("status") == "done":
                    rag_findings = status_for_file.get("final_results") or status_for_file.get("gaps_found", [])
                    print(f"[DEBUG] Found RAG findings via filename task '{task_id_for_file}': {len(rag_findings)} gaps")

            # Strategy 2: fallback to most recent completed analysis task
            if not rag_findings:
                for task_id, status_data in sorted(
                    ANALYSIS_STATUS.items(),
                    key=lambda x: x[1].get("finished_at", 0),
                    reverse=True,
                ):
                    if status_data.get("status") == "done" and (status_data.get("final_results") or status_data.get("gaps_found")):
                        rag_findings = status_data.get("final_results") or status_data.get("gaps_found", [])
                        print(f"[DEBUG] Found RAG findings from recent task '{task_id}': {len(rag_findings)} gaps")
                        break
        
        # Merge if RAG findings exist
        if rag_findings:
            print(f"[DEBUG] Merging {len(rag_findings)} RAG findings with {len(report.compliance_gaps)} LLM gaps")
            
            from models.report_models import ComplianceGap, NISTFunction, RiskLevel
            import uuid
            
            # Get existing control IDs from LLM-generated gaps to avoid duplicates
            existing_control_ids = {gap.control_id for gap in report.compliance_gaps}
            
            merged_count = 0
                
            # Convert RAG findings to ComplianceGap objects and merge
            for finding in rag_findings:
                control_id = finding.get("control_id", "")
                
                # Skip if already covered by LLM gaps
                if control_id in existing_control_ids:
                    print(f"[DEBUG] Skipping duplicate gap: {control_id}")
                    continue
                
                # Map risk level string to enum
                risk_str = finding.get("risk_level", "Medium")
                risk_map = {"Critical": RiskLevel.CRITICAL, "High": RiskLevel.HIGH, 
                            "Medium": RiskLevel.MEDIUM, "Moderate": RiskLevel.MEDIUM, "Low": RiskLevel.LOW}
                risk_level = risk_map.get(risk_str, RiskLevel.MEDIUM)
                
                # Determine NIST function from control_id prefix
                nist_function = NISTFunction.GOVERN  # Default
                ctrl_upper = control_id.upper()
                if ctrl_upper.startswith(("GV", "GOVERN")):
                    nist_function = NISTFunction.GOVERN
                elif ctrl_upper.startswith(("ID", "IDENTIFY")):
                    nist_function = NISTFunction.IDENTIFY
                elif ctrl_upper.startswith(("PR", "PROTECT")):
                    nist_function = NISTFunction.PROTECT
                elif ctrl_upper.startswith(("DE", "DETECT")):
                    nist_function = NISTFunction.DETECT
                elif ctrl_upper.startswith(("RS", "RESPOND")):
                    nist_function = NISTFunction.RESPOND
                elif ctrl_upper.startswith(("RC", "RECOVER")):
                    nist_function = NISTFunction.RECOVER
                
                # Create ComplianceGap from RAG finding
                rag_gap = ComplianceGap(
                    gap_id=f"RAG-{uuid.uuid4().hex[:8]}",
                    control_id=control_id,
                    control_title=finding.get("control_summary", finding.get("control_title", control_id)),
                    nist_function=nist_function,
                    category=control_id.split(".")[0] if "." in control_id else control_id,
                    subcategory=control_id,
                    description=finding.get("example_quote", finding.get("consolidated_reason", "")),
                    reasoning=finding.get("consolidated_reason", finding.get("risk_reason", "Found during RAG analysis")),
                    risk_level=risk_level,
                    affected_assets=[],
                    evidence_sources=[f"Page {p}" for p in finding.get("affected_pages", [])] if finding.get("affected_pages") else [],
                    source_metadata=finding.get("source_references", []),
                    related_questions=[],
                    confidence_score=float(finding.get("confidence", 0.7))
                )
                
                report.compliance_gaps.append(rag_gap)
                existing_control_ids.add(control_id)
                merged_count += 1
            
            print(f"[DEBUG] Successfully merged {merged_count} RAG gaps. Total gaps now: {len(report.compliance_gaps)}")
        else:
            print(f"[DEBUG] No RAG findings to merge. Using only questionnaire-generated gaps: {len(report.compliance_gaps)}")

        # Recalculate compliance summary after merging gaps
        if rag_findings and merged_count > 0:
            print(f"[DEBUG] Recalculating compliance summary with all {len(report.compliance_gaps)} gaps")
            
            # Recalculate gaps by function
            gaps_by_function = {}
            gaps_by_risk = {}
            
            for gap in report.compliance_gaps:
                func = gap.nist_function.value if hasattr(gap.nist_function, 'value') else str(gap.nist_function)
                risk = gap.risk_level.value if hasattr(gap.risk_level, 'value') else str(gap.risk_level)
                
                gaps_by_function[func] = gaps_by_function.get(func, 0) + 1
                gaps_by_risk[risk] = gaps_by_risk.get(risk, 0) + 1
            
            # Update compliance summary
            report.compliance_summary.total_gaps = len(report.compliance_gaps)
            report.compliance_summary.gaps_by_function = gaps_by_function
            report.compliance_summary.gaps_by_risk_level = gaps_by_risk
            report.compliance_summary.critical_findings = gaps_by_risk.get("Critical", 0)
            
            # Recalculate risk score based on gap severity
            risk_score = (
                gaps_by_risk.get("Critical", 0) * 3 +
                gaps_by_risk.get("High", 0) * 2 +
                gaps_by_risk.get("Medium", 0) * 1
            )
            report.compliance_summary.overall_risk_score = min(10.0, risk_score / len(report.compliance_gaps) * 10) if report.compliance_gaps else 0.0
            
            print(f"[DEBUG] Updated compliance summary: {report.compliance_summary.total_gaps} total gaps, risk score: {report.compliance_summary.overall_risk_score}")

        # Validate report quality
        update_report_status(3, "Validating report")
        validation = llm_service.validate_report_quality(report)
        if not validation["is_valid"]:
            REPORT_STATUS[session_id]["status"] = "error"
            REPORT_STATUS[session_id]["error"] = "Report validation failed"
            REPORT_STATUS[session_id]["finished_at"] = time.time()
            return jsonify({
                "error": "Generated report did not meet quality standards",
                "validation_details": validation
            }), 500

        # Store report
        update_report_status(4, "Finalizing report")
        report_id = report.report_id

        REPORTS[report_id] = {
            "report": report,
            "session_id": session_id,
            "filename": filename,
            "generated_at": time.time(),
            "validation": validation
        }

        # Update session
        questionnaire_session["report_id"] = report_id
        questionnaire_session["status"] = "report_generated"

        # Save report to database for persistence (so it shows on documents page)
        try:
            user_id = session.get("user_id")
            pending_doc_id = session.get("pending_doc_id")
            
            if user_id and pending_doc_id:
                db = get_db_connection()
                doc_row = db.execute("SELECT id FROM documents WHERE unique_id = ?", (pending_doc_id,)).fetchone()
                document_id = doc_row["id"] if doc_row else None
                
                if document_id:
                    # Prepare report data for database
                    compliance_summary_json = json.dumps(model_to_dict(report.compliance_summary), cls=CustomJSONEncoder)
                    gap_analysis_json = json.dumps([model_to_dict(gap) for gap in report.compliance_gaps], cls=CustomJSONEncoder)
                    risk_assessment_json = json.dumps(report.risk_assessment, cls=CustomJSONEncoder)
                    
                    # Get heatmap from HEATMAP_REPORTS if available (generated during the session)
                    heatmap_data = None
                    for hmap in HEATMAP_REPORTS.values():
                        if hmap.session_id == session_id:
                            heatmap_data = {
                                "report_id": hmap.report_id,
                                "items_above_appetite": hmap.items_above_appetite,
                                "total_items": len(hmap.heat_map_items),
                                "risk_appetite": hmap.risk_appetite_profile.max_acceptable_risk.value if hasattr(hmap.risk_appetite_profile, 'max_acceptable_risk') else 5,
                                "visualization_path": hmap.visualization_path,
                                "items": [
                                    {
                                        "name": item.name,
                                        "likelihood": item.likelihood,
                                        "impact": item.impact,
                                        "risk_level": item.risk_level,
                                        "color_code": getattr(item, 'color_code', '#888888'),
                                        "above_appetite": item.above_appetite,
                                        "reasoning": item.reasoning
                                    }
                                    for item in hmap.heat_map_items
                                ],
                                "heat_map_items": [
                                    {
                                        "name": item.name,
                                        "likelihood": item.likelihood,
                                        "impact": item.impact,
                                        "risk_level": item.risk_level,
                                        "color_code": getattr(item, 'color_code', '#888888'),
                                        "above_appetite": item.above_appetite,
                                        "reasoning": item.reasoning
                                    }
                                    for item in hmap.heat_map_items
                                ]
                            }
                            break
                    
                    # Fall back to report.heatmap if no session heatmap
                    if heatmap_data is None and report.heatmap:
                        heatmap_data = report.heatmap
                    
                    heatmap_json = json.dumps(heatmap_data, cls=CustomJSONEncoder) if heatmap_data else None
                    recommendations_json = json.dumps(report.recommendations, cls=CustomJSONEncoder)
                    
                    db.execute(
                        """INSERT INTO report (document_id, user_id, compliance_summary, gap_analysis, 
                           risk_assessment, risk_heat_map, recommendations, created_at, 
                           organization_name, industry, size, scope) 
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (
                            document_id,
                            user_id,
                            compliance_summary_json,
                            gap_analysis_json,
                            risk_assessment_json,
                            heatmap_json,
                            recommendations_json,
                            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            organization_info.organization_name,
                            organization_info.industry,
                            organization_info.size,
                            organization_info.scope
                        )
                    )
                    # Get the newly created report ID
                    new_report_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
                    
                    # Log the initial creation in edit history
                    user_name = session.get("full_name", "System")
                    db.execute("""
                        INSERT INTO report_edit_history (report_id, user_id, user_name, edit_type, summary)
                        VALUES (?, ?, ?, 'created', 'Report generated from compliance analysis')
                    """, (new_report_id, user_id, user_name))
                    
                    db.commit()
                    print(f"[SUCCESS] Report saved to database for document_id={document_id}, user_id={user_id}")
                else:
                    print(f"[WARNING] Could not find document with unique_id={pending_doc_id}")
                db.close()
            else:
                print(f"[WARNING] Missing user_id or pending_doc_id in session, report not saved to database")
        except Exception as db_error:
            print(f"[ERROR] Failed to save report to database: {db_error}")
            import traceback
            traceback.print_exc()

        REPORT_STATUS[session_id]["status"] = "done"
        REPORT_STATUS[session_id]["finished_at"] = time.time()

        return jsonify({
            "report_id": report_id,
            "report": model_to_dict(report),
            "validation": validation,
            "message": "Compliance report generated successfully"
        })

    except Exception as e:
        if session_id:
            REPORT_STATUS[session_id] = {
                "status": "error",
                "processed_steps": 0,
                "total_steps": 4,
                "stage": "Failed",
                "started_at": time.time(),
                "finished_at": time.time(),
                "error": str(e)
            }
        return jsonify({"error": f"Failed to generate report: {str(e)}"}), 500


@app.route("/api/reports/<report_id>", methods=["GET"])
def get_report(report_id):
    """
    ENDPOINT: GET /api/reports/<report_id>

    Get a previously generated report.

    Returns:
        Report data if found
    """
    if report_id not in REPORTS:
        return jsonify({"error": "Report not found"}), 404

    report_data = REPORTS[report_id]
    return jsonify({
        "report_id": report_id,
        "report": model_to_dict(report_data["report"]),
        "generated_at": report_data["generated_at"],
        "validation": report_data["validation"]
    })


@app.route("/api/reports/<report_id>/full", methods=["GET"])
def get_full_report_display(report_id):
    """Return complete report data for web display including heatmap."""
    if report_id not in REPORTS:
        return jsonify({"error": "Report not found"}), 404

    report_data = REPORTS[report_id]
    report = report_data["report"]

    heatmap_report = None
    for hmap in HEATMAP_REPORTS.values():
        if hmap.session_id == report_data["session_id"]:
            heatmap_report = hmap
            break

    heatmap_display = None
    if heatmap_report:
        heatmap_display = {
            "report_id": heatmap_report.report_id,
            "items_above_appetite": heatmap_report.items_above_appetite,
            "total_items": len(heatmap_report.heat_map_items),
            "risk_appetite": heatmap_report.risk_appetite_profile.max_acceptable_risk.value,
            "visualization_path": heatmap_report.visualization_path,
            "items": [
                {
                    "name": item.name,
                    "likelihood": item.likelihood,
                    "impact": item.impact,
                    "risk_level": item.risk_level,
                    "color_code": item.color_code,
                    "above_appetite": item.above_appetite,
                    "reasoning": item.reasoning
                }
                for item in heatmap_report.heat_map_items
            ]
        }

    return jsonify({
        "report_id": report_id,
        "organization": model_to_dict(report.organization_info),
        "compliance_summary": model_to_dict(report.compliance_summary),
        "compliance_gaps": [model_to_dict(gap) for gap in report.compliance_gaps],
        "risk_assessment": [model_to_dict(risk) for risk in report.risk_assessment],
        "recommendations": [model_to_dict(rec) for rec in report.recommendations],
        "heatmap": heatmap_display,
        "generated_at": report.generated_at.isoformat()
    })


@app.route("/api/report/<int:report_id>/data", methods=["GET"])
def get_report_data(report_id):
    """
    ENDPOINT: GET /api/report/<report_id>/data

    Get report data for editing. Only the document owner can access.
    """
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"error": "Not authenticated"}), 401

    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Verify the report exists and belongs to a document owned by this user
        cursor.execute("""
            SELECT r.*, d.user_id as owner_id
            FROM report r
            JOIN documents d ON r.document_id = d.id
            WHERE r.id = ?
        """, (report_id,))
        report = cursor.fetchone()
        
        if not report:
            return jsonify({"error": "Report not found"}), 404
        
        if report["owner_id"] != user_id:
            return jsonify({"error": "You do not have permission to edit this report"}), 403

        return jsonify({
            "id": report["id"],
            "organization_name": report["organization_name"],
            "industry": report["industry"],
            "scope": report["scope"],
            "size": report["size"],
            "compliance_summary": report["compliance_summary"],
            "gap_analysis": report["gap_analysis"],
            "risk_assessment": report["risk_assessment"],
            "recommendations": report["recommendations"]
        })
        
    except Exception as e:
        logger.error(f"Error fetching report {report_id}: {str(e)}")
        return jsonify({"error": f"Failed to fetch report: {str(e)}"}), 500
    finally:
        conn.close()


@app.route("/api/document/<int:doc_id>/reports", methods=["GET"])
def get_document_reports(doc_id):
    """
    ENDPOINT: GET /api/document/<doc_id>/reports

    Get list of reports for a document. Used by Edit button in document header.
    """
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"error": "Not authenticated"}), 401

    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Verify the document belongs to this user
        cursor.execute("SELECT user_id FROM documents WHERE id = ?", (doc_id,))
        doc = cursor.fetchone()
        
        if not doc:
            return jsonify({"error": "Document not found"}), 404
        
        if doc["user_id"] != user_id:
            return jsonify({"error": "You do not have permission to access this document"}), 403

        # Get all reports for this document
        cursor.execute("""
            SELECT id, organization_name, created_at
            FROM report
            WHERE document_id = ?
            ORDER BY created_at DESC
        """, (doc_id,))
        reports = cursor.fetchall()
        
        return jsonify({
            "reports": [{"id": r["id"], "organization_name": r["organization_name"], "created_at": r["created_at"]} for r in reports]
        })
        
    except Exception as e:
        logger.error(f"Error fetching reports for document {doc_id}: {str(e)}")
        return jsonify({"error": f"Failed to fetch reports: {str(e)}"}), 500
    finally:
        conn.close()


@app.route("/api/report/<int:report_id>/edit", methods=["POST"])
def edit_report(report_id):
    """
    ENDPOINT: POST /api/report/<report_id>/edit

    Edit a compliance report. Only the document owner can edit.

    Request Body:
        organization_name, industry, scope, size, compliance_summary, gap_analysis, risk_assessment, recommendations
    """
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"error": "Not authenticated"}), 401
    
    data = request.get_json()
    
    if not data:
        return jsonify({"error": "No data provided"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Verify the report exists and belongs to a document owned by this user
        cursor.execute("""
            SELECT r.*, d.user_id as owner_id, d.documentTitle
            FROM report r
            JOIN documents d ON r.document_id = d.id
            WHERE r.id = ?
        """, (report_id,))
        report = cursor.fetchone()
        
        if not report:
            return jsonify({"error": "Report not found"}), 404
        
        if report["owner_id"] != user_id:
            return jsonify({"error": "You do not have permission to edit this report"}), 403

        document_id = report["document_id"]
        document_title = report["documentTitle"]
        user_name = session.get("full_name", "Unknown User")

        # Store old values for change tracking
        old_values = {
            "organization_name": report["organization_name"] or "",
            "industry": report["industry"] or "",
            "scope": report["scope"] or "",
            "size": report["size"] or "",
            "compliance_summary": report["compliance_summary"] or "{}",
            "gap_analysis": report["gap_analysis"] or "[]",
            "risk_assessment": report["risk_assessment"] or "[]",
            "recommendations": report["recommendations"] or "[]"
        }

        # Prepare data for update
        organization_name = data.get("organization_name", "")
        industry = data.get("industry", "")
        scope = data.get("scope", "")
        size = data.get("size", "")
        
        # JSON fields
        compliance_summary = json.dumps(data.get("compliance_summary", {}))
        gap_analysis = json.dumps(data.get("gap_analysis", []))
        risk_assessment = json.dumps(data.get("risk_assessment", []))
        recommendations = json.dumps(data.get("recommendations", []))

        new_values = {
            "organization_name": organization_name,
            "industry": industry,
            "scope": scope,
            "size": size,
            "compliance_summary": compliance_summary,
            "gap_analysis": gap_analysis,
            "risk_assessment": risk_assessment,
            "recommendations": recommendations
        }

        # Track changes and log to history
        changes_made = []
        field_labels = {
            "organization_name": "Organization Name",
            "industry": "Industry",
            "scope": "Scope",
            "size": "Size",
            "compliance_summary": "Compliance Summary",
            "gap_analysis": "Gap Analysis",
            "risk_assessment": "Risk Assessment",
            "recommendations": "Recommendations"
        }

        json_fields = ("compliance_summary", "gap_analysis", "risk_assessment", "recommendations")

        for field, new_val in new_values.items():
            old_val = old_values[field]
            
            # For JSON fields, parse both values to compare actual content (not string formatting)
            if field in json_fields:
                try:
                    old_parsed = json.loads(old_val) if old_val else ([] if field != "compliance_summary" else {})
                    new_parsed = json.loads(new_val) if new_val else ([] if field != "compliance_summary" else {})
                    values_differ = old_parsed != new_parsed
                except (json.JSONDecodeError, TypeError):
                    values_differ = old_val != new_val
            else:
                # For string fields, normalize empty values
                old_normalized = (old_val or "").strip()
                new_normalized = (new_val or "").strip()
                values_differ = old_normalized != new_normalized

            if values_differ:
                changes_made.append(field_labels[field])
                # For JSON fields, don't store full values (too large), just note it changed
                if field in json_fields:
                    cursor.execute("""
                        INSERT INTO report_edit_history (report_id, user_id, user_name, edit_type, field_changed, summary)
                        VALUES (?, ?, ?, 'field_update', ?, ?)
                    """, (report_id, user_id, user_name, field_labels[field], f"Updated {field_labels[field]}"))
                else:
                    cursor.execute("""
                        INSERT INTO report_edit_history (report_id, user_id, user_name, edit_type, field_changed, old_value, new_value, summary)
                        VALUES (?, ?, ?, 'field_update', ?, ?, ?, ?)
                    """, (report_id, user_id, user_name, field_labels[field], old_val, new_val, f"Changed {field_labels[field]}"))

        # Update the report
        cursor.execute("""
            UPDATE report
            SET organization_name = ?,
                industry = ?,
                scope = ?,
                size = ?,
                compliance_summary = ?,
                gap_analysis = ?,
                risk_assessment = ?,
                recommendations = ?
            WHERE id = ?
        """, (organization_name, industry, scope, size, compliance_summary, gap_analysis, risk_assessment, recommendations, report_id))
        
        # Notify all viewers that the shared document was updated
        owner_name = session.get("full_name", "The owner")
        viewers = cursor.execute("""
            SELECT viewer_id FROM collaborators 
            WHERE document_id = ? AND status = 'active' AND viewer_id IS NOT NULL
        """, (document_id,)).fetchall()
        for viewer in viewers:
            cursor.execute(
                "INSERT INTO notifications (user_id, message, document_id, read) VALUES (?, ?, ?, 0)",
                (viewer["viewer_id"], f"{owner_name} updated the shared document '{document_title}'", document_id)
            )
        
        conn.commit()
        
        return jsonify({
            "success": True, 
            "message": "Report updated successfully",
            "changes": changes_made
        })
        
    except Exception as e:
        conn.rollback()
        logger.error(f"Error updating report {report_id}: {str(e)}")
        return jsonify({"error": f"Failed to update report: {str(e)}"}), 500
    finally:
        conn.close()


# DEINTEGRATED - kept for future use
# @app.route("/api/download-report/<report_id>/<format>", methods=["GET"])
# def download_report(report_id, format):
#     """
#     ENDPOINT: GET /api/download-report/<report_id>/<format>
#
#     Download a report in specified format (pdf or docx).
#
#     Args:
#         report_id: ID of report to download
#         format: Export format (pdf or docx)
#
#     Returns:
#         File download response
#     """
#     try:
#         if report_id not in REPORTS:
#             return jsonify({"error": "Report not found"}), 404
#
#         if format not in ["pdf", "docx"]:
#             return jsonify({"error": "Format must be 'pdf' or 'docx'"}), 400
#
#         report_data = REPORTS[report_id]
#         report = report_data["report"]
#         session_id = report_data["session_id"]
#
#         # Look for existing heatmap or generate one
#         heatmap_report = None
#
#         for hmap in HEATMAP_REPORTS.values():
#             if hmap.session_id == session_id:
#                 heatmap_report = hmap
#                 break
#
#         if not heatmap_report and report.compliance_gaps:
#             try:
#                 logger.info(
#                     f"Generating heatmap for report {report_id} from {len(report.compliance_gaps)} gaps"
#                 )
#                 heatmap_report = heatmap_service.generate_heatmap_from_gaps(
#                     compliance_gaps=report.compliance_gaps,
#                     organization_name=report.organization_info.organization_name,
#                     session_id=session_id
#                 )
#                 HEATMAP_REPORTS[heatmap_report.report_id] = heatmap_report
#             except Exception as e:
#                 logger.error(f"Failed to generate heatmap: {str(e)}")
#                 heatmap_report = None
#
#         # Generate export
#         if format == "pdf":
#             filepath = report_exporter.export_to_pdf(report, heatmap_report)
#         else:  # docx
#             filepath = report_exporter.export_to_word(report, heatmap_report)
#
#         # Return file for download
#         return send_from_directory(
#             directory=os.path.dirname(filepath),
#             path=os.path.basename(filepath),
#             as_attachment=True,
#             download_name=os.path.basename(filepath)
#         )
#
#     except Exception as e:
#         return jsonify({"error": f"Failed to export report: {str(e)}"}), 500

# ============================================
# RISK APPETITE & HEAT-MAP ENDPOINTS
# ============================================

@app.route("/api/risk-appetite-questions", methods=["GET"])
def get_risk_appetite_questions():
    """
    ENDPOINT: GET /api/risk-appetite-questions

    Get risk appetite assessment questions for questionnaire.

    Returns:
        List of risk appetite questions
    """
    try:
        questions = questionnaire_engine.get_risk_appetite_questions()

        return jsonify({
            "questions": questions,
            "total_questions": len(questions),
            "estimated_time_minutes": len(questions) * 3
        })
    except Exception as e:
        return jsonify({"error": f"Failed to get risk appetite questions: {str(e)}"}), 500


@app.route("/api/heatmap-template", methods=["GET"])
def get_heatmap_template():
    """
    ENDPOINT: GET /api/heatmap-template

    Get heat-map input template fields.

    Returns:
        List of heat-map input fields
    """
    try:
        template = questionnaire_engine.get_heatmap_input_template()

        return jsonify({
            "fields": template,
            "description": "Use these fields to collect data for each item in your risk register"
        })
    except Exception as e:
        return jsonify({"error": f"Failed to get heat-map template: {str(e)}"}), 500


@app.route("/api/submit-risk-appetite", methods=["POST"])
def submit_risk_appetite():
    """
    ENDPOINT: POST /api/submit-risk-appetite

    Submit organizational risk appetite profile.

    Request body:
    {
        "session_id": "...",
        "organization_name": "...",
        "overall_risk_posture": "Balanced",
        "max_acceptable_risk": "Medium is acceptable; High must be mitigated",
        "impact_sensitivities": ["Regulatory / legal breaches", "Financial loss"],
        "high_risk_mitigation_timeline": "3 months",
        "preferred_risk_treatment": "Reduce (add controls)"
    }

    Returns:
        Profile ID and confirmation
    """
    try:
        data = request.json
        session_id = data.get("session_id")

        if not session_id or session_id not in QUESTIONNAIRE_SESSIONS:
            return jsonify({"error": "Invalid session ID"}), 400

        # Convert string enums to proper enum types
        # Helper function to normalize risk approach values
        def normalize_risk_approach(value):
            """Convert long description to enum value"""
            if not value:
                return "Balanced"
            # Extract first part before em-dash or comma
            value_lower = value.lower().split('–')[0].split(',')[0].strip()
            if 'very conservative' in value_lower or 'extremely avoid' in value_lower:
                return "Very conservative"
            elif 'conservative' in value_lower:
                return "Conservative"
            elif 'aggressive' in value_lower and 'very' not in value_lower:
                return "Aggressive"
            elif 'very aggressive' in value_lower or 'maximize' in value_lower:
                return "Very aggressive"
            else:  # default to Balanced
                return "Balanced"

        risk_posture_str = normalize_risk_approach(data.get("overall_risk_posture", "Balanced"))
        risk_posture = RiskApproach(risk_posture_str)

        # Normalize max acceptable risk
        max_risk_input = data.get("max_acceptable_risk", "Medium acceptable; High must be mitigated")
        if "only low" in max_risk_input.lower():
            max_risk = MaxAcceptableRisk("Only Low")
        elif "high" in max_risk_input.lower() and "approval" in max_risk_input.lower():
            max_risk = MaxAcceptableRisk("High acceptable with management sign-off")
        elif "high" in max_risk_input.lower() and "mitigat" in max_risk_input.lower():
            max_risk = MaxAcceptableRisk("Medium acceptable; High must be mitigated")
        else:
            max_risk = MaxAcceptableRisk("Low and some Medium")

        impact_sensitivities = [ImpactType(s) for s in data.get("impact_sensitivities", [])]

        # Normalize mitigation timeline
        timeline_input = data.get("high_risk_mitigation_timeline", "3 months")
        if "1 month" in timeline_input.lower() or "1 month" == timeline_input.lower():
            mitigation_timeline = MitigationTimeline("1 month")
        elif "executive" in timeline_input.lower():
            mitigation_timeline = MitigationTimeline("Executive approval")
        elif "other" in timeline_input.lower():
            mitigation_timeline = MitigationTimeline("Other")
        else:
            mitigation_timeline = MitigationTimeline("3 months")

        # Normalize risk treatment
        treatment_input = data.get("preferred_risk_treatment", "Reduce (add controls)")
        if "transfer" in treatment_input.lower() or "insurance" in treatment_input.lower():
            treatment = RiskTreatment("Transfer (insurance, contracts)")
        elif "avoid" in treatment_input.lower():
            treatment = RiskTreatment("Avoid (change design, stop activity)")
        elif "accept" in treatment_input.lower():
            treatment = RiskTreatment("Accept with justification")
        else:
            treatment = RiskTreatment("Reduce (add controls)")

        # Create risk appetite profile
        profile_id = f"appetite_{uuid.uuid4().hex[:12]}"

        profile = RiskAppetiteProfile(
            profile_id=profile_id,
            session_id=session_id,
            organization_name=data.get("organization_name"),
            overall_risk_posture=risk_posture,
            max_acceptable_risk=max_risk,
            impact_sensitivities=impact_sensitivities,
            high_risk_mitigation_timeline=mitigation_timeline,
            high_risk_mitigation_timeline_other=data.get("high_risk_mitigation_timeline_other"),
            preferred_risk_treatment=treatment
        )

        # Store profile in session
        QUESTIONNAIRE_SESSIONS[session_id]["risk_appetite_profile"] = profile

        return jsonify({
            "profile_id": profile_id,
            "message": "Risk appetite profile saved successfully"
        })

    except Exception as e:
        return jsonify({"error": f"Failed to save risk appetite profile: {str(e)}"}), 500


@app.route("/api/submit-heatmap-items", methods=["POST"])
def submit_heatmap_items():
    """
    ENDPOINT: POST /api/submit-heatmap-items

    Submit heat-map items (documents/policies/systems for risk assessment).

    Request body:
    {
        "session_id": "...",
        "items": [
            {
                "name": "AI Hiring Policy",
                "description": "Controls use of AI in hiring decisions",
                "impact_score": 5,
                "likelihood_score": 3,
                "primary_risk_type": "Fairness / Bias / Ethics",
                "residual_risk_level": "High"
            }
        ]
    }

    Returns:
        Confirmation and items count
    """
    try:
        data = request.json
        session_id = data.get("session_id")

        if not session_id or session_id not in QUESTIONNAIRE_SESSIONS:
            return jsonify({"error": "Invalid session ID"}), 400

        items_data = data.get("items", [])
        if not items_data:
            return jsonify({"error": "No items provided"}), 400

        # Convert to HeatMapItem objects
        items = []
        for i, item_data in enumerate(items_data):
            item = HeatMapItem(
                item_id=f"item_{i:03d}_{uuid.uuid4().hex[:8]}",
                name=item_data.get("name"),
                description=item_data.get("description", ""),
                impact_score=int(item_data.get("impact_score", 1)),
                likelihood_score=int(item_data.get("likelihood_score", 1)),
                primary_risk_type=item_data.get("primary_risk_type", "Operational / Availability"),
                residual_risk_level=item_data.get("residual_risk_level", "Medium")
            )
            items.append(item)

        # Store items in session
        QUESTIONNAIRE_SESSIONS[session_id]["heatmap_items"] = items

        return jsonify({
            "items_count": len(items),
            "message": f"Stored {len(items)} heat-map items successfully"
        })

    except Exception as e:
        return jsonify({"error": f"Failed to store heat-map items: {str(e)}"}), 500


@app.route("/api/generate-heatmap", methods=["POST"])
def generate_heatmap():
    """
    ENDPOINT: POST /api/generate-heatmap

    Generate risk heat-map report and visualization.

    Request body:
    {
        "session_id": "..."
    }

    Returns:
        Heat-map report with analysis and summary
    """
    try:
        data = request.json
        session_id = data.get("session_id")

        if not session_id or session_id not in QUESTIONNAIRE_SESSIONS:
            return jsonify({"error": "Invalid session ID"}), 400

        session = QUESTIONNAIRE_SESSIONS[session_id]

        # Get risk appetite profile
        if "risk_appetite_profile" not in session:
            return jsonify({"error": "Risk appetite profile not yet submitted"}), 400

        appetite_profile = session["risk_appetite_profile"]

        # Get heat-map items
        if "heatmap_items" not in session or not session["heatmap_items"]:
            return jsonify({"error": "No heat-map items submitted"}), 400

        items = session["heatmap_items"]

        # Generate heat-map report
        report = heatmap_service.generate_heat_map_report(items, appetite_profile, session_id)

        # Store report
        HEATMAP_REPORTS[report.report_id] = report

        # Get summary
        summary = heatmap_service.get_heatmap_summary(report)

        return jsonify({
            "report_id": report.report_id,
            "session_id": session_id,
            "summary": summary,
            "visualization_path": report.visualization_path,
            "items_analyzed": len(report.heat_map_items),
            "generated_at": report.generated_at.isoformat()
        })

    except Exception as e:
        return jsonify({"error": f"Failed to generate heat-map: {str(e)}"}), 500


@app.route("/api/generate-heatmap-from-gaps", methods=["POST"])
def generate_heatmap_from_gaps():
    """
    ENDPOINT: POST /api/generate-heatmap-from-gaps

    Generate risk heat map directly from compliance gaps.

    Request body:
    {
        "report_id": "...",  // ID of existing report
        "session_id": "..."   // OR session ID
    }

    Returns:
        Heat-map report with visualization
    """
    try:
        data = request.json
        report_id = data.get("report_id")
        session_id = data.get("session_id")

        if not report_id and not session_id:
            return jsonify({"error": "Either report_id or session_id required"}), 400

        compliance_gaps = []
        organization_name = "Unknown Organization"

        if report_id and report_id in REPORTS:
            report_data = REPORTS[report_id]
            report = report_data["report"]
            compliance_gaps = report.compliance_gaps
            organization_name = report.organization_info.organization_name
            session_id = report_data.get("session_id", session_id)
        elif session_id and session_id in QUESTIONNAIRE_SESSIONS:
            session = QUESTIONNAIRE_SESSIONS[session_id]
            if "report_id" in session and session["report_id"] in REPORTS:
                report_data = REPORTS[session["report_id"]]
                report = report_data["report"]
                compliance_gaps = report.compliance_gaps
                organization_name = report.organization_info.organization_name

        if not compliance_gaps:
            return jsonify({"error": "No compliance gaps found"}), 404

        heatmap_report = heatmap_service.generate_heatmap_from_gaps(
            compliance_gaps=compliance_gaps,
            organization_name=organization_name,
            session_id=session_id or f"session_{uuid.uuid4().hex[:12]}"
        )

        HEATMAP_REPORTS[heatmap_report.report_id] = heatmap_report

        summary = heatmap_service.get_heatmap_summary(heatmap_report)

        return jsonify({
            "report_id": heatmap_report.report_id,
            "session_id": session_id,
            "summary": summary,
            "visualization_path": heatmap_report.visualization_path,
            "items_analyzed": len(heatmap_report.heat_map_items),
            "generated_at": heatmap_report.generated_at.isoformat() if heatmap_report.generated_at else None
        })

    except Exception as e:
        return jsonify({"error": f"Failed to generate heatmap: {str(e)}"}), 500


@app.route("/api/heatmap-report/<report_id>", methods=["GET"])
def get_heatmap_report(report_id):
    """
    ENDPOINT: GET /api/heatmap-report/<report_id>

    Get a previously generated heat-map report.

    Returns:
        Full heat-map report with all analysis data
    """
    try:
        if report_id not in HEATMAP_REPORTS:
            return jsonify({"error": "Report not found"}), 404

        report = HEATMAP_REPORTS[report_id]

        # Convert to dictionary for JSON serialization
        report_dict = {
            "report_id": report.report_id,
            "session_id": report.session_id,
            "organization": report.organization,
            "risk_appetite": {
                "overall_posture": report.risk_appetite_profile.overall_risk_posture.value,
                "max_acceptable_risk": report.risk_appetite_profile.max_acceptable_risk.value,
                "impact_sensitivities": [s.value for s in report.risk_appetite_profile.impact_sensitivities],
                "mitigation_timeline": report.risk_appetite_profile.high_risk_mitigation_timeline.value
            },
            "items": [
                {
                    "item_id": item.item_id,
                    "name": item.name,
                    "likelihood": item.likelihood,
                    "impact": item.impact,
                    "risk_level": item.risk_level,
                    "color_code": item.color_code,
                    "above_appetite": item.above_appetite,
                    "reasoning": item.reasoning
                }
                for item in report.heat_map_items
            ],
            "items_above_appetite": report.items_above_appetite,
            "total_items": len(report.heat_map_items),
            "visualization_path": report.visualization_path,
            "generated_at": report.generated_at.isoformat()
        }

        return jsonify(report_dict)

    except Exception as e:
        return jsonify({"error": f"Failed to retrieve heat-map report: {str(e)}"}), 500


@app.route("/api/heatmap-image/<report_id>", methods=["GET"])
def download_heatmap_image(report_id):
    """
    ENDPOINT: GET /api/heatmap-image/<report_id>

    Download the generated heat-map visualization image.

    Returns:
        PNG image file
    """
    try:
        # First check in-memory HEATMAP_REPORTS
        if report_id in HEATMAP_REPORTS:
            report = HEATMAP_REPORTS[report_id]
            if report.visualization_path and os.path.exists(report.visualization_path):
                return send_from_directory(
                    directory=os.path.dirname(report.visualization_path),
                    path=os.path.basename(report.visualization_path),
                    as_attachment=False,
                    download_name=f"risk_heatmap_{report_id}.png"
                )
        
        # Fallback: Check if we can find the image in exports directory by report_id
        exports_dir = os.path.join(BASE_DIR, "exports")
        possible_files = [
            f"heatmap_{report_id}.png",
            f"risk_heatmap_{report_id}.png",
            f"{report_id}.png"
        ]
        for fname in possible_files:
            fpath = os.path.join(exports_dir, fname)
            if os.path.exists(fpath):
                return send_from_directory(
                    directory=exports_dir,
                    path=fname,
                    as_attachment=False,
                    download_name=f"risk_heatmap_{report_id}.png"
                )
        
        # Not found in memory or exports
        return jsonify({"error": "Heatmap visualization not found"}), 404

    except Exception as e:
        return jsonify({"error": f"Failed to retrieve heat-map image: {str(e)}"}), 500


# ============================================
# COLLABORATION & PERMISSIONS SYSTEM
# ============================================

VALID_SECTIONS = {
    "org_info": "Organization Info",
    "risk_appetite": "Risk Appetite",
    "questionnaire": "Questionnaire Responses",
    "heatmap": "Risk Heat Map",
    "report": "Final Report Preview",
}


def _extract_framework_version_from_message(message: str):
    """Extract a framework version token from audit log message text."""
    if not message:
        return None

    patterns = [
        r"version\s+([0-9]+(?:\.[0-9]+)*)",
        r"version_id\s*=\s*([0-9]+(?:\.[0-9]+)*)",
        r"@[^\s()]*([0-9]+(?:\.[0-9]+)*)",
    ]
    for pattern in patterns:
        m = re.search(pattern, str(message), flags=re.IGNORECASE)
        if m:
            return m.group(1)
    return None


def _infer_framework_version_for_report(db, created_at: str):
    """Infer likely framework version from the latest activation/audit event before report creation."""
    if not db or not created_at:
        return (None, None)

    try:
        row = db.execute(
            """
            SELECT message
            FROM framework_audit_log
            WHERE created_at <= ?
              AND (
                event_type IN ('manual_activate', 'shadow_swap_success')
                OR message LIKE '%Activated framework version%'
                OR message LIKE '%version_id=%'
              )
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (created_at,),
        ).fetchone()
        if not row:
            return (None, None)

        inferred_version_id = _extract_framework_version_from_message(row["message"])
        if inferred_version_id:
            return (inferred_version_id, inferred_version_id)
    except Exception:
        pass

    return (None, None)


def _parse_report_row(rep, db=None):
    """Convert a DB report row to a dict with parsed JSON fields and framework-version fallbacks."""
    rep_dict = dict(rep)
    for field in ["compliance_summary", "gap_analysis", "risk_assessment", "risk_heat_map", "recommendations"]:
        default = {} if field in ("compliance_summary", "risk_heat_map") else []
        try:
            rep_dict[field] = json.loads(rep_dict[field]) if rep_dict[field] else default
        except Exception:
            rep_dict[field] = default

    # Framework provenance fallback chain:
    # 1) explicit report columns
    # 2) JSON metadata fields (if present)
    # 3) infer from framework audit log at report timestamp
    framework_name = rep_dict.get("framework_name")
    framework_version_id = rep_dict.get("framework_version_id")
    framework_version_label = rep_dict.get("framework_version_label")
    framework_used_at = rep_dict.get("framework_used_at")

    metadata_obj = {}
    raw_metadata = rep_dict.get("metadata")
    if raw_metadata:
        try:
            metadata_obj = raw_metadata if isinstance(raw_metadata, dict) else json.loads(raw_metadata)
        except Exception:
            metadata_obj = {}

    if not framework_name:
        framework_name = metadata_obj.get("framework_name")
    if not framework_version_id:
        framework_version_id = metadata_obj.get("framework_version_id")
    if not framework_version_label:
        framework_version_label = metadata_obj.get("framework_version_label")
    if not framework_used_at:
        framework_used_at = metadata_obj.get("framework_used_at")

    if (not framework_version_id and not framework_version_label) and db is not None:
        inferred_id, inferred_label = _infer_framework_version_for_report(db, rep_dict.get("created_at"))
        framework_version_id = framework_version_id or inferred_id
        framework_version_label = framework_version_label or inferred_label

    rep_dict["framework_name"] = framework_name or "NIST CSF"
    rep_dict["framework_version_id"] = framework_version_id
    rep_dict["framework_version_label"] = framework_version_label
    rep_dict["framework_used_at"] = framework_used_at

    # Fetch edit history for this report
    rep_dict["edit_history"] = []
    if db is not None:
        try:
            history_rows = db.execute("""
                SELECT id, user_id, user_name, edit_type, field_changed, old_value, new_value, summary, edited_at
                FROM report_edit_history
                WHERE report_id = ?
                ORDER BY edited_at DESC
                LIMIT 50
            """, (rep_dict.get("id"),)).fetchall()
            rep_dict["edit_history"] = [dict(h) for h in history_rows]
        except Exception:
            # Table may not exist yet
            rep_dict["edit_history"] = []

    return rep_dict


# --- Invite a viewer ---
@app.route("/api/collaborators/invite", methods=["POST"])
def invite_collaborator():
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json()
    document_id = data.get("document_id")
    viewer_email = (data.get("email") or "").strip().lower()

    if not document_id or not viewer_email:
        return jsonify({"error": "document_id and email are required"}), 400

    db = get_db_connection()

    doc = db.execute(
        "SELECT * FROM documents WHERE id=? AND user_id=?", (document_id, user_id)
    ).fetchone()
    if not doc:
        db.close()
        return jsonify({"error": "Document not found or not authorized"}), 403

    # Don't allow owner to invite themselves
    owner_row = db.execute("SELECT email FROM users WHERE id=?", (user_id,)).fetchone()
    if owner_row and owner_row["email"].lower() == viewer_email:
        db.close()
        return jsonify({"error": "You cannot invite yourself"}), 400

    viewer = db.execute("SELECT id, full_name FROM users WHERE email=?", (viewer_email,)).fetchone()
    viewer_id = viewer["id"] if viewer else None

    existing = db.execute(
        "SELECT id FROM collaborators WHERE document_id=? AND viewer_email=? AND status='active'",
        (document_id, viewer_email),
    ).fetchone()
    if existing:
        db.close()
        return jsonify({"error": "This user already has viewer access"}), 400

    db.execute(
        "INSERT INTO collaborators (document_id, owner_id, viewer_id, viewer_email, status) VALUES (?,?,?,?,'active')",
        (document_id, user_id, viewer_id, viewer_email),
    )

    owner_name = session.get("full_name", "Someone")
    if viewer_id:
        db.execute(
            "INSERT INTO notifications (user_id, message, document_id, read) VALUES (?,?,?,0)",
            (viewer_id, f"{owner_name} shared '{doc['documentTitle']}' with you for viewing", document_id),
        )

    db.execute(
        "INSERT INTO notifications (user_id, message, document_id, read) VALUES (?,?,?,0)",
        (user_id, f"You invited {viewer_email} to view '{doc['documentTitle']}'", document_id),
    )

    db.commit()
    db.close()
    return jsonify({"success": True, "message": f"Invited {viewer_email} as viewer"})


# --- List collaborators for a document ---
@app.route("/api/collaborators/<int:document_id>", methods=["GET"])
def list_collaborators(document_id):
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401

    db = get_db_connection()
    doc = db.execute(
        "SELECT id FROM documents WHERE id=? AND user_id=?", (document_id, user_id)
    ).fetchone()
    if not doc:
        db.close()
        return jsonify({"error": "Not authorized"}), 403

    collabs = db.execute(
        "SELECT id, viewer_email, viewer_id, status, invited_at FROM collaborators "
        "WHERE document_id=? AND status='active' ORDER BY invited_at DESC",
        (document_id,),
    ).fetchall()
    db.close()
    return jsonify({"collaborators": [dict(c) for c in collabs]})


# --- Revoke a collaborator ---
@app.route("/api/collaborators/revoke/<int:collab_id>", methods=["POST"])
def revoke_collaborator(collab_id):
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401

    db = get_db_connection()
    collab = db.execute(
        "SELECT c.*, d.documentTitle FROM collaborators c "
        "JOIN documents d ON c.document_id = d.id "
        "WHERE c.id=? AND c.owner_id=?",
        (collab_id, user_id),
    ).fetchone()
    if not collab:
        db.close()
        return jsonify({"error": "Not found or not authorized"}), 403

    db.execute("UPDATE collaborators SET status='revoked' WHERE id=?", (collab_id,))

    if collab["viewer_id"]:
        db.execute(
            "INSERT INTO notifications (user_id, message, document_id, read) VALUES (?,?,?,0)",
            (collab["viewer_id"], f"Your viewer access to '{collab['documentTitle']}' has been revoked", collab["document_id"]),
        )

    db.commit()
    db.close()
    return jsonify({"success": True})


# --- Create a section share link ---
@app.route("/api/share-link/create", methods=["POST"])
def create_share_link():
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json()
    document_id = data.get("document_id")
    section = data.get("section")
    expires_in_hours = data.get("expires_in_hours")

    if section not in VALID_SECTIONS:
        return jsonify({"error": f"Invalid section. Must be one of: {', '.join(VALID_SECTIONS)}"}), 400

    db = get_db_connection()
    doc = db.execute(
        "SELECT * FROM documents WHERE id=? AND user_id=?", (document_id, user_id)
    ).fetchone()
    if not doc:
        db.close()
        return jsonify({"error": "Not authorized"}), 403

    token = str(uuid.uuid4())
    expires_at = None
    if expires_in_hours:
        expires_at = (datetime.now() + timedelta(hours=int(expires_in_hours))).strftime("%Y-%m-%d %H:%M:%S")

    db.execute(
        "INSERT INTO share_links (token, owner_id, document_id, section, expires_at, revoked) VALUES (?,?,?,?,?,0)",
        (token, user_id, document_id, section, expires_at),
    )
    db.commit()
    
    # Get link ID
    link = db.execute("SELECT id FROM share_links WHERE token=?", (token,)).fetchone()
    link_id = link["id"] if link else None
    
    db.close()
    
    # Log share link creation
    AuditLogger.log("document_share", "share_link", link_id,
                   f"Created share link for document {document_id} (section: {section}, expires: {expires_at})", "success")

    return jsonify({
        "success": True,
        "token": token,
        "url": f"/share/{token}",
        "section": section,
        "section_name": VALID_SECTIONS[section],
        "expires_at": expires_at,
    })


# --- List share links for a document ---
@app.route("/api/share-links/<int:document_id>", methods=["GET"])
def list_share_links(document_id):
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401

    db = get_db_connection()
    doc = db.execute(
        "SELECT id FROM documents WHERE id=? AND user_id=?", (document_id, user_id)
    ).fetchone()
    if not doc:
        db.close()
        return jsonify({"error": "Not authorized"}), 403

    links = db.execute(
        "SELECT id, token, section, expires_at, revoked, created_at FROM share_links "
        "WHERE document_id=? AND revoked=0 ORDER BY created_at DESC",
        (document_id,),
    ).fetchall()

    results = []
    for link in links:
        link_dict = dict(link)
        link_dict["section_name"] = VALID_SECTIONS.get(link_dict["section"], link_dict["section"])
        count = db.execute(
            "SELECT COUNT(*) FROM share_link_access_log WHERE share_link_id=?", (link["id"],)
        ).fetchone()[0]
        link_dict["access_count"] = count
        link_dict["is_expired"] = (
            datetime.strptime(link_dict["expires_at"], "%Y-%m-%d %H:%M:%S") < datetime.now()
            if link_dict["expires_at"] else False
        )
        results.append(link_dict)

    db.close()
    return jsonify({"links": results})


# --- Revoke a share link ---
@app.route("/api/share-links/revoke/<int:link_id>", methods=["POST"])
def revoke_share_link(link_id):
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401

    db = get_db_connection()
    link = db.execute(
        "SELECT id FROM share_links WHERE id=? AND owner_id=?", (link_id, user_id)
    ).fetchone()
    if not link:
        db.close()
        return jsonify({"error": "Not found or not authorized"}), 403

    db.execute("UPDATE share_links SET revoked=1 WHERE id=?", (link_id,))
    db.commit()
    
    # Log share link revocation
    AuditLogger.log("document_share_revoke", "share_link", link_id, "Revoked share link", "success")
    
    db.close()
    return jsonify({"success": True})


# --- Access log for a share link ---
@app.route("/api/share-links/<int:link_id>/access-log", methods=["GET"])
def share_link_access_log_view(link_id):
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401

    db = get_db_connection()
    link = db.execute(
        "SELECT id FROM share_links WHERE id=? AND owner_id=?", (link_id, user_id)
    ).fetchone()
    if not link:
        db.close()
        return jsonify({"error": "Not found or not authorized"}), 403

    logs = db.execute(
        "SELECT l.accessor_ip, l.accessor_user_id, l.accessed_at, u.full_name, u.email "
        "FROM share_link_access_log l "
        "LEFT JOIN users u ON l.accessor_user_id = u.id "
        "WHERE l.share_link_id=? ORDER BY l.accessed_at DESC",
        (link_id,),
    ).fetchall()
    db.close()
    return jsonify({"access_log": [dict(log) for log in logs]})


# --- Public shared section view ---
@app.route("/share/<token>")
def view_shared_section(token):
    db = get_db_connection()

    link = db.execute(
        "SELECT * FROM share_links WHERE token=? AND revoked=0", (token,)
    ).fetchone()

    if not link:
        db.close()
        return render_template("shared_section.html", error="This link is invalid or has been revoked.", section=None, doc=None, section_data=None, section_name=None, expires_at=None)

    if link["expires_at"]:
        if datetime.strptime(link["expires_at"], "%Y-%m-%d %H:%M:%S") < datetime.now():
            db.close()
            return render_template("shared_section.html", error="This share link has expired.", section=None, doc=None, section_data=None, section_name=None, expires_at=link["expires_at"])

    accessor_ip = request.remote_addr
    accessor_user_id = session.get("user_id")
    db.execute(
        "INSERT INTO share_link_access_log (share_link_id, accessor_ip, accessor_user_id) VALUES (?,?,?)",
        (link["id"], accessor_ip, accessor_user_id),
    )

    doc = db.execute("SELECT * FROM documents WHERE id=?", (link["document_id"],)).fetchone()
    section_name = VALID_SECTIONS.get(link["section"], link["section"])

    db.execute(
        "INSERT INTO notifications (user_id, message, document_id, read) VALUES (?,?,?,0)",
        (link["owner_id"], f"Your shared '{section_name}' for '{doc['documentTitle'] if doc else 'a document'}' was accessed", link["document_id"]),
    )
    db.commit()

    report_row = db.execute(
        "SELECT * FROM report WHERE document_id=? ORDER BY created_at DESC", (link["document_id"],)
    ).fetchone()

    section_data = {}
    if report_row:
        section_data["report"] = _parse_report_row(report_row, db=db)

    db.close()

    return render_template(
        "shared_section.html",
        error=None,
        section=link["section"],
        section_name=section_name,
        doc=dict(doc) if doc else {},
        section_data=section_data,
        expires_at=link["expires_at"],
    )


# --- Authenticated viewer full document view ---
@app.route("/viewer/document/<int:document_id>")
def viewer_document(document_id):
    user_id = session.get("user_id")
    if not user_id:
        return redirect(url_for("login"))

    db = get_db_connection()
    user_row = db.execute("SELECT email FROM users WHERE id=?", (user_id,)).fetchone()
    user_email = user_row["email"].lower() if user_row else ""

    doc = db.execute("SELECT * FROM documents WHERE id=?", (document_id,)).fetchone()
    if not doc:
        db.close()
        return "Document not found", 404

    is_owner = doc["user_id"] == user_id

    if not is_owner:
        collab = db.execute(
            "SELECT id FROM collaborators WHERE document_id=? AND (viewer_id=? OR viewer_email=?) AND status='active'",
            (document_id, user_id, user_email),
        ).fetchone()
        if not collab:
            db.close()
            return render_template("viewer_document.html", error="You do not have viewer access to this document.", doc=None, report_cards=[], is_owner=False, full_name=session.get("full_name"), role=session.get("role"), user_id=user_id)

    report_rows = db.execute(
        "SELECT * FROM report WHERE document_id=? ORDER BY created_at DESC", (document_id,)
    ).fetchall()
    report_cards = [_parse_report_row(r, db=db) for r in report_rows]

    db.close()

    return render_template(
        "viewer_document.html",
        error=None,
        doc=dict(doc),
        report_cards=report_cards,
        is_owner=is_owner,
        full_name=session.get("full_name"),
        role=session.get("role"),
        user_id=user_id,
    )


# --- Documents shared with the current user (viewer) ---
@app.route("/api/my-shared-documents", methods=["GET"])
def my_shared_documents():
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401

    db = get_db_connection()
    user_row = db.execute("SELECT email FROM users WHERE id=?", (user_id,)).fetchone()
    user_email = user_row["email"].lower() if user_row else ""

    rows = db.execute(
        "SELECT d.id, d.documentTitle, d.uploadDate, d.dueDate, d.Review, "
        "u.full_name AS owner_name, c.invited_at "
        "FROM collaborators c "
        "JOIN documents d ON c.document_id = d.id "
        "JOIN users u ON c.owner_id = u.id "
        "WHERE (c.viewer_id=? OR c.viewer_email=?) AND c.status='active' "
        "ORDER BY c.invited_at DESC",
        (user_id, user_email),
    ).fetchall()
    db.close()
    return jsonify({"documents": [dict(r) for r in rows]})


# --- Documents shared by the current user (owner) ---
@app.route("/api/shared-by-me", methods=["GET"])
def shared_by_me():
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401

    db = get_db_connection()
    rows = db.execute(
        "SELECT c.id AS collaborator_id, d.id AS document_id, d.documentTitle, "
        "c.viewer_email, c.viewer_id, c.invited_at, c.status, "
        "COALESCE(u.full_name, c.viewer_email) AS viewer_name "
        "FROM collaborators c "
        "JOIN documents d ON c.document_id = d.id "
        "LEFT JOIN users u ON c.viewer_id = u.id "
        "WHERE c.owner_id = ? "
        "ORDER BY c.invited_at DESC",
        (user_id,),
    ).fetchall()
    db.close()
    return jsonify({"shares": [dict(r) for r in rows]})


# --- Revoke collaborator by ID (alternative endpoint) ---
@app.route("/api/collaborators/<int:collab_id>/revoke", methods=["POST"])
def revoke_collaborator_alt(collab_id):
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401

    db = get_db_connection()
    # Verify ownership
    collab = db.execute(
        "SELECT * FROM collaborators WHERE id=? AND owner_id=?", (collab_id, user_id)
    ).fetchone()
    if not collab:
        db.close()
        return jsonify({"error": "Not found or not authorized"}), 404
    
    db.execute("UPDATE collaborators SET status='revoked' WHERE id=?", (collab_id,))
    db.commit()
    db.close()
    return jsonify({"success": True})


# ============================================
# CHAT ATTACHMENT UPLOAD
# ============================================

CHAT_UPLOADS_FOLDER = os.path.join(BASE_DIR, "uploads", "chat_attachments")
os.makedirs(CHAT_UPLOADS_FOLDER, exist_ok=True)

ALLOWED_CHAT_EXTENSIONS = {'png', 'jpg', 'jpeg', 'pdf'}

def allowed_chat_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_CHAT_EXTENSIONS

@app.route("/api/chat/upload", methods=["POST"])
def upload_chat_attachment():
    """Upload a file attachment for chat messages."""
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"error": "Not authenticated"}), 401
    
    if 'file' not in request.files:
        return jsonify({"error": "No file provided"}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No file selected"}), 400
    
    if not allowed_chat_file(file.filename):
        return jsonify({"error": "File type not allowed"}), 400
    
    # Check file size (max 100MB)
    file.seek(0, 2)
    size = file.tell()
    file.seek(0)
    if size > 100 * 1024 * 1024:
        return jsonify({"error": "File too large (max 100MB)"}), 400
    
    # Generate unique filename
    ext = file.filename.rsplit('.', 1)[1].lower()
    unique_name = f"{uuid.uuid4().hex}_{int(time.time())}.{ext}"
    save_path = os.path.join(CHAT_UPLOADS_FOLDER, unique_name)
    
    file.save(save_path)
    
    # Determine attachment type
    image_exts = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
    attachment_type = 'image' if ext in image_exts else 'file'
    
    return jsonify({
        "success": True,
        "url": f"/uploads/chat_attachments/{unique_name}",
        "type": attachment_type,
        "name": file.filename
    })


@app.route("/uploads/chat_attachments/<filename>")
def serve_chat_attachment(filename):
    """Serve chat attachment files."""
    return send_from_directory(CHAT_UPLOADS_FOLDER, filename)


# ============================================
# COLLABORATION CHAT — SOCKET.IO EVENT HANDLERS
# ============================================

# Track online users per room: {room: {sid: {user_id, user_name, role}}}
_chat_online = {}


def _room(document_id):
    return f"doc_{document_id}"


@socketio.on("join_session")
def handle_join_session(data):
    """Client joins a document chat room and receives message history."""
    doc_id = data.get("session_id")
    user_id = data.get("user_id")
    user_name = data.get("user_name", "User")
    role = data.get("role", "viewer")

    if not doc_id or not user_id:
        emit("error", {"message": "session_id and user_id required"})
        return

    room = _room(doc_id)
    join_room(room)

    # Track online presence
    if room not in _chat_online:
        _chat_online[room] = {}
    from flask import request as _req
    _chat_online[room][_req.sid] = {
        "user_id": user_id,
        "user_name": user_name,
        "role": role,
        "is_online": True,
    }

    # Load message history (last 100 messages)
    db = get_db_connection()
    rows = db.execute(
        "SELECT * FROM chat_messages WHERE document_id=? ORDER BY created_at ASC LIMIT 100",
        (doc_id,),
    ).fetchall()
    db.close()

    messages = [dict(r) for r in rows]

    # Build participants list from online users
    participants = list(_chat_online[room].values())

    emit("session_joined", {
        "messages": messages,
        "participants": participants,
        "unread_count": 0,
    })

    # Notify others in the room that this user joined
    emit("user_joined", {
        "user_id": user_id,
        "user_name": user_name,
        "role": role,
    }, to=room, include_self=False)


@socketio.on("send_message")
def handle_send_message(data):
    """Persist message to DB and broadcast to all room members."""
    doc_id = data.get("session_id")
    user_id = data.get("user_id")
    user_name = data.get("user_name", "User")
    role = data.get("role", "viewer")
    content = (data.get("content") or "").strip()
    attachment_url = data.get("attachment_url")
    attachment_type = data.get("attachment_type")
    attachment_name = data.get("attachment_name")

    if not doc_id or not user_id:
        return
    
    # Allow messages with just attachments (no text content required)
    if not content and not attachment_url:
        return

    db = get_db_connection()
    db.execute(
        """INSERT INTO chat_messages
           (document_id, sender_id, sender_name, sender_role, content, message_type, attachment_url, attachment_type, attachment_name)
           VALUES (?, ?, ?, ?, ?, 'user', ?, ?, ?)""",
        (doc_id, user_id, user_name, role, content or "", attachment_url, attachment_type, attachment_name),
    )
    db.commit()
    row = db.execute(
        "SELECT * FROM chat_messages WHERE id = last_insert_rowid()"
    ).fetchone()
    db.close()

    msg = dict(row)
    emit("new_message", msg, to=_room(doc_id))


@socketio.on("delete_message")
def handle_delete_message(data):
    """Mark a message as deleted (soft delete)."""
    doc_id = data.get("session_id")
    message_id = data.get("message_id")
    user_id = data.get("user_id")
    
    if not doc_id or not message_id or not user_id:
        return
    
    db = get_db_connection()
    # Only allow sender to delete their own messages
    msg = db.execute("SELECT * FROM chat_messages WHERE id = ? AND sender_id = ?", (message_id, user_id)).fetchone()
    if not msg:
        db.close()
        emit("error", {"message": "Cannot delete this message"})
        return
    
    db.execute(
        "UPDATE chat_messages SET is_deleted = 1, deleted_at = datetime('now'), content = '' WHERE id = ?",
        (message_id,)
    )
    db.commit()
    db.close()
    
    emit("message_deleted", {"message_id": message_id}, to=_room(doc_id))


@socketio.on("clear_chat")
def handle_clear_chat(data):
    """Clear all messages in a chat (owner only)."""
    doc_id = data.get("session_id")
    user_id = data.get("user_id")
    
    if not doc_id or not user_id:
        return
    
    # Verify user is document owner
    db = get_db_connection()
    doc = db.execute("SELECT user_id FROM documents WHERE id = ?", (doc_id,)).fetchone()
    if not doc or doc["user_id"] != user_id:
        db.close()
        emit("error", {"message": "Only the owner can clear chat history"})
        return
    
    db.execute("DELETE FROM chat_messages WHERE document_id = ?", (doc_id,))
    db.commit()
    db.close()
    
    emit("chat_cleared", {"session_id": doc_id}, to=_room(doc_id))


@socketio.on("typing")
def handle_typing(data):
    """Broadcast typing status to room (excluding sender)."""
    doc_id = data.get("session_id")
    if not doc_id:
        return
    emit("user_typing", {
        "user_id": data.get("user_id"),
        "user_name": data.get("user_name", "User"),
        "is_typing": data.get("is_typing", False),
    }, to=_room(doc_id), include_self=False)


@socketio.on("mark_read")
def handle_mark_read(data):
    """Unread tracking is client-side; no server action needed."""
    pass


@socketio.on("disconnect")
def handle_chat_disconnect():
    """Remove user from online tracker and notify room peers."""
    from flask import request as _req
    for room, users in list(_chat_online.items()):
        if _req.sid in users:
            user_info = users.pop(_req.sid)
            emit("user_left", {
                "user_id": user_info["user_id"],
                "user_name": user_info["user_name"],
            }, to=room)
            if not users:
                del _chat_online[room]
            break
    
    # Also handle DM disconnect
    if _req.sid in _dm_online_sids:
        user_id = _dm_online_sids.pop(_req.sid)
        print(f"[DM Disconnect] User {user_id} disconnected (sid: {_req.sid})")
        if user_id in _dm_online_users:
            del _dm_online_users[user_id]
        # Broadcast user offline to all
        emit("dm_user_offline", {"user_id": user_id}, broadcast=True)
    else:
        print(f"[DM Disconnect] Unknown sid disconnected: {_req.sid}")


# ============================================
# DIRECT MESSAGING (DM) SYSTEM
# ============================================

from services.collaboration_service import get_collaboration_service

# DM Online tracking
_dm_online_users = {}  # user_id -> sid
_dm_online_sids = {}   # sid -> user_id

# --- DM API Routes ---

@app.route("/api/dm/debug/online")
def api_dm_debug_online():
    """Debug endpoint: show who's online."""
    return jsonify({
        "online_users": {str(k): v for k, v in _dm_online_users.items()},
        "online_sids": _dm_online_sids
    })

@app.route("/api/dm/users")
def api_dm_users():
    """Get all users for DM selection."""
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401
    
    collab_service = get_collaboration_service()
    users = collab_service.get_all_users()
    
    return jsonify({"users": users})


@app.route("/api/dm/conversations")
def api_dm_conversations():
    """Get all DM conversations for current user."""
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401
    
    collab_service = get_collaboration_service()
    conversations = collab_service.get_dm_conversations(user_id)
    total_unread = collab_service.get_dm_unread_total(user_id)
    
    return jsonify({
        "conversations": conversations,
        "total_unread": total_unread
    })


@app.route("/api/dm/messages/<int:other_user_id>")
def api_dm_messages(other_user_id):
    """Get DM messages with another user."""
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401
    
    collab_service = get_collaboration_service()
    messages = collab_service.get_dm_messages(user_id, other_user_id)
    
    return jsonify({"messages": messages})


@app.route("/api/dm/messages", methods=["POST"])
def api_dm_send_message():
    """Send a new DM message."""
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401
    
    data = request.get_json()
    recipient_id = data.get("recipient_id")
    content = data.get("content", "").strip()
    attachment_url = data.get("attachment_url")
    attachment_type = data.get("attachment_type")
    attachment_name = data.get("attachment_name")
    
    if not recipient_id or (not content and not attachment_url):
        return jsonify({"error": "Missing recipient_id or content/attachment"}), 400
    
    # Ensure recipient_id is an integer
    recipient_id = int(recipient_id)
    
    collab_service = get_collaboration_service()
    message = collab_service.send_direct_message(
        user_id, recipient_id, content,
        attachment_url=attachment_url,
        attachment_type=attachment_type,
        attachment_name=attachment_name
    )
    
    # Get sender's name for the socket message
    db = get_db_connection()
    sender = db.execute("SELECT full_name FROM users WHERE id=?", (user_id,)).fetchone()
    db.close()
    message["sender_name"] = sender["full_name"] if sender else "User"
    
    # Emit to recipient via socket for real-time delivery
    print(f"[DM] Checking if recipient {recipient_id} is online. Online users: {list(_dm_online_users.keys())}")
    if recipient_id in _dm_online_users:
        recipient_sid = _dm_online_users[recipient_id]
        print(f"[DM] Emitting dm_message to {recipient_id} (sid: {recipient_sid})")
        socketio.emit("dm_message", message, to=recipient_sid)
    else:
        print(f"[DM] Recipient {recipient_id} is NOT online")
    
    return jsonify({"message": message})


@app.route("/api/dm/messages/<int:message_id>", methods=["DELETE"])
def api_dm_delete_message(message_id):
    """Delete a single DM message."""
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401
    
    collab_service = get_collaboration_service()
    success = collab_service.delete_dm_message(message_id, user_id)
    
    if success:
        # Notify via socket if connected
        if socketio:
            socketio.emit('dm_message_deleted', {'message_id': message_id})
        return jsonify({"success": True})
    else:
        return jsonify({"error": "Message not found or not authorized"}), 404


@app.route("/api/dm/messages/<int:other_user_id>/clear", methods=["DELETE"])
def api_dm_clear_chat(other_user_id):
    """Clear all messages with another user."""
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401
    
    collab_service = get_collaboration_service()
    count = collab_service.clear_dm_conversation(user_id, other_user_id)
    
    # Notify via socket
    if socketio:
        socketio.emit('dm_chat_cleared', {'user_id': user_id, 'other_user_id': other_user_id})
    
    return jsonify({"success": True, "cleared_count": count})


@app.route("/api/dm/messages/<int:other_user_id>/read", methods=["POST"])
def api_dm_mark_read(other_user_id):
    """Mark all messages from a user as read."""
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401
    
    collab_service = get_collaboration_service()
    count = collab_service.mark_dm_messages_read(user_id, other_user_id)
    
    return jsonify({"marked_read": count})


# --- DM WebSocket Handlers ---

@socketio.on("dm_connect")
def handle_dm_connect(data):
    """Handle user connecting to DM system."""
    from flask import request as _req
    user_id = data.get("user_id")
    user_name = data.get("user_name", "User")
    
    if not user_id:
        print(f"[DM Connect] No user_id provided")
        return
    
    # Ensure user_id is an integer for consistent lookups
    user_id = int(user_id)
    
    # Track online status
    _dm_online_users[user_id] = _req.sid
    _dm_online_sids[_req.sid] = user_id
    print(f"[DM Connect] User {user_id} ({user_name}) connected with sid: {_req.sid}")
    
    # Broadcast user online
    emit("dm_user_online", {"user_id": user_id, "user_name": user_name}, broadcast=True)
    
    # Send current online users to the connecting user
    online_user_ids = list(_dm_online_users.keys())
    emit("dm_connected", {"online_users": online_user_ids})


@socketio.on("dm_send_message")
def handle_dm_send_message(data):
    """Handle sending a DM message via WebSocket."""
    sender_id = data.get("sender_id")
    sender_name = data.get("sender_name", "User")
    recipient_id = data.get("recipient_id")
    content = data.get("content", "").strip()
    attachment_url = data.get("attachment_url")
    
    # Need sender, recipient, and either content or attachment
    if not sender_id or not recipient_id or (not content and not attachment_url):
        return
    
    # Ensure IDs are integers
    sender_id = int(sender_id)
    recipient_id = int(recipient_id)
    
    # Get sender's name from DB if not provided
    if sender_name == "User":
        db = get_db_connection()
        user = db.execute("SELECT full_name FROM users WHERE id=?", (sender_id,)).fetchone()
        db.close()
        if user:
            sender_name = user["full_name"]
    
    # Get attachment data if present
    attachment_url = data.get("attachment_url")
    attachment_type = data.get("attachment_type")
    attachment_name = data.get("attachment_name")
    
    # Save message to database
    collab_service = get_collaboration_service()
    message = collab_service.send_direct_message(
        sender_id, recipient_id, content,
        attachment_url=attachment_url,
        attachment_type=attachment_type,
        attachment_name=attachment_name
    )
    message["sender_name"] = sender_name
    
    # Send to recipient if online
    if recipient_id in _dm_online_users:
        recipient_sid = _dm_online_users[recipient_id]
        emit("dm_message", message, to=recipient_sid)
    
    # Also send back to sender for confirmation
    emit("dm_message", message)


@socketio.on("dm_typing")
def handle_dm_typing(data):
    """Handle typing indicator for DM."""
    user_id = data.get("user_id") or data.get("sender_id")
    user_name = data.get("user_name") or data.get("sender_name", "User")
    recipient_id = data.get("recipient_id")
    
    if not user_id or not recipient_id:
        return
    
    # Ensure IDs are integers
    user_id = int(user_id)
    recipient_id = int(recipient_id)
    
    # Send to recipient if online
    if recipient_id in _dm_online_users:
        recipient_sid = _dm_online_users[recipient_id]
        emit("dm_typing", {
            "user_id": user_id,
            "user_name": user_name
        }, to=recipient_sid)


@socketio.on("dm_stop_typing")
def handle_dm_stop_typing(data):
    """Handle stop typing indicator for DM."""
    user_id = data.get("user_id") or data.get("sender_id")
    recipient_id = data.get("recipient_id")
    
    if not user_id or not recipient_id:
        return
    
    # Ensure IDs are integers
    user_id = int(user_id)
    recipient_id = int(recipient_id)
    
    # Send to recipient if online
    if recipient_id in _dm_online_users:
        recipient_sid = _dm_online_users[recipient_id]
        emit("dm_stop_typing", {
            "user_id": user_id
        }, to=recipient_sid)


#################################################
# ============================================
# APPLICATION ENTRY POINT WITH HTTPS SUPPORT
# ============================================

def generate_self_signed_cert():
    """Generate self-signed SSL certificate for development HTTPS."""
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.backends import default_backend
        import ipaddress
        
        CERT_FILE = 'cert.pem'
        KEY_FILE = 'key.pem'
        
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        # Create certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Development"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Local"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ComplyAI Dev"),
            x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
        ])
        
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=365)
        ).add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
            ]),
            critical=False,
        ).sign(private_key, hashes.SHA256(), default_backend())
        
        # Write certificate and key
        with open(CERT_FILE, 'wb') as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        
        with open(KEY_FILE, 'wb') as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        return CERT_FILE, KEY_FILE
    except ImportError:
        print("[WARNING] cryptography library not installed. Run: pip install cryptography")
        return None, None


if __name__ == "__main__":
    import ssl
    
    # Check if HTTPS mode is enabled via environment variable
    use_https = os.environ.get('FLASK_HTTPS', '').lower() in ('true', '1', 'yes')
    
    if use_https:
        CERT_FILE = os.environ.get('SSL_CERT_FILE', 'cert.pem')
        KEY_FILE = os.environ.get('SSL_KEY_FILE', 'key.pem')
        
        # Generate self-signed cert if not exists
        if not os.path.exists(CERT_FILE) or not os.path.exists(KEY_FILE):
            print("[INFO] Generating self-signed SSL certificate for development...")
            CERT_FILE, KEY_FILE = generate_self_signed_cert()
        
        if CERT_FILE and KEY_FILE:
            print("[INFO] Starting server with HTTPS on https://127.0.0.1:5005")
            print("[WARNING] Using self-signed certificate - browser will show security warning")
            socketio.run(
                app,
                debug=True,
                host="127.0.0.1",
                port=5005,
                use_reloader=False,
                ssl_context=(CERT_FILE, KEY_FILE)
            )
        else:
            print("[WARNING] Could not setup HTTPS, falling back to HTTP")
            socketio.run(app, debug=True, host="127.0.0.1", port=5005, use_reloader=False)
    else:
        # Default: HTTP mode for development
        print("[INFO] Starting server on http://127.0.0.1:5005")
        print("[TIP] Set FLASK_HTTPS=true to enable HTTPS")
        socketio.run(app, debug=True, host="127.0.0.1", port=5005, use_reloader=False)