import sys
import ast
import os
import sqlite3
import hashlib
from pathlib import Path
from collections import Counter
from joblib import load, dump
from flask import Flask, request, jsonify
from flask_cors import CORS
import pandas as pd
from flask import send_file
from io import BytesIO
from fpdf import FPDF, XPos, YPos
from datetime import datetime, timezone
import subprocess
import threading
import re
import time
import hmac
import uuid
import logging
import json as json_stdlib
import requests
import html as _html
from functools import wraps, lru_cache

BUZZ_WORDS = {}       # Placeholder - will be loaded from vulnerability_db
LANGUAGE_FILTER = {}  # Placeholder - pattern → frozenset of applicable languages

# to make normalizer_AST file accessable 
ROOT = Path(__file__).resolve().parent.parent
# Ensure this points to the FOLDER, not the file
SOURCEPATH = str(ROOT / 'backend' / 'src')

if SOURCEPATH not in sys.path:
    sys.path.append(SOURCEPATH)



# --- INITIALIZATION ---
normalizer = None

try:
    # This looks for normalizer_AST.py inside the SOURCEPATH folder
    from normalizer_AST import codeNormalizer
    normalizer = codeNormalizer()
    print("✅ Normalizer loaded successfully!")
except ImportError as e:
    print(f"❌ Critical Error: Could not find normalizer_AST in {SOURCEPATH}")
    print(f"Technical detail: {e}")
    # Fallback to prevent NameError crash
    class DummyNormalizer:
        def visit(self, tree): return tree
    normalizer = DummyNormalizer()
    print("⚠️ Using Dummy Normalizer (Analysis will be less accurate)")

# Language detection — pure Python, always available regardless of tree-sitter
try:
    from language_detector import detect_language as _detect_language
    _LANG_DETECT_ENABLED = True
    print("✅ Language detector loaded")
except ImportError as e:
    _LANG_DETECT_ENABLED = False
    _detect_language = None
    print(f"⚠️ Language detector unavailable: {e}")

# Tree-sitter AST parsing — requires compiled language packages
try:
    from treesitter_parser import get_node_counts, get_supported_languages
    MULTI_LANG_ENABLED = True
    print(f"✅ Tree-sitter enabled: {get_supported_languages()}")
except ImportError as e:
    MULTI_LANG_ENABLED = False
    get_node_counts = None
    get_supported_languages = lambda: []
    print(f"⚠️ Tree-sitter unavailable (install tree-sitter-* packages): {e}")

# Vulnerability database
try:
    from vulnerability_db import VULNERABILITY_PATTERNS, LANGUAGE_FILTER
    BUZZ_WORDS = {pattern: info[0] for pattern, info in VULNERABILITY_PATTERNS.items()}
    # Also create a severity lookup
    SEVERITY_LOOKUP = {pattern: info[1] for pattern, info in VULNERABILITY_PATTERNS.items()}
    CWE_LOOKUP = {pattern: info[2] for pattern, info in VULNERABILITY_PATTERNS.items()}
    print(f"✅ Vulnerability database loaded: {len(VULNERABILITY_PATTERNS)} patterns, {len(LANGUAGE_FILTER)} language-filtered")
except ImportError as e:
    print(f"⚠️ Vulnerability database not loaded: {e}")
    SEVERITY_LOOKUP = {}
    CWE_LOOKUP = {}
    LANGUAGE_FILTER = {}

# Entropy profiler (Phase 2) — torch-free; fails silently if unavailable
try:
    from entropy_profiler import get_anomalous_annotations as _get_entropy_flags
    ENTROPY_ENABLED = True
    print("✅ Entropy profiler loaded successfully!")
except ImportError as e:
    ENTROPY_ENABLED = False
    _get_entropy_flags = None  # type: ignore[assignment]
    print(f"⚠️ Entropy profiler not available: {e}")

# Semgrep deep scanner — optional 4th detection layer (AST-level, community rules)
try:
    from semgrep_scanner import scan as _semgrep_scan, is_available as _semgrep_available
    SEMGREP_ENABLED = _semgrep_available()
    print(f"{'✅' if SEMGREP_ENABLED else '⚠️'} Semgrep scanner: {'available' if SEMGREP_ENABLED else 'binary not found (pip install semgrep)'}")
except ImportError as e:
    SEMGREP_ENABLED = False
    _semgrep_scan = None  # type: ignore[assignment]
    print(f"⚠️ Semgrep scanner module not loadable: {e}")

# Engine 3: SNN Micro-Temporal Profiler (Kyber) — lazy-loaded on first Python scan
# Deferred to avoid heavy torch/snntorch import during worker boot (Render timeout)
SNN_ENABLED = False
_snn_profiler = None
_snn_init_attempted = False

def _init_snn_once():
    """Lazy-load SNN profiler on first call. Safe to call repeatedly."""
    global SNN_ENABLED, _snn_profiler, _snn_init_attempted
    if _snn_init_attempted:
        return
    _snn_init_attempted = True
    try:
        _kyber_path = str(ROOT / 'engines' / 'kyber')
        if _kyber_path not in sys.path:
            sys.path.insert(0, _kyber_path)
        from snn.profiler import BaselineProfiler as _SNNProfiler
        _SNN_CKPT = ROOT / 'engines' / 'kyber' / 'snn' / 'snn_baseline.pt'
        if _SNN_CKPT.exists():
            _snn_profiler = _SNNProfiler.load(str(_SNN_CKPT))
            SNN_ENABLED = True
            print(f"✅ SNN temporal profiler loaded from {_SNN_CKPT}")
        else:
            print("⚠️ SNN profiler: no checkpoint found — run engines/kyber/snn/bootstrap.py to train")
    except Exception as _snn_e:
        print(f"⚠️ SNN temporal profiler not available: {_snn_e}")

# GCN model (Phase 3b) — loaded once at startup via lazy singleton
_gcn_model = None
_gcn_f1    = 0.0   # test F1 from training checkpoint; blend only if >= 0.60
_GCN_ENABLED = False

def _load_gcn_model_once():
    """Lazy singleton: load MalwareGCN on first call, cache thereafter."""
    global _gcn_model, _gcn_f1, _GCN_ENABLED
    if _gcn_model is not None:
        return  # already loaded
    try:
        from trainerModel_GCN import load_gcn_model
        import torch
        from pathlib import Path as _Path
        _ckpt_path = ROOT / 'backend' / 'ML_master' / 'acidModel_gcn.pt'
        if _ckpt_path.exists():
            # Read test_f1 from checkpoint before loading model
            ckpt = torch.load(_ckpt_path, map_location='cpu', weights_only=True)
            _gcn_f1 = ckpt.get('test_metrics', {}).get('f1', 0.0)
            _gcn_model = load_gcn_model(str(_ckpt_path))
            _GCN_ENABLED = True
            print(f"✅ GCN model loaded (test F1={_gcn_f1:.3f}); blending {'ON' if _gcn_f1 >= 0.60 else 'OFF (F1 < 0.60)'}.")
        else:
            print("⚠️ GCN model checkpoint not found; GCN inference disabled.")
    except ImportError as e:
        print(f"⚠️ GCN inference disabled (PyTorch not available): {e}")
    except Exception as e:
        print(f"⚠️ GCN model load failed: {e}")

# Attempt GCN load at startup (graceful — no crash if torch absent)
_load_gcn_model_once()

# CWE → human-readable category mapping for vulnerability grouping
CWE_CATEGORY_MAP = {
    'CWE-78': 'Command Injection', 'CWE-89': 'SQL Injection', 'CWE-94': 'Code Injection',
    'CWE-79': 'Cross-Site Scripting (XSS)', 'CWE-22': 'Path Traversal',
    'CWE-120': 'Buffer Overflow', 'CWE-122': 'Buffer Overflow',
    'CWE-502': 'Insecure Deserialization', 'CWE-798': 'Hardcoded Secrets',
    'CWE-327': 'Weak Cryptography', 'CWE-328': 'Weak Cryptography', 'CWE-330': 'Weak Cryptography',
    'CWE-319': 'Insecure Network', 'CWE-295': 'Insecure Network',
    'CWE-611': 'XML External Entity (XXE)', 'CWE-918': 'Server-Side Request Forgery',
    'CWE-287': 'Authentication Issues', 'CWE-384': 'Session Fixation',
    'CWE-614': 'Insecure Cookie', 'CWE-1004': 'Insecure Cookie', 'CWE-1275': 'Insecure Cookie',
    'CWE-347': 'JWT Vulnerability',
    'CWE-362': 'Race Condition', 'CWE-367': 'Race Condition',
    'CWE-532': 'Information Disclosure', 'CWE-215': 'Information Disclosure', 'CWE-209': 'Information Disclosure', 'CWE-200': 'Information Disclosure',
    'CWE-20': 'Input Validation', 'CWE-621': 'Variable Injection',
    'CWE-829': 'Supply Chain Attack', 'CWE-506': 'Supply Chain Attack', 'CWE-1357': 'Supply Chain Attack',
    'CWE-943': 'NoSQL Injection', 'CWE-90': 'LDAP Injection',
    'CWE-1336': 'Template Injection (SSTI)',
    'CWE-377': 'Insecure File Operations', 'CWE-732': 'Insecure File Operations',
    'CWE-915': 'Mass Assignment', 'CWE-639': 'Mass Assignment',
    'CWE-416': 'Memory Safety', 'CWE-476': 'Memory Safety', 'CWE-843': 'Memory Safety',
    'CWE-676': 'Unsafe Function Usage', 'CWE-862': 'Missing Authorization',
    'CWE-921': 'Data Exposure', 'CWE-926': 'Improper Export', 'CWE-311': 'Data Protection',
}


def _cwe_to_category(cwe_id):
    """Map a CWE ID to a human-readable category name."""
    return CWE_CATEGORY_MAP.get(cwe_id, 'Security Issue')


def generate_tldr_summary(vulnerabilities):
    """Generate a one-sentence executive summary from vulnerability findings."""
    if not vulnerabilities:
        return "No vulnerabilities detected. Code follows standard safety profiles."

    total = len(vulnerabilities)
    sev_counts = {}
    categories = {}
    for v in vulnerabilities:
        sev = v.get('severity', 'MEDIUM')
        sev_counts[sev] = sev_counts.get(sev, 0) + 1
        cat = v.get('category', 'Security Issue')
        if cat not in categories:
            categories[cat] = []
        categories[cat].append(v.get('line', '?'))

    # Build summary
    parts = []
    if sev_counts.get('CRITICAL', 0):
        parts.append(f"{sev_counts['CRITICAL']} critical")
    if sev_counts.get('HIGH', 0):
        parts.append(f"{sev_counts['HIGH']} high")
    if sev_counts.get('MEDIUM', 0):
        parts.append(f"{sev_counts['MEDIUM']} medium")

    severity_text = ", ".join(parts) if parts else f"{total} low"

    # Top 2 categories by count
    sorted_cats = sorted(categories.items(), key=lambda x: len(x[1]), reverse=True)[:2]
    cat_texts = []
    for cat_name, lines in sorted_cats:
        line_str = ", ".join(str(l) for l in lines[:3])
        if len(lines) > 3:
            line_str += f" (+{len(lines)-3} more)"
        cat_texts.append(f"{cat_name} on line{'s' if len(lines) > 1 else ''} {line_str}")

    return f"{total} issues found ({severity_text}): {'; '.join(cat_texts)}. Address critical findings first."


# Deterministic fix recommendations per CWE (instant, no AI needed)
CWE_FIX_HINTS = {
    'CWE-78': 'Use subprocess with a list of args instead of shell=True. Never pass user input to os.system().',
    'CWE-89': 'Use parameterized queries (e.g., cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))). Never use f-strings or concatenation in SQL.',
    'CWE-94': 'Remove eval()/exec(). Use ast.literal_eval() for safe data parsing, or a proper parser for expressions.',
    'CWE-79': 'Escape all user output with html.escape(). Use template auto-escaping (Jinja2 does this by default).',
    'CWE-22': 'Use os.path.realpath() to resolve paths and verify they stay within allowed directories. Reject inputs containing "..".',
    'CWE-120': 'Use bounded string functions (strncpy instead of strcpy, snprintf instead of sprintf). Check buffer sizes.',
    'CWE-122': 'Validate allocation sizes. Use safe allocation wrappers. Check return values of malloc/calloc.',
    'CWE-502': 'Never deserialize untrusted data with pickle/yaml.load. Use json.loads() or yaml.safe_load() instead.',
    'CWE-798': 'Move secrets to environment variables or a secrets manager (AWS Secrets Manager, HashiCorp Vault). Never commit credentials.',
    'CWE-327': 'Replace weak algorithms: use AES-256-GCM instead of DES/RC4, SHA-256+ instead of MD5/SHA-1, bcrypt/argon2 for passwords.',
    'CWE-328': 'Use SHA-256 or SHA-3 instead of MD5/SHA-1 for hashing. For passwords, use bcrypt or argon2id.',
    'CWE-330': 'Use secrets.token_bytes() or os.urandom() instead of random.random() for security-sensitive randomness.',
    'CWE-319': 'Enforce HTTPS everywhere. Use TLS 1.2+ for all network connections. Set HSTS headers.',
    'CWE-295': 'Never disable SSL verification (verify=False). Use valid certificates and pin known CAs.',
    'CWE-611': 'Disable external entity processing: set defusedxml or use etree with resolve_entities=False.',
    'CWE-918': 'Validate and whitelist URLs before making server-side requests. Block internal/private IP ranges.',
    'CWE-287': 'Use established auth libraries (e.g., Passport.js, Django auth). Implement rate limiting and MFA.',
    'CWE-347': 'Always verify JWT signatures. Use RS256 instead of HS256 for public-facing APIs. Set short expiration times.',
    'CWE-384': 'Regenerate session ID after login. Use secure, HttpOnly, SameSite cookie flags.',
    'CWE-614': 'Set Secure, HttpOnly, and SameSite=Strict flags on all authentication cookies.',
    'CWE-1004': 'Set HttpOnly flag on cookies to prevent JavaScript access.',
    'CWE-1275': 'Set SameSite=Strict or SameSite=Lax on cookies to prevent CSRF.',
    'CWE-362': 'Use locks, mutexes, or atomic operations to prevent race conditions. Use database transactions for shared data.',
    'CWE-367': 'Use file locking or atomic operations. Check-then-act patterns are inherently racy.',
    'CWE-532': 'Never log passwords, tokens, or PII. Use structured logging with sensitive field redaction.',
    'CWE-215': 'Disable debug mode in production. Set DEBUG=False and remove stack traces from error responses.',
    'CWE-209': 'Return generic error messages to users. Log detailed errors server-side only.',
    'CWE-200': 'Avoid exposing internal paths, versions, or stack traces. Return minimal error information.',
    'CWE-20': 'Validate and sanitize all user input. Use allowlists over denylists. Enforce type and length constraints.',
    'CWE-829': 'Pin dependency versions. Use lockfiles. Verify package checksums. Audit new dependencies.',
    'CWE-506': 'Review all dependencies for backdoors. Use npm audit / pip-audit. Check package provenance.',
    'CWE-1357': 'Use integrity hashes (SRI) for CDN resources. Pin exact versions in package managers.',
    'CWE-943': 'Sanitize NoSQL query inputs. Use MongoDB\'s $eq operator explicitly. Never pass raw user input to $where.',
    'CWE-90': 'Escape special LDAP characters (*, (, ), \\, NUL). Use parameterized LDAP queries.',
    'CWE-1336': 'Never pass user input to render_template_string(). Use render_template() with separate template files.',
    'CWE-377': 'Use tempfile.mkstemp() or tempfile.NamedTemporaryFile() instead of mktemp(). Set restrictive permissions.',
    'CWE-732': 'Use restrictive file permissions (0o600 for sensitive files). Never use chmod 777 or umask(0).',
    'CWE-915': 'Whitelist allowed fields explicitly. Never pass raw request data to model constructors.',
    'CWE-639': 'Verify object ownership before access. Use scoped queries (WHERE user_id = current_user.id).',
    'CWE-416': 'Set pointers to NULL after free(). Use RAII in C++ or smart pointers. In Rust, avoid unsafe blocks.',
    'CWE-476': 'Check for NULL/None before dereferencing. Use Option/Result types in Rust, Optional in Java.',
    'CWE-843': 'Avoid type confusion with proper type checking. In C, avoid casting between incompatible pointer types.',
    'CWE-676': 'Replace dangerous functions: gets→fgets, strcpy→strncpy, sprintf→snprintf.',
    'CWE-621': 'Never use extract() or register_globals. Pass variables explicitly.',
    'CWE-862': 'Add authorization checks before every sensitive operation. Use middleware/decorators for access control.',
}


def _cwe_to_fix_hint(cwe_id):
    """Get a deterministic fix recommendation for a CWE."""
    return CWE_FIX_HINTS.get(cwe_id, 'Review this code for security best practices. Consider using established security libraries.')


app = Flask(__name__)

try:
    from flasgger import Swagger
    # Disable Swagger UI in production unless explicitly opted-in via env var
    _swagger_enabled = os.environ.get('ENABLE_SWAGGER_UI', '').lower() in ('1', 'true', 'yes')
    if os.environ.get('FLASK_ENV') == 'production' or os.environ.get('RENDER'):
        _swagger_enabled = False
    swagger_config = {
        'headers': [],
        'specs': [{'endpoint': 'apispec', 'route': '/apispec.json', 'rule_filter': lambda rule: True, 'model_filter': lambda tag: True}],
        'static_url_path': '/flasgger_static',
        'swagger_ui': _swagger_enabled,
        'specs_route': '/apidocs',
    }
    swagger_template = {
        'swagger': '2.0',
        'info': {
            'title': 'Soteria API',
            'description': 'AI-powered supply chain security scanning engine',
            'version': '3.0.0',
            'contact': {'email': 'admin@acid.dev'},
        },
        'securityDefinitions': {
            'Bearer': {
                'type': 'apiKey',
                'name': 'Authorization',
                'in': 'header',
                'description': 'JWT token: Bearer <token>',
            }
        },
        'consumes': ['application/json'],
        'produces': ['application/json'],
    }
    Swagger(app, config=swagger_config, template=swagger_template)
    print("✅ Swagger UI available at /apidocs")
except ImportError:
    print("⚠️  flasgger not installed — /apidocs unavailable (pip install flasgger)")

# Secure CORS configuration
allowed_origins_env = os.environ.get('ALLOWED_ORIGINS', 'http://localhost:5173,http://127.0.0.1:5173,https://www.trysoteria.live,https://trysoteria.live,https://codebasesentinel.vercel.app,https://codebasesentinel-n2ikfeqq5-manu-j3400s-projects.vercel.app')
allowed_origins = [origin.strip() for origin in allowed_origins_env.split(',') if origin.strip()]
# Add support for vercel preview branches using regex if needed, but explicit list is safer
CORS(app, resources={r"/*": {
    'origins': allowed_origins,
    'allow_headers': ['Content-Type', 'Authorization'],
    'methods': ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    'supports_credentials': True,
}})

# ── STRUCTURED LOGGING WITH REQUEST IDs ──────────────────────────────────────

class StructuredFormatter(logging.Formatter):
    """JSON-line log format for easy parsing by log aggregators."""
    def format(self, record):
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "message": record.getMessage(),
            "logger": record.name,
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }
        if hasattr(record, 'request_id'):
            log_entry["request_id"] = record.request_id
        if hasattr(record, 'endpoint'):
            log_entry["endpoint"] = record.endpoint
        if hasattr(record, 'method'):
            log_entry["method"] = record.method
        if hasattr(record, 'status_code'):
            log_entry["status_code"] = record.status_code
        if hasattr(record, 'duration_ms'):
            log_entry["duration_ms"] = record.duration_ms
        if hasattr(record, 'ip'):
            log_entry["ip"] = record.ip
        if record.exc_info and record.exc_info[0]:
            log_entry["exception"] = self.formatException(record.exc_info)
        return json_stdlib.dumps(log_entry)


_log_handler = logging.StreamHandler()
_log_handler.setFormatter(StructuredFormatter())
app.logger.handlers.clear()
app.logger.addHandler(_log_handler)
app.logger.setLevel(logging.INFO)
logging.getLogger('werkzeug').setLevel(logging.WARNING)


@app.before_request
def attach_request_id():
    """Generate a unique request ID and attach it to every request."""
    raw_rid = request.headers.get('X-Request-ID', '')
    import re as _re
    if raw_rid and _re.match(r'^[a-zA-Z0-9_\-]{1,64}$', raw_rid):
        request.request_id = raw_rid
    else:
        request.request_id = uuid.uuid4().hex[:12]
    request.start_time = time.time()


@app.after_request
def add_security_headers(response):
    """Add critical HTTP security headers and request ID to all responses."""
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Cache-Control'] = 'no-store, max-age=0'
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['Content-Security-Policy'] = (
        "default-src 'none'; "
        "script-src 'none'; "
        "frame-ancestors 'none'"
    )
    # Echo client ID separately; server-generated ID is authoritative for logging
    _client_req_id = getattr(request, 'request_id', 'unknown')
    response.headers['X-Request-ID'] = _client_req_id

    duration_ms = round((time.time() - getattr(request, 'start_time', time.time())) * 1000, 1)
    extra = {
        'request_id': getattr(request, 'request_id', 'unknown'),
        'endpoint': request.path,
        'method': request.method,
        'status_code': response.status_code,
        'duration_ms': duration_ms,
        'ip': request.remote_addr,
    }
    log_record = app.logger.makeRecord(
        'soteria', logging.INFO, '', 0,
        f"{request.method} {request.path} → {response.status_code} ({duration_ms}ms)",
        (), None
    )
    for k, v in extra.items():
        setattr(log_record, k, v)
    app.logger.handle(log_record)

    return response
# --- RATE LIMITER ---
RATE_LIMITS = {}
RATE_LIMIT_LOCK = threading.Lock()


# --- AUTOMATION WEBHOOK STATE ---
AUTOMATION_RUNS = {}
AUTOMATION_LOCK = threading.Lock()
AUTOMATION_TTL_SECONDS = 60 * 60 * 24  # 24h idempotency window

def rate_limit(max_requests=20, window_seconds=60):
    """
    Sliding window rate limiter. Uses JWT user_id for authenticated requests,
    falls back to IP address for anonymous requests.
    """
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            # Prefer user_id from JWT; fall back to IP
            key = None
            auth_header = request.headers.get('Authorization', '')
            if auth_header.startswith('Bearer '):
                try:
                    payload = pyjwt.decode(
                        auth_header.split(' ', 1)[1], JWT_SECRET, algorithms=['HS256']
                    )
                    key = f"user:{payload.get('user_id')}"
                except Exception:
                    pass
            if not key:
                # Use only request.remote_addr — never trust client-supplied X-Forwarded-For
                # for rate-limit keying (prevents header-spoofing bypass)
                ip = request.remote_addr or 'unknown'
                key = f"ip:{ip}"

            now = time.time()
            with RATE_LIMIT_LOCK:
                if key not in RATE_LIMITS:
                    RATE_LIMITS[key] = []
                RATE_LIMITS[key] = [t for t in RATE_LIMITS[key] if now - t < window_seconds]
                if len(RATE_LIMITS[key]) >= max_requests:
                    return jsonify({
                        'error': 'Rate limit exceeded. Please wait a minute before scanning again.',
                        'malicious': False,
                        'confidence': 0,
                        'risk_level': 'UNKNOWN',
                        'vulnerabilities': []
                    }), 429
                RATE_LIMITS[key].append(now)
            return f(*args, **kwargs)
        return wrapped
    return decorator

def _truncate_text(value, limit=8000):
    """Keep webhook responses bounded for Make and logs."""
    if not isinstance(value, str):
        value = str(value or "")
    if len(value) <= limit:
        return value, False
    return value[:limit] + "\n...[truncated]...", True

def _cleanup_automation_runs(now_ts):
    """Drop expired idempotency entries."""
    expired = [k for k, v in AUTOMATION_RUNS.items() if now_ts - v.get('created_at', 0) > AUTOMATION_TTL_SECONDS]
    for key in expired:
        AUTOMATION_RUNS.pop(key, None)

def _extract_instruction(payload):
    """
    Convert structured request payload to a compact instruction string
    that auto_improver.py can consume via argv.
    """
    if not isinstance(payload, dict):
        return None

    explicit = payload.get('instruction')
    if isinstance(explicit, str) and explicit.strip():
        return explicit.strip()[:2000]

    task_type = payload.get('task_type', 'incremental_improvement')
    llm_strategy = payload.get('llm_strategy', {})
    scope = payload.get('scope', {})
    quality_gates = payload.get('quality_gates', {})
    metadata = payload.get('metadata', {})

    # Keep instruction deterministic and concise.
    return (
        f"Task: {task_type}. "
        f"LLM strategy: {llm_strategy}. "
        f"Scope: {scope}. "
        f"Quality gates: {quality_gates}. "
        f"Metadata: {metadata}. "
        "Generate isolated improvements only, prioritize AI/ML reliability, and keep outputs safe for draft PR review."
    )[:2000]

def _require_json_body():
    """Ensure request body is a JSON object. Returns (data, is_valid)."""
    data = request.get_json(silent=True)
    return data, isinstance(data, dict)

def _clean_text(value, max_len=None, lower=False):
    """Basic sanitization for user-provided text fields."""
    if value is None:
        value = ""
    if not isinstance(value, str):
        value = str(value)
    value = value.replace('\x00', '').strip()
    if lower:
        value = value.lower()
    if max_len is not None:
        value = value[:max_len]
    return value

MODELPATH = ROOT / 'backend'/ 'ML_master' / 'acidModel.pkl'
lastModelTime = 0
model = None
modelFeatures = None

print("🔄 ACID MIDDLEWARE INITIALIZATION")
try:
    model = load(MODELPATH)
    modelFeatures = model.feature_names_in_
    print("✅ Model loaded successfully!")
except Exception as e:
    print(f"Could not load model, {e}")

# --- SCAN HISTORY DATABASE ---
# Thread-safe SQLite with WAL mode to prevent "database is locked" under
# concurrent batch scans. All DB access goes through get_db_connection().
SCAN_DB_PATH = ROOT / 'middleware' / 'scan_history.db'
_db_lock = threading.Lock()


def get_db_connection(readonly=False):
    """
    Get a SQLite connection with WAL mode and busy timeout.
    WAL allows concurrent reads while a write is in progress.
    The 10s busy_timeout retries automatically on lock contention.
    """
    conn = sqlite3.connect(str(SCAN_DB_PATH), timeout=10)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=10000")
    if readonly:
        conn.execute("PRAGMA query_only=ON")
    return conn


_SCAN_DB_MIGRATIONS = [
    (1, 'ALTER TABLE scans ADD COLUMN user_id INTEGER'),
    (2, 'ALTER TABLE training_data ADD COLUMN user_id INTEGER DEFAULT NULL'),
    (3, 'ALTER TABLE scans ADD COLUMN features TEXT'),
    (4, 'ALTER TABLE scans ADD COLUMN user_label INTEGER'),
]


def init_scan_db():
    """Initialize SQLite database for scan history."""
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        timestamp TEXT NOT NULL,
        language TEXT,
        risk_level TEXT,
        confidence REAL,
        malicious INTEGER,
        code_hash TEXT,
        nodes_scanned INTEGER,
        reason TEXT
    )''')

    # Training data table — stores scanned code for future model retraining
    c.execute('''CREATE TABLE IF NOT EXISTS training_data (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        code_hash TEXT NOT NULL,
        code TEXT NOT NULL,
        language TEXT NOT NULL,
        is_malicious INTEGER NOT NULL,
        risk_level TEXT,
        vuln_count INTEGER DEFAULT 0,
        confidence REAL,
        timestamp TEXT NOT NULL,
        source TEXT DEFAULT 'scanner',
        user_id INTEGER DEFAULT NULL
    )''')

    # Schema version tracking
    c.execute('''CREATE TABLE IF NOT EXISTS schema_version (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        version INTEGER NOT NULL DEFAULT 0
    )''')
    c.execute('INSERT OR IGNORE INTO schema_version (id, version) VALUES (1, 0)')
    c.execute('SELECT version FROM schema_version WHERE id = 1')
    current_ver = c.fetchone()[0]

    for ver, sql in _SCAN_DB_MIGRATIONS:
        if current_ver < ver:
            try:
                c.execute(sql)
            except sqlite3.OperationalError:
                pass  # column already exists (idempotent)
            c.execute('UPDATE schema_version SET version = ? WHERE id = 1', (ver,))
            current_ver = ver
    try:
        c.execute('CREATE UNIQUE INDEX IF NOT EXISTS idx_training_hash ON training_data(code_hash)')
    except sqlite3.OperationalError:
        pass

    conn.commit()
    conn.close()
    print("✅ Scan history database initialized (WAL mode)")


def _save_training_sample(code: str, language: str, is_malicious: bool,
                          risk_level: str, vuln_count: int, confidence: float,
                          source: str = 'scanner', user_id: int = None):
    """
    Persist a completed scan as a training sample.
    Uses INSERT OR IGNORE so identical code hashes are not duplicated.
    Runs in a daemon thread to not block the response.
    """
    import threading
    code_hash = hashlib.sha256(code.encode('utf-8', errors='replace')).hexdigest()[:32]
    ts = datetime.now(timezone.utc).isoformat()
    # Truncate very large code samples (>50k chars) to keep DB size manageable
    code_stored = code[:50000] if len(code) > 50000 else code

    def _write():
        try:
            with _db_lock:
                conn = get_db_connection()
                conn.execute(
                    '''INSERT OR IGNORE INTO training_data
                       (code_hash, code, language, is_malicious, risk_level,
                        vuln_count, confidence, timestamp, source, user_id)
                       VALUES (?,?,?,?,?,?,?,?,?,?)''',
                    (code_hash, code_stored, language, int(is_malicious),
                     risk_level, vuln_count, confidence, ts, source, user_id)
                )
                conn.commit()
                conn.close()
        except Exception as e:
            print(f"Training data save failed: {e}")

    threading.Thread(target=_write, daemon=True).start()


init_scan_db()

# --- USER AUTHENTICATION DATABASE ---
import bcrypt
import jwt as pyjwt
import secrets

JWT_SECRET = os.environ.get('JWT_SECRET')
if not JWT_SECRET:
    if os.environ.get('FLASK_ENV') == 'production' or os.environ.get('RENDER'):
        raise RuntimeError("JWT_SECRET environment variable must be set in production. Refusing to start.")
    print("⚠️ WARNING: JWT_SECRET not set — using ephemeral random secret. Sessions won't survive restarts. Set JWT_SECRET in production.")
    JWT_SECRET = secrets.token_hex(32)

def init_users_db():
    """Initialize SQLite users table."""
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        is_admin INTEGER DEFAULT 0,
        created_at TEXT NOT NULL
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS user_settings (
        user_id INTEGER PRIMARY KEY,
        webhook_url TEXT,
        updated_at TEXT
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS revoked_tokens (
        jti TEXT PRIMARY KEY,
        exp INTEGER NOT NULL
    )''')
    c.execute('CREATE INDEX IF NOT EXISTS idx_revoked_tokens_exp ON revoked_tokens(exp)')
    conn.commit()

    # Seed default admin if none exists
    c.execute('SELECT id FROM users WHERE is_admin = 1')
    if not c.fetchone():
        admin_password = os.environ.get('ADMIN_PASSWORD')
        is_random = False
        if not admin_password:
            admin_password = secrets.token_urlsafe(16)
            is_random = True
        pw_hash = bcrypt.hashpw(admin_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        c.execute(
            'INSERT INTO users (name, email, password_hash, is_admin, created_at) VALUES (?, ?, ?, ?, ?)',
            ('Admin', 'admin@soteria.dev', pw_hash, 1, datetime.now().isoformat())
        )
        conn.commit()
        if is_random:
            print("WARNING: ADMIN_PASSWORD not set — generated a random admin password for bootstrap. Set ADMIN_PASSWORD env var to persist.")
        else:
            print("Default admin seeded (admin@soteria.dev / [from ADMIN_PASSWORD env])")
    
    conn.close()
    print("✅ Users database initialized")

init_users_db()

def generate_token(user_id, email, is_admin=False):
    """Generate a JWT token."""
    import time
    payload = {
        'user_id': user_id,
        'email': email,
        'is_admin': is_admin,
        'jti': secrets.token_hex(16),
        'exp': int(time.time()) + 60 * 60 * 24  # 24 hours
    }
    return pyjwt.encode(payload, JWT_SECRET, algorithm='HS256')

def decode_token(token):
    """Decode and validate a JWT token."""
    try:
        payload = pyjwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        jti = payload.get('jti')
        if not jti:
            return None  # tokens without jti are rejected (legacy or tampered)
        # Check in-memory set first (fast path), then DB (survives restarts)
        exp = payload.get('exp', 0)
        with _TOKEN_REVOCATION_LOCK:
            if (jti, exp) in _TOKEN_REVOCATION_SET:
                return None
        try:
            conn = get_db_connection()
            row = conn.execute('SELECT 1 FROM revoked_tokens WHERE jti = ?', (jti,)).fetchone()
            conn.close()
            if row:
                with _TOKEN_REVOCATION_LOCK:
                    _TOKEN_REVOCATION_SET.add((jti, exp))
                return None
        except Exception:
            pass
        return payload
    except pyjwt.ExpiredSignatureError:
        return None
    except pyjwt.InvalidTokenError:
        return None

# ══════════════════════════════════════
# AUTH API ENDPOINTS
# ══════════════════════════════════════

def token_required(optional=False):
    """Decorator to enforce JWT authentication and extract user_id."""
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            token = None
            if 'Authorization' in request.headers:
                auth_header = request.headers['Authorization']
                if auth_header.startswith('Bearer '):
                    token = auth_header.split(" ")[1]
            
            if not token:
                if optional:
                    return f(None, *args, **kwargs)
                return jsonify({'error': 'Authentication token is missing'}), 401

            decoded = decode_token(token)
            if not decoded:
                if optional:
                    return f(None, *args, **kwargs)
                return jsonify({'error': 'Invalid or expired token'}), 401
                
            return f(decoded, *args, **kwargs)
        return wrapped
    return decorator

@app.route('/api/auth/signup', methods=['POST'])
@rate_limit(max_requests=5, window_seconds=300)  # 5 signups per 5 minutes per IP
def auth_signup():
    """
    Register a new user account.
    ---
    tags: [Auth]
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          required: [name, email, password]
          properties:
            name: {type: string}
            email: {type: string, format: email}
            password: {type: string, minLength: 6}
    responses:
      201: {description: User created, schema: {type: object, properties: {token: {type: string}, user: {type: object}}}}
      400: {description: Validation error}
      409: {description: Email already registered}
    """
    data, valid = _require_json_body()
    if not valid:
        return jsonify({'error': 'Request body must be a valid JSON object'}), 400
    name = _clean_text(data.get('name'), max_len=120)
    email = _clean_text(data.get('email'), max_len=255, lower=True)
    password = _clean_text(data.get('password'), max_len=256)

    if not name or not email or not password:
        return jsonify({'error': 'Name, email, and password are required'}), 400
    if '@' not in email or '.' not in email.split('@')[-1]:
        return jsonify({'error': 'A valid email is required'}), 400
    if len(password) < 8:
        return jsonify({'error': 'Password must be at least 8 characters'}), 400

    conn = None
    try:
        pw_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        conn = get_db_connection()
        c = conn.cursor()
        c.execute(
            'INSERT INTO users (name, email, password_hash, is_admin, created_at) VALUES (?, ?, ?, ?, ?)',
            (name, email, pw_hash, 0, datetime.now().isoformat())
        )
        conn.commit()
        user_id = c.lastrowid

        token = generate_token(user_id, email)
        return jsonify({
            'token': token,
            'user': {'id': user_id, 'name': name, 'email': email, 'is_admin': False}
        })
    except sqlite3.IntegrityError:
        return jsonify({'error': 'An account with this email already exists'}), 409
    except Exception as e:
        app.logger.exception('Signup error')
        return jsonify({'error': 'An internal error occurred. Please try again.'}), 500
    finally:
        if conn:
            conn.close()


@app.route('/api/auth/login', methods=['POST'])
@rate_limit(max_requests=10, window_seconds=300) # 10 login attempts per 5 minutes
def auth_login():
    """
    Authenticate and receive a JWT token.
    ---
    tags: [Auth]
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          required: [email, password]
          properties:
            email: {type: string, format: email}
            password: {type: string}
    responses:
      200: {description: Login successful, schema: {type: object, properties: {token: {type: string}, user: {type: object}}}}
      401: {description: Invalid credentials}
    """
    data, valid = _require_json_body()
    if not valid:
        return jsonify({'error': 'Request body must be a valid JSON object'}), 400
    email = _clean_text(data.get('email'), max_len=255, lower=True)
    password = _clean_text(data.get('password'), max_len=256)

    if not email or not password:
        return jsonify({'error': 'Email and password are required'}), 400

    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE email = ?', (email,))
    user = c.fetchone()
    conn.close()

    if not user or not bcrypt.checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8')):
        return jsonify({'error': 'Invalid email or password'}), 401

    token = generate_token(user['id'], user['email'], bool(user['is_admin']))
    return jsonify({
        'token': token,
        'user': {
            'id': user['id'],
            'name': user['name'],
            'email': user['email'],
            'is_admin': bool(user['is_admin'])
        }
    })


_TOKEN_REVOCATION_SET: set = set()
_TOKEN_REVOCATION_LOCK = threading.Lock()

@app.route('/api/auth/logout', methods=['POST'])
@token_required(optional=False)
def auth_logout(current_user):
    """Revoke the current JWT by adding its jti/exp to the revocation set."""
    auth_header = request.headers.get('Authorization', '')
    if auth_header.startswith('Bearer '):
        token = auth_header.split(' ', 1)[1]
        try:
            payload = pyjwt.decode(token, JWT_SECRET, algorithms=['HS256'])
            exp = payload.get('exp', 0)
            jti = payload.get('jti')
            if jti:
                # Persist to DB so revocation survives restarts
                try:
                    conn = get_db_connection()
                    conn.execute(
                        'INSERT OR IGNORE INTO revoked_tokens (jti, exp) VALUES (?, ?)',
                        (jti, exp)
                    )
                    # Prune expired rows
                    conn.execute('DELETE FROM revoked_tokens WHERE exp < ?', (int(time.time()),))
                    conn.commit()
                    conn.close()
                except Exception:
                    pass
                with _TOKEN_REVOCATION_LOCK:
                    _TOKEN_REVOCATION_SET.add((jti, exp))
                    now = int(time.time())
                    _TOKEN_REVOCATION_SET -= {e for e in _TOKEN_REVOCATION_SET if e[1] < now}
        except Exception:
            pass
    return jsonify({'status': 'logged out'}), 200


@app.route('/api/auth/me', methods=['GET'])
def auth_me():
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return jsonify({'error': 'No token provided'}), 401

    token = auth_header[7:]
    payload = decode_token(token)
    if not payload:
        return jsonify({'error': 'Invalid or expired token'}), 401

    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('SELECT id, name, email, is_admin FROM users WHERE id = ?', (payload['user_id'],))
    user = c.fetchone()
    conn.close()

    if not user:
        return jsonify({'error': 'User not found'}), 404

    return jsonify({
        'user': {
            'id': user['id'],
            'name': user['name'],
            'email': user['email'],
            'is_admin': bool(user['is_admin'])
        }
    })


@app.route('/api/auth/admin/login', methods=['POST'])
@rate_limit(max_requests=5, window_seconds=300) # 5 admin login attempts per 5 minutes
def auth_admin_login():
    data, valid = _require_json_body()
    if not valid:
        return jsonify({'error': 'Request body must be a valid JSON object'}), 400
    email = _clean_text(data.get('email'), max_len=255, lower=True)
    password = _clean_text(data.get('password'), max_len=256)

    if not email or not password:
        return jsonify({'error': 'Email and password are required'}), 400

    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE email = ? AND is_admin = 1', (email,))
    user = c.fetchone()
    conn.close()

    if not user:
        return jsonify({'error': 'Invalid admin credentials'}), 401

    if not bcrypt.checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8')):
        return jsonify({'error': 'Invalid admin credentials'}), 401

    token = generate_token(user['id'], user['email'], is_admin=True)
    return jsonify({
        'token': token,
        'user': {
            'id': user['id'],
            'name': user['name'],
            'email': user['email'],
            'is_admin': True
        }
    })

@app.route('/api/admin/users', methods=['GET'])
@token_required(optional=False)
def admin_users(current_user):
    """
    List all registered users. Admin-only.
    ---
    tags: [Admin]
    security: [{Bearer: []}]
    responses:
      200:
        description: User list
        schema:
          type: object
          properties:
            users: {type: array, items: {type: object}}
      403: {description: Admin access required}
    """
    if not current_user.get('is_admin'):
        return jsonify({'error': 'Admin access required'}), 403
    try:
        conn = get_db_connection()
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute('SELECT id, name, email, is_admin, created_at FROM users ORDER BY created_at DESC')
        users = [dict(row) for row in c.fetchall()]
        conn.close()
        return jsonify({'users': users})
    except Exception as e:
        app.logger.error("Internal error: %s", str(e), exc_info=True)
        return jsonify({'error': 'Internal server error'}), 500


def save_scan_result(user_id=None, language=None, risk_level=None, confidence=None,
                     malicious=None, code="", nodes_scanned=0, reason="", features=None):
    """Save a scan result to the history database (thread-safe). Returns scan row id."""
    import json as _json
    try:
        code_hash = hashlib.sha256(code.encode()).hexdigest()[:16]
        features_blob = _json.dumps(features) if features else None
        with _db_lock:
            conn = get_db_connection()
            c = conn.cursor()
            c.execute(
                'INSERT INTO scans (user_id, timestamp, language, risk_level, confidence, '
                'malicious, code_hash, nodes_scanned, reason, features) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                (user_id, datetime.now().isoformat(), language, risk_level, confidence,
                 1 if malicious else 0, code_hash, nodes_scanned, reason, features_blob)
            )
            conn.commit()
            scan_id = c.lastrowid
            conn.close()
        return scan_id
    except Exception as e:
        print(f"Failed to save scan result: {e}")
        return None

def load_model_if_updated():
    global model, lastModelTime
    try:
        # Get the timestamp of when the file was last saved
        current_mtime = os.path.getmtime(MODELPATH)
        
        # If the timestamp has changed (Watcher updated it), reload!
        if current_mtime > lastModelTime:
            print("🔄 New model detected! Reloading into memory...")
            model = load(MODELPATH)
            lastModelTime = current_mtime
    except Exception as e:
        print(f"❌ Error loading model: {e}")


# ── Performance: LRU cache for parsed results ──
_PARSE_CACHE_SIZE = 128
_parse_cache: dict = {}  # code_hash -> (df_aligned, language)
_LARGE_FILE_THRESHOLD = 10_000  # lines
_SAMPLE_HEAD = 5_000  # lines from start
_SAMPLE_TAIL = 2_000  # lines from end


def _sample_large_code(raw_code: str) -> str:
    """For files >10k lines, keep the first 5k + last 2k lines."""
    lines = raw_code.splitlines(True)  # keep newlines
    if len(lines) <= _LARGE_FILE_THRESHOLD:
        return raw_code
    print(f"⚡ Large file ({len(lines)} lines) — sampling first {_SAMPLE_HEAD} + last {_SAMPLE_TAIL} lines")
    sampled = lines[:_SAMPLE_HEAD] + ['\n# ... [sampled: middle omitted] ...\n'] + lines[-_SAMPLE_TAIL:]
    return ''.join(sampled)


# Processing Engine
def structuralDNAExtraction(rawCode, filename=None):
    """
    Extract structural features from code using AST analysis.
    Supports multiple languages via tree-sitter.

    Optimizations for large files (>10k lines):
    - LRU cache by code hash to avoid re-parsing identical code
    - Line sampling: first 5k + last 2k lines for oversized files
    - Bounded AST traversal (via tree-sitter node cap)
    """
    t_start = time.perf_counter()

    # ── Cache check ──
    code_hash = hashlib.sha256(rawCode.encode('utf-8', errors='replace')).hexdigest()[:24]
    if code_hash in _parse_cache:
        return _parse_cache[code_hash]

    # ── Large-file sampling ──
    code_to_parse = _sample_large_code(rawCode)

    detected_language = 'python'
    confidence = 0.0

    # ── Language detection — always runs (pure Python, no tree-sitter needed) ──
    if _LANG_DETECT_ENABLED and _detect_language is not None:
        try:
            detected_language, confidence = _detect_language(code_to_parse, filename=filename)
            print(f"🔍 Detected language: {detected_language} (confidence: {confidence:.2f})")
        except Exception as e:
            print(f"Language detection failed: {e}")
            detected_language = 'python'

    # ── Tree-sitter AST parsing (when packages are installed) ──
    if MULTI_LANG_ENABLED and get_node_counts is not None:
        supported = get_supported_languages()
        if detected_language not in supported:
            # Unsupported language (e.g. kotlin, swift) — skip AST, use zeroed features
            print(f"ℹ️ {detected_language} has no tree-sitter parser — using pattern-only scan")
            if modelFeatures is not None:
                df_aligned = pd.DataFrame([{col: 0 for col in modelFeatures}])
            else:
                df_aligned = pd.DataFrame([{}])
            result = (df_aligned, detected_language)
            _cache_result(code_hash, result)
            _log_perf(t_start, len(rawCode), detected_language)
            return result

        try:
            counts = get_node_counts(code_to_parse, detected_language)

            if not counts:
                return "SYNTAX_ERROR", detected_language

            # Create DataFrame with node counts
            if not isinstance(counts, dict):
                counts = {}
            df = pd.DataFrame([counts])

            # Align with model features (fill missing with 0)
            if modelFeatures is not None:
                df_aligned = df.reindex(columns=modelFeatures, fill_value=0)
            else:
                df_aligned = df

            # Add any extra columns from detection that model doesn't know about
            for col in df.columns:
                if col not in df_aligned.columns:
                    df_aligned[col] = df[col]

            result = (df_aligned, detected_language)
            _cache_result(code_hash, result)
            _log_perf(t_start, len(rawCode), detected_language)
            return result

        except Exception as e:
            print(f"Tree-sitter parsing failed for {detected_language}: {e}")
            # If tree-sitter fails for non-Python, use zeroed features and continue
            if detected_language != 'python':
                if modelFeatures is not None:
                    df_aligned = pd.DataFrame([{col: 0 for col in modelFeatures}])
                else:
                    df_aligned = pd.DataFrame([{}])
                result = (df_aligned, detected_language)
                _cache_result(code_hash, result)
                _log_perf(t_start, len(rawCode), detected_language)
                return result
            # For Python, fall through to native AST parser below
    
    # Non-Python code when tree-sitter is unavailable: skip ML features, allow pattern scan
    if detected_language != 'python':
        print(f"ℹ️ Tree-sitter unavailable for {detected_language} — using pattern-only scan")
        if modelFeatures is not None:
            df_aligned = pd.DataFrame([{col: 0 for col in modelFeatures}])
        else:
            df_aligned = pd.DataFrame([{}])
        result = (df_aligned, detected_language)
        _cache_result(code_hash, result)
        _log_perf(t_start, len(rawCode), detected_language)
        return result

    # Python-only AST parsing (native, no tree-sitter needed)
    try:
        tree = ast.parse(code_to_parse)
        normalizer.reset()  # bound memory on large files
        normalizedTree = normalizer.visit(tree)

        nodes = [type(node).__name__ for node in ast.walk(normalizedTree)]
        counts = dict(Counter(nodes))

        # ── Engineered security features (mirrors extractor_AST.py) ──────────
        _DANGEROUS_CALLS_MW = frozenset({"eval", "exec", "compile", "__import__"})
        _DANGEROUS_ATTR_MW  = frozenset({"system", "popen", "call", "Popen", "run", "check_output"})
        _SUSPICIOUS_IMP_MW  = frozenset({"os", "subprocess", "socket", "ctypes", "pickle", "marshal", "base64"})

        counts["cyclomatic_complexity"] = (
            counts.get("If", 0) + counts.get("For", 0)
            + counts.get("While", 0) + counts.get("Try", 0) + 1
        )

        # Re-parse the raw (un-normalized) code for call/import analysis
        try:
            _raw_tree = ast.parse(code_to_parse)
            n_dangerous = 0
            n_suspicious = 0
            import_count = 0
            for _node in ast.walk(_raw_tree):
                if isinstance(_node, ast.Call):
                    if isinstance(_node.func, ast.Name) and _node.func.id in _DANGEROUS_CALLS_MW:
                        n_dangerous += 1
                    elif isinstance(_node.func, ast.Attribute) and _node.func.attr in _DANGEROUS_ATTR_MW:
                        n_dangerous += 1
                elif isinstance(_node, ast.Import):
                    import_count += len(_node.names)
                    for _alias in _node.names:
                        if _alias.name.split(".")[0] in _SUSPICIOUS_IMP_MW:
                            n_suspicious += 1
                elif isinstance(_node, ast.ImportFrom):
                    import_count += 1
                    if _node.module and _node.module.split(".")[0] in _SUSPICIOUS_IMP_MW:
                        n_suspicious += 1
            counts["n_dangerous_calls"]   = n_dangerous
            counts["n_suspicious_imports"] = n_suspicious
            counts["import_count"]         = import_count
        except Exception:
            counts["n_dangerous_calls"]   = 0
            counts["n_suspicious_imports"] = 0
            counts["import_count"]         = 0

        # Entropy features — use codeInput (not sampled) for full fidelity
        try:
            if _get_entropy_flags is not None:
                from entropy_profiler import profile_source as _profile_src  # type: ignore[import]
                _anns = _profile_src(rawCode)
                if _anns:
                    _ents = [a.entropy for a in _anns]
                    counts["max_entropy"]          = max(_ents)
                    counts["mean_entropy"]         = sum(_ents) / len(_ents)
                    counts["n_high_entropy_nodes"] = sum(1 for a in _anns if a.is_anomalous)
                else:
                    counts["max_entropy"] = counts["mean_entropy"] = counts["n_high_entropy_nodes"] = 0
        except Exception:
            counts["max_entropy"] = counts["mean_entropy"] = counts["n_high_entropy_nodes"] = 0
        # ────────────────────────────────────────────────────────────────────

        df = pd.DataFrame([counts])
        if modelFeatures is not None:
            df_aligned = df.reindex(columns=modelFeatures, fill_value=0)
        else:
            df_aligned = df

        result = (df_aligned, 'python')
        _cache_result(code_hash, result)
        _log_perf(t_start, len(rawCode), 'python')
        return result

    except SyntaxError:
        return "SYNTAX_ERROR", 'python'

    except Exception as e:
        print(f"Error processing code: {e}")
        return None, detected_language


def _cache_result(code_hash: str, result):
    """Store parse result in bounded cache."""
    if len(_parse_cache) >= _PARSE_CACHE_SIZE:
        # Evict oldest entry (FIFO)
        oldest = next(iter(_parse_cache))
        del _parse_cache[oldest]
    _parse_cache[code_hash] = result


# ── 24-hour scan result cache (keyed by full SHA-256 code hash) ──
_RESULT_CACHE_TTL = 24 * 60 * 60
_result_cache: dict = {}        # code_hash -> (result_dict, timestamp)
_result_cache_lock = threading.Lock()

# ── GCN probability drift buffer ──
import collections as _collections
_GCN_PROB_BUFFER: _collections.deque = _collections.deque(maxlen=500)
_GCN_DRIFT_BASELINE: list = []   # first 100 samples become the reference
_GCN_DRIFT_LOCK = threading.Lock()


def _kl_divergence(p: list, q: list, bins: int = 20) -> float:
    """KL divergence D(P||Q) via histogram estimates over [0, 1]."""
    try:
        if len(p) < 2 or len(q) < 2:
            return -1.0
        import numpy as np
        edges = np.linspace(0, 1, bins + 1)
        ph, _ = np.histogram(p, bins=edges, density=True)
        qh, _ = np.histogram(q, bins=edges, density=True)
        eps = 1e-10
        ph = (ph + eps) / (ph + eps).sum()
        qh = (qh + eps) / (qh + eps).sum()
        return float(np.sum(ph * np.log(ph / qh)))
    except Exception:
        return -1.0


def _log_perf(t_start: float, code_size: int, language: str):
    """Warn when parsing is slow."""
    elapsed = time.perf_counter() - t_start
    if elapsed > 2.0:
        print(f"⚠️ Slow parse: {elapsed:.2f}s for {code_size} chars ({language})")
    elif elapsed > 0.5:
        print(f"📊 Parse time: {elapsed:.2f}s for {code_size} chars ({language})")
    
def _remove_block_comments(s: str) -> str:
    """
    Remove /* ... */ block comments using a linear character scan.
    No regex backtracking — O(n) time regardless of input structure.
    """
    out: list[str] = []
    i = 0
    n = len(s)
    while i < n:
        if s[i] == '/' and i + 1 < n and s[i + 1] == '*':
            i += 2
            while i < n - 1:
                if s[i] == '*' and s[i + 1] == '/':
                    i += 2
                    break
                i += 1
            else:
                i = n  # unclosed comment — consume rest
        else:
            out.append(s[i])
            i += 1
    return ''.join(out)


def strip_comments(code_str):
    """
    Remove comments and multi-line strings from code before keyword scanning.
    Prevents AI explanations (e.g., // Removed exec()) from triggering false positives.
    """
    if len(code_str) > 100_000:
        code_str = code_str[:100_000]
    # Remove single-line comments (Python # and JS/Java //)
    code_str = re.sub(r'//.*', '', code_str)
    code_str = re.sub(r'#.*', '', code_str)
    # Remove block comments (JS/Java /* */) — use linear scanner, not regex
    code_str = _remove_block_comments(code_str)
    # Remove Python multi-line strings (often used as comments)
    code_str = re.sub(r'\"\"\"(.*?)\"\"\"', '', code_str, flags=re.DOTALL)
    code_str = re.sub(r"\'\'\'(.*?)\'\'\'", '', code_str, flags=re.DOTALL)
    return code_str


@app.route('/analyze', methods=['POST'])
@rate_limit(max_requests=20, window_seconds=60)
@token_required(optional=True)
def analyze(current_user):
    """
    Scan a code snippet for malicious patterns.
    ---
    tags: [Scanning]
    security: [{Bearer: []}]
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          required: [code]
          properties:
            code: {type: string, description: Source code to scan (max 50 000 chars)}
    responses:
      200:
        description: Scan result
        schema:
          type: object
          properties:
            malicious: {type: boolean}
            risk_level: {type: string, enum: [LOW, MEDIUM, HIGH, CRITICAL]}
            confidence: {type: number}
            reason: {type: string}
            language: {type: string}
            vulnerabilities: {type: array, items: {type: object}}
      429: {description: Rate limit exceeded}
    """
    data = request.get_json(silent=True) or {}
    codeInput = data.get('code', '')
    filename = data.get('filename', None)  # e.g. "main.go", "package.json"

    if not isinstance(codeInput, str):
        return jsonify({'status': 'error', 'message': 'code must be a string'}), 400

    if len(codeInput) > 50000:
        return jsonify({
            'status':'error',
            'message': 'Code exceeds maximum character limit (50k).'
        }), 400

    if not codeInput:
        return jsonify({'status': 'error', 'message': 'No code provided'}), 400

    # ── 24h result cache check — keyed on (user_id, code) so results don't leak cross-user ──
    _uid_for_cache = current_user.get('user_id', 'anon') if current_user else 'anon'
    _cache_key = hashlib.sha256(f"{_uid_for_cache}:{codeInput}".encode('utf-8', errors='replace')).hexdigest()
    with _result_cache_lock:
        _cached = _result_cache.get(_cache_key)
        if _cached:
            _cached_result, _cached_at = _cached
            if time.time() - _cached_at < _RESULT_CACHE_TTL:
                return jsonify(_cached_result)

    # Strip comments to prevent AI explanations from triggering false positives
    clean_code = strip_comments(codeInput)

    # Pre-parse Python AST once; reused by entropy_profiler + cfg_extractor
    # to avoid redundant ast.parse() calls (saves ~40-100ms on large files).
    _py_tree = None
    try:
        _py_tree = ast.parse(codeInput)
    except SyntaxError:
        pass

    # 2. TRANSFORM CODE INTO NUMBERS + DETECT LANGUAGE
    result = structuralDNAExtraction(codeInput, filename=filename)

    # Handle tuple return (dataframe, language)
    if isinstance(result, tuple):
        featuresDf, detected_language = result
    else:
        featuresDf = result
        detected_language = 'python'

    # 1. KEYWORD SAFETY NET — language-aware: only apply patterns valid for this language
    _active_kw = {
        p for p in BUZZ_WORDS
        if p not in LANGUAGE_FILTER or detected_language in LANGUAGE_FILTER[p]
    }
    triggerKeywords = [k for k in _active_kw if k in clean_code]

    # 3. ERROR HANDLING
    # Parse failure is NEVER fatal — pattern-based + entropy scanning always runs.
    # We zero out AST/ML features and attach a parse_warning to the final response.
    _parse_failed = False
    if isinstance(featuresDf, str) and featuresDf == "SYNTAX_ERROR":
        _parse_failed = True
        if modelFeatures is not None:
            featuresDf = pd.DataFrame([{col: 0 for col in modelFeatures}])
        else:
            featuresDf = pd.DataFrame([{}])
        
    if featuresDf is None:
        return jsonify({'status': 'error', 'message': 'Analysis failed.', 'language': detected_language}), 500
    
    load_model_if_updated()

    # 1.5. ENTROPY PRE-SCAN (Phase 2) — torch-free; runs before ML models
    # Pass pre-parsed tree to skip redundant ast.parse() inside profiler.
    entropy_flags = []
    if ENTROPY_ENABLED and _get_entropy_flags is not None:
        try:
            entropy_flags = _get_entropy_flags(codeInput, tree=_py_tree)
        except Exception as _e:
            print(f"Entropy profiler error: {_e}")

    # 1.6. SNN TEMPORAL ANOMALY PROFILING (Kyber Engine 3) — Python only
    if detected_language == 'python':
        _init_snn_once()  # lazy-load torch/snntorch on first Python scan
    snn_result = None
    if SNN_ENABLED and _snn_profiler is not None and detected_language == 'python':
        try:
            snn_result = _snn_profiler.profile(codeInput)
        except Exception as _e:
            print(f"SNN profiler error: {_e}")

    # 4. INITIALIZE DEFAULTS
    maliciousProb = 0.1
    confidence = 50.0

    # Determine highest keyword severity FIRST before AI prediction
    highest_keyword_severity = "LOW"
    critical_or_high_keyword = None

    if triggerKeywords:
        severity_ranks = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        for kw in triggerKeywords:
            sev = SEVERITY_LOOKUP.get(kw, "MEDIUM")
            if severity_ranks.get(sev, 0) > severity_ranks.get(highest_keyword_severity, 0):
                highest_keyword_severity = sev
                if sev in ["CRITICAL", "HIGH"]:
                    critical_or_high_keyword = kw

    # If we found a critical keyword, bump base probability before ML
    if critical_or_high_keyword:
        maliciousProb = 0.85

    # Entropy floor: high-entropy literals indicate packed/obfuscated payloads
    if entropy_flags:
        maliciousProb = max(maliciousProb, 0.75)

    # SNN floor: anomalous execution rhythm (decryption loops, network probing)
    if snn_result is not None and snn_result.is_anomalous:
        maliciousProb = max(maliciousProb, 0.65)

    # 5. AI VERDICT
    try:
        if model is not None and hasattr(model, 'predict_proba'):
            probability = model.predict_proba(featuresDf)[0]
            # ONLY override if ML actually thinks it's strictly worse, or if no critical keywords exist
            if probability[1] > maliciousProb:
                maliciousProb = probability[1]
                confidence = round(max(probability) * 100, 1)
    except Exception as e:
        # Model may not support new language features - use keyword detection only
        print(f"Model prediction failed: {e}")

    # 5.5. GCN INFERENCE (Phase 3b) — blend if model exists and F1 >= 0.60
    gcn_probability = None
    gcn_enabled     = _GCN_ENABLED
    if _GCN_ENABLED and _gcn_model is not None and detected_language == 'python':
        try:
            from cfg_extractor import extract_function_graph  # type: ignore[import]
            # Pass pre-parsed tree; cfg_extractor will normalize it in-place.
            # entropy_profiler already ran on un-normalized tree, so order is safe.
            gcn_data = extract_function_graph(codeInput, normalize=True, _tree=_py_tree)
            if gcn_data is not None:
                from trainerModel_GCN import predict_gcn  # type: ignore[import]
                _, gcn_prob = predict_gcn(_gcn_model, gcn_data)
                gcn_probability = round(gcn_prob, 4)
                if _gcn_f1 >= 0.60:
                    # Confidence = distance from 0.5 (0=uncertain, 1=very confident)
                    gcn_confidence = 2.0 * abs(gcn_prob - 0.5)
                    gcn_weight = 0.2 + 0.4 * gcn_confidence  # 0.2 (uncertain) → 0.6 (confident)
                    maliciousProb = (1 - gcn_weight) * maliciousProb + gcn_weight * gcn_prob
                # Update drift buffer
                with _GCN_DRIFT_LOCK:
                    _GCN_PROB_BUFFER.append(gcn_probability)
                    if len(_GCN_DRIFT_BASELINE) < 100:
                        _GCN_DRIFT_BASELINE.append(gcn_probability)
        except Exception as _gcn_err:
            print(f"GCN inference error (non-fatal): {_gcn_err}")

    # 6. RISK HIERARCHY LOGIC
    code_line_count = len([l for l in codeInput.splitlines() if l.strip()])

    # Priority 1: CRITICAL or HIGH Keyword Match (always wins)
    if critical_or_high_keyword:
        verdict = True
        riskLabel = highest_keyword_severity
        detail = BUZZ_WORDS.get(critical_or_high_keyword, "Suspicious pattern detected")
        message = f"Immediate threat: {detail}"
        
    # Priority 2: Very High AI Confidence on complex code (ML-only verdict)
    # Require 0.97+ threshold AND at least 5 meaningful lines to prevent false positives on trivial code
    elif maliciousProb > 0.97 and code_line_count >= 5 and not critical_or_high_keyword:
        verdict = True
        riskLabel = "HIGH"
        message = f"AI detected complex threat pattern: {round(maliciousProb * 100)}% confidence"
        
    # Priority 3: Medium Risk / Suspicious
    elif maliciousProb > 0.60 or highest_keyword_severity == "MEDIUM":
        verdict = False
        riskLabel = "MEDIUM"
        message = "Suspicious patterns noted, but insufficient evidence for threat classification"
        
    # Priority 4: Safe (LOW or no keywords, low ML risk)
    else:
        verdict = False
        riskLabel = "LOW"
        message = "Code structure follows standard safety profiles"

    result = {
        'malicious': verdict,
        'confidence': confidence,
        'risk_level': riskLabel,
        'reason': message,
        'language': detected_language,
        'metadata': {
            'nodes_scanned':    len(featuresDf.columns),
            'engine':           'ACID v3.0 (Multi-Language)',
            'supported_languages': ['python', 'java', 'javascript', 'typescript', 'c', 'cpp', 'c_sharp', 'go', 'ruby', 'php', 'rust', 'kotlin', 'swift'],
            'process_time':     'Real-time',
            'gcn_probability':  gcn_probability,
            'gcn_enabled':      gcn_enabled,
            'parse_warning':    'AST parse failed — ML features zeroed, pattern scan ran normally' if _parse_failed else None,
        }
    }

    # SNN temporal metadata
    if snn_result is not None:
        result['metadata']['snn_temporal'] = {
            'anomaly_prob':   round(snn_result.anomaly_prob, 4),
            'is_anomalous':   snn_result.is_anomalous,
            'isi_cv':         round(snn_result.isi_cv, 3),
            'firing_rate_hz': round(snn_result.firing_rate_hz, 1),
            'n_events':       snn_result.n_events,
            'inference_ms':   round(snn_result.inference_ms, 1),
        }

    # LINE-LEVEL VULNERABILITY DETECTION (language-filtered)
    vulnerabilities = []
    code_lines = codeInput.split('\n')
    for line_num, line_text in enumerate(code_lines, 1):
        for pattern in _active_kw:
            if pattern in line_text:
                severity = SEVERITY_LOOKUP.get(pattern, 'MEDIUM')
                cwe = CWE_LOOKUP.get(pattern, '')
                vulnerabilities.append({
                    'line': line_num,
                    'pattern': pattern,
                    'severity': severity,
                    'description': BUZZ_WORDS[pattern],
                    'cwe': cwe,
                    'category': _cwe_to_category(cwe),
                    'fix_hint': _cwe_to_fix_hint(cwe),
                    'snippet': line_text.strip()[:100]
                })

    # REGEX SCAN — semantic patterns not expressible as literal strings
    import re as _re
    if detected_language in ('c', 'cpp'):
        # CWE-457: Uninitialized variable — declaration without assignment
        _uninit_re = _re.compile(
            r'^\s*(?:unsigned\s+)?(?:int|long|char|short|float|double|size_t|uint\d*_t|int\d*_t|bool)\s+(\w+)\s*;',
            _re.MULTILINE
        )
        _decl_names = {}
        for _m in _uninit_re.finditer(codeInput):
            _ln = codeInput[:_m.start()].count('\n') + 1
            _decl_names[_m.group(1)] = _ln

        for _var, _decl_ln in _decl_names.items():
            # Flag only if variable is used in arithmetic/assignment after declaration
            _use_re = _re.compile(r'\b' + _re.escape(_var) + r'\s*[\+\-\*\/]')
            if _use_re.search(codeInput):
                vulnerabilities.append({
                    'line':        _decl_ln,
                    'pattern':     f'{_var} (uninitialized)',
                    'severity':    'HIGH',
                    'description': (
                        f"Variable '{_var}' declared without initialization "
                        f"then used in arithmetic — contains indeterminate value (UB)"
                    ),
                    'cwe':         'CWE-457',
                    'category':    'Memory Safety',
                    'fix_hint':    'Initialize all variables at declaration: int x = 0;',
                    'snippet':     next(
                        (l.strip()[:100] for l in codeInput.split('\n')[_decl_ln-1:_decl_ln]),
                        ''
                    ),
                })

    # SNN temporal anomaly (Kyber Engine 3) — CWE-506: Embedded Malicious Code
    if snn_result is not None and snn_result.is_anomalous:
        vulnerabilities.append({
            'line':     0,
            'pattern':  'SNN_TEMPORAL_ANOMALY',
            'severity': 'HIGH',
            'description': (
                f'Anomalous execution rhythm detected '
                f'(ISI-CV={snn_result.isi_cv:.2f}, '
                f'rate={snn_result.firing_rate_hz:.0f} Hz). '
                'Pattern consistent with decryption loops, unpacking, or network probing.'
            ),
            'cwe':      'CWE-506',
            'category': 'Temporal Execution Anomaly',
            'fix_hint': 'Review timed/deferred execution, eval, exec, and subprocess calls.',
            'snippet':  '',
        })

    # Entropy anomaly flags (Phase 2) — CWE-506: Embedded Malicious Code
    for eflag in entropy_flags:
        vulnerabilities.append({
            'line':        eflag.line_no,
            'pattern':     f'high_entropy_{eflag.node_type.lower()}',
            'severity':    'HIGH',
            'description': (
                f'High-entropy literal detected ({eflag.entropy:.2f} bits/byte) — '
                'possible packed, base64-encoded, or encrypted payload.'
            ),
            'cwe':      'CWE-506',
            'category': 'Supply Chain Attack',
            'fix_hint': CWE_FIX_HINTS.get('CWE-506', ''),
            'snippet':  eflag.literal_preview[:100],
        })

    # SEMGREP DEEP SCAN — AST-level community rules (4th detection layer)
    if SEMGREP_ENABLED and _semgrep_scan is not None:
        try:
            sg_findings = _semgrep_scan(codeInput, detected_language, timeout=30)
            # Deduplicate: skip findings already reported at the same (line, cwe) pair
            existing_pairs = {(v['line'], v.get('cwe', '')) for v in vulnerabilities}
            for f in sg_findings:
                if (f['line'], f.get('cwe', '')) not in existing_pairs:
                    vulnerabilities.append(f)
            if sg_findings:
                result['metadata']['semgrep_findings'] = len(sg_findings)
        except Exception as _sg_e:
            print(f"Semgrep scan error: {_sg_e}")

    if vulnerabilities:
        result['vulnerabilities'] = vulnerabilities
        result['summary'] = generate_tldr_summary(vulnerabilities)

        # Elevate verdict/risk if scanner found HIGH or CRITICAL issues the ML missed
        _sev_rank = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
        _max_sev = max((_sev_rank.get(v.get('severity', 'LOW'), 1) for v in vulnerabilities), default=1)
        _cur_rank = _sev_rank.get(result.get('risk_level', 'LOW'), 1)
        if _max_sev > _cur_rank:
            _new_label = {4: 'CRITICAL', 3: 'HIGH', 2: 'MEDIUM', 1: 'LOW'}[_max_sev]
            result['risk_level'] = _new_label
            if _max_sev >= 3:  # HIGH or CRITICAL → flag as threat
                result['malicious'] = True
                if not result.get('reason') or result.get('risk_level') in ('LOW', 'MEDIUM'):
                    result['reason'] = f"{_new_label.capitalize()} severity vulnerability detected by pattern scanner"
    else:
        result['summary'] = "No vulnerabilities detected. Code follows standard safety profiles."

    # Auto-save to scan history if logged in
    user_id = current_user['user_id'] if current_user else None

    _feat_row = featuresDf.iloc[0].to_dict() if not featuresDf.empty else {}
    _features = {
        'max_entropy':           _feat_row.get('max_entropy', 0),
        'mean_entropy':          _feat_row.get('mean_entropy', 0),
        'n_high_entropy_nodes':  _feat_row.get('n_high_entropy_nodes', 0),
        'cyclomatic_complexity': _feat_row.get('cyclomatic_complexity', 0),
        'n_dangerous_calls':     _feat_row.get('n_dangerous_calls', 0),
        'n_suspicious_imports':  _feat_row.get('n_suspicious_imports', 0),
        'import_count':          _feat_row.get('import_count', 0),
        'n_sql_sink_calls':      _feat_row.get('n_sql_sink_calls', 0),
        'has_sql_concat':        _feat_row.get('has_sql_concat', 0),
        'n_user_input_sources':  _feat_row.get('n_user_input_sources', 0),
        'taint_reaches_sql':     _feat_row.get('taint_reaches_sql', 0),
        'taint_reaches_shell':   _feat_row.get('taint_reaches_shell', 0),
        'gcn_prob':              result.get('metadata', {}).get('gcn_probability'),
        'rf_confidence':         confidence,
    }

    scan_id = save_scan_result(
        user_id=user_id,
        language=detected_language,
        risk_level=riskLabel,
        confidence=confidence,
        malicious=verdict,
        code=codeInput,
        nodes_scanned=len(featuresDf.columns),
        reason=message,
        features=_features,
    )
    result['scan_id'] = scan_id

    # Populate 24h result cache
    with _result_cache_lock:
        _result_cache[_cache_key] = (result, time.time())
        _now_ts = time.time()
        for _k in [k for k, (_, ts) in _result_cache.items() if _now_ts - ts >= _RESULT_CACHE_TTL]:
            del _result_cache[_k]

    # Fire webhook if user has one configured and verdict is malicious
    if verdict and user_id:
        try:
            conn = get_db_connection()
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            c.execute('SELECT webhook_url FROM user_settings WHERE user_id = ?', (user_id,))
            row = c.fetchone()
            webhook_url = row['webhook_url'] if row else None
        except Exception:
            webhook_url = None
        finally:
            try:
                conn.close()
            except Exception:
                pass
        if webhook_url and _is_safe_external_url(webhook_url):
            try:
                requests.post(webhook_url, json={
                    'event': 'malicious_scan',
                    'risk_level': riskLabel,
                    'confidence': confidence,
                    'language': detected_language,
                    'reason': message,
                }, timeout=5)
            except Exception:
                pass  # webhook failures are non-fatal

    # Save scan as training sample (fire-and-forget, never blocks response)
    _save_training_sample(
        code=codeInput,
        language=detected_language,
        is_malicious=verdict,
        risk_level=riskLabel,
        vuln_count=len(vulnerabilities),
        confidence=confidence,
        source='scanner',
        user_id=user_id,
    )

    return jsonify(result)


@app.route('/generate-report', methods=['POST'])
@token_required(optional=False)
@rate_limit(max_requests=10, window_seconds=60)
def generateReport(current_user):
    data = request.get_json()
    snippet = data.get('code', '')
    verdict = data.get('verdict', 'UNKNOWN')
    confidence = data.get('confidence', 0)
    risk_level = data.get('risk_level', verdict)
    reason = data.get('reason', '')
    language = data.get('language', 'Unknown')
    deep_scan = data.get('deep_scan', '')
    nodes_scanned = data.get('nodes_scanned', 0)
    vulnerabilities = data.get('vulnerabilities', [])

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=25)
    pdf.add_page()

    # ═══════════════════════════════════
    # HEADER — Professional branding
    # ═══════════════════════════════════
    # Navy header bar
    pdf.set_fill_color(2, 6, 23)  # Very dark navy
    pdf.rect(0, 0, 210, 40, 'F')
    
    logo_path = os.path.join(os.path.dirname(__file__), '../frontend/public/soteria-logo.png')
    if os.path.exists(logo_path):
        # fpdf2 allows adding an image with alpha channel for PNG
        pdf.image(logo_path, x=15, y=7, w=25)
    
    pdf.set_font("Helvetica", "B", 22)
    pdf.set_text_color(255, 255, 255)
    pdf.set_y(10)
    pdf.cell(0, 10, "SOTERIA SECURITY REPORT", new_x=XPos.LMARGIN, new_y=YPos.NEXT, align="C")
    
    pdf.set_font("Helvetica", size=9)
    pdf.set_text_color(148, 163, 184)  # Slate-400
    pdf.cell(0, 6, f"Soteria AI Security Engine  |  {datetime.now().strftime('%B %d, %Y at %H:%M')}", 
             new_x=XPos.LMARGIN, new_y=YPos.NEXT, align="C")
    
    pdf.ln(15)

    # ═══════════════════════════════════
    # EXECUTIVE SUMMARY
    # ═══════════════════════════════════
    pdf.set_font("Helvetica", "B", 14)
    pdf.set_text_color(30, 41, 59)  # Slate-800
    pdf.cell(0, 10, "1. Executive Summary", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(2)
    
    # Risk level badge
    risk_colors = {
        'CRITICAL': (239, 68, 68),    # Red
        'HIGH': (249, 115, 22),        # Orange
        'MEDIUM': (245, 158, 11),      # Amber
        'LOW': (34, 197, 94),          # Green
    }
    badge_color = risk_colors.get(risk_level, (100, 116, 139))
    
    pdf.set_fill_color(*badge_color)
    pdf.set_font("Helvetica", "B", 11)
    pdf.set_text_color(255, 255, 255)
    badge_text = f"  {risk_level} RISK  "
    badge_width = pdf.get_string_width(badge_text) + 8
    pdf.cell(badge_width, 8, badge_text, new_x=XPos.RIGHT, new_y=YPos.TOP, fill=True)
    
    pdf.set_font("Helvetica", size=11)
    pdf.set_text_color(71, 85, 105)  # Slate-600
    pdf.cell(0, 8, f"   Confidence: {confidence}%  |  Language: {language.upper()}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(4)
    
    # Summary box
    pdf.set_fill_color(248, 250, 252)  # Slate-50
    pdf.set_draw_color(226, 232, 240)  # Slate-200
    pdf.set_font("Helvetica", size=10)
    pdf.set_text_color(51, 65, 85)    # Slate-700
    pdf.multi_cell(0, 6, f"Analysis: {reason}", fill=True, border=1)
    pdf.ln(4)
    
    # Stats row
    pdf.set_font("Helvetica", size=9)
    pdf.set_text_color(100, 116, 139)
    pdf.cell(60, 6, f"Nodes Scanned: {nodes_scanned}", new_x=XPos.RIGHT, new_y=YPos.TOP)
    pdf.cell(60, 6, f"Engine: Soteria v2.4", new_x=XPos.RIGHT, new_y=YPos.TOP)
    pdf.cell(0, 6, f"Classification: {'THREAT' if risk_level in ['CRITICAL', 'HIGH'] else 'SAFE'}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(8)

    # ═══════════════════════════════════
    # CODE ANALYSIS
    # ═══════════════════════════════════
    pdf.set_font("Helvetica", "B", 14)
    pdf.set_text_color(30, 41, 59)
    pdf.cell(0, 10, "2. Code Under Review", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(2)
    
    # Code block with dark background
    pdf.set_fill_color(15, 23, 42)  # Slate-900
    pdf.set_text_color(226, 232, 240)  # Slate-200
    pdf.set_font("Courier", size=8)
    
    code_display = snippet[:3000]
    if len(snippet) > 3000:
        code_display += "\n\n... [truncated — full code available in application]"
    
    # Add line numbers
    lines = code_display.split('\n')
    numbered = '\n'.join(f"{i+1:4d} | {line}" for i, line in enumerate(lines[:60]))
    
    pdf.multi_cell(0, 4, numbered, fill=True)
    pdf.ln(6)

    # ═══════════════════════════════════
    # VULNERABILITY FINDINGS
    # ═══════════════════════════════════
    if vulnerabilities:
        pdf.set_font("Helvetica", "B", 14)
        pdf.set_text_color(30, 41, 59)
        pdf.cell(0, 10, "3. Vulnerability Findings", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(2)

        sev_colors = {'CRITICAL': (239, 68, 68), 'HIGH': (249, 115, 22), 'MEDIUM': (245, 158, 11), 'LOW': (34, 197, 94)}
        for vuln in vulnerabilities[:30]:
            sev = vuln.get('severity', 'MEDIUM')
            col = sev_colors.get(sev, (100, 116, 139))
            pdf.set_fill_color(*col)
            pdf.set_font("Helvetica", "B", 8)
            pdf.set_text_color(255, 255, 255)
            pdf.cell(18, 5, f" {sev}", fill=True, new_x=XPos.RIGHT, new_y=YPos.TOP)
            pdf.set_font("Helvetica", size=8)
            pdf.set_text_color(30, 41, 59)
            line_info = f" Line {vuln.get('line', '?')}: {vuln.get('pattern', '')} — {vuln.get('description', '')}"
            pdf.cell(0, 5, line_info[:120], new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            if vuln.get('snippet'):
                pdf.set_font("Courier", size=7)
                pdf.set_text_color(71, 85, 105)
                pdf.cell(0, 4, f"  {vuln['snippet'][:100]}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.ln(1)
        pdf.ln(4)

    # ═══════════════════════════════════
    # AI DEEP SCAN ANALYSIS (if available)
    # ═══════════════════════════════════
    if deep_scan:
        pdf.set_font("Helvetica", "B", 14)
        pdf.set_text_color(30, 41, 59)
        _ds_section = 4 if vulnerabilities else 3
        pdf.cell(0, 10, f"{_ds_section}. AI-Powered Deep Analysis", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(2)
        
        pdf.set_font("Helvetica", size=9)
        pdf.set_text_color(51, 65, 85)
        
        # Clean up markdown formatting for PDF
        clean_analysis = deep_scan.replace('## ', '\n').replace('### ', '\n').replace('**', '').replace('```', '\n---\n')
        pdf.multi_cell(0, 5, clean_analysis[:5000])
        pdf.ln(6)

    # ═══════════════════════════════════
    # RECOMMENDATIONS
    # ═══════════════════════════════════
    section_num = 3 + bool(vulnerabilities) + bool(deep_scan)
    pdf.set_font("Helvetica", "B", 14)
    pdf.set_text_color(30, 41, 59)
    pdf.cell(0, 10, f"{section_num}. Recommendations", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(2)
    
    pdf.set_font("Helvetica", size=10)
    pdf.set_text_color(51, 65, 85)
    
    if risk_level in ['CRITICAL', 'HIGH']:
        recommendations = [
            "IMMEDIATE: Do not deploy this code to production",
            "Review all flagged vulnerability patterns",
            "Apply the suggested fixes from the AI deep scan",
            "Re-scan after applying fixes to verify resolution",
            "Consider a manual security review by a senior developer"
        ]
    elif risk_level == 'MEDIUM':
        recommendations = [
            "Review flagged patterns before deploying",
            "Consider using the AI deep scan for detailed analysis",
            "Apply input validation and output escaping",
            "Re-scan after modifications"
        ]
    else:
        recommendations = [
            "Code passes automated security checks",
            "Continue following secure coding best practices",
            "Consider periodic re-scans as dependencies update",
            "Use the Code Reviewer for new code additions"
        ]
    
    for i, rec in enumerate(recommendations, 1):
        pdf.set_font("Helvetica", "B", 10)
        pdf.cell(8, 6, f"{i}.", new_x=XPos.RIGHT, new_y=YPos.TOP)
        pdf.set_font("Helvetica", size=10)
        pdf.cell(0, 6, f" {rec}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    
    pdf.ln(10)

    # ═══════════════════════════════════
    # FOOTER
    # ═══════════════════════════════════
    pdf.set_draw_color(226, 232, 240)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(4)
    pdf.set_font("Helvetica", "I", 8)
    pdf.set_text_color(148, 163, 184)
    pdf.cell(0, 5, "This report was generated automatically by the Soteria AI Security Engine.", new_x=XPos.LMARGIN, new_y=YPos.NEXT, align="C")
    pdf.cell(0, 5, "Results are based on ML analysis and should be supplemented with manual review for critical systems.", new_x=XPos.LMARGIN, new_y=YPos.NEXT, align="C")

    pdf_output = pdf.output() 

    return send_file(
        BytesIO(pdf_output),
        mimetype='application/pdf',
        as_attachment=True,
        download_name=f"Soteria_Security_Report_{datetime.now().strftime('%Y%m%d_%H%M')}.pdf"
    )

@app.route('/api/feedback', methods=['POST'])
@token_required(optional=False)
def api_submit_feedback(current_user):
    """
    Submit user feedback on a scan verdict.
    ---
    tags: [Feedback]
    security: [{Bearer: []}]
    parameters:
      - in: body
        schema:
          type: object
          required: [scan_id, correct]
          properties:
            scan_id: {type: integer}
            correct:  {type: boolean}
    responses:
      200: {description: Feedback recorded}
      400: {description: Missing fields}
    """
    data = request.get_json(silent=True) or {}
    scan_id = data.get('scan_id')
    correct  = data.get('correct')
    if scan_id is None or correct is None:
        return jsonify({'error': 'scan_id and correct required'}), 400
    label = 1 if correct else 0
    with _db_lock:
        conn = get_db_connection()
        conn.execute(
            'UPDATE scans SET user_label=? WHERE id=? AND user_id=?',
            (label, scan_id, current_user['user_id'])
        )
        conn.commit()
        conn.close()
    return jsonify({'ok': True})


@app.route('/scan-history', methods=['GET'])
@token_required(optional=True)
def scan_history(current_user):
    """
    Return paginated scan history. Admins see all scans; regular users see only their own.
    ---
    tags: [History]
    security: [{Bearer: []}]
    parameters:
      - {in: query, name: limit, type: integer, default: 50}
      - {in: query, name: offset, type: integer, default: 0}
    responses:
      200:
        description: Paginated scan records
        schema:
          type: object
          properties:
            scans: {type: array, items: {type: object}}
            total: {type: integer}
            limit: {type: integer}
            offset: {type: integer}
    """
    limit = request.args.get('limit', 50, type=int)
    offset = request.args.get('offset', 0, type=int)

    try:
        conn = get_db_connection()
        conn.row_factory = sqlite3.Row
        c = conn.cursor()

        is_admin = current_user and current_user.get('is_admin')
        if is_admin:
            c.execute('SELECT COUNT(*) FROM scans')
            total = c.fetchone()[0]
            c.execute('SELECT * FROM scans ORDER BY timestamp DESC LIMIT ? OFFSET ?', (limit, offset))
        elif current_user:
            user_id = current_user['user_id']
            c.execute('SELECT COUNT(*) FROM scans WHERE user_id = ?', (user_id,))
            total = c.fetchone()[0]
            c.execute('SELECT * FROM scans WHERE user_id = ? ORDER BY timestamp DESC LIMIT ? OFFSET ?',
                      (user_id, limit, offset))
        else:
            conn.close()
            return jsonify({'scans': [], 'total': 0, 'limit': limit, 'offset': offset})

        rows = [dict(row) for row in c.fetchall()]
        conn.close()
        return jsonify({'scans': rows, 'total': total, 'limit': limit, 'offset': offset})
    except Exception as e:
        app.logger.error("Internal error: %s", str(e), exc_info=True)
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/api/scan-history/compare', methods=['GET'])
@token_required(optional=False)
def scan_history_compare(current_user):
    """
    Compare two scan results by ID and return a JSON diff.
    ---
    tags: [History]
    security: [{Bearer: []}]
    parameters:
      - {in: query, name: id1, type: integer, required: true}
      - {in: query, name: id2, type: integer, required: true}
    responses:
      200:
        description: Diff of the two scans
        schema:
          type: object
      403: {description: Forbidden — scan does not belong to this user}
      404: {description: One or both scans not found}
    """
    id1 = request.args.get('id1', type=int)
    id2 = request.args.get('id2', type=int)
    if id1 is None or id2 is None:
        return jsonify({'error': 'Both id1 and id2 query parameters are required'}), 400

    user_id = current_user['user_id']
    is_admin = current_user.get('is_admin', False)

    try:
        conn = get_db_connection()
        conn.row_factory = sqlite3.Row
        c = conn.cursor()

        c.execute('SELECT * FROM scans WHERE id = ?', (id1,))
        row1 = c.fetchone()
        c.execute('SELECT * FROM scans WHERE id = ?', (id2,))
        row2 = c.fetchone()
        conn.close()

        if row1 is None or row2 is None:
            missing = id1 if row1 is None else id2
            return jsonify({'error': f'Scan {missing} not found'}), 404

        if not is_admin:
            if row1['user_id'] != user_id or row2['user_id'] != user_id:
                return jsonify({'error': 'Access denied: one or both scans do not belong to you'}), 403

        def _risk_level(row):
            try:
                return row['risk_level']
            except Exception:
                return None

        def _confidence(row):
            try:
                return float(row['confidence']) if row['confidence'] is not None else None
            except Exception:
                return None

        def _verdict(row):
            # stored as `malicious` (int 0/1) in the scans table
            try:
                return bool(row['malicious'])
            except Exception:
                return None

        def _filename(row):
            try:
                return row['filename']
            except Exception:
                return None

        risk1 = _risk_level(row1)
        risk2 = _risk_level(row2)
        conf1 = _confidence(row1)
        conf2 = _confidence(row2)
        verdict1 = _verdict(row1)
        verdict2 = _verdict(row2)

        conf_delta = None
        if conf1 is not None and conf2 is not None:
            conf_delta = round(conf2 - conf1, 2)

        return jsonify({
            'id1': id1,
            'id2': id2,
            'timestamp1': row1['timestamp'],
            'timestamp2': row2['timestamp'],
            'language': row1['language'],
            'risk_level_1': risk1,
            'risk_level_2': risk2,
            'risk_changed': risk1 != risk2,
            'confidence_1': conf1,
            'confidence_2': conf2,
            'confidence_delta': conf_delta,
            'verdict_1': verdict1,
            'verdict_2': verdict2,
            'verdict_changed': verdict1 != verdict2,
            'filename_1': _filename(row1),
            'filename_2': _filename(row2),
        })
    except Exception as e:
        app.logger.error("Internal error: %s", str(e), exc_info=True)
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/api/scan-history/export', methods=['GET'])
@token_required(optional=False)
def scan_history_export(current_user):
    """
    Download the authenticated user's scan history as CSV.
    ---
    tags: [History]
    security: [{Bearer: []}]
    produces: [text/csv]
    responses:
      200: {description: CSV file download}
      401: {description: Unauthorized}
    """
    import csv
    from io import StringIO
    from flask import Response as FlaskResponse
    user_id = current_user['user_id']
    try:
        conn = get_db_connection()
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute('SELECT * FROM scans WHERE user_id = ? ORDER BY timestamp DESC', (user_id,))
        rows = c.fetchall()
        conn.close()

        si = StringIO()
        writer = csv.writer(si)
        writer.writerow(['id', 'user_id', 'timestamp', 'language', 'risk_level',
                         'confidence', 'malicious', 'code_hash', 'nodes_scanned', 'reason'])
        for row in rows:
            writer.writerow([row['id'], row['user_id'], row['timestamp'], row['language'],
                             row['risk_level'], row['confidence'], row['malicious'],
                             row['code_hash'], row['nodes_scanned'], row['reason']])

        filename = f"soteria_scans_{datetime.now().strftime('%Y%m%d')}.csv"
        return FlaskResponse(
            si.getvalue(),
            mimetype='text/csv',
            headers={'Content-Disposition': f'attachment; filename="{filename}"'}
        )
    except Exception as e:
        app.logger.error("Internal error: %s", str(e), exc_info=True)
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/api/training-data/export', methods=['GET'])
@token_required(optional=False)
def training_data_export(current_user):
    """
    Export collected training samples as CSV (admin use / model retraining).
    Returns code, language, is_malicious, risk_level, vuln_count, confidence, timestamp.
    Code column is omitted by default; pass ?include_code=1 to include it.
    ---
    tags: [Admin]
    security: [{Bearer: []}]
    produces: [text/csv]
    """
    if not current_user.get('is_admin'):
        return jsonify({'error': 'Admin access required'}), 403
    import csv
    from io import StringIO
    from flask import Response as FlaskResponse
    include_code = request.args.get('include_code', '0') == '1'
    try:
        conn = get_db_connection()
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute('SELECT * FROM training_data ORDER BY timestamp DESC')
        rows = c.fetchall()
        conn.close()

        si = StringIO()
        writer = csv.writer(si)
        headers = ['id', 'language', 'is_malicious', 'risk_level',
                   'vuln_count', 'confidence', 'timestamp', 'source']
        if include_code:
            headers.append('code')
        writer.writerow(headers)
        for row in rows:
            record = [row['id'], row['language'], row['is_malicious'],
                      row['risk_level'], row['vuln_count'],
                      row['confidence'], row['timestamp'], row['source']]
            if include_code:
                record.append(row['code'])
            writer.writerow(record)

        filename = f"soteria_training_{datetime.now().strftime('%Y%m%d')}.csv"
        return FlaskResponse(
            si.getvalue(),
            mimetype='text/csv',
            headers={'Content-Disposition': f'attachment; filename="{filename}"'}
        )
    except Exception as e:
        app.logger.error("Internal error: %s", str(e), exc_info=True)
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/api/training-data/stats', methods=['GET'])
@token_required(optional=False)
def training_data_stats(current_user):
    """
    Return aggregate statistics about the training data collected from scanner runs.
    Used by the AdminDashboard to display training corpus health.
    ---
    tags: [Admin]
    security: [{Bearer: []}]
    responses:
      200:
        description: Training data statistics
    """
    if not current_user.get('is_admin'):
        return jsonify({'error': 'Admin access required'}), 403
    try:
        conn = get_db_connection()
        conn.row_factory = sqlite3.Row
        c = conn.cursor()

        c.execute('SELECT COUNT(*) AS total FROM training_data')
        total = c.fetchone()['total']

        c.execute('SELECT COUNT(*) AS cnt FROM training_data WHERE is_malicious = 1')
        malicious_count = c.fetchone()['cnt']

        c.execute('SELECT COUNT(*) AS cnt FROM training_data WHERE is_malicious = 0')
        clean_count = c.fetchone()['cnt']

        c.execute('''SELECT language, COUNT(*) AS cnt FROM training_data
                     GROUP BY language ORDER BY cnt DESC LIMIT 10''')
        by_language = [{'language': row['language'], 'count': row['cnt']}
                       for row in c.fetchall()]

        c.execute('''SELECT risk_level, COUNT(*) AS cnt FROM training_data
                     GROUP BY risk_level ORDER BY cnt DESC''')
        by_risk = [{'risk_level': row['risk_level'], 'count': row['cnt']}
                   for row in c.fetchall()]

        c.execute('SELECT MAX(timestamp) AS last FROM training_data')
        last_row = c.fetchone()
        last_collected = last_row['last'] if last_row else None

        conn.close()
        return jsonify({
            'total': total,
            'malicious': malicious_count,
            'clean': clean_count,
            'by_language': by_language,
            'by_risk': by_risk,
            'last_collected': last_collected,
        })
    except Exception as e:
        app.logger.error("Internal error: %s", str(e), exc_info=True)
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/api/training-data/stats/me', methods=['GET'])
@token_required(optional=False)
def training_data_stats_me(current_user):
    """Personal training corpus contribution stats for the logged-in user."""
    uid = current_user['user_id']
    try:
        conn = get_db_connection()
        conn.row_factory = sqlite3.Row
        c = conn.cursor()

        c.execute('SELECT COUNT(*) AS total FROM training_data WHERE user_id = ?', (uid,))
        total = c.fetchone()['total']

        c.execute('SELECT COUNT(*) AS cnt FROM training_data WHERE user_id = ? AND is_malicious = 1', (uid,))
        malicious_count = c.fetchone()['cnt']

        c.execute('SELECT COUNT(*) AS cnt FROM training_data WHERE user_id = ? AND is_malicious = 0', (uid,))
        clean_count = c.fetchone()['cnt']

        c.execute('''SELECT language, COUNT(*) AS cnt FROM training_data
                     WHERE user_id = ? GROUP BY language ORDER BY cnt DESC LIMIT 6''', (uid,))
        by_language = [{'language': r['language'], 'count': r['cnt']} for r in c.fetchall()]

        c.execute('SELECT MAX(timestamp) AS last FROM training_data WHERE user_id = ?', (uid,))
        last_row = c.fetchone()
        last_collected = last_row['last'] if last_row else None

        conn.close()
        return jsonify({
            'total': total,
            'malicious': malicious_count,
            'clean': clean_count,
            'by_language': by_language,
            'last_collected': last_collected,
        })
    except Exception as e:
        app.logger.error("Internal error: %s", str(e), exc_info=True)
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/api/settings/webhook', methods=['GET'])
@token_required(optional=False)
def get_webhook_setting(current_user):
    """
    Get the authenticated user's webhook URL for malicious-scan notifications.
    ---
    tags: [Settings]
    security: [{Bearer: []}]
    responses:
      200:
        description: Webhook configuration
        schema:
          type: object
          properties:
            webhook_url: {type: string, nullable: true}
            updated_at: {type: string, nullable: true}
    """
    user_id = current_user['user_id']
    try:
        conn = get_db_connection()
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute('SELECT webhook_url, updated_at FROM user_settings WHERE user_id = ?', (user_id,))
        row = c.fetchone()
        conn.close()
        return jsonify({'webhook_url': row['webhook_url'] if row else None,
                        'updated_at': row['updated_at'] if row else None})
    except Exception as e:
        app.logger.error("Internal error: %s", str(e), exc_info=True)
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/api/settings/webhook', methods=['POST'])
@rate_limit(max_requests=10, window_seconds=60)
@token_required(optional=False)
def set_webhook_setting(current_user):
    """
    Save or clear the authenticated user's webhook URL.
    ---
    tags: [Settings]
    security: [{Bearer: []}]
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          properties:
            webhook_url: {type: string, description: "http/https URL, or empty string to clear"}
    responses:
      200: {description: Saved successfully}
      400: {description: Invalid URL format}
    """
    user_id = current_user['user_id']
    data = request.get_json(silent=True) or {}
    webhook_url = data.get('webhook_url', '').strip()

    # Allow empty string to clear the webhook; validate non-empty URLs
    if webhook_url and not webhook_url.startswith(('https://', 'http://')):
        return jsonify({'error': 'webhook_url must be a valid http/https URL'}), 400
    if webhook_url and not _is_safe_external_url(webhook_url):
        return jsonify({'error': 'webhook_url must point to a public internet host'}), 400

    try:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute('''INSERT INTO user_settings (user_id, webhook_url, updated_at)
                     VALUES (?, ?, ?)
                     ON CONFLICT(user_id) DO UPDATE SET webhook_url=excluded.webhook_url,
                                                        updated_at=excluded.updated_at''',
                  (user_id, webhook_url or None, datetime.now().isoformat()))
        conn.commit()
        conn.close()
        return jsonify({'ok': True, 'webhook_url': webhook_url or None})
    except Exception as e:
        app.logger.error("Internal error: %s", str(e), exc_info=True)
        return jsonify({'error': 'Internal server error'}), 500


# ── Online retraining state ───────────────────────────────────────────────────
_retrain_state: dict = {'status': 'idle', 'result': None}
_retrain_lock  = threading.Lock()


@app.route('/api/admin/retrain', methods=['POST'])
@token_required(optional=False)
def trigger_retrain(current_user):
    """
    Kick off RF online retraining in a background thread.
    Admin-only. Uses labeled scan rows accumulated since last retrain.
    ---
    tags: [Admin]
    security: [{Bearer: []}]
    parameters:
      - in: body
        schema:
          type: object
          properties:
            dry_run:      {type: boolean, default: false}
            min_samples:  {type: integer, default: 10}
    responses:
      202: {description: Retrain started}
      400: {description: Already running}
      403: {description: Admin only}
    """
    if not current_user.get('is_admin'):
        return jsonify({'error': 'Admin access required'}), 403

    with _retrain_lock:
        if _retrain_state['status'] == 'running':
            return jsonify({'error': 'Retrain already in progress'}), 400
        _retrain_state['status'] = 'running'
        _retrain_state['result'] = None

    data      = request.get_json(silent=True) or {}
    dry_run   = bool(data.get('dry_run', False))
    min_samp  = int(data.get('min_samples', 10))

    def _run():
        try:
            sys.path.insert(0, str(ROOT / 'backend' / 'src'))
            from retrain_pipeline import run_retrain  # type: ignore[import]
            res = run_retrain(min_new_samples=min_samp, dry_run=dry_run)
            # If model was swapped, reload it
            if res.get('swapped'):
                load_model_if_updated()
            with _retrain_lock:
                _retrain_state['status'] = 'done'
                _retrain_state['result'] = res
        except Exception as exc:
            with _retrain_lock:
                _retrain_state['status'] = 'failed'
                _retrain_state['result'] = {'status': 'error', 'reason': str(exc)}

    threading.Thread(target=_run, daemon=True).start()
    return jsonify({'status': 'started', 'dry_run': dry_run}), 202


@app.route('/api/admin/retrain/status', methods=['GET'])
@token_required(optional=False)
def retrain_status(current_user):
    """
    Poll retrain job status.
    ---
    tags: [Admin]
    security: [{Bearer: []}]
    responses:
      200:
        description: Current retrain state
        schema:
          type: object
          properties:
            status: {type: string, enum: [idle, running, done, failed]}
            result: {type: object}
      403: {description: Admin only}
    """
    if not current_user.get('is_admin'):
        return jsonify({'error': 'Admin access required'}), 403
    with _retrain_lock:
        return jsonify({
            'status': _retrain_state['status'],
            'result': _retrain_state['result'],
        })


@app.route('/api/model/drift', methods=['GET'])
@token_required(optional=False)
def model_drift(current_user):
    """
    GCN model drift report: KL divergence of recent predictions vs. baseline.
    ---
    tags: [Model]
    security: [{Bearer: []}]
    responses:
      200:
        description: Drift metrics
        schema:
          type: object
          properties:
            status: {type: string}
            total_samples: {type: integer}
            kl_divergence: {type: number}
            drift_alert: {type: boolean}
            recent_mean: {type: number}
            baseline_mean: {type: number}
    """
    with _GCN_DRIFT_LOCK:
        buf = list(_GCN_PROB_BUFFER)
        baseline = list(_GCN_DRIFT_BASELINE)

    if len(buf) < 10:
        return jsonify({'status': 'insufficient_data', 'samples': len(buf)})

    recent = buf[-min(100, len(buf)):]
    kl = _kl_divergence(baseline, recent) if len(baseline) >= 10 else -1.0
    return jsonify({
        'status': 'ok',
        'total_samples': len(buf),
        'baseline_samples': len(baseline),
        'recent_window': len(recent),
        'kl_divergence': round(kl, 4),
        'drift_alert': kl > 0.5 if kl >= 0 else False,
        'recent_mean': round(sum(recent) / len(recent), 4),
        'baseline_mean': round(sum(baseline) / len(baseline), 4) if baseline else None,
    })


@app.route('/security-score', methods=['GET'])
@token_required(optional=False)
def security_score(current_user):
    """Calculate aggregate security score and analytics from scan history for specific user."""
    try:
        user_id = current_user['user_id']
        conn = get_db_connection()
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        
        # Total stats
        c.execute('SELECT COUNT(*) as total FROM scans WHERE user_id = ?', (user_id,))
        total = c.fetchone()['total']
        
        if total == 0:
            return jsonify({
                'score': 100,
                'grade': 'A',
                'total_scans': 0,
                'threats': 0,
                'clean': 0,
                'languages': {},
                'risk_distribution': {},
                'daily_trend': [],
                'recent_scans': []
            })
        
        c.execute('SELECT COUNT(*) as threats FROM scans WHERE malicious = 1 AND user_id = ?', (user_id,))
        threats = c.fetchone()['threats']
        clean = total - threats
        
        # Language breakdown
        c.execute('SELECT language, COUNT(*) as count FROM scans WHERE user_id = ? GROUP BY language ORDER BY count DESC', (user_id,))
        languages = {row['language']: row['count'] for row in c.fetchall()}
        
        # Risk distribution
        c.execute('SELECT risk_level, COUNT(*) as count FROM scans WHERE user_id = ? GROUP BY risk_level', (user_id,))
        risk_dist = {row['risk_level']: row['count'] for row in c.fetchall()}
        
        # Daily trend (last 30 days)
        c.execute('''
            SELECT DATE(timestamp) as day, 
                   COUNT(*) as total,
                   SUM(CASE WHEN malicious = 1 THEN 1 ELSE 0 END) as threats,
                   AVG(confidence) as avg_confidence
            FROM scans 
            WHERE timestamp >= datetime('now', '-30 days') AND user_id = ?
            GROUP BY DATE(timestamp) 
            ORDER BY day ASC
        ''', (user_id,))
        daily_trend = [dict(row) for row in c.fetchall()]
        
        # Recent scans (last 10)
        c.execute('SELECT * FROM scans WHERE user_id = ? ORDER BY timestamp DESC LIMIT 10', (user_id,))
        recent = [dict(row) for row in c.fetchall()]
        
        conn.close()
        
        # Calculate security score (0-100)
        # Score decreases with more threats, weighted by severity
        threat_ratio = threats / total if total > 0 else 0
        critical_count = risk_dist.get('CRITICAL', 0)
        high_count = risk_dist.get('HIGH', 0)
        
        # Weighted penalty: CRITICAL = 3pts, HIGH = 2pts, MEDIUM = 1pt per scan
        penalty = (critical_count * 3 + high_count * 2 + risk_dist.get('MEDIUM', 0) * 1) / max(total, 1)
        score = max(0, round(100 - (penalty * 20) - (threat_ratio * 30)))
        
        # Letter grade
        if score >= 90: grade = 'A'
        elif score >= 80: grade = 'B'
        elif score >= 70: grade = 'C'
        elif score >= 60: grade = 'D'
        else: grade = 'F'
        
        return jsonify({
            'score': score,
            'grade': grade,
            'total_scans': total,
            'threats': threats,
            'clean': clean,
            'languages': languages,
            'risk_distribution': risk_dist,
            'daily_trend': daily_trend,
            'recent_scans': recent
        })
    except Exception as e:
        app.logger.error("Internal error: %s", str(e), exc_info=True)
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/model-stats', methods=['GET'])
@token_required(optional=True)
def model_stats(current_user=None):
    """Return real model stats from the actual model file on disk."""
    stats = {
        'status': 'no_model',
        'accuracy': 'N/A',
        'last_trained': 'N/A',
        'model_type': 'Unknown',
        'file_size': 'N/A',
        'features_count': 0
    }

    if MODELPATH.exists():
        stats['status'] = 'ready'
        # File metadata
        file_stat = MODELPATH.stat()
        size_kb = file_stat.st_size / 1024
        stats['file_size'] = f"{size_kb:.0f} KB" if size_kb < 1024 else f"{size_kb/1024:.1f} MB"
        stats['last_trained'] = datetime.fromtimestamp(file_stat.st_mtime).strftime('%Y-%m-%d %H:%M')

        if model is not None:
            stats['model_type'] = type(model).__name__
            if hasattr(model, 'feature_names_in_'):
                stats['features_count'] = len(model.feature_names_in_)
            # Try to get accuracy from model if available
            if hasattr(model, 'score'):
                stats['accuracy'] = 'Available'
            if hasattr(model, 'best_score_'):
                stats['accuracy'] = f"{model.best_score_ * 100:.1f}%"
            elif hasattr(model, 'oob_score_'):
                stats['accuracy'] = f"{model.oob_score_ * 100:.1f}%"
            else:
                stats['accuracy'] = 'Trained'
    else:
        stats['status'] = 'no_model'

    # Active detection engines — use runtime flags (not just file existence)
    stats['engines'] = {
        'sklearn':  model is not None or MODELPATH.exists(),
        'gcn':      _GCN_ENABLED,
        'entropy':  ENTROPY_ENABLED,
        'snn':      SNN_ENABLED,
    }

    return jsonify(stats)


_TRAINING_LOCK = threading.Lock()

@app.route('/train-stream', methods=['POST'])
@token_required(optional=False)
def train_stream(current_user):
    """Run training pipeline and stream output via SSE."""
    if not current_user.get('is_admin'):
        return jsonify({'error': 'Admin access required'}), 403
    if not _TRAINING_LOCK.acquire(blocking=False):
        return jsonify({'error': 'Training already in progress'}), 409
    def generate():
        pipeline_path = str((ROOT / 'backend' / 'train_full_pipeline.py').resolve())
        # Verify path is inside repo root before executing
        try:
            _rel = (ROOT / 'backend' / 'train_full_pipeline.py').resolve().relative_to(ROOT.resolve())
        except ValueError:
            yield "data: [ERROR] Pipeline path traversal detected\n\n"
            _TRAINING_LOCK.release()
            return
        try:
            # Minimal env — strip PYTHONPATH and other injections
            _train_env = {
                'PATH': '/usr/local/bin:/usr/bin:/bin',
                'HOME': os.environ.get('HOME', '/tmp'),
                'LANG': 'en_US.UTF-8',
            }
            for _k in ('VIRTUAL_ENV', 'CONDA_PREFIX', 'GEMINI_API_KEY', 'JWT_SECRET', 'DB_PATH'):
                if _k in os.environ:
                    _train_env[_k] = os.environ[_k]
            proc = subprocess.Popen(
                [sys.executable, pipeline_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                env=_train_env,
                cwd=str(ROOT / 'backend')
            )
            for line in proc.stdout:
                line = line.rstrip('\n')
                # Sanitize: strip absolute paths and noisy warnings
                line = re.sub(r'/[\w/.-]*/ACID/', './', line)
                line = re.sub(r'/[\w/.-]*/site-packages/[\w/.-]+\.py:\d+:', '[sklearn]:', line)
                if '/Library/Frameworks/' in line or '/usr/local/lib/' in line:
                    continue  # Skip full traceback lines from system libraries
                yield f"data: {line}\n\n"
            proc.wait()
            if proc.returncode == 0:
                yield f"data: [DONE] Training completed successfully!\n\n"
                # Reload the model after training
                load_model_if_updated()
            else:
                yield f"data: [ERROR] Training failed with exit code {proc.returncode}\n\n"
        except Exception as e:
            app.logger.error("Training stream error: %s", str(e), exc_info=True)
            yield "data: [ERROR] Internal server error\n\n"
        finally:
            _TRAINING_LOCK.release()
        yield "data: [STREAM_END]\n\n"

    response = app.response_class(generate(), mimetype='text/event-stream')
    response.headers['Cache-Control'] = 'no-cache'
    response.headers['X-Accel-Buffering'] = 'no'
    return response


_CWE_INFO = {
    'CWE-120': ('Buffer Copy without Checking Size of Input', 'Allows attacker to overwrite adjacent memory, corrupt stack, hijack control flow.'),
    'CWE-122': ('Heap-based Buffer Overflow', 'Overwrites heap metadata or adjacent allocations, enabling arbitrary code execution.'),
    'CWE-89':  ('SQL Injection', 'Attacker injects SQL to dump, modify, or delete database contents, or bypass auth.'),
    'CWE-79':  ('Cross-Site Scripting (XSS)', 'Attacker injects scripts into pages viewed by other users, stealing sessions or credentials.'),
    'CWE-78':  ('OS Command Injection', 'Attacker injects shell commands executed with the server\'s privileges.'),
    'CWE-22':  ('Path Traversal', 'Attacker reads or writes arbitrary files outside intended directory (e.g. ../../etc/passwd).'),
    'CWE-326': ('Inadequate Encryption Strength', 'Weak cipher broken by brute-force or known attacks, exposing plaintext.'),
    'CWE-327': ('Use of Broken Cryptographic Algorithm', 'Deprecated algorithm (MD5/SHA1/DES) provides no meaningful protection.'),
    'CWE-312': ('Cleartext Storage of Sensitive Information', 'Credentials/keys visible in logs, files, or stdout — readable by anyone with access.'),
    'CWE-798': ('Use of Hard-coded Credentials', 'Backdoor credentials ship with every deployment — trivially exploited.'),
    'CWE-502': ('Deserialization of Untrusted Data', 'Attacker crafts malicious payload deserialized into arbitrary code execution.'),
    'CWE-918': ('Server-Side Request Forgery (SSRF)', 'Server fetches attacker-controlled URLs, exposing internal services and cloud metadata.'),
    'CWE-457': ('Use of Uninitialized Variable', 'Indeterminate stack value used in logic — unpredictable behavior, potential info leak.'),
    'CWE-476': ('NULL Pointer Dereference', 'Crash or exploitable condition when pointer assumed non-null is actually null.'),
    'CWE-190': ('Integer Overflow or Wraparound', 'Arithmetic overflow produces wrong size, leading to buffer allocation smaller than needed.'),
    'CWE-295': ('Improper Certificate Validation', 'TLS cert not verified — trivial man-in-the-middle attack on encrypted channel.'),
    'CWE-330': ('Use of Insufficiently Random Values', 'Predictable tokens enable session hijacking, CSRF bypass, or collision attacks.'),
}


def _build_deep_report(code: str, vulnerabilities: list, language: str, risk_level: str, confidence: float) -> str:
    """Build a self-contained security report from Kyber engine output. No external API."""
    import json as _json

    lines = []

    lines.append(f"## KYBER ENGINE — DEEP ANALYSIS REPORT\n")
    lines.append(f"**Language**: {language.upper()}  |  **Risk**: {risk_level}  |  **Confidence**: {round(confidence)}%\n")
    lines.append("---\n")

    if not vulnerabilities:
        lines.append("## No Vulnerabilities Detected\n")
        lines.append("Kyber pattern engine found no known vulnerability signatures in this code.\n")
        lines.append("This does not guarantee the code is secure — logic flaws and business-layer issues require manual review.\n")
        return '\n'.join(lines)

    # Group by severity
    sev_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
    sorted_vulns = sorted(vulnerabilities, key=lambda v: sev_order.get(v.get('severity', 'LOW'), 3))

    lines.append(f"## Vulnerabilities Found — {len(vulnerabilities)} Issue{'s' if len(vulnerabilities) != 1 else ''}\n")

    seen_patterns: set = set()
    unique_vulns = []
    for v in sorted_vulns:
        key = (v.get('pattern', ''), v.get('line', 0))
        if key not in seen_patterns:
            seen_patterns.add(key)
            unique_vulns.append(v)

    for i, v in enumerate(unique_vulns, 1):
        sev     = v.get('severity', 'MEDIUM')
        cwe     = v.get('cwe', '')
        pat     = v.get('pattern', 'unknown pattern')
        desc    = v.get('description', v.get('message', ''))
        fix     = v.get('fix_hint', '')
        lnum    = v.get('line', '?')
        cat     = v.get('category', 'Security Issue')
        snippet = v.get('snippet', '').strip()

        cwe_name, cwe_impact = _CWE_INFO.get(cwe, ('', ''))
        cwe_tag = f" ({cwe})" if cwe else ''
        cwe_name_str = f" — {cwe_name}" if cwe_name else ''

        lines.append(f"### {i}. {cat}{cwe_tag}{cwe_name_str} — {sev}  Line {lnum}\n")
        lines.append(f"Pattern: `{pat}`\n")
        if desc:
            lines.append(f"{desc}\n")
        if cwe_impact:
            lines.append(f"**Impact**: {cwe_impact}\n")
        # Inline before/after fix guidance
        if snippet or fix:
            vulnerable_line = snippet if snippet else pat
            lines.append(f"```\n▸ Vulnerable:  {vulnerable_line}\n```\n")
        if fix:
            lines.append(f"```\n▸ Fix:         {fix}\n```\n")
        lines.append("")

    # Attack scenarios derived from CWEs found
    cwes_found = {v.get('cwe', '') for v in unique_vulns if v.get('cwe')}
    if cwes_found:
        lines.append("---\n")
        lines.append("## Attack Scenarios\n")
        for cwe in sorted(cwes_found):
            _, impact = _CWE_INFO.get(cwe, ('', ''))
            if impact:
                lines.append(f"- **{cwe}**: {impact}\n")

    lines.append("---\n")
    lines.append("## Recommendations\n")
    lines.append("1. Fix all CRITICAL and HIGH findings before any deployment.\n")
    lines.append("2. Run Kyber re-scan after applying fixes to verify resolution.\n")
    if language in ('c', 'cpp'):
        lines.append("3. Compile with `-fstack-protector-strong -D_FORTIFY_SOURCE=2 -Wformat-security`.\n")
        lines.append("4. Consider static analysis tools: `cppcheck`, `clang-tidy`, `AddressSanitizer`.\n")
    elif language == 'python':
        lines.append("3. Use parameterized queries (never string-format SQL).\n")
        lines.append("4. Run `bandit -r .` for additional Python-specific checks.\n")
    elif language in ('javascript', 'typescript'):
        lines.append("3. Sanitize all user input before rendering to DOM.\n")
        lines.append("4. Use `npm audit` and `eslint-plugin-security`.\n")

    return '\n'.join(lines)


@app.route('/deep-scan', methods=['POST'])
@token_required(optional=True)
@rate_limit(max_requests=5, window_seconds=60)
def deep_scan(current_user):
    """Kyber deep scan — self-contained security report, no external AI."""
    import json as json_mod

    data = request.get_json(silent=True) or {}
    code = data.get('code', '')
    scan_result = data.get('scan_result', {})

    if not code:
        return jsonify({'error': 'No code provided'}), 400
    if not isinstance(code, str):
        code = str(code)
    if len(code) > 50000:
        return jsonify({'error': 'Code too large for deep scan (50k limit)'}), 400

    risk_level  = scan_result.get('risk_level', 'UNKNOWN') if isinstance(scan_result, dict) else 'UNKNOWN'
    confidence  = float(scan_result.get('confidence', 50))  if isinstance(scan_result, dict) else 50.0
    language    = scan_result.get('language', '')            if isinstance(scan_result, dict) else ''
    vulnerabilities = data.get('vulnerabilities', [])

    # Re-run pattern scan if caller didn't pass vulnerabilities
    if not vulnerabilities:
        try:
            detected_language = language or _detect_language(code)
            clean = strip_comments(code)
            active_kw = {p for p in BUZZ_WORDS if p not in LANGUAGE_FILTER or detected_language in LANGUAGE_FILTER[p]}
            triggered = [k for k in active_kw if k in clean]
            for kw in triggered:
                desc  = BUZZ_WORDS.get(kw, 'Suspicious pattern')
                sev   = SEVERITY_LOOKUP.get(kw, 'MEDIUM')
                cwe   = CWE_LOOKUP.get(kw, '')
                ln    = next((i+1 for i, l in enumerate(code.splitlines()) if kw in l), 1)
                vulnerabilities.append({
                    'line': ln, 'pattern': kw, 'severity': sev,
                    'description': desc, 'cwe': cwe,
                    'category': 'Security Issue',
                    'fix_hint': f'Remove or replace `{kw}` with a safe alternative.',
                })
            language = detected_language
        except Exception:
            pass

    report = _build_deep_report(code, vulnerabilities, language or 'unknown', risk_level, confidence)

    def generate():
        yield ": heartbeat\n\n"
        for line in report.split('\n'):
            safe = json_mod.dumps(line + '\n')[1:-1]
            yield f'data: {{"type": "token", "content": "{safe}"}}\n\n'
        yield "data: [STREAM_END]\n\n"

    response = app.response_class(generate(), mimetype='text/event-stream')
    response.headers['Cache-Control'] = 'no-cache'
    response.headers['X-Accel-Buffering'] = 'no'
    return response


@app.route('/batch-scan', methods=['POST'])
@token_required(optional=False)
@rate_limit(max_requests=10, window_seconds=60)
def batch_scan(current_user):
    """Scan multiple files at once."""
    data = request.get_json(silent=True) or {}
    files = data.get('files', [])

    result = process_files_batch(files, user_id=current_user.get('user_id'))
    if isinstance(result, tuple):
        return jsonify(result[0]), result[1]
    return jsonify(result), 200

@app.route('/automation/run-improver', methods=['POST'])
@rate_limit(max_requests=6, window_seconds=60)
def run_improver():
    """
    Secure webhook endpoint for Make to enqueue improvement tasks.
    Cursor reads and executes the queue — no LLM calls here.
    Guardrails: shared-secret auth, idempotency, structured response.
    """
    configured_secret = os.environ.get('MAKE_WEBHOOK_SECRET')
    provided_secret = request.headers.get('X-Automation-Secret', '')
    if not configured_secret:
        return jsonify({
            'status': 'error',
            'error_code': 'automation_secret_not_configured',
            'message': 'MAKE_WEBHOOK_SECRET is not configured on the server.'
        }), 503

    if not provided_secret or not hmac.compare_digest(provided_secret, configured_secret):
        return jsonify({
            'status': 'error',
            'error_code': 'unauthorized',
            'message': 'Invalid automation secret.'
        }), 401

    idempotency_key = (request.headers.get('Idempotency-Key') or '').strip()
    if not idempotency_key:
        return jsonify({
            'status': 'error',
            'error_code': 'missing_idempotency_key',
            'message': 'Idempotency-Key header is required.'
        }), 400

    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({
            'status': 'error',
            'error_code': 'invalid_json',
            'message': 'Request body must be valid JSON object.'
        }), 400

    mode = payload.get('mode')
    if mode != 'draft_only':
        return jsonify({
            'status': 'error',
            'error_code': 'invalid_mode',
            'message': "Only mode='draft_only' is allowed."
        }), 400

    now_ts = time.time()
    with AUTOMATION_LOCK:
        _cleanup_automation_runs(now_ts)
        existing = AUTOMATION_RUNS.get(idempotency_key)
        if existing:
            cached = dict(existing.get('response', {}))
            cached['duplicate'] = True
            cached['idempotency_key'] = idempotency_key
            return jsonify(cached), 200

    try:
        sys.path.insert(0, str(ROOT))
        from auto_improver import add_task, queue_summary

        task = add_task(
            task_type=payload.get('task_type', 'incremental_improvement'),
            scope=payload.get('scope'),
            quality_gates=payload.get('quality_gates'),
            metadata=payload.get('metadata'),
            instruction=_extract_instruction(payload)
        )
        summary = queue_summary()

        response_payload = {
            'status': 'success',
            'task_id': task['id'],
            'idempotency_key': idempotency_key,
            'mode': mode,
            'message': 'Task enqueued. Cursor will execute on next check-in.',
            'queue_summary': summary
        }
        http_status = 200
    except ValueError as e:
        app.logger.warning("Queue operation rejected: %s", str(e))
        response_payload = {
            'status': 'error',
            'error_code': 'queue_full',
            'message': 'Task queue is full or request was rejected. Please try again later.',
            'idempotency_key': idempotency_key
        }
        http_status = 429
    except Exception as e:
        app.logger.error("Enqueue failed: %s", str(e), exc_info=True)
        response_payload = {
            'status': 'error',
            'error_code': 'enqueue_failed',
            'message': 'Internal server error',
            'idempotency_key': idempotency_key
        }
        http_status = 500

    with AUTOMATION_LOCK:
        AUTOMATION_RUNS[idempotency_key] = {
            'status': 'completed',
            'created_at': now_ts,
            'response': response_payload
        }

    return jsonify(response_payload), http_status


def _automation_error(endpoint, error_code, message, status_code=500):
    """Build a JSON error response with email_html for automation endpoints."""
    # Log full details server-side; never expose raw exception strings in HTTP responses
    app.logger.error("Automation error [%s] %s: %s", endpoint, error_code, message)
    response_message = 'Internal server error' if status_code >= 500 else 'Automation request failed.'
    sys.path.insert(0, str(ROOT))
    try:
        from email_builder import error_email
        # Use response_message (never raw exception string) so html field is clean
        html = error_email(endpoint, error_code, response_message, status_code)
    except Exception:
        html = (f"<p>Error on {_html.escape(str(endpoint))}: "
                f"{_html.escape(str(error_code))}</p>")
    return jsonify({
        'status': 'error',
        'error_code': error_code,
        'notification_summary': f'{_html.escape(str(endpoint))} error: {_html.escape(str(error_code))}',
        'message': response_message,
        'email_html': html
    }), status_code


def _is_safe_external_url(url: str) -> bool:
    """Return False if url resolves to an RFC1918/loopback/link-local address."""
    import ipaddress
    import socket
    from urllib.parse import urlparse
    try:
        host = urlparse(url).hostname
        if not host:
            return False
        # Always resolve to IP — mitigates DNS rebinding
        try:
            resolved = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
            for r in resolved:
                addr = ipaddress.ip_address(r[4][0])
                if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved:
                    return False
            return True
        except socket.gaierror:
            # Can't resolve — reject
            return False
    except Exception:
        return False


def _require_automation_secret():
    """Shared auth check for automation endpoints. Returns error tuple or None."""
    configured_secret = os.environ.get('MAKE_WEBHOOK_SECRET')
    provided_secret = (request.headers.get('X-Automation-Secret')
                       or request.args.get('secret', ''))
    if not configured_secret:
        return jsonify({
            'status': 'error',
            'error_code': 'automation_secret_not_configured',
            'message': 'MAKE_WEBHOOK_SECRET is not configured on the server.'
        }), 503
    if not provided_secret or not hmac.compare_digest(provided_secret, configured_secret):
        return jsonify({
            'status': 'error',
            'error_code': 'unauthorized',
            'message': 'Invalid automation secret.'
        }), 401
    return None


@app.route('/automation/webhook/render-deploy', methods=['POST'])
@rate_limit(max_requests=10, window_seconds=60)
def render_deploy_webhook():
    """
    Reactive Healing Loop entry point.
    Render POSTs here on deploy failure. Circuit breaker prevents loops.
    """
    auth_error = _require_automation_secret()
    if auth_error:
        return auth_error

    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({'status': 'error', 'error_code': 'invalid_json',
                        'notification_summary': 'Render webhook rejected — invalid JSON payload',
                        'message': 'Request body must be valid JSON.'}), 400

    try:
        sys.path.insert(0, str(ROOT))
        from automation_agent import handle_render_failure
        result = handle_render_failure(payload)
        status_code = 200 if result.get('status') != 'circuit_breaker_open' else 429
        return jsonify(result), status_code
    except Exception as e:
        return _automation_error('/automation/webhook/render-deploy', 'healing_failed', str(e))


@app.route('/automation/improve', methods=['GET', 'POST'])
@rate_limit(max_requests=6, window_seconds=60)
def proactive_improve():
    """
    Proactive Improvement Loop entry point.
    Triggered by Make cron or manual GET. Reads ROADMAP.md and enqueues
    the next highest-priority task for Cursor.
    """
    auth_error = _require_automation_secret()
    if auth_error:
        return auth_error

    try:
        sys.path.insert(0, str(ROOT))
        from automation_agent import handle_proactive_improvement
        result = handle_proactive_improvement()
        return jsonify(result), 200
    except Exception as e:
        return _automation_error('/automation/improve', 'improve_failed', str(e))


@app.route('/automation/status', methods=['GET'])
@rate_limit(max_requests=20, window_seconds=60)
def automation_status():
    """Diagnostics: queue summary + circuit breaker state."""
    auth_error = _require_automation_secret()
    if auth_error:
        return auth_error

    try:
        sys.path.insert(0, str(ROOT))
        from auto_improver import queue_summary
        from automation_agent import circuit_breaker
        qs = queue_summary()
        cb = circuit_breaker.status()
        blocked_count = sum(1 for v in cb.values() if v.get("blocked"))
        return jsonify({
            'notification_summary': (
                f"Queue: {qs.get('pending', 0)} pending, {qs.get('in_progress', 0)} in progress, "
                f"{qs.get('completed', 0)} completed | "
                f"Circuit breaker: {blocked_count} blocked error(s)"
            ),
            'queue': qs,
            'circuit_breaker': cb
        }), 200
    except Exception as e:
        return _automation_error('/automation/status', 'status_failed', str(e))


@app.route('/automation/digest', methods=['GET'])
@rate_limit(max_requests=10, window_seconds=60)
def daily_digest():
    """
    Daily Security Digest — morning briefing with health score, queue state,
    scan stats (24h), roadmap progress, and circuit breaker status.
    """
    auth_error = _require_automation_secret()
    if auth_error:
        return auth_error

    try:
        sys.path.insert(0, str(ROOT))
        from automation_agent import generate_daily_digest
        result = generate_daily_digest()
        return jsonify(result), 200
    except Exception as e:
        return _automation_error('/automation/digest', 'digest_failed', str(e))


@app.route('/automation/webhook/github-push', methods=['POST'])
@rate_limit(max_requests=30, window_seconds=60)
def github_push_webhook():
    """
    Scan-on-Push — receives a GitHub push webhook, extracts changed files,
    fetches their content, runs security scans, and returns results.
    """
    auth_error = _require_automation_secret()
    if auth_error:
        return auth_error

    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({'status': 'error', 'error_code': 'invalid_json',
                        'notification_summary': 'GitHub push webhook rejected — invalid JSON',
                        'message': 'Request body must be valid JSON.'}), 400

    try:
        sys.path.insert(0, str(ROOT))
        from automation_agent import extract_push_files
        file_info = extract_push_files(payload)

        if not file_info.get("files"):
            return jsonify(file_info), 200

        import urllib.request
        from urllib.parse import urlparse as _urlparse
        scan_results = []
        threats_found = 0
        batch_files = []

        for entry in file_info["files"][:20]:
            raw_url = entry.get("raw_url", "")
            _parsed = _urlparse(raw_url)
            if _parsed.scheme != "https" or _parsed.netloc != "raw.githubusercontent.com":
                scan_results.append({"file": entry.get("path", "?"), "status": "skipped",
                                     "reason": "Disallowed raw_url host"})
                continue
            try:
                req_obj = urllib.request.Request(raw_url, headers={"User-Agent": "Soteria/1.0"})
                with urllib.request.urlopen(req_obj, timeout=10) as resp:
                    code = resp.read().decode("utf-8", errors="replace")
                if len(code) > 50000:
                    scan_results.append({"file": entry["path"], "status": "skipped",
                                         "reason": "File too large (>50KB)"})
                    continue
                batch_files.append({"filename": entry["path"], "code": code})
            except Exception as fetch_err:
                app.logger.warning("File fetch error for %s: %s", entry.get("path"), str(fetch_err))
                scan_results.append({"file": entry.get("path", "?"), "status": "error",
                                     "reason": "Failed to fetch file content"})

        if batch_files:
            batch_result = process_files_batch(batch_files)
            batch_data = batch_result[0] if isinstance(batch_result, tuple) else batch_result
            for r in batch_data.get("results", []):
                is_threat = r.get("status") == "malicious"
                if is_threat:
                    threats_found += 1
                scan_results.append({
                    "file": r.get("filename", ""),
                    "status": "scanned",
                    "risk_level": r.get("risk_level", "UNKNOWN"),
                    "confidence": r.get("confidence", 0),
                    "malicious": is_threat,
                    "reason": r.get("message", ""),
                    "language": r.get("language", "unknown"),
                    "vulnerabilities": r.get("vulnerabilities", []),
                })

        total_scanned = sum(1 for r in scan_results if r.get("status") == "scanned")
        high_risk = sum(1 for r in scan_results
                        if r.get("risk_level") in ("HIGH", "CRITICAL"))

        threat_label = f"{threats_found} THREAT(S)" if threats_found else "clean"
        file_info["scan_results"] = scan_results
        file_info["scan_summary"] = {
            "total_scanned": total_scanned,
            "threats_found": threats_found,
            "high_risk": high_risk,
            "skipped": sum(1 for r in scan_results if r.get("status") == "skipped"),
            "errors": sum(1 for r in scan_results if r.get("status") == "error"),
        }
        file_info["notification_summary"] = (
            f"Push to {file_info['repo']}/{file_info['branch']} by {file_info['pusher']} — "
            f"{total_scanned} file(s) scanned, {threat_label}"
            + (f", {high_risk} HIGH/CRITICAL" if high_risk else "")
        )
        file_info["status"] = "scan_complete"

        status_code = 200 if threats_found == 0 else 200
        return jsonify(file_info), status_code

    except Exception as e:
        return _automation_error('/automation/webhook/github-push', 'push_scan_failed', str(e))


# ── SELF-IMPROVING ML ENDPOINTS ──────────────────────────────────────────────

@app.route('/feedback', methods=['POST'])
@token_required(optional=False)
@rate_limit(max_requests=10, window_seconds=60)
def submit_feedback(current_user):
    """
    Users submit feedback on scan results (false positive, false negative, correct).
    Requires auth to prevent training data poisoning.
    """
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({'status': 'error', 'message': 'JSON body required.'}), 400

    try:
        sys.path.insert(0, str(ROOT))
        from ml_feedback import record_feedback
        result = record_feedback(
            scan_id=data.get("scan_id"),
            code_hash=data.get("code_hash"),
            original_verdict=data.get("original_verdict", ""),
            user_verdict=data.get("user_verdict", ""),
            feedback_type=data.get("feedback_type", ""),
            comment=data.get("comment", "")
        )
        return jsonify(result), 201
    except ValueError as e:
        app.logger.warning("Feedback validation error: %s", str(e))
        return jsonify({'status': 'error', 'message': 'Invalid feedback data. Check required fields.'}), 400
    except Exception as e:
        app.logger.error("Feedback error: %s", str(e), exc_info=True)
        return jsonify({'status': 'error', 'message': 'Internal server error'}), 500


@app.route('/automation/ml-health', methods=['GET'])
@rate_limit(max_requests=10, window_seconds=60)
def ml_health():
    """
    ML model health check. If accuracy drops below threshold, auto-triggers retrain.
    Called by Make cron (e.g. daily).
    """
    auth_error = _require_automation_secret()
    if auth_error:
        return auth_error

    try:
        sys.path.insert(0, str(ROOT))
        from ml_feedback import ml_health_check
        result = ml_health_check()
        return jsonify(result), 200
    except Exception as e:
        return _automation_error('/automation/ml-health', 'ml_health_failed', str(e))


@app.route('/automation/ml-retrain', methods=['POST'])
@rate_limit(max_requests=2, window_seconds=3600)
def ml_retrain():
    """Force a model retrain. Rate-limited to 2/hour."""
    auth_error = _require_automation_secret()
    if auth_error:
        return auth_error

    try:
        sys.path.insert(0, str(ROOT))
        from ml_feedback import trigger_retrain
        reason = (request.get_json(silent=True) or {}).get("reason", "manual_trigger")
        result = trigger_retrain(reason=reason)
        status_code = 200 if result["status"] == "retrain_success" else 500
        return jsonify(result), status_code
    except Exception as e:
        return _automation_error('/automation/ml-retrain', 'retrain_failed', str(e))


# ── LEAD GENERATION ENDPOINTS ────────────────────────────────────────────────

@app.route('/automation/lead-scan', methods=['POST'])
@rate_limit(max_requests=5, window_seconds=3600)
def lead_scan():
    """
    Scan GitHub for repos with vulnerabilities and generate leads.
    Rate-limited to 5/hour to respect GitHub API limits.
    """
    auth_error = _require_automation_secret()
    if auth_error:
        return auth_error

    try:
        sys.path.insert(0, str(ROOT))
        from lead_generator import scan_for_leads
        payload = request.get_json(silent=True) or {}
        query_index = payload.get("query_index")
        result = scan_for_leads(query_index=query_index)
        return jsonify(result), 200
    except Exception as e:
        return _automation_error('/automation/lead-scan', 'lead_scan_failed', str(e))


@app.route('/automation/leads', methods=['GET'])
@rate_limit(max_requests=20, window_seconds=60)
def leads_pipeline():
    """Get lead pipeline summary and top leads ready for outreach."""
    auth_error = _require_automation_secret()
    if auth_error:
        return auth_error

    try:
        sys.path.insert(0, str(ROOT))
        from lead_generator import get_lead_pipeline_status
        result = get_lead_pipeline_status()
        return jsonify(result), 200
    except Exception as e:
        return _automation_error('/automation/leads', 'leads_failed', str(e))


# ── GTM INTELLIGENCE ENDPOINT ────────────────────────────────────────────────

@app.route('/automation/gtm-intel', methods=['GET'])
@rate_limit(max_requests=5, window_seconds=3600)
def gtm_intelligence():
    """
    Go-To-Market intelligence report. Discovers communities, monitors competitors,
    scans trends, and generates prioritized actions.
    """
    auth_error = _require_automation_secret()
    if auth_error:
        return auth_error

    try:
        sys.path.insert(0, str(ROOT))
        from gtm_engine import run_gtm_intel
        result = run_gtm_intel()
        return jsonify(result), 200
    except Exception as e:
        return _automation_error('/automation/gtm-intel', 'gtm_failed', str(e))


import tempfile
import subprocess
import os

def process_files_batch(files, user_id=None):
    if not files:
        return {'error': 'No files provided'}, 400
    
    if len(files) > 50:
        return {'error': 'Maximum 50 files per batch scan'}, 400
    
    results = []
    total_threats = 0
    risk_weights = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 0}
    total_risk_score = 0
    
    for file_item in files:
        if not isinstance(file_item, dict):
            continue
            
        filename = _html.escape(str(file_item.get('filename', 'unknown'))[:255])
        code = file_item.get('code', '')
        
        if not isinstance(code, str):
            code = str(code)
            
        if not code or len(code) > 50000:
            results.append({
                'filename': filename,
                'status': 'error',
                'message': 'Empty or too large (50k limit)',
                'risk_level': 'INVALID',
                'confidence': 0,
                'language': 'unknown'
            })
            continue
        
        try:
            # Detect language and extract features
            result = structuralDNAExtraction(code)
            
            if isinstance(result, tuple):
                featuresDf, detected_language = result
            else:
                featuresDf = result
                detected_language = 'python'
            
            _parse_failed_b = False
            if isinstance(featuresDf, str) and featuresDf == "SYNTAX_ERROR":
                _parse_failed_b = True
                if modelFeatures is not None:
                    featuresDf = pd.DataFrame([{col: 0 for col in modelFeatures}])
                else:
                    featuresDf = pd.DataFrame([{}])

            if featuresDf is None:
                results.append({
                    'filename': filename,
                    'status': 'error',
                    'message': 'Analysis failed',
                    'risk_level': 'INVALID',
                    'confidence': 0,
                    'language': detected_language
                })
                continue

            load_model_if_updated()

            # Keyword check (language-aware) — use comment-stripped code to match /analyze behavior
            clean_code_b = strip_comments(code)
            _active_kw_b = {
                p for p in BUZZ_WORDS
                if p not in LANGUAGE_FILTER or detected_language in LANGUAGE_FILTER[p]
            }
            triggerKeywords = [k for k in _active_kw_b if k in clean_code_b]
            
            # ML prediction
            maliciousProb = 0.5 if triggerKeywords else 0.1
            confidence = 50.0

            try:
                if model is not None and hasattr(model, 'predict_proba'):
                    probability = model.predict_proba(featuresDf)[0]
                    maliciousProb = probability[1]
                    confidence = round(max(probability) * 100, 1)
            except Exception as e:
                print(f"Batch model prediction failed: {e}")
            
            # Risk classification
            highest_keyword_severity = "LOW"
            critical_or_high_keyword = None
            if triggerKeywords:
                severity_ranks = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
                for kw in triggerKeywords:
                    sev = SEVERITY_LOOKUP.get(kw, "MEDIUM")
                    if severity_ranks.get(sev, 0) > severity_ranks.get(highest_keyword_severity, 0):
                        highest_keyword_severity = sev
                        critical_or_high_keyword = kw

            if critical_or_high_keyword and highest_keyword_severity in ["CRITICAL", "HIGH"]:
                verdict = True
                riskLabel = highest_keyword_severity
                message = f"Immediate threat: {BUZZ_WORDS.get(critical_or_high_keyword, 'Suspicious pattern')}"
            elif maliciousProb > 0.85:
                verdict = True
                riskLabel = "HIGH"
                message = f"Critical structural anomaly: {round(maliciousProb * 100)}% confidence"
            elif maliciousProb > 0.40 or highest_keyword_severity == "MEDIUM":
                verdict = False
                riskLabel = "MEDIUM"
                message = "Suspicious patterns noted"
            else:
                verdict = False
                riskLabel = "LOW"
                message = "Standard safety profile"
            
            if verdict:
                total_threats += 1
            total_risk_score += risk_weights.get(riskLabel, 0)
            
            results.append({
                'filename': filename,
                'status': 'malicious' if verdict else 'clean',
                'message': message,
                'risk_level': riskLabel,
                'confidence': confidence,
                'language': detected_language,
                'nodes_scanned': len(featuresDf.columns),
                'parse_warning': 'AST parse failed — pattern scan ran normally' if _parse_failed_b else None,
            })
            
            # Save to scan history + training data
            save_scan_result(
                language=detected_language,
                risk_level=riskLabel,
                confidence=confidence,
                malicious=verdict,
                code=code,
                nodes_scanned=len(featuresDf.columns),
                reason=message
            )
            _save_training_sample(
                code=code, language=detected_language,
                is_malicious=verdict, risk_level=riskLabel,
                vuln_count=len([k for k in BUZZ_WORDS if k in code]),
                confidence=confidence, source='batch',
                user_id=user_id,
            )
            
        except Exception as e:
            app.logger.error("Batch scan error for %s: %s", filename, str(e), exc_info=True)
            results.append({
                'filename': filename,
                'status': 'error',
                'message': 'Error processing file',
                'risk_level': 'INVALID',
                'confidence': 0,
                'language': 'unknown'
            })
    
    # Calculate project risk score
    max_possible = len(files) * 4
    project_score = max(0, round(100 - (total_risk_score / max(max_possible, 1)) * 100))
    
    if project_score >= 90: project_grade = 'A'
    elif project_score >= 80: project_grade = 'B'
    elif project_score >= 70: project_grade = 'C'
    elif project_score >= 60: project_grade = 'D'
    else: project_grade = 'F'
    
    return {
        'results': results,
        'summary': {
            'total_files': len(files),
            'threats': total_threats,
            'clean': len(files) - total_threats,
            'project_score': project_score,
            'project_grade': project_grade
        }
    }

GITHUB_CLIENT_ID = os.environ.get("GITHUB_CLIENT_ID")
GITHUB_CLIENT_SECRET = os.environ.get("GITHUB_CLIENT_SECRET")

if not GITHUB_CLIENT_ID or not GITHUB_CLIENT_SECRET:
    print("⚠️ WARNING: GITHUB_CLIENT_ID or GITHUB_CLIENT_SECRET not set. GitHub OAuth login will be disabled.")

@app.route('/github/pkce/state', methods=['POST'])
@rate_limit(max_requests=10, window_seconds=60)
def github_pkce_state():
    """Issue a signed state JWT containing the PKCE code_challenge."""
    if not GITHUB_CLIENT_ID or not GITHUB_CLIENT_SECRET:
        return jsonify({'error': 'GitHub OAuth not configured.'}), 501

    data = request.get_json(silent=True) or {}
    code_challenge = data.get('code_challenge', '')
    # S256 code_challenge is base64url(sha256), always 43 chars without padding
    if not isinstance(code_challenge, str) or len(code_challenge) < 43:
        return jsonify({'error': 'Invalid code_challenge'}), 400

    state_payload = {
        'jti': uuid.uuid4().hex,
        'code_challenge': code_challenge,
        'exp': int(time.time()) + 300,  # 5-minute TTL
    }
    state_token = pyjwt.encode(state_payload, JWT_SECRET, algorithm='HS256')
    return jsonify({'state': state_token})


@app.route('/github/token', methods=['POST'])
@rate_limit(max_requests=10, window_seconds=300)
def github_token():
    data = request.get_json(silent=True) or {}
    code          = data.get('code')
    state         = data.get('state')
    code_verifier = data.get('code_verifier')

    if not code:
        return jsonify({'error': 'No code provided'}), 400

    # PKCE + state are unconditionally required — no fallback path without them
    if not state or not code_verifier:
        return jsonify({'error': 'state and code_verifier are required'}), 400

    try:
        state_payload = pyjwt.decode(state, JWT_SECRET, algorithms=['HS256'])
    except pyjwt.ExpiredSignatureError:
        return jsonify({'error': 'OAuth state expired. Please restart the login flow.'}), 400
    except pyjwt.InvalidTokenError:
        return jsonify({'error': 'Invalid OAuth state.'}), 400

    import hashlib, base64
    computed = base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode()).digest()
    ).rstrip(b'=').decode()
    expected = state_payload.get('code_challenge', '')
    # Constant-time compare to prevent timing attacks
    if not hmac.compare_digest(computed, expected):
        return jsonify({'error': 'PKCE verification failed.'}), 400

    if not GITHUB_CLIENT_ID or not GITHUB_CLIENT_SECRET:
        return jsonify({'error': 'GitHub OAuth login is not configured.'}), 501

    resp = requests.post(
        'https://github.com/login/oauth/access_token',
        json={
            'client_id': GITHUB_CLIENT_ID,
            'client_secret': GITHUB_CLIENT_SECRET,
            'code': code,
        },
        headers={'Accept': 'application/json'},
        timeout=30,
    )
    return jsonify(resp.json()), resp.status_code

@app.route('/github/repos', methods=['GET'])
@rate_limit(max_requests=30, window_seconds=60)
def github_repos():
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        return jsonify({'error': 'No token provided'}), 401
        
    resp = requests.get('https://api.github.com/user/repos', headers={
        'Authorization': auth_header,
        'Accept': 'application/vnd.github.v3+json'
    }, params={'sort': 'updated', 'per_page': 100}, timeout=30)
    
    return jsonify(resp.json()), resp.status_code


@app.route('/github-scan', methods=['POST'])
@token_required(optional=False)
@rate_limit(max_requests=5, window_seconds=300)
def github_scan(current_user):
    """Clone a GitHub repository and scan it."""
    data = request.get_json(silent=True) or {}
    repo_url = data.get('repo_url')
    access_token = data.get('access_token')
    
    if not repo_url or not repo_url.startswith('https://github.com/'):
        return jsonify({'error': 'Invalid or missing GitHub URL'}), 400
        
    # Strict allowlist for access_token: alphanumeric + underscore, 20-255 chars
    _TOKEN_RE = re.compile(r'^[A-Za-z0-9_\-]{20,255}$')
    if access_token and not _TOKEN_RE.match(access_token):
        return jsonify({'error': 'Invalid access_token format'}), 400

    clone_url = repo_url
    if access_token:
        # Use GIT_ASKPASS env var instead of embedding token in URL to avoid
        # token appearing in git logs, ps output, or server access logs
        pass  # clone_url stays as repo_url; token injected via env below
        
    code_extensions = [
        '.py', '.js', '.ts', '.tsx', '.jsx', '.java', '.c', '.cpp', '.h', '.hpp',
        '.cs', '.go', '.rb', '.php', '.rs', '.swift', '.kt', '.scala', '.sh',
        '.sql', '.html', '.css', '.vue', '.svelte'
    ]
    
    files_data = []
    
    with tempfile.TemporaryDirectory() as temp_dir:
        try:
            # Shallow clone — pass token via env GIT_ASKPASS to avoid URL embedding
            clone_env = os.environ.copy()
            if access_token:
                # Write a minimal askpass script that outputs the token
                askpass_script = os.path.join(temp_dir, '_askpass.sh')
                with open(askpass_script, 'w') as _f:
                    _f.write(f'#!/bin/sh\necho "{access_token}"\n')
                os.chmod(askpass_script, 0o700)
                clone_env['GIT_ASKPASS'] = askpass_script
                clone_env['GIT_TERMINAL_PROMPT'] = '0'
            subprocess.run(
                ['git', 'clone', '--depth', '1', clone_url, temp_dir],
                check=True, capture_output=True, env=clone_env
            )
            
            for root, dirs, files in os.walk(temp_dir):
                if '.git' in dirs:
                    dirs.remove('.git')
                for file in files:
                    ext = os.path.splitext(file)[1].lower()
                    if ext in code_extensions:
                        filepath = os.path.join(root, file)
                        # Size limit 50KB to keep it safe
                        if os.path.getsize(filepath) < 50000:
                            try:
                                with open(filepath, 'r', encoding='utf-8') as f:
                                    content = f.read()
                                rel_path = os.path.relpath(filepath, temp_dir)
                                files_data.append({'filename': rel_path, 'code': content})
                                if len(files_data) >= 50:
                                    break
                            except Exception:
                                pass
                if len(files_data) >= 50:
                    break
        except Exception as e:
            app.logger.error(f'git clone failed: {e}')
            return jsonify({'error': 'Failed to clone repository'}), 500
            
    batch_result = process_files_batch(files_data)
    result, status = batch_result if isinstance(batch_result, tuple) else (batch_result, 200)
    return jsonify(result), status


@app.route('/api/engines/status', methods=['GET'])
@token_required(optional=True)
def engines_status(current_user=None):
    """
    Return the live status of all Kyber detection engines.
    Checks file existence and importability without running inference.
    ---
    tags: [Engines]
    responses:
      200:
        description: Engine status map
    """
    import importlib, os

    def _check_engine(module_path: str, checkpoint: str = None) -> dict:
        status = {"loaded": False, "checkpoint": None, "error": None}
        try:
            importlib.import_module(module_path)
            status["loaded"] = True
        except Exception as e:
            app.logger.error("Engine load error for %s: %s", module_path, str(e))
            status["error"] = "Load failed"
        if checkpoint:
            cp = os.path.join(ROOT, checkpoint) if not os.path.isabs(checkpoint) else checkpoint
            status["checkpoint"] = os.path.exists(cp)
        return status

    engines = {
        "sklearn_ensemble": {
            "label": "Ensemble Classifier",
            "description": "Random forest + gradient boosting over 52 AST features",
            "checkpoint_exists": os.path.exists(ROOT / "backend" / "ML_master" / "acidModel.pkl"),
            **_check_engine("backend.src.trainerModel_AST"),
        },
        "gcn": {
            "label": "Graph Neural Net (GATConv)",
            "description": "Control-flow graph analysis for structural obfuscation",
            "checkpoint_exists": os.path.exists(ROOT / "backend" / "ML_master" / "acidModel_gcn.pt"),
            **_check_engine("backend.src.trainerModel_GCN"),
        },
        "entropy": {
            "label": "Entropy Scanner",
            "description": "Shannon entropy per string/bytes literal — flags shellcode/base64",
            **_check_engine("backend.src.entropy_profiler"),
        },
        "snn": {
            "label": "Spiking Neural Net (Kyber Engine 3)",
            "description": "Micro-temporal anomaly profiler over execution traces",
            "checkpoint_exists": os.path.exists(ROOT / "engines" / "kyber" / "snn" / "snn_baseline.pt"),
            **_check_engine("engines.kyber.snn.profiler"),
        },
        "deceptinet": {
            "label": "DeceptiNet (Engine #10)",
            "description": "Hypergame-theoretic DRL honeypot orchestrator",
            **_check_engine("engines.deceptinet"),
        },
        "symbapt": {
            "label": "SymbAPT (Engine #11)",
            "description": "Differentiable MITRE ATT&CK rules + Kafka APT detection",
            **_check_engine("engines.symbapt"),
        },
        "rlshield": {
            "label": "RLShield (Engine #12)",
            "description": "MAPPO multi-agent SOC orchestrator + Wazuh",
            **_check_engine("engines.rlshield"),
        },
        "memshield": {
            "label": "MemShield (Engine #13)",
            "description": "Taint tracking + ROP chain + heap spray detection",
            **_check_engine("engines.memshield"),
        },
        "containerguard": {
            "label": "ContainerGuard (Engine #14)",
            "description": "eBPF syscall GNN — container escape detection",
            **_check_engine("engines.containerguard"),
        },
        "agentshield": {
            "label": "AgentShield (Engine #9)",
            "description": "DOM Merkle-hash TOCTOU mitigation for browser agents",
            **_check_engine("engines.agentshield"),
        },
    }

    n_loaded = sum(1 for e in engines.values() if e.get("loaded"))
    return jsonify({
        "engines": engines,
        "summary": {
            "total": len(engines),
            "loaded": n_loaded,
            "vulnerability_patterns": len(VULNERABILITY_PATTERNS),
        },
        "timestamp": time.time(),
    })


if __name__ == "__main__":
    print("Backend running at port 500")
    app.run(host='0.0.0.0', port=5001)
