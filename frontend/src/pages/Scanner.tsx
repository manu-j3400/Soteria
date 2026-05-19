import { useState, useEffect, useRef, useCallback } from 'react';
import { AnimatePresence, motion } from 'framer-motion';
import CodeEditor from '@/components/CodeEditor';
import { useGame } from '@/context/GameContext';
import { useAuth } from '@/context/AuthContext';
import { API_BASE_URL } from '@/lib/api';

// ── Supported extensions ────────────────────────────────────────────────────
const SUPPORTED_EXTENSIONS = [
  '.py','.pyx','.pxd',
  '.js','.jsx','.mjs','.cjs',
  '.ts','.tsx',
  '.go', '.rs', '.java',
  '.c','.cpp','.cc','.cxx','.h','.hpp',
  '.cs', '.php', '.rb',
  '.sh','.bash','.zsh',
  '.kt','.kts', '.swift', '.scala',
  '.r', '.lua', '.pl','.pm',
];
const ACCEPT_STRING = SUPPORTED_EXTENSIONS.join(',');

// ── Language detection ───────────────────────────────────────────────────────
const EXT_TO_MONACO: Record<string, string> = {
  '.py':'python','.pyx':'python','.pxd':'python',
  '.js':'javascript','.jsx':'javascript','.mjs':'javascript','.cjs':'javascript',
  '.ts':'typescript','.tsx':'typescript',
  '.go':'go', '.rs':'rust',
  '.java':'java',
  '.c':'c','.h':'c','.cpp':'cpp','.cc':'cpp','.cxx':'cpp','.hpp':'cpp',
  '.cs':'csharp', '.php':'php', '.rb':'ruby',
  '.sh':'shell','.bash':'shell','.zsh':'shell',
  '.kt':'kotlin','.kts':'kotlin', '.swift':'swift', '.scala':'scala',
  '.r':'r', '.lua':'lua', '.pl':'perl','.pm':'perl',
  '.sql':'sql','.html':'html','.css':'css',
  '.json':'json','.yaml':'yaml','.yml':'yaml','.xml':'xml','.md':'markdown',
};

const BACKEND_TO_MONACO: Record<string, string> = {
  python:'python', java:'java', javascript:'javascript', typescript:'typescript',
  c:'c', cpp:'cpp', 'c++':'cpp', c_sharp:'csharp', 'c#':'csharp', csharp:'csharp',
  go:'go', golang:'go', ruby:'ruby', php:'php', rust:'rust',
  kotlin:'kotlin', swift:'swift', scala:'scala', shell:'shell', bash:'shell',
  r:'r', lua:'lua', perl:'perl', sql:'sql',
};

const CODE_PATTERNS: Array<[RegExp, string]> = [
  [/^\s*package\s+\w+\s*\n.*import\s+"[\w/]+"/ms, 'go'],
  [/\bfn\s+\w+\s*\(.*\)\s*(->|{)|\blet\s+mut\b|\buse\s+std::/m, 'rust'],
  [/\bpub\s+(fn|struct|enum|impl)\b|\bprintln!\s*\(/m, 'rust'],
  [/\bfun\s+\w+\s*\(|\bval\s+\w+|\bdata\s+class\b|\bsuspend\s+fun\b/m, 'kotlin'],
  [/\bimport\s+(Foundation|UIKit|SwiftUI)\b|\bvar\s+body\s*:\s*some\s+View\b|@State\s+/m, 'swift'],
  [/\bpublic\s+(class|interface|enum)\s+\w+|\bSystem\.out\.println\b|\bimport\s+java\./m, 'java'],
  [/\bString\s+\w+\s*=|\bResultSet\b|\bPreparedStatement\b|\bexecuteQuery\b|\brequest\.getParameter\b|\bStatement\b.*\bexecute/m, 'java'],
  [/\busing\s+System;|\bnamespace\s+\w+|\bConsole\.Write(Line)?\s*\(/m, 'csharp'],
  [/\bfrom\s+\w+\s+import\b|\bdef\s+\w+\s*\(|\bself\.\w+|\belif\b|\b__\w+__\b/m, 'python'],
  [/\bconst\s+\w+\s*=\s*(require\s*\(|async\s*\()|\bexport\s+default\b|\bdocument\./m, 'javascript'],
  [/\binterface\s+\w+\s*{|\btype\s+\w+\s*=\s*\{|\bReadonly<|<T>\s*:\s*\w+/m, 'typescript'],
  [/\becho\s+["']|\bfunction\s+\w+\s*\(\)\s*{.*\$\w+|^\s*\$\w+=/ms, 'php'],
  [/\bdef\s+\w+|\bputs\s+|\battr_(accessor|reader)\b|\.each\s+do\s*\|/m, 'ruby'],
  [/^#!/m, 'shell'],
  [/\bchar\s+\w+\s*\[|\bstrcpy\s*\(|\bstrcat\s*\(|\bsprintf\s*\(|\bprintf\s*\(|\bmalloc\s*\(|\bNULL\b.*[;{]|\bchar\s*\*\w/m, 'c'],
  [/#include\s*<\w+\.h>|\bint\s+main\s*\(|\bstd::|\bcout\s*<</m, 'cpp'],
];

function detectEditorLang(backendLang: string | undefined, filename: string, code: string): string {
  if (backendLang) {
    const n = BACKEND_TO_MONACO[backendLang.toLowerCase()];
    if (n) return n;
  }
  const ext = filename && filename.includes('.') ? '.' + filename.split('.').pop()!.toLowerCase() : '';
  if (ext && EXT_TO_MONACO[ext]) return EXT_TO_MONACO[ext];
  for (const [pat, lang] of CODE_PATTERNS) if (pat.test(code)) return lang;
  return 'plaintext';
}

// ── Types ────────────────────────────────────────────────────────────────────
interface VulnerabilityItem {
  line: number; pattern: string; severity: string;
  description: string; cwe: string; category: string;
  fix_hint: string; snippet: string;
}
interface AnalysisResult {
  status: 'waiting' | 'loading' | 'malicious' | 'clean' | 'error';
  message?: string; confidence?: number; riskLevel?: string;
  language?: string; summary?: string; scanId?: number | null; malicious?: boolean;
  metadata?: {
    nodes_scanned?: number;
    engine?: string;
    process_time?: string;
    gcn_probability?: number | null;
    gcn_enabled?: boolean;
    snn_temporal?: {
      anomaly_prob: number;
      is_anomalous: boolean;
      isi_cv: number;
      firing_rate_hz: number;
      n_events: number;
      inference_ms: number;
    } | null;
  };
  vulnerabilities?: VulnerabilityItem[];
}
interface HistoryItem {
  id: string; timestamp: string; verdict: 'malicious' | 'clean';
  riskLevel: string; codePreview: string; fullCode: string;
  language?: string; confidence?: number; nodesScanned?: number;
}
type DeepScanStatus = 'idle' | 'scanning' | 'done' | 'error';
type ResultTab = 'verdict' | 'analysis';

// ── Helpers ──────────────────────────────────────────────────────────────────
const TypewriterText = ({ text }: { text: string }) => {
  const [displayed, setDisplayed] = useState('');
  useEffect(() => {
    setDisplayed('');
    let i = 0, cancelled = false;
    const next = () => { if (cancelled) return; if (i < text.length) { setDisplayed(text.slice(0, ++i)); setTimeout(next, 18); } };
    next();
    return () => { cancelled = true; };
  }, [text]);
  return <span>{displayed}</span>;
};


// ── Design tokens ────────────────────────────────────────────────────────────
import { COLORS } from '../theme/colors';
const C = {
  acid:    COLORS.acid,
  red:     COLORS.red,
  amber:   COLORS.orange,
  dim:     COLORS.surface2,
  border:  COLORS.border,
  muted:   COLORS.muted,
  text:    COLORS.text,
  subdued: COLORS.sub,
};

const sevColor = (s: string) =>
  s === 'CRITICAL' ? C.red : s === 'HIGH' ? C.amber : s === 'MEDIUM' ? '#FFD700' : C.subdued;

// ── Code examples ─────────────────────────────────────────────────────────────
const CODE_EXAMPLES = [
  {
    label: 'SSRF — Webhook validator (Python)',
    filename: 'webhook.py',
    code: `import requests
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/api/webhooks/test', methods=['POST'])
def test_webhook():
    """Validates a user-supplied webhook URL by sending a test ping."""
    data = request.get_json()
    target_url = data.get('url')
    secret     = data.get('secret', '')

    if not target_url:
        return jsonify({'error': 'url required'}), 400

    # No validation — attacker can point to internal services:
    # http://169.254.169.254/latest/meta-data/  (AWS metadata)
    # http://localhost:6379  (Redis)
    # http://10.0.0.1/admin
    resp = requests.post(
        target_url,
        json={'event': 'ping', 'secret': secret},
        timeout=5,
    )
    return jsonify({'status': resp.status_code, 'ok': resp.ok})
`,
  },
  {
    label: 'Path traversal — report downloader (Python)',
    filename: 'reports.py',
    code: `import os
from flask import Flask, request, send_file, abort

app = Flask(__name__)
REPORTS_DIR = '/var/app/reports'

@app.route('/download')
def download_report():
    """Downloads a report PDF by name."""
    name = request.args.get('name', '')
    # No sanitisation — ../../etc/passwd works fine
    full_path = os.path.join(REPORTS_DIR, name)
    if not os.path.exists(full_path):
        abort(404)
    return send_file(full_path, as_attachment=True)

@app.route('/preview')
def preview_report():
    name = request.args.get('name', '')
    full_path = os.path.join(REPORTS_DIR, name)
    with open(full_path, 'r') as f:
        return f.read()
`,
  },
  {
    label: 'Pickle deserialization (Python)',
    filename: 'session_store.py',
    code: `import pickle
import base64
from flask import Flask, request, jsonify

app = Flask(__name__)

def load_session(token: str) -> dict:
    """Restores user session from a base64-encoded cookie."""
    raw = base64.b64decode(token)
    # Attacker can craft a pickle payload that runs arbitrary code
    session = pickle.loads(raw)
    return session

@app.route('/profile')
def profile():
    token = request.cookies.get('session')
    if not token:
        return jsonify({'error': 'no session'}), 401
    sess = load_session(token)
    return jsonify({'user': sess.get('username'), 'role': sess.get('role')})

@app.route('/save_prefs', methods=['POST'])
def save_prefs():
    prefs = request.get_json()
    serialised = base64.b64encode(pickle.dumps(prefs)).decode()
    return jsonify({'token': serialised})
`,
  },
  {
    label: 'SSTI — Email template engine (Python)',
    filename: 'mailer.py',
    code: `from jinja2 import Environment
from flask import Flask, request, jsonify

app = Flask(__name__)
jinja_env = Environment()

TEMPLATES = {
    'welcome':  'Hello {{ name }}, welcome to the platform!',
    'reset':    'Click here to reset: {{ link }}',
}

@app.route('/api/preview-email', methods=['POST'])
def preview_email():
    """Renders a custom email template with user variables."""
    data     = request.get_json()
    template = data.get('template', '')
    context  = data.get('context', {})

    # Renders ARBITRARY user-supplied template string — SSTI
    # Payload: {{ ''.__class__.__mro__[1].__subclasses__() }}
    rendered = jinja_env.from_string(template).render(**context)
    return jsonify({'preview': rendered})
`,
  },
  {
    label: 'Prototype pollution (JavaScript)',
    filename: 'config_merge.js',
    code: `function deepMerge(target, source) {
    for (const key of Object.keys(source)) {
        if (source[key] && typeof source[key] === 'object') {
            // No __proto__ / constructor guard
            if (!target[key]) target[key] = {};
            deepMerge(target[key], source[key]);
        } else {
            target[key] = source[key];
        }
    }
    return target;
}

// Attacker POST body: {"__proto__": {"isAdmin": true}}
// After merge every object in the process has isAdmin = true
app.post('/api/settings', (req, res) => {
    const userSettings = {};
    deepMerge(userSettings, req.body);
    db.save(req.user.id, userSettings);

    if (userSettings.isAdmin) {
        // Unexpectedly true for all users post-pollution
        grantAdminAccess(req.user.id);
    }
    res.json({ saved: true });
});
`,
  },
  {
    label: 'JWT algorithm confusion (TypeScript)',
    filename: 'auth_middleware.ts',
    code: `import jwt from 'jsonwebtoken';
import { Request, Response, NextFunction } from 'express';
import fs from 'fs';

const PUBLIC_KEY = fs.readFileSync('./keys/public.pem', 'utf8');

export function verifyToken(req: Request, res: Response, next: NextFunction) {
    const header = req.headers.authorization ?? '';
    const token  = header.replace('Bearer ', '');

    // VULNERABLE: trusts 'alg' field from the token header itself.
    // Attacker can set alg=HS256 and sign with the PUBLIC KEY as HMAC secret,
    // since the public key is often discoverable.
    const decoded = jwt.verify(token, PUBLIC_KEY, { algorithms: undefined } as any);
    (req as any).user = decoded;
    next();
}

export function issueToken(payload: object): string {
    return jwt.sign(payload, PUBLIC_KEY, {
        algorithm: 'RS256',
        expiresIn:  '7d',
    });
}
`,
  },
  {
    label: 'Race condition — wallet debit (Go)',
    filename: 'wallet.go',
    code: `package wallet

import (
    "errors"
    "sync"
)

type Wallet struct {
    balance float64
    // No mutex protecting balance reads+writes
}

var wallets = map[string]*Wallet{}
var mu sync.Mutex

func Debit(userID string, amount float64) error {
    w := wallets[userID]

    // Read and write are not atomic — concurrent requests
    // can both pass the balance check and both debit
    if w.balance < amount {
        return errors.New("insufficient funds")
    }

    // Another goroutine can debit between the check and this line
    w.balance -= amount
    return nil
}

func Credit(userID string, amount float64) {
    mu.Lock()
    defer mu.Unlock()
    wallets[userID].balance += amount
}
`,
  },
  {
    label: 'Integer overflow — slab allocator (C)',
    filename: 'slab.c',
    code: `#include <stdlib.h>
#include <string.h>
#include <stdint.h>

typedef struct {
    uint32_t count;
    uint32_t item_size;
    void    *data;
} Slab;

Slab *slab_create(uint32_t count, uint32_t item_size) {
    Slab *s = malloc(sizeof(Slab));
    s->count     = count;
    s->item_size = item_size;

    // VULNERABLE: count * item_size overflows uint32 for large inputs
    // e.g. count=0x10000, item_size=0x10000 → wraps to 0 → malloc(0)
    uint32_t total = count * item_size;
    s->data = malloc(total);
    return s;
}

void slab_write(Slab *s, uint32_t index, void *item) {
    // No bounds check relative to true allocation size
    memcpy((char *)s->data + index * s->item_size, item, s->item_size);
}
`,
  },
  {
    label: 'Use-after-free — event dispatcher (C++)',
    filename: 'dispatcher.cpp',
    code: `#include <vector>
#include <functional>
#include <memory>

struct Listener {
    int id;
    std::function<void(const std::string&)> callback;
};

class EventBus {
    std::vector<Listener*> listeners_;
public:
    void subscribe(Listener* l) { listeners_.push_back(l); }

    void unsubscribe(int id) {
        for (auto it = listeners_.begin(); it != listeners_.end(); ++it) {
            if ((*it)->id == id) {
                delete *it;          // freed here
                listeners_.erase(it);
                return;
            }
        }
    }

    void emit(const std::string& event) {
        for (auto* l : listeners_) {
            l->callback(event);      // may call into freed memory if
        }                            // unsubscribe called during iteration
    }
};
`,
  },
  {
    label: 'XXE — invoice parser (Java)',
    filename: 'InvoiceParser.java',
    code: `import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.DocumentBuilder;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import java.io.ByteArrayInputStream;

public class InvoiceParser {

    public Document parse(String xmlData) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        // External entities NOT disabled — XXE possible
        // Attacker payload: <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
        DocumentBuilder builder = factory.newDocumentBuilder();
        return builder.parse(new ByteArrayInputStream(xmlData.getBytes()));
    }

    public String extractTotal(String xmlData) throws Exception {
        Document doc = parse(xmlData);
        NodeList nodes = doc.getElementsByTagName("total");
        return nodes.item(0).getTextContent();
    }
}
`,
  },
  {
    label: 'Mass assignment — user update (Python)',
    filename: 'users_api.py',
    code: `from flask import Flask, request, jsonify
from models import User, db

app = Flask(__name__)

@app.route('/api/users/<int:user_id>', methods=['PATCH'])
def update_user(user_id):
    """Updates a user's profile fields."""
    user = User.query.get_or_404(user_id)
    data = request.get_json()

    # VULNERABLE: sets ANY field from the JSON body directly onto the model
    # Attacker sends: {"role": "admin", "is_verified": true, "credits": 99999}
    for key, value in data.items():
        setattr(user, key, value)

    db.session.commit()
    return jsonify({'updated': True, 'id': user_id})
`,
  },
  {
    label: 'Timing attack — API key check (Python)',
    filename: 'api_auth.py',
    code: `import hashlib
from flask import Flask, request, jsonify, abort

app = Flask(__name__)

VALID_API_KEY = "prod-key-a3f9c2b81e74d650"

def verify_key(provided: str) -> bool:
    # VULNERABLE: early-exit string comparison leaks timing info.
    # Attacker can measure response time per character to brute-force the key.
    return provided == VALID_API_KEY

@app.before_request
def check_auth():
    key = request.headers.get('X-API-Key', '')
    if not verify_key(key):
        abort(401)

@app.route('/api/data')
def get_data():
    return jsonify({'records': db.fetch_all()})
`,
  },
  {
    label: 'Open redirect — OAuth callback (TypeScript)',
    filename: 'oauth_callback.ts',
    code: `import { Router, Request, Response } from 'express';

const router = Router();

router.get('/auth/callback', async (req: Request, res: Response) => {
    const { code, state } = req.query as Record<string, string>;

    // state param was set by client — not validated server-side
    const redirectTo = state || '/dashboard';

    try {
        const tokens = await exchangeCode(code);
        req.session!.tokens = tokens;

        // VULNERABLE: redirectTo is fully attacker-controlled.
        // Phishing: ?state=https://evil.com/steal
        res.redirect(redirectTo);
    } catch (err) {
        res.redirect('/login?error=oauth_failed');
    }
});

export default router;
`,
  },
  {
    label: 'ReDoS — log line validator (JavaScript)',
    filename: 'log_validator.js',
    code: `/**
 * Validates incoming log lines before writing to storage.
 * Called on every inbound log event from agents.
 */

// VULNERABLE: catastrophic backtracking on malicious input
// e.g. 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA!' takes exponential time
const LOG_LINE_RE = /^(INFO|WARN|ERROR)\\s+(\\w+\\s+)+\\[\\d+\\]$/;
const IP_RE       = /^([0-9]+\\.)+[0-9]+$/;   // also catastrophic

function validateLogLine(line) {
    if (line.length > 1024) return false;
    return LOG_LINE_RE.test(line);
}

function validateIp(ip) {
    return IP_RE.test(ip);
}

// Attacker sends: "INFO " + "a ".repeat(50) + "!"
// Server hangs processing a single log line (event loop blocked)
module.exports = { validateLogLine, validateIp };
`,
  },
  {
    label: 'Insecure deserialization (Java)',
    filename: 'SessionLoader.java',
    code: `import java.io.*;
import java.util.Base64;
import javax.servlet.http.*;

public class SessionLoader extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws IOException {

        String cookie = req.getHeader("X-Session-Data");
        if (cookie == null) { resp.sendError(401); return; }

        byte[] raw = Base64.getDecoder().decode(cookie);

        // VULNERABLE: deserialises arbitrary bytes from the client.
        // Attacker provides a gadget chain (e.g. Commons Collections)
        // to achieve RCE.
        try (ObjectInputStream ois = new ObjectInputStream(
                new ByteArrayInputStream(raw))) {
            Object session = ois.readObject();
            req.setAttribute("session", session);
        } catch (ClassNotFoundException e) {
            resp.sendError(400);
        }
    }
}
`,
  },
  {
    label: 'TOCTOU — temp file processing (Python)',
    filename: 'processor.py',
    code: `import os
import tempfile
import subprocess

def process_upload(data: bytes, filename: str) -> str:
    """Writes upload to tmp, checks it, then processes it."""
    tmp_path = f"/tmp/{filename}"

    with open(tmp_path, 'wb') as f:
        f.write(data)

    # TOCTOU: attacker replaces /tmp/{filename} with a symlink
    # to /etc/passwd between the check and the read below
    if not os.path.isfile(tmp_path):
        raise ValueError("not a file")

    if os.path.getsize(tmp_path) > 10_000_000:
        os.remove(tmp_path)
        raise ValueError("too large")

    # Gap here — symlink swap window
    result = subprocess.check_output(['file', tmp_path])
    return result.decode()
`,
  },
  {
    label: 'Format string — C diagnostics',
    filename: 'diagnostics.c',
    code: `#include <stdio.h>
#include <syslog.h>
#include <string.h>

#define MAX_MSG 512

void log_event(const char *user_message) {
    char buf[MAX_MSG];
    // VULNERABLE: user_message used directly as format string
    // Attacker sends "%x %x %x %n" to read/write stack memory
    snprintf(buf, sizeof(buf), user_message);
    syslog(LOG_INFO, buf);
}

void report_error(const char *component, const char *detail) {
    // VULNERABLE: detail not sanitised before being used as format
    char msg[256];
    sprintf(msg, detail);
    fprintf(stderr, "[%s] %s\\n", component, msg);
}

int main(int argc, char **argv) {
    if (argc > 1) log_event(argv[1]);
    return 0;
}
`,
  },
  {
    label: 'Local file inclusion (PHP)',
    filename: 'page_loader.php',
    code: `<?php
/**
 * Loads page templates based on the ?page= query parameter.
 * Templates live in /var/www/html/templates/
 */

$page = $_GET['page'] ?? 'home';

// Strip .php extension if provided
$page = str_replace('.php', '', $page);

// VULNERABLE: no whitelist, path not normalised
// ?page=../../../../etc/passwd%00 (null byte)
// ?page=../config/database
// ?page=php://filter/convert.base64-encode/resource=index
$template = __DIR__ . '/templates/' . $page . '.php';

if (file_exists($template)) {
    include $template;
} else {
    include __DIR__ . '/templates/404.php';
}
?>
`,
  },
  {
    label: 'Unvalidated file upload (Python)',
    filename: 'upload_handler.py',
    code: `import os
from flask import Flask, request, jsonify

app = Flask(__name__)
UPLOAD_DIR = '/var/www/uploads'

@app.route('/api/upload/avatar', methods=['POST'])
def upload_avatar():
    """Accepts a profile picture upload."""
    f = request.files.get('file')
    if not f:
        return jsonify({'error': 'no file'}), 400

    # Only checks the MIME type header — easily spoofed
    if f.content_type not in ('image/jpeg', 'image/png'):
        return jsonify({'error': 'invalid type'}), 400

    # Saves with the original filename — path traversal + .php upload
    # e.g. filename="../../cgi-bin/shell.php"
    dest = os.path.join(UPLOAD_DIR, f.filename)
    f.save(dest)

    public_url = f'/uploads/{f.filename}'
    return jsonify({'url': public_url})
`,
  },
  {
    label: 'Hardcoded creds + weak crypto (Go)',
    filename: 'db_connect.go',
    code: `package database

import (
    "crypto/md5"
    "database/sql"
    "fmt"
    _ "github.com/lib/pq"
)

const (
    DB_HOST = "prod-db.internal"
    DB_USER = "admin"
    DB_PASS = "Adm1nP@ssw0rd2024!"   // hardcoded production password
    DB_NAME = "customers"
)

func Connect() (*sql.DB, error) {
    dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s sslmode=disable",
        DB_HOST, DB_USER, DB_PASS, DB_NAME)
    return sql.Open("postgres", dsn)
}

// VULNERABLE: MD5 is cryptographically broken — do not use for passwords
func HashPassword(password string) string {
    sum := md5.Sum([]byte(password))
    return fmt.Sprintf("%x", sum)
}

func VerifyPassword(password, hash string) bool {
    return HashPassword(password) == hash
}
`,
  },
];

// ── Component ────────────────────────────────────────────────────────────────
export default function Scanner() {
  const { token } = useAuth();
  const { addXp } = useGame();

  const [code, setCode]                       = useState('');
  const [filename, setFilename]               = useState('');
  const [isDragging, setIsDragging]           = useState(false);
  const [result, setResult]                   = useState<AnalysisResult>({ status: 'waiting' });
  const [history, setHistory]                 = useState<HistoryItem[]>([]);
  const [deepScanStatus, setDeepScanStatus]   = useState<DeepScanStatus>('idle');
  const [llmOutput, setLlmOutput]             = useState('');
  const [activeTab, setActiveTab]             = useState<ResultTab>('verdict');
  const [activeLine, setActiveLine]           = useState<number | null>(null);
  const [expandedGroups, setExpandedGroups]   = useState<Record<string, boolean>>({});
  const [toastError, setToastError]           = useState<string | null>(null);
  const [historyOpen, setHistoryOpen]         = useState(false);
  const [feedbackSent, setFeedbackSent]       = useState(false);
  const [examplesOpen, setExamplesOpen]       = useState(false);
  const llmOutputRef                          = useRef('');
  const fileInputRef                          = useRef<HTMLInputElement>(null);
  const resultsRef                            = useRef<HTMLDivElement>(null);

  const showError = (msg: string) => { setToastError(msg); setTimeout(() => setToastError(null), 5000); };

  // Persistence
  useEffect(() => { const s = localStorage.getItem('soteria_audit_v2'); if (s) setHistory(JSON.parse(s)); }, []);
  useEffect(() => { localStorage.setItem('soteria_audit_v2', JSON.stringify(history)); }, [history]);

  const loadFile = useCallback((file: File) => {
    const ext = '.' + file.name.split('.').pop()?.toLowerCase();
    if (!SUPPORTED_EXTENSIONS.includes(ext)) { showError(`Unsupported: ${ext}`); return; }
    const reader = new FileReader();
    reader.onload = e => { setCode(e.target?.result as string ?? ''); setFilename(file.name); setResult({ status: 'waiting' }); };
    reader.readAsText(file);
  }, []);

  const handleFileDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault(); setIsDragging(false);
    const f = e.dataTransfer.files[0]; if (f) loadFile(f);
  }, [loadFile]);

  const handleFileInput = (e: React.ChangeEvent<HTMLInputElement>) => {
    const f = e.target.files?.[0]; if (f) loadFile(f); e.target.value = '';
  };

  const handleDownloadReport = async () => {
    try {
      const _pdfHeaders: Record<string, string> = { 'Content-Type': 'application/json' };
      if (token) _pdfHeaders['Authorization'] = `Bearer ${token}`;
      const res = await fetch(`${API_BASE_URL}/generate-report`, {
        method: 'POST',
        headers: _pdfHeaders,
        body: JSON.stringify({
          code, verdict: result.status.toUpperCase(),
          confidence: result.confidence, risk_level: result.riskLevel,
          reason: result.message, language: result.language,
          deep_scan: llmOutput || '', nodes_scanned: result.metadata?.nodes_scanned || 0,
          vulnerabilities: result.vulnerabilities || []
        })
      });
      if (!res.ok) {
        const ct = res.headers.get('content-type') ?? '';
        const msg = ct.includes('json')
          ? ((await res.json()).error ?? `HTTP ${res.status}`)
          : `HTTP ${res.status}`;
        showError(`PDF failed: ${msg}`);
        return;
      }
      const blob = await res.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url; a.download = `Soteria_Report_${Date.now()}.pdf`;
      document.body.appendChild(a); a.click(); a.remove();
      window.URL.revokeObjectURL(url);
    } catch (err) {
      showError(`PDF failed: ${err instanceof Error ? err.message : 'Network error'}`);
    }
  };

  const analyzeCode = async () => {
    if (!code.trim()) return;
    if (code.length > 50000) { setResult({ status: 'error', message: 'Payload too large. Limit: 50,000 chars.' }); return; }
    setDeepScanStatus('idle'); setLlmOutput(''); setActiveTab('verdict');
    setActiveLine(null); llmOutputRef.current = ''; setFeedbackSent(false); setResult({ status: 'loading' });
    try {
      const headers: Record<string, string> = { 'Content-Type': 'application/json' };
      if (token) headers['Authorization'] = `Bearer ${token}`;
      const res = await fetch(`${API_BASE_URL}/analyze`, {
        method: 'POST', headers,
        body: JSON.stringify({ code, filename: filename || undefined })
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      const verdict = data.malicious ? 'malicious' : 'clean';
      addXp(10); if (verdict === 'clean') addXp(50);
      // Normalize confidence: backend may return 0-1 fraction or 0-100 percentage
      const rawConf = data.confidence ?? 0;
      const normalizedConf = rawConf <= 1 ? Math.round(rawConf * 100 * 10) / 10 : rawConf;
      const item: HistoryItem = {
        id: Date.now().toString(),
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        verdict, riskLevel: data.risk_level,
        codePreview: code.trim().substring(0, 35) + '…',
        fullCode: code, language: data.language,
        confidence: normalizedConf, nodesScanned: data.metadata?.nodes_scanned
      };
      setHistory(prev => [item, ...prev].slice(0, 15));
      setResult({
        status: verdict, message: data.reason, confidence: normalizedConf,
        riskLevel: data.risk_level, language: data.language, summary: data.summary,
        metadata: data.metadata, vulnerabilities: data.vulnerabilities,
        scanId: data.scan_id ?? null, malicious: !!data.malicious,
      });
      if (data.vulnerabilities) {
        const grps: Record<string, boolean> = {};
        data.vulnerabilities.forEach((v: VulnerabilityItem) => { grps[v.category || 'Security Issue'] = true; });
        setExpandedGroups(grps);
      }
      // Auto-run Kyber deep scan (self-contained, no external API)
      startDeepScan({
        vulnerabilities: data.vulnerabilities || [],
        riskLevel: data.risk_level,
        confidence: normalizedConf,
        message: data.reason,
        language: data.language,
      });
    } catch { setResult({ status: 'error', message: 'INTELLIGENCE LINK OFFLINE — backend unreachable' }); }
  };

  const submitFeedback = async (correct: boolean) => {
    if (!token || !result.scanId) return;
    await fetch(`${API_BASE_URL}/api/feedback`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
      body: JSON.stringify({ scan_id: result.scanId, correct }),
    }).catch(() => {});
    setFeedbackSent(true);
    setTimeout(() => setFeedbackSent(false), 3000);
  };

  const startDeepScan = async (scanData?: { vulnerabilities: VulnerabilityItem[]; riskLevel: string; confidence: number; message: string; language: string }) => {
    setDeepScanStatus('scanning'); setLlmOutput(''); llmOutputRef.current = '';
    const vulns      = scanData?.vulnerabilities ?? result.vulnerabilities ?? [];
    const scanResult = {
      risk_level: scanData?.riskLevel  ?? result.riskLevel,
      confidence: scanData?.confidence ?? result.confidence,
      reason:     scanData?.message    ?? result.message,
      language:   scanData?.language   ?? result.language,
    };
    try {
      const headers: Record<string, string> = { 'Content-Type': 'application/json' };
      if (token) headers['Authorization'] = `Bearer ${token}`;
      const res = await fetch(`${API_BASE_URL}/deep-scan`, {
        method: 'POST', headers,
        body: JSON.stringify({ code, vulnerabilities: vulns, scan_result: scanResult })
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const reader = res.body?.getReader();
      const decoder = new TextDecoder();
      if (!reader) throw new Error('No stream');
      while (true) {
        const { done, value } = await reader.read(); if (done) break;
        const chunk = decoder.decode(value, { stream: true });
        for (const line of chunk.split('\n')) {
          if (!line.startsWith('data: ')) continue;
          const raw = line.slice(6);
          if (raw === '[STREAM_END]') { setDeepScanStatus('done'); return; }
          try {
            const p = JSON.parse(raw);
            if (p.type === 'token') { llmOutputRef.current += p.content.replace(/\\n/g, '\n'); setLlmOutput(llmOutputRef.current); }
            else if (p.type === 'done') setDeepScanStatus('done');
            else if (p.type === 'error') { setLlmOutput(p.content); setDeepScanStatus('error'); }
          } catch { continue; }
        }
      }
    } catch (e) { setLlmOutput(`CONNECTION FAILED: ${e}`); setDeepScanStatus('error'); }
  };

  const hasResults = result.status === 'malicious' || result.status === 'clean';
  const lineCount = code.split('\n').length;
  const charCount = code.length;

  // Status bar label
  const statusLabel = result.status === 'loading' ? '[ SCANNING ]'
    : result.status === 'malicious' ? '[ THREAT DETECTED ]'
    : result.status === 'clean' ? '[ CLEAN ]'
    : result.status === 'error' ? '[ ERROR ]'
    : '[ READY ]';
  const statusColor = result.status === 'malicious' ? C.red
    : result.status === 'clean' ? C.acid
    : result.status === 'loading' ? C.amber
    : result.status === 'error' ? C.red
    : C.subdued;

  const editorLang = detectEditorLang(result.language, filename, code);

  // Vuln grouping
  const vulnGroups: Record<string, VulnerabilityItem[]> = {};
  (result.vulnerabilities || []).forEach(v => {
    const cat = v.category || 'Security Issue';
    if (!vulnGroups[cat]) vulnGroups[cat] = [];
    vulnGroups[cat].push(v);
  });
  const sevRank = (s: string) => s === 'CRITICAL' ? 4 : s === 'HIGH' ? 3 : s === 'MEDIUM' ? 2 : 1;
  const sortedGroups = Object.entries(vulnGroups).sort((a, b) => {
    const aMax = Math.max(...a[1].map(v => sevRank(v.severity)));
    const bMax = Math.max(...b[1].map(v => sevRank(v.severity)));
    return bMax - aMax;
  });

  return (
    <div
      style={{
        display: 'flex', flexDirection: 'column', height: '100%',
        background: '#030712', fontFamily: "'JetBrains Mono', monospace",
        color: C.text, overflow: 'hidden',
      }}
    >
      {/* ── TOP STATUS STRIP ─────────────────────────────────────────────── */}
      <div style={{
        display: 'flex', alignItems: 'center', height: '36px',
        borderBottom: `1px solid ${C.border}`, flexShrink: 0,
        fontSize: '10px', letterSpacing: '0.08em',
      }}>
        <Cell style={{ color: statusColor, minWidth: 160, fontWeight: 700 }}>{statusLabel}</Cell>
        <Cell>LANG: <span style={{ color: editorLang === 'plaintext' ? C.subdued : C.text }}>{editorLang === 'plaintext' ? '---' : editorLang.toUpperCase()}</span></Cell>
        <Cell>LINES: <span style={{ color: C.text }}>{lineCount}</span></Cell>
        <Cell>CHARS: <span style={{ color: C.text }}>{charCount.toLocaleString()}</span></Cell>
        {result.confidence != null && hasResults && (
          <Cell>CONF: <span style={{ color: C.text }}>{result.confidence}%</span></Cell>
        )}
        {result.metadata?.nodes_scanned && (
          <Cell>NODES: <span style={{ color: C.text }}>{result.metadata.nodes_scanned}</span></Cell>
        )}
        <Cell style={{ marginLeft: 'auto' }}>
          <button
            onClick={() => setHistoryOpen(o => !o)}
            style={{ color: historyOpen ? C.acid : C.subdued, cursor: 'pointer', background: 'none', border: 'none', fontFamily: 'inherit', fontSize: 10, letterSpacing: '0.08em' }}
          >
            HISTORY [{history.length}]
          </button>
        </Cell>
        <Cell>
          <button
            onClick={() => { setCode(''); setFilename(''); setResult({ status: 'waiting' }); setLlmOutput(''); setDeepScanStatus('idle'); }}
            style={{ color: C.subdued, cursor: 'pointer', background: 'none', border: 'none', fontFamily: 'inherit', fontSize: 10, letterSpacing: '0.08em' }}
          >
            [ CLR ]
          </button>
        </Cell>
      </div>

      {/* ── TOAST ERROR ──────────────────────────────────────────────────── */}
      <AnimatePresence>
        {toastError && (
          <motion.div
            initial={{ opacity: 0, y: -8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }}
            style={{
              position: 'fixed', top: 44, left: '12rem', right: 0, zIndex: 50,
              background: '#1A0000', borderBottom: `1px solid ${C.red}`,
              color: C.red, fontSize: 11, padding: '8px 16px',
              display: 'flex', alignItems: 'center', justifyContent: 'space-between',
            }}
          >
            <span>! {toastError}</span>
            <button onClick={() => setToastError(null)} style={{ color: C.red, background: 'none', border: 'none', cursor: 'pointer', fontFamily: 'inherit', fontSize: 14 }} aria-label="Dismiss error" title="Dismiss">×</button>
          </motion.div>
        )}
      </AnimatePresence>

      {/* ── MAIN BODY ────────────────────────────────────────────────────── */}
      <div style={{ display: 'flex', flex: 1, overflow: 'hidden' }}>

        {/* HISTORY DRAWER */}
        <AnimatePresence>
          {historyOpen && (
            <motion.div
              initial={{ width: 0, opacity: 0 }} animate={{ width: 200, opacity: 1 }} exit={{ width: 0, opacity: 0 }}
              transition={{ duration: 0.15 }}
              style={{
                borderRight: `1px solid ${C.border}`, flexShrink: 0,
                overflowY: 'auto', overflowX: 'hidden',
                background: '#030712',
              }}
            >
              <div style={{ padding: '8px', borderBottom: `1px solid ${C.border}`, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ fontSize: 9, color: C.subdued, letterSpacing: '0.12em' }}>SCAN LOG</span>
                {history.length > 0 && (
                  <button onClick={() => setHistory([])} style={{ color: C.red, background: 'none', border: 'none', cursor: 'pointer', fontSize: 9, fontFamily: 'inherit' }} aria-label="Clear scan history" title="Clear history">CLR</button>
                )}
              </div>
              {history.length === 0 ? (
                <div style={{ padding: 12, fontSize: 9, color: C.muted }}>no entries</div>
              ) : history.map(item => (
                <div
                  key={item.id}
                  onClick={() => setCode(item.fullCode)}
                  style={{
                    padding: '8px', borderBottom: `1px solid ${C.border}`,
                    cursor: 'pointer', transition: 'background 0.1s',
                  }}
                  onMouseEnter={e => (e.currentTarget.style.background = C.dim)}
                  onMouseLeave={e => (e.currentTarget.style.background = 'transparent')}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 3 }}>
                    <span style={{ fontSize: 8, color: item.verdict === 'malicious' ? C.red : C.acid, fontWeight: 700 }}>
                      {item.riskLevel}
                    </span>
                    <span style={{ fontSize: 8, color: C.subdued }}>{item.timestamp}</span>
                  </div>
                  <div style={{ fontSize: 9, color: C.subdued, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {item.codePreview}
                  </div>
                  {item.language && (
                    <div style={{ fontSize: 8, color: C.muted, marginTop: 2 }}>{item.language.toUpperCase()}</div>
                  )}
                </div>
              ))}
            </motion.div>
          )}
        </AnimatePresence>

        {/* ── LEFT: EDITOR PANE ─────────────────────────────────────────── */}
        <div style={{ flex: '0 0 50%', display: 'flex', flexDirection: 'column', borderRight: `1px solid ${C.border}` }}>

          {/* Filename + upload row */}
          <div style={{
            display: 'flex', alignItems: 'center', gap: 0,
            borderBottom: `1px solid ${C.border}`, height: 36, flexShrink: 0,
          }}>
            <input
              type="text"
              value={filename}
              onChange={e => setFilename(e.target.value)}
              placeholder="filename.ext  (optional)"
              style={{
                flex: 1, background: 'transparent', border: 'none', outline: 'none',
                borderRight: `1px solid ${C.border}`, padding: '0 12px',
                fontFamily: "'JetBrains Mono', monospace", fontSize: 10,
                color: C.subdued, height: '100%',
              }}
            />
            <button
              onClick={() => fileInputRef.current?.click()}
              style={{
                height: '100%', padding: '0 14px', background: 'transparent',
                border: 'none', borderRight: `1px solid ${C.border}`,
                color: C.subdued, fontFamily: "'JetBrains Mono', monospace",
                fontSize: 10, cursor: 'pointer', letterSpacing: '0.08em',
                transition: 'color 0.15s',
              }}
              onMouseEnter={e => (e.currentTarget.style.color = C.text)}
              onMouseLeave={e => (e.currentTarget.style.color = C.subdued)}
            >
              [ UPLOAD ]
            </button>
            <input ref={fileInputRef} type="file" accept={ACCEPT_STRING} onChange={handleFileInput} style={{ display: 'none' }} />
            {/* Examples dropdown */}
            <div style={{ position: 'relative' }}>
              <button
                onClick={() => setExamplesOpen(o => !o)}
                style={{
                  height: '100%', padding: '0 14px', background: 'transparent',
                  border: 'none', borderRight: `1px solid ${C.border}`,
                  color: C.subdued, fontFamily: "'JetBrains Mono', monospace",
                  fontSize: 10, cursor: 'pointer', letterSpacing: '0.08em',
                  transition: 'color 0.15s',
                }}
                onMouseEnter={e => (e.currentTarget.style.color = C.acid)}
                onMouseLeave={e => (e.currentTarget.style.color = C.subdued)}
              >
                [ EXAMPLES ▾ ]
              </button>
              {examplesOpen && (
                <div style={{
                  position: 'absolute', top: '100%', left: 0, zIndex: 100,
                  background: '#0D1829', border: `1px solid ${C.border}`,
                  minWidth: '240px', boxShadow: '0 8px 24px rgba(0,0,0,0.5)',
                  maxHeight: '60vh', overflowY: 'auto',
                }}>
                  {CODE_EXAMPLES.map((ex) => (
                    <button
                      key={ex.label}
                      onClick={() => {
                        setCode(ex.code);
                        setFilename(ex.filename);
                        setResult({ status: 'waiting' });
                        setExamplesOpen(false);
                      }}
                      style={{
                        display: 'block', width: '100%', textAlign: 'left',
                        padding: '10px 16px', background: 'transparent',
                        border: 'none', borderBottom: `1px solid ${C.border}`,
                        color: C.subdued, fontFamily: "'JetBrains Mono', monospace",
                        fontSize: 10, cursor: 'pointer', letterSpacing: '0.06em',
                        transition: 'background 0.1s, color 0.1s',
                      }}
                      onMouseEnter={e => {
                        e.currentTarget.style.background = C.border;
                        e.currentTarget.style.color = C.text;
                      }}
                      onMouseLeave={e => {
                        e.currentTarget.style.background = 'transparent';
                        e.currentTarget.style.color = C.subdued;
                      }}
                    >
                      {ex.label}
                    </button>
                  ))}
                </div>
              )}
            </div>
          </div>

          {/* Action bar */}
          <div style={{
            display: 'flex', alignItems: 'center', height: 44,
            borderBottom: `1px solid ${C.border}`, flexShrink: 0,
          }}>
            {/* ANALYZE button */}
            <button
              onClick={analyzeCode}
              disabled={!code.trim() || result.status === 'loading'}
              style={{
                height: '100%', flex: '0 0 auto', padding: '0 24px',
                background: code.trim() && result.status !== 'loading' ? C.acid : 'transparent',
                border: 'none', borderRight: `1px solid ${C.border}`,
                outline: code.trim() || result.status === 'loading' ? 'none' : `1px solid ${C.border}`,
                color: code.trim() && result.status !== 'loading' ? '#000' : C.subdued,
                fontFamily: "'JetBrains Mono', monospace", fontSize: 11,
                fontWeight: 700, letterSpacing: '0.1em', cursor: code.trim() ? 'pointer' : 'not-allowed',
                transition: 'background 0.15s, color 0.15s',
              }}
            >
              {result.status === 'loading' ? '[ SCANNING... ]' : '[ ANALYZE ]'}
            </button>

            {/* Re-run full analysis — only when a result exists */}
            {hasResults && (
              <button
                onClick={() => analyzeCode()}
                style={{
                  height: '100%', flex: '0 0 auto', padding: '0 20px',
                  background: 'transparent', border: 'none',
                  borderRight: `1px solid ${C.border}`,
                  color: C.text,
                  fontFamily: "'JetBrains Mono', monospace", fontSize: 11,
                  letterSpacing: '0.1em', cursor: 'pointer',
                  transition: 'color 0.15s',
                }}
                onMouseEnter={e => { e.currentTarget.style.color = C.acid; }}
                onMouseLeave={e => { e.currentTarget.style.color = C.text; }}
              >
                [ RE-SCAN ]
              </button>
            )}

            {/* Report download */}
            {hasResults && (
              <button
                onClick={handleDownloadReport}
                style={{
                  height: '100%', flex: '0 0 auto', padding: '0 16px',
                  background: 'transparent', border: 'none',
                  borderRight: `1px solid ${C.border}`,
                  color: C.subdued, fontFamily: "'JetBrains Mono', monospace",
                  fontSize: 10, letterSpacing: '0.08em', cursor: 'pointer',
                  transition: 'color 0.15s',
                }}
                onMouseEnter={e => (e.currentTarget.style.color = C.text)}
                onMouseLeave={e => (e.currentTarget.style.color = C.subdued)}
              >
                [ PDF ]
              </button>
            )}

            <div style={{ marginLeft: 'auto', padding: '0 14px', fontSize: 9, color: C.muted }}>
              soteria scanner v2
            </div>
          </div>

          {/* Editor */}
          <div
            style={{ flex: 1, position: 'relative', overflow: 'hidden' }}
            onDragOver={e => { e.preventDefault(); setIsDragging(true); }}
            onDragLeave={() => setIsDragging(false)}
            onDrop={handleFileDrop}
          >
            <CodeEditor
              code={code}
              setCode={setCode}
              language={editorLang}
              className="h-full"
              vulnerabilities={result.vulnerabilities}
              activeLine={activeLine}
            />

            {/* Drag overlay */}
            <AnimatePresence>
              {isDragging && (
                <motion.div
                  initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
                  style={{
                    position: 'absolute', inset: 0, zIndex: 10,
                    border: `2px dashed ${C.acid}`,
                    background: 'rgba(173,255,47,0.04)',
                    display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center',
                    gap: 8, pointerEvents: 'none',
                  }}
                >
                  <div style={{ fontSize: 28, color: C.acid }}>⬇</div>
                  <div style={{ fontSize: 11, color: C.acid, letterSpacing: '0.1em' }}>DROP FILE TO LOAD</div>
                  <div style={{ fontSize: 9, color: C.subdued }}>{SUPPORTED_EXTENSIONS.slice(0, 8).join('  ')} …</div>
                </motion.div>
              )}
            </AnimatePresence>
          </div>
        </div>

        {/* ── RIGHT: RESULTS PANE ───────────────────────────────────────── */}
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }} ref={resultsRef}>

          {/* Tab bar */}
          {hasResults && (
            <div style={{
              display: 'flex', alignItems: 'center', height: 36,
              borderBottom: `1px solid ${C.border}`, flexShrink: 0,
            }}>
              {([
                { key: 'verdict' as ResultTab, label: 'VERDICT' },
                { key: 'analysis' as ResultTab, label: 'KYBER REPORT', disabled: !hasResults },
              ]).map(tab => (
                <button
                  key={tab.key}
                  onClick={() => !tab.disabled && setActiveTab(tab.key)}
                  disabled={tab.disabled}
                  style={{
                    height: '100%', padding: '0 16px', background: 'transparent', border: 'none',
                    borderRight: `1px solid ${C.border}`,
                    borderBottom: activeTab === tab.key ? `2px solid ${C.acid}` : '2px solid transparent',
                    color: activeTab === tab.key ? C.acid : tab.disabled ? C.muted : C.subdued,
                    fontFamily: "'JetBrains Mono', monospace", fontSize: 9, letterSpacing: '0.12em',
                    cursor: tab.disabled ? 'not-allowed' : 'pointer', fontWeight: activeTab === tab.key ? 700 : 400,
                    transition: 'color 0.1s',
                  }}
                >
                  {tab.label}
                </button>
              ))}
              {deepScanStatus === 'scanning' && (
                <div style={{ marginLeft: 'auto', padding: '0 14px', fontSize: 9, color: C.amber, display: 'flex', alignItems: 'center', gap: 6 }}>
                  <span style={{ display: 'inline-block', width: 6, height: 6, borderRadius: '50%', background: C.amber, animation: 'pulse 1s infinite' }} />
                  STREAMING
                </div>
              )}
            </div>
          )}

          {/* Results content */}
          <div style={{ flex: 1, overflow: 'auto', padding: '0' }}>
            <AnimatePresence mode="wait">

              {/* WAITING STATE */}
              {result.status === 'waiting' && (
                <motion.div key="waiting" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
                  style={{ padding: 32, display: 'flex', flexDirection: 'column', alignItems: 'flex-start', justifyContent: 'flex-start', height: '100%' }}
                >
                  <div style={{ fontSize: 9, color: C.muted, letterSpacing: '0.1em', lineHeight: 2, fontFamily: "'JetBrains Mono', monospace" }}>
                    <div style={{ color: C.subdued }}>soteria@scanner:~$ <span style={{ color: C.acid }}>_</span></div>
                    <div style={{ marginTop: 16, color: C.muted }}>PASTE OR UPLOAD CODE TO BEGIN ANALYSIS</div>
                    <div style={{ color: C.muted }}>SUPPORTED: {SUPPORTED_EXTENSIONS.slice(0, 6).join(' ').toUpperCase()} + MORE</div>
                    <div style={{ marginTop: 16, color: C.muted }}>ENGINES: GCN · ENTROPY · SNN · PATTERN</div>
                    <div style={{ color: C.muted }}>DEEP SCAN: KYBER REPORT AUTO-GENERATES AFTER ANALYSIS</div>
                  </div>
                </motion.div>
              )}

              {/* LOADING */}
              {result.status === 'loading' && (
                <motion.div key="loading" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
                  style={{ padding: 32, fontFamily: "'JetBrains Mono', monospace" }}
                >
                  <div style={{ fontSize: 9, color: C.amber, letterSpacing: '0.1em', lineHeight: 2 }}>
                    <div>{'>'} INITIALIZING SCAN PIPELINE...</div>
                    <div>{'>'} PHASE 1: PATTERN ENGINE</div>
                    <div>{'>'} PHASE 2: ENTROPY PROFILER</div>
                    <div>{'>'} PHASE 3: GCN INFERENCE</div>
                    <div>{'>'} PHASE 4: SNN TEMPORAL</div>
                    <div style={{ marginTop: 8, color: C.acid }}>
                      {'>'} PROCESSING<span style={{ animation: 'blink 1s step-end infinite' }}>...</span>
                    </div>
                  </div>
                </motion.div>
              )}

              {/* ERROR */}
              {result.status === 'error' && (
                <motion.div key="error" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
                  style={{ padding: 32, fontFamily: "'JetBrains Mono', monospace" }}
                >
                  <div style={{ fontSize: 11, color: C.red, letterSpacing: '0.06em', lineHeight: 1.8 }}>
                    <div>! SCAN FAILURE</div>
                    <div style={{ fontSize: 9, color: C.muted, marginTop: 8 }}>{result.message}</div>
                  </div>
                </motion.div>
              )}

              {/* VERDICT TAB */}
              {hasResults && activeTab === 'verdict' && (
                <motion.div key="verdict" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
                  style={{ padding: 20, fontFamily: "'JetBrains Mono', monospace" }}
                >
                  {/* Verdict headline */}
                  <div style={{
                    borderLeft: `3px solid ${result.status === 'malicious' ? C.red : C.acid}`,
                    paddingLeft: 14, marginBottom: 20,
                  }}>
                    <div style={{ fontSize: 9, color: C.subdued, letterSpacing: '0.12em', marginBottom: 4 }}>VERDICT</div>
                    <div style={{ fontSize: 22, fontWeight: 700, color: result.status === 'malicious' ? C.red : C.acid, letterSpacing: '0.04em' }}>
                      {result.status === 'malicious' ? 'THREAT DETECTED' : 'CLEAN'}
                    </div>
                    <div style={{ fontSize: 10, color: C.subdued, marginTop: 4 }}>
                      {result.riskLevel} RISK · {(result.language || (editorLang !== 'plaintext' ? editorLang : '')).toUpperCase()}
                    </div>
                  </div>

                  {/* Confidence meter */}
                  {result.confidence != null && (
                    <div style={{ marginBottom: 20 }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 9, color: C.subdued, marginBottom: 4, letterSpacing: '0.1em' }}>
                        <span>CONFIDENCE</span>
                        <span style={{ color: C.text }}>{result.confidence}%</span>
                      </div>
                      <div style={{ height: 2, background: C.dim, position: 'relative' }}>
                        <motion.div
                          initial={{ width: 0 }}
                          animate={{ width: `${result.confidence}%` }}
                          transition={{ duration: 0.8, ease: 'easeOut' }}
                          style={{
                            height: '100%', position: 'absolute', left: 0, top: 0,
                            background: result.confidence > 80 ? (result.status === 'malicious' ? C.red : C.acid) : C.amber,
                          }}
                        />
                      </div>
                    </div>
                  )}

                  {/* Reason */}
                  {result.message && (
                    <div style={{ marginBottom: 20, borderLeft: `1px solid ${C.border}`, paddingLeft: 12 }}>
                      <div style={{ fontSize: 9, color: C.subdued, letterSpacing: '0.1em', marginBottom: 6 }}>ANALYSIS</div>
                      <div style={{ fontSize: 10, color: C.subdued, lineHeight: 1.7 }}>
                        <TypewriterText text={result.message} />
                      </div>
                    </div>
                  )}

                  {/* Metadata row */}
                  {result.metadata && (
                    <div style={{ display: 'flex', gap: 0, marginBottom: 20, borderTop: `1px solid ${C.border}`, borderBottom: `1px solid ${C.border}` }}>
                      {result.metadata.nodes_scanned && (
                        <MetaCell label="NODES" value={String(result.metadata.nodes_scanned)} />
                      )}
                      {result.metadata.process_time && (
                        <MetaCell label="TIME" value={result.metadata.process_time} />
                      )}
                      {result.metadata.engine && (
                        <MetaCell label="ENGINE" value={result.metadata.engine.split('+')[0].trim()} />
                      )}
                    </div>
                  )}

                  {/* User feedback */}
                  {result.scanId && result.malicious && (
                    <div style={{ display: 'flex', gap: 8, marginTop: 16, marginBottom: 8, alignItems: 'center' }}>
                      {feedbackSent ? (
                        <span style={{ fontSize: 9, color: C.acid, letterSpacing: '0.1em' }}>[ ✓ REPORTED ]</span>
                      ) : (
                        <button onClick={() => submitFeedback(false)}
                          style={{ padding: '4px 12px', background: 'transparent', border: `1px solid ${C.subdued}`,
                                   color: C.subdued, fontFamily: "'JetBrains Mono', monospace", fontSize: 9,
                                   letterSpacing: '0.08em', cursor: 'pointer' }}>
                          [ REPORT FALSE POSITIVE ]
                        </button>
                      )}
                    </div>
                  )}

                  {/* Engine Signal Panel — GCN + SNN */}
                  {result.metadata && (result.metadata.gcn_probability != null || result.metadata.snn_temporal) && (
                    <div style={{ marginBottom: 20, borderTop: `1px solid ${C.border}`, borderBottom: `1px solid ${C.border}` }}>
                      {/* GCN structural row */}
                      {result.metadata.gcn_probability != null && (
                        <div style={{ padding: '10px 14px', borderBottom: result.metadata.snn_temporal ? `1px solid ${C.border}` : 'none' }}>
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 5 }}>
                            <span style={{ fontSize: 8, color: C.subdued, letterSpacing: '0.12em' }}>GCN STRUCT</span>
                            <span style={{ fontSize: 10, color: result.metadata.gcn_probability > 0.5 ? C.red : C.acid, fontFamily: "'JetBrains Mono', monospace" }}>
                              {(result.metadata.gcn_probability * 100).toFixed(1)}%
                            </span>
                          </div>
                          <div style={{ height: 2, background: C.border, width: '100%' }}>
                            <div style={{
                              height: '100%',
                              width: `${result.metadata.gcn_probability * 100}%`,
                              background: result.metadata.gcn_probability > 0.5 ? C.red : C.acid,
                              transition: 'width 0.4s ease',
                            }} />
                          </div>
                        </div>
                      )}
                      {/* SNN temporal row */}
                      {result.metadata.snn_temporal && (
                        <div style={{ padding: '10px 14px' }}>
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 5 }}>
                            <span style={{ fontSize: 8, color: C.subdued, letterSpacing: '0.12em' }}>SNN TEMPORAL</span>
                            <span style={{ fontSize: 10, color: result.metadata.snn_temporal.is_anomalous ? C.red : C.acid, fontFamily: "'JetBrains Mono', monospace" }}>
                              {(result.metadata.snn_temporal.anomaly_prob * 100).toFixed(1)}%
                            </span>
                          </div>
                          <div style={{ height: 2, background: C.border, width: '100%', marginBottom: 4 }}>
                            <div style={{
                              height: '100%',
                              width: `${result.metadata.snn_temporal.anomaly_prob * 100}%`,
                              background: result.metadata.snn_temporal.is_anomalous ? C.red : C.acid,
                              transition: 'width 0.4s ease',
                            }} />
                          </div>
                          <div style={{ fontSize: 8, color: C.subdued, fontFamily: "'JetBrains Mono', monospace", letterSpacing: '0.08em' }}>
                            ISI-CV: {result.metadata.snn_temporal.isi_cv.toFixed(2)}&nbsp;&nbsp;RATE: {result.metadata.snn_temporal.firing_rate_hz.toFixed(1)} Hz
                          </div>
                        </div>
                      )}
                    </div>
                  )}

                  {/* Summary banner */}
                  {result.summary && result.vulnerabilities && result.vulnerabilities.length > 0 && (
                    <div style={{
                      background: 'rgba(255,140,0,0.06)', border: `1px solid rgba(255,140,0,0.25)`,
                      padding: '10px 14px', marginBottom: 20, fontSize: 10, color: '#FFBA60', lineHeight: 1.6,
                    }}>
                      <span style={{ color: C.amber, fontWeight: 700, marginRight: 8 }}>!</span>
                      {result.summary}
                    </div>
                  )}

                  {/* Vuln groups */}
                  {sortedGroups.length > 0 && (
                    <div>
                      <div style={{ fontSize: 9, color: C.subdued, letterSpacing: '0.12em', marginBottom: 10 }}>
                        FINDINGS — {result.vulnerabilities!.length} ISSUE{result.vulnerabilities!.length !== 1 ? 'S' : ''} / {sortedGroups.length} CATEGOR{sortedGroups.length !== 1 ? 'IES' : 'Y'}
                      </div>
                      {sortedGroups.map(([cat, items]) => {
                        const topSev = items.find(v => v.severity === 'CRITICAL') ? 'CRITICAL'
                          : items.find(v => v.severity === 'HIGH') ? 'HIGH'
                          : items.find(v => v.severity === 'MEDIUM') ? 'MEDIUM' : 'LOW';
                        const isOpen = expandedGroups[cat] !== false;
                        return (
                          <div key={cat} style={{ marginBottom: 2, border: `1px solid ${C.border}` }}>
                            {/* Category header */}
                            <button
                              onClick={() => setExpandedGroups(p => ({ ...p, [cat]: !isOpen }))}
                              style={{
                                width: '100%', display: 'flex', alignItems: 'center', gap: 10,
                                padding: '8px 12px', background: isOpen ? C.dim : 'transparent',
                                border: 'none', cursor: 'pointer', fontFamily: "'JetBrains Mono', monospace",
                                transition: 'background 0.1s',
                              }}
                            >
                              <span style={{ width: 6, height: 6, borderRadius: '50%', background: sevColor(topSev), flexShrink: 0 }} />
                              <span style={{ fontSize: 10, color: C.text, flex: 1, textAlign: 'left', fontWeight: 700 }}>{cat}</span>
                              <div style={{ display: 'flex', gap: 4 }}>
                                {['CRITICAL','HIGH','MEDIUM','LOW'].map(sev => {
                                  const cnt = items.filter(v => v.severity === sev).length;
                                  return cnt > 0 ? (
                                    <span key={sev} style={{ fontSize: 8, padding: '1px 4px', color: sevColor(sev), border: `1px solid ${sevColor(sev)}`, opacity: 0.7 }}>
                                      {cnt}{sev[0]}
                                    </span>
                                  ) : null;
                                })}
                              </div>
                              <span style={{ fontSize: 10, color: C.muted }}>{isOpen ? '▾' : '▸'}</span>
                            </button>

                            {/* Expanded findings */}
                            {isOpen && (
                              <div style={{ borderTop: `1px solid ${C.border}` }}>
                                {items.map((v, i) => (
                                  <div
                                    key={i}
                                    onClick={() => setActiveLine(v.line)}
                                    style={{
                                      padding: '8px 12px 8px 20px', cursor: 'pointer',
                                      borderBottom: i < items.length - 1 ? `1px solid ${C.border}` : 'none',
                                      transition: 'background 0.1s',
                                    }}
                                    onMouseEnter={e => (e.currentTarget.style.background = C.dim)}
                                    onMouseLeave={e => (e.currentTarget.style.background = 'transparent')}
                                  >
                                    <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 3 }}>
                                      <span style={{ fontSize: 8, color: sevColor(v.severity), fontWeight: 700, border: `1px solid ${sevColor(v.severity)}`, padding: '1px 4px', opacity: 0.8 }}>
                                        {v.severity}
                                      </span>
                                      <span style={{ fontSize: 9, color: C.acid }}>LINE {v.line}</span>
                                      {v.cwe && <span style={{ fontSize: 8, color: C.muted }}>{v.cwe}</span>}
                                    </div>
                                    <div style={{ fontSize: 9, color: C.subdued, lineHeight: 1.5 }}>{v.description}</div>
                                    {v.snippet && (
                                      <div style={{ fontSize: 8, color: C.muted, marginTop: 3, fontFamily: "'JetBrains Mono', monospace", overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                                        {v.snippet}
                                      </div>
                                    )}
                                    {v.fix_hint && (
                                      <div style={{ fontSize: 8, color: '#5AE65A', marginTop: 4 }}>
                                        FIX → {v.fix_hint}
                                      </div>
                                    )}
                                  </div>
                                ))}
                              </div>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  )}
                </motion.div>
              )}

              {/* ANALYSIS TAB */}
              {hasResults && activeTab === 'analysis' && (
                <motion.div key="analysis" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
                  style={{ padding: 20, height: '100%', display: 'flex', flexDirection: 'column' }}
                >
                  <div style={{ fontSize: 9, color: C.subdued, letterSpacing: '0.12em', marginBottom: 12, display: 'flex', alignItems: 'center', gap: 8 }}>
                    <span>KYBER DEEP ANALYSIS</span>
                    {deepScanStatus === 'done' && <span style={{ color: C.acid }}>[ COMPLETE ]</span>}
                  </div>
                  <div style={{ flex: 1, overflow: 'auto', background: C.dim, padding: 16, border: `1px solid ${C.border}` }}>
                    <pre style={{ fontSize: 10, color: C.text, lineHeight: 1.7, whiteSpace: 'pre-wrap', margin: 0, fontFamily: "'JetBrains Mono', monospace" }}>
                      {llmOutput || (deepScanStatus === 'scanning' ? 'RUNNING KYBER ANALYSIS...' : '')}
                      {deepScanStatus === 'scanning' && (
                        <span style={{ display: 'inline-block', width: 8, height: 14, background: C.acid, marginLeft: 2, verticalAlign: 'middle', animation: 'blink 0.8s step-end infinite' }} />
                      )}
                    </pre>
                  </div>
                </motion.div>
              )}

            </AnimatePresence>
          </div>
        </div>
      </div>

      {/* Global keyframe animations */}
      <style>{`
        @keyframes blink { 0%,100% { opacity: 1; } 50% { opacity: 0; } }
        @keyframes pulse { 0%,100% { opacity: 1; } 50% { opacity: 0.4; } }
      `}</style>
    </div>
  );
}

// ── Sub-components ────────────────────────────────────────────────────────────
function Cell({ children, style }: { children: React.ReactNode; style?: React.CSSProperties }) {
  return (
    <div style={{
      display: 'flex', alignItems: 'center',
      padding: '0 14px', height: '100%',
      borderRight: '1px solid #1E1E1E',
      fontSize: 10, color: '#707070', letterSpacing: '0.08em',
      gap: 6, whiteSpace: 'nowrap',
      ...style,
    }}>
      {children}
    </div>
  );
}

function MetaCell({ label, value }: { label: string; value: string }) {
  return (
    <div style={{
      flex: 1, padding: '8px 12px',
      borderRight: '1px solid #1E1E1E',
    }}>
      <div style={{ fontSize: 8, color: '#404040', letterSpacing: '0.1em', marginBottom: 3 }}>{label}</div>
      <div style={{ fontSize: 10, color: '#E5E5E5' }}>{value}</div>
    </div>
  );
}
