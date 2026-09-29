from flask import Flask, render_template, request, jsonify, send_file, session, redirect
import sqlite3, re, json, os, uuid, io, threading, time
from datetime import datetime
from email import policy
from email.parser import BytesParser

app = Flask(__name__)
app.secret_key = os.environ.get('THREATLENS_SECRET', 'dev-secret-change-me')

BASE = os.path.dirname(__file__)
DB = os.path.join(BASE, 'threatlens.db')
UP = os.path.join(BASE, 'uploads')
os.makedirs(UP, exist_ok=True)

# ---------------------------------------------------------------------------
# Serializes every DB WRITE across threads (Flask request threads + the
# background Gmail watcher thread). SQLite only allows one writer at a time
# anyway; without this, two writers racing produced
# "sqlite3.OperationalError: database is locked".
# ---------------------------------------------------------------------------
DB_LOCK = threading.Lock()

# ---------------------------------------------------------------------------
# Training data (kept intentionally small/readable but wider-coverage than a
# tiny 8-row demo so the classifier isn't trivially overfit to a few phrases)
# ---------------------------------------------------------------------------
DEMO_DATA = [
    ('meeting agenda project update schedule attached', 'safe'),
    ('your order has shipped tracking information', 'safe'),
    ('team meeting is confirmed for tomorrow at 10am', 'safe'),
    ('invoice for your recent purchase is attached', 'safe'),
    ('here are the notes from todays standup', 'safe'),
    ('lunch on friday to celebrate the launch', 'safe'),
    ('quarterly report is ready for review', 'safe'),
    ('reminder your subscription renews next month', 'safe'),
    ('thanks for joining the call today', 'safe'),
    ('please find attached the signed contract', 'safe'),
    ('your flight itinerary and boarding pass', 'safe'),
    ('new comment on your pull request', 'safe'),
    ('welcome to the team here is your onboarding guide', 'safe'),
    ('your package will arrive tomorrow between 9 and 5', 'safe'),
    ('monthly newsletter product updates and tips', 'safe'),
    ('your receipt for todays purchase', 'safe'),
    ('urgent verify your account password immediately click here', 'threat'),
    ('your mailbox will be suspended confirm login now', 'threat'),
    ('you won a prize send bank details to claim reward', 'threat'),
    ('security alert click the link and enter your password', 'threat'),
    ('your account has been limited verify identity within 24 hours', 'threat'),
    ('final notice your payment failed update billing information now', 'threat'),
    ('congratulations you have been selected claim your gift card', 'threat'),
    ('irs tax refund pending confirm your social security number', 'threat'),
    ('unusual sign in activity detected verify it was you immediately', 'threat'),
    ('your package could not be delivered pay a small fee to reschedule', 'threat'),
    ('act now your subscription will be cancelled unless you confirm payment', 'threat'),
    ('ceo urgent wire transfer needed today confidential', 'threat'),
    ('click here to reset your password before it expires in 1 hour', 'threat'),
    ('you have a pending inheritance claim send your bank details', 'threat'),
    ('microsoft support your computer has a virus call this number', 'threat'),
    ('verify your paypal account or it will be permanently limited', 'threat'),
]

SEVERITY_WEIGHT = {
    'urgent': 6, 'immediately': 6, 'verify': 5, 'password': 6, 'login': 4,
    'suspended': 7, 'click here': 6, 'bank details': 9, 'gift card': 7,
    'prize': 6, 'confirm': 4, 'account': 3, 'security alert': 6,
    'wire transfer': 9, 'social security': 9, 'act now': 6, 'winner': 6,
    'free': 3, 'limited time': 5, 'confidential': 4, 'refund': 4,
    'inheritance': 8, 'lottery': 8, 'gift': 3, 'update your billing': 6,
    'final notice': 6, 'reset your password': 5,
}
SUSPICIOUS = list(SEVERITY_WEIGHT.keys())

URL_RE = r'https?://[^\s<>"\']+'
IP_RE = r'(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)'
EMAIL_RE = r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}'
URL_SHORTENERS = {'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly', 'rebrand.ly'}
SUSPICIOUS_TLDS = {'.zip', '.top', '.xyz', '.click', '.gq', '.tk', '.ml', '.cf', '.work', '.support'}


def db():
    # timeout: if the DB is briefly locked by another thread, SQLite will
    # retry internally for up to this many seconds before raising
    # "database is locked", instead of failing instantly.
    c = sqlite3.connect(DB, timeout=15, check_same_thread=False)
    c.row_factory = sqlite3.Row
    # WAL mode lets readers and a writer work concurrently instead of the
    # default mode where a writer blocks everyone else.
    c.execute('PRAGMA journal_mode=WAL')
    c.execute('PRAGMA busy_timeout=15000')
    return c


def init_db():
    c = db()
    c.execute('''CREATE TABLE IF NOT EXISTS analyses(
        id TEXT PRIMARY KEY, created TEXT, subject TEXT, sender TEXT, label TEXT,
        risk INTEGER, ml_probability REAL, urls TEXT, ips TEXT, emails TEXT,
        findings TEXT, raw TEXT, top_features TEXT)''')
    # Live Gmail monitoring: alerts that fire while polling the inbox in the
    # background, and a de-dupe table so the same message isn't re-analyzed
    # and re-alerted every poll cycle.
    c.execute('''CREATE TABLE IF NOT EXISTS gmail_alerts(
        id TEXT PRIMARY KEY, msg_id TEXT UNIQUE, created TEXT, subject TEXT,
        sender TEXT, risk INTEGER, label TEXT, seen INTEGER DEFAULT 0)''')
    c.execute('''CREATE TABLE IF NOT EXISTS gmail_processed(
        msg_id TEXT PRIMARY KEY, created TEXT)''')
    c.commit()
    c.close()
    # Lightweight migration for older DBs created before top_features existed
    c = db()
    cols = [r['name'] for r in c.execute('PRAGMA table_info(analyses)').fetchall()]
    if 'top_features' not in cols:
        c.execute('ALTER TABLE analyses ADD COLUMN top_features TEXT')
        c.commit()
    c.close()


init_db()

# ---------------------------------------------------------------------------
# ML: an ensemble of Logistic Regression + Multinomial Naive Bayes over a
# shared TF-IDF space. Averaging two different model families is more
# stable on tiny datasets than relying on a single classifier, and the LR
# coefficients let us surface *why* something scored high (explainability).
# ---------------------------------------------------------------------------
ML = False
try:
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.naive_bayes import MultinomialNB

    _X = [x for x, y in DEMO_DATA]
    _y = [y for x, y in DEMO_DATA]
    VEC = TfidfVectorizer(ngram_range=(1, 2), lowercase=True, min_df=1)
    _Xv = VEC.fit_transform(_X)
    LR = LogisticRegression(max_iter=2000).fit(_Xv, _y)
    NB = MultinomialNB().fit(_Xv, _y)
    THREAT_IDX_LR = list(LR.classes_).index('threat')
    THREAT_IDX_NB = list(NB.classes_).index('threat')
    FEATURE_NAMES = VEC.get_feature_names_out()
    ML = True
except Exception:
    ML = False


def top_contributing_terms(text, n=5):
    """Return the n-grams in `text` most responsible for a threat score."""
    if not ML:
        return []
    try:
        vec = VEC.transform([text])
        coefs = LR.coef_[0]
        contributions = []
        for idx in vec.nonzero()[1]:
            weight = coefs[idx] * vec[0, idx]
            if weight > 0:
                contributions.append((FEATURE_NAMES[idx], round(float(weight), 3)))
        contributions.sort(key=lambda t: t[1], reverse=True)
        return [{'term': t, 'weight': w} for t, w in contributions[:n]]
    except Exception:
        return []


def extract(text):
    urls = [u.rstrip('.,;:)\'"') for u in re.findall(URL_RE, text or '', re.I)]
    ips = []
    for ip in re.findall(IP_RE, text or ''):
        if all(int(x) <= 255 for x in ip.split('.')):
            ips.append(ip)
    emails = list(dict.fromkeys(re.findall(EMAIL_RE, text or '', re.I)))
    return list(dict.fromkeys(urls)), list(dict.fromkeys(ips)), emails


def url_findings(urls):
    out = []
    for u in urls:
        host = re.sub(r'^https?://', '', u, flags=re.I).split('/')[0].lower()
        host = host.split('@')[-1]  # strip userinfo tricks like http://real.com@evil.com
        if host.startswith('xn--') or '.xn--' in host:
            out.append({'type': 'Possible homograph/punycode domain', 'value': u, 'severity': 'high'})
        if any(host == s or host.endswith('.' + s) for s in URL_SHORTENERS):
            out.append({'type': 'URL shortener (destination hidden)', 'value': u, 'severity': 'medium'})
        if any(host.endswith(tld) for tld in SUSPICIOUS_TLDS):
            out.append({'type': 'Suspicious top-level domain', 'value': u, 'severity': 'medium'})
        if re.match(r'^(?:\d{1,3}\.){3}\d{1,3}$', host):
            out.append({'type': 'Raw IP address used as link', 'value': u, 'severity': 'high'})
    return out


def sender_findings(sender, reply):
    out = []
    m = re.match(r'^\s*"?([^"<]*)"?\s*<([^>]+)>\s*$', sender or '')
    if m:
        display_name, addr = m.group(1).strip(), m.group(2).strip()
        if display_name and '@' in display_name and display_name.lower() not in addr.lower():
            out.append({'type': 'Display-name spoofing', 'value': f'"{display_name}" != {addr}', 'severity': 'high'})
    if sender and reply:
        s_dom = sender.split('@')[-1].lower().strip('> ')
        r_dom = reply.split('@')[-1].lower().strip('> ')
        if s_dom and r_dom and s_dom != r_dom:
            out.append({'type': 'Header anomaly', 'value': 'From and Reply-To domains differ', 'severity': 'high'})
    return out


def analyze(text, subject='', sender='', reply=''):
    full = f"{subject} {sender} {reply} {text or ''}"
    t = full.lower()
    hits = [p for p in SUSPICIOUS if p in t]
    rule_score = sum(SEVERITY_WEIGHT[h] for h in hits)
    if 'http://' in t:
        rule_score += 10
    caps_ratio = sum(1 for c in subject if c.isupper()) / max(1, len(subject))
    if len(subject) > 6 and caps_ratio > 0.6:
        rule_score += 8
    if subject.count('!') >= 2:
        rule_score += 5
    rule = min(90, rule_score)

    if ML:
        vec = VEC.transform([t])
        p_lr = float(LR.predict_proba(vec)[0][THREAT_IDX_LR])
        p_nb = float(NB.predict_proba(vec)[0][THREAT_IDX_NB])
        prob = (p_lr + p_nb) / 2
        ml = round(prob * 100, 1)
        ml_label = 'THREAT' if prob >= 0.5 else 'SAFE'
        top_terms = top_contributing_terms(t)
    else:
        ml, ml_label, top_terms = 50.0, 'UNKNOWN', []

    risk = min(100, round(0.55 * rule + 0.45 * ml))
    label = 'CRITICAL' if risk >= 80 else 'HIGH' if risk >= 60 else 'MEDIUM' if risk >= 35 else 'LOW'

    urls, ips, emails = extract(text)
    findings = []
    for h in hits:
        findings.append({'type': 'Suspicious phrase', 'value': h, 'severity': 'high' if SEVERITY_WEIGHT[h] >= 6 else 'medium'})
    if ips:
        findings.append({'type': 'IP indicator', 'value': ', '.join(ips), 'severity': 'medium'})
    findings += url_findings(urls)
    findings += sender_findings(sender, reply)
    if caps_ratio > 0.6 and len(subject) > 6:
        findings.append({'type': 'Excessive capitalization in subject', 'value': subject, 'severity': 'low'})

    return dict(risk=risk, label=label, ml_probability=ml, ml_label=ml_label,
                urls=urls, ips=ips, emails=emails, findings=findings, top_features=top_terms)


def save_result(subject, sender, raw, result):
    aid = 'TL-' + uuid.uuid4().hex[:10].upper()
    # Only one writer touches the DB at a time now.
    with DB_LOCK:
        c = db()
        try:
            c.execute('INSERT INTO analyses VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)', (
                aid, datetime.now().strftime('%Y-%m-%d %H:%M:%S'), subject, sender, result['label'],
                result['risk'], result['ml_probability'], json.dumps(result['urls']), json.dumps(result['ips']),
                json.dumps(result['emails']), json.dumps(result['findings']), raw, json.dumps(result.get('top_features', []))
            ))
            c.commit()
        finally:
            c.close()
    result['analysis_id'] = aid
    result['raw'] = raw
    result['subject'] = subject
    result['sender'] = sender
    return result


# ---------------------------------------------------------------------------
# Any unhandled exception anywhere in the app now returns JSON instead of
# Flask's default HTML error page. Without this, the frontend's
# `response.json()` call would fail with "Unexpected token '<' ... is not
# valid JSON" whenever a route crashed (e.g. a transient DB lock, an
# expired Gmail token, etc).
# ---------------------------------------------------------------------------
@app.errorhandler(Exception)
def handle_any_error(e):
    from werkzeug.exceptions import HTTPException
    if isinstance(e, HTTPException):
        return jsonify(error=e.description), e.code
    app.logger.exception('Unhandled error')
    return jsonify(error=str(e) or 'Internal server error'), 500


@app.route('/')
def home():
    return render_template('index.html', gmail_enabled=GMAIL_ENABLED)


@app.post('/api/analyze')
def api_analyze():
    data = request.get_json(silent=True) or {}
    subject = data.get('subject', '')
    sender = data.get('sender', '')
    reply = data.get('reply', '')
    body = data.get('body', '')
    if not body.strip() and not subject.strip():
        return jsonify(error='Enter an email subject or body.'), 400
    r = analyze(body, subject, sender, reply)
    return jsonify(save_result(subject, sender, body, r))


@app.post('/api/analyze-eml')
def api_eml():
    f = request.files.get('file')
    if not f:
        return jsonify(error='Choose an .eml file.'), 400
    msg = BytesParser(policy=policy.default).parse(f.stream)
    subject = str(msg.get('Subject', ''))
    sender = str(msg.get('From', ''))
    reply = str(msg.get('Reply-To', ''))
    body = msg.get_body(preferencelist=('plain', 'html'))
    text = body.get_content() if body else ''
    headers = {k: str(v) for k, v in msg.items()}
    auth = headers.get('Authentication-Results', '')
    findings = []
    if auth and re.search(r'spf=(fail|softfail)|dkim=(fail|none)|dmarc=(fail|none)', auth, re.I):
        findings.append({'type': 'Authentication failure', 'value': auth[:300], 'severity': 'high'})
    attachments = []
    for part in msg.iter_attachments():
        fname = part.get_filename() or ''
        attachments.append(fname)
        if re.search(r'\.(exe|scr|bat|js|vbs|jar|zip|iso)$', fname, re.I):
            findings.append({'type': 'Risky attachment type', 'value': fname, 'severity': 'high'})
    r = analyze(text, subject, sender, reply)
    r['findings'] = findings + r['findings']
    r['headers'] = headers
    r['attachments'] = attachments
    r['body_preview'] = text[:4000]
    return jsonify(save_result(subject, sender, text, r))


@app.get('/api/history')
def history():
    c = db()
    rows = c.execute('SELECT id,created,subject,sender,label,risk,ml_probability FROM analyses ORDER BY created DESC LIMIT 50').fetchall()
    c.close()
    return jsonify([dict(x) for x in rows])


@app.get('/api/stats')
def stats():
    c = db()
    rows = c.execute('SELECT created, risk FROM analyses ORDER BY created ASC LIMIT 200').fetchall()
    c.close()
    return jsonify([{'created': r['created'], 'risk': r['risk']} for r in rows])


@app.get('/api/report/<aid>')
def report(aid):
    c = db()
    row = c.execute('SELECT * FROM analyses WHERE id=?', (aid,)).fetchone()
    c.close()
    if not row:
        return jsonify(error='Report not found'), 404
    d = dict(row)
    d['urls'] = json.loads(d['urls'])
    d['ips'] = json.loads(d['ips'])
    d['emails'] = json.loads(d['emails'])
    d['findings'] = json.loads(d['findings'])
    d['top_features'] = json.loads(d.get('top_features') or '[]')
    return jsonify(d)


@app.get('/api/export/<aid>')
def export(aid):
    fmt = request.args.get('format', 'json')
    c = db()
    row = c.execute('SELECT * FROM analyses WHERE id=?', (aid,)).fetchone()
    c.close()
    if not row:
        return jsonify(error='Report not found'), 404
    d = dict(row)
    if fmt == 'txt':
        lines = [
            f"ThreatLens Forensic Report - {d['id']}", '=' * 50,
            f"Generated: {d['created']}", f"Subject: {d['subject']}", f"Sender: {d['sender']}",
            f"Risk Score: {d['risk']}% ({d['label']})", f"ML Probability: {d['ml_probability']}%", '',
            'Findings:',
        ]
        for f in json.loads(d['findings']):
            lines.append(f"  - [{f['severity'].upper()}] {f['type']}: {f['value']}")
        lines += ['', 'Indicators of Compromise:', f"  URLs: {', '.join(json.loads(d['urls'])) or 'none'}",
                  f"  IPs: {', '.join(json.loads(d['ips'])) or 'none'}",
                  f"  Emails: {', '.join(json.loads(d['emails'])) or 'none'}"]
        buf = io.BytesIO('\n'.join(lines).encode())
        return send_file(buf, mimetype='text/plain', as_attachment=True, download_name=f'{aid}.txt')
    buf = io.BytesIO(json.dumps(d, indent=2).encode())
    return send_file(buf, mimetype='application/json', as_attachment=True, download_name=f'{aid}.json')


@app.get('/api/geo/<ip>')
def geo(ip):
    import urllib.request
    try:
        with urllib.request.urlopen('https://ipwho.is/' + ip, timeout=6) as x:
            data = json.loads(x.read().decode())
        return jsonify(data)
    except Exception:
        return jsonify(error='Geo lookup unavailable. Check internet connection.'), 502


@app.post('/api/demo')
def demo():
    subject = 'URGENT: Security Alert - Verify Your Account'
    sender = '"PayPal Support" <security-alert@example-mail.com>'
    body = ('Your account will be suspended immediately. Verify your password and click here: '
            'http://secure-login.example.com/verify. If you do not confirm, access will be disabled.')
    return jsonify(save_result(subject, sender, body, analyze(body, subject, sender, '')))


# ---------------------------------------------------------------------------
# Optional Gmail integration. Fully feature-flagged: if the google-auth
# libraries or a credentials.json are missing, GMAIL_ENABLED is False, no
# gmail routes do anything unexpected, and the rest of the app is completely
# unaffected. See README.txt for setup steps.
# ---------------------------------------------------------------------------
@app.get('/api/gmail/alerts')
def gmail_alerts_list():
    c = db()
    rows = c.execute('SELECT * FROM gmail_alerts ORDER BY created DESC LIMIT 100').fetchall()
    c.close()
    return jsonify([dict(r) for r in rows])


@app.get('/api/gmail/alerts/unseen-count')
def gmail_alerts_unseen_count():
    c = db()
    n = c.execute('SELECT COUNT(*) n FROM gmail_alerts WHERE seen=0').fetchone()['n']
    c.close()
    return jsonify(count=n)


@app.post('/api/gmail/alerts/<aid>/dismiss')
def gmail_alert_dismiss(aid):
    with DB_LOCK:
        c = db()
        try:
            c.execute('UPDATE gmail_alerts SET seen=1 WHERE id=?', (aid,))
            c.commit()
        finally:
            c.close()
    return jsonify(ok=True)


@app.post('/api/gmail/alerts/dismiss-all')
def gmail_alerts_dismiss_all():
    with DB_LOCK:
        c = db()
        try:
            c.execute('UPDATE gmail_alerts SET seen=1 WHERE seen=0')
            c.commit()
        finally:
            c.close()
    return jsonify(ok=True)


# ---------------------------------------------------------------------------
# Optional email notifications: in addition to the PC alarm, send yourself
# an email whenever a risky message is detected. Stored locally in a plain
# JSON file (never shown back to the frontend once saved) — this file lives
# only on this computer and holds a Gmail App Password, so never share it.
# ---------------------------------------------------------------------------
NOTIFY_CONFIG_PATH = os.path.join(BASE, 'notify_config.json')


def _load_notify_config():
    if os.path.exists(NOTIFY_CONFIG_PATH):
        try:
            with open(NOTIFY_CONFIG_PATH) as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def _send_alert_email(subject, sender, risk, label):
    cfg = _load_notify_config()
    if not cfg.get('enabled'):
        return
    email_from, app_password = cfg.get('email'), cfg.get('app_password')
    email_to = cfg.get('to') or email_from
    if not email_from or not app_password:
        return
    try:
        import smtplib
        from email.mime.text import MIMEText
        body = (f"ThreatLens flagged a risky email in your inbox.\n\n"
                f"Subject: {subject}\nFrom: {sender}\nRisk: {risk}% ({label})\n\n"
                f"Open ThreatLens (http://127.0.0.1:5000) to review it.")
        msg = MIMEText(body)
        msg['Subject'] = f'[ThreatLens Alert] {label} risk email detected ({risk}%)'
        msg['From'] = email_from
        msg['To'] = email_to
        with smtplib.SMTP_SSL('smtp.gmail.com', 465, timeout=10) as server:
            server.login(email_from, app_password)
            server.sendmail(email_from, [email_to], msg.as_string())
    except Exception:
        pass  # never let a notification failure break the background watcher


@app.get('/api/notify/config')
def notify_config_get():
    cfg = _load_notify_config()
    return jsonify(enabled=bool(cfg.get('enabled')), email=cfg.get('email', ''), to=cfg.get('to', ''))


@app.post('/api/notify/config')
def notify_config_set():
    data = request.get_json(silent=True) or {}
    cfg = _load_notify_config()
    if 'email' in data:
        cfg['email'] = data['email']
    if data.get('app_password'):
        cfg['app_password'] = data['app_password']
    if 'to' in data:
        cfg['to'] = data['to']
    if 'enabled' in data:
        cfg['enabled'] = bool(data['enabled'])
    with open(NOTIFY_CONFIG_PATH, 'w') as f:
        json.dump(cfg, f)
    return jsonify(ok=True)


GMAIL_ENABLED = False
try:
    # OAuth normally requires https. We're running on plain http://127.0.0.1
    # for local development, so allow that here. Never do this in production.
    os.environ.setdefault('OAUTHLIB_INSECURE_TRANSPORT', '1')
    from google_auth_oauthlib.flow import Flow
    from googleapiclient.discovery import build
    from google.oauth2.credentials import Credentials
    import base64

    CREDENTIALS_PATH = os.path.join(BASE, 'credentials.json')
    TOKEN_PATH = os.path.join(BASE, 'token.json')
    SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']
    GMAIL_ENABLED = os.path.exists(CREDENTIALS_PATH)

    def _redirect_uri():
        return request.url_root.rstrip('/') + '/api/gmail/oauth2callback'

    def _load_creds():
        if not os.path.exists(TOKEN_PATH):
            return None
        creds = Credentials.from_authorized_user_file(TOKEN_PATH, SCOPES)
        # Access tokens expire (~1hr). Since the watcher may run for hours
        # (e.g. overnight), refresh automatically using the refresh_token
        # instead of silently going quiet once the token expires.
        if creds and creds.expired and creds.refresh_token:
            try:
                from google.auth.transport.requests import Request as GoogleRequest
                creds.refresh(GoogleRequest())
                with open(TOKEN_PATH, 'w') as f:
                    f.write(creds.to_json())
            except Exception:
                pass
        return creds

    @app.get('/api/gmail/status')
    def gmail_status():
        if not GMAIL_ENABLED:
            return jsonify(enabled=False, connected=False)
        creds = _load_creds()
        return jsonify(enabled=True, connected=bool(creds and creds.valid))

    @app.get('/api/gmail/login')
    def gmail_login():
        flow = Flow.from_client_secrets_file(CREDENTIALS_PATH, scopes=SCOPES, redirect_uri=_redirect_uri())
        flow.autogenerate_code_verifier = True
        flow.code_verifier = None  # force a fresh PKCE verifier for this login attempt
        auth_url, state = flow.authorization_url(access_type='offline', prompt='consent')
        session['gmail_oauth_state'] = state
        session['gmail_code_verifier'] = flow.code_verifier
        return redirect(auth_url)

    @app.get('/api/gmail/oauth2callback')
    def gmail_callback():
        state = session.get('gmail_oauth_state')
        flow = Flow.from_client_secrets_file(CREDENTIALS_PATH, scopes=SCOPES, state=state, redirect_uri=_redirect_uri())
        flow.code_verifier = session.get('gmail_code_verifier')
        flow.fetch_token(authorization_response=request.url)
        creds = flow.credentials
        with open(TOKEN_PATH, 'w') as f:
            f.write(creds.to_json())
        return redirect('/#gmail-connected')

    @app.post('/api/gmail/disconnect')
    def gmail_disconnect():
        if os.path.exists(TOKEN_PATH):
            os.remove(TOKEN_PATH)
        session.pop('gmail_oauth_state', None)
        session.pop('gmail_code_verifier', None)
        return jsonify(ok=True)

    @app.get('/api/gmail/messages')
    def gmail_messages():
        creds = _load_creds()
        if not creds:
            return jsonify(error='Not connected. Connect Gmail first.'), 401
        service = build('gmail', 'v1', credentials=creds)
        results = service.users().messages().list(userId='me', maxResults=15, labelIds=['INBOX']).execute()
        out = []
        for m in results.get('messages', []):
            msg = service.users().messages().get(userId='me', id=m['id'], format='metadata',
                                                   metadataHeaders=['Subject', 'From']).execute()
            headers = {h['name']: h['value'] for h in msg['payload']['headers']}
            out.append({'id': m['id'], 'subject': headers.get('Subject', '(no subject)'),
                        'from': headers.get('From', ''), 'snippet': msg.get('snippet', '')})
        return jsonify(out)

    def _walk_body(part):
        if part.get('mimeType', '').startswith('text/') and 'data' in part.get('body', {}):
            return base64.urlsafe_b64decode(part['body']['data']).decode('utf-8', 'ignore')
        for p in part.get('parts', []) or []:
            t = _walk_body(p)
            if t:
                return t
        return ''

    @app.post('/api/gmail/analyze/<msg_id>')
    def gmail_analyze(msg_id):
        creds = _load_creds()
        if not creds:
            return jsonify(error='Not connected. Connect Gmail first.'), 401
        service = build('gmail', 'v1', credentials=creds)
        msg = service.users().messages().get(userId='me', id=msg_id, format='full').execute()
        headers = {h['name']: h['value'] for h in msg['payload']['headers']}
        subject, sender = headers.get('Subject', ''), headers.get('From', '')
        reply = headers.get('Reply-To', '')
        body = _walk_body(msg['payload'])
        r = analyze(body, subject, sender, reply)
        return jsonify(save_result(subject, sender, body, r))

    # -----------------------------------------------------------------------
    # Live inbox monitoring: a background thread polls the connected Gmail
    # inbox every GMAIL_POLL_SECONDS. Any newly-seen message is analyzed the
    # same way as everything else; if it scores at/above ALERT_RISK_THRESHOLD
    # it's logged as an alert and a local alarm sound is played, so a threat
    # that arrives while you're away (or asleep) is waiting for you to review
    # instead of getting missed.
    # -----------------------------------------------------------------------
    ALERT_RISK_THRESHOLD = 60
    # Check Gmail frequently during local development. Override with GMAIL_POLL_SECONDS if needed.
    POLL_INTERVAL_SECONDS = int(os.environ.get('GMAIL_POLL_SECONDS', '10'))

    def _play_alarm():
        try:
            import winsound
            for _ in range(3):
                winsound.Beep(1000, 400)
                time.sleep(0.15)
        except Exception:
            try:
                print('\a', flush=True)  # fallback: terminal bell on non-Windows
            except Exception:
                pass

    def _gmail_poll_once():
        creds = _load_creds()
        if not creds or not creds.valid:
            print('⚠️ Gmail watcher: Gmail is not connected or token is invalid.', flush=True)
            return
        service = build('gmail', 'v1', credentials=creds)
        results = service.users().messages().list(userId='me', maxResults=10, labelIds=['INBOX']).execute()
        with DB_LOCK:
            c = db()
            try:
                processed = {r['msg_id'] for r in c.execute('SELECT msg_id FROM gmail_processed').fetchall()}
                new_msg_ids = [m['id'] for m in results.get('messages', []) if m['id'] not in processed]
            finally:
                c.close()

        # Fetch/analyze each new message OUTSIDE the lock (network calls are
        # slow) — save_result() takes the lock itself only for the quick
        # write, so the lock is held for the shortest time possible.
        for mid in new_msg_ids:
            msg = service.users().messages().get(userId='me', id=mid, format='full').execute()
            headers = {h['name']: h['value'] for h in msg['payload']['headers']}
            subject, sender = headers.get('Subject', ''), headers.get('From', '')
            reply = headers.get('Reply-To', '')
            body = _walk_body(msg['payload'])
            r = analyze(body, subject, sender, reply)
            save_result(subject, sender, body, r)

            with DB_LOCK:
                c = db()
                try:
                    c.execute('INSERT OR IGNORE INTO gmail_processed VALUES(?,?)',
                               (mid, datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
                    if r['risk'] >= ALERT_RISK_THRESHOLD:
                        aid = 'AL-' + uuid.uuid4().hex[:8].upper()
                        c.execute('INSERT OR IGNORE INTO gmail_alerts VALUES(?,?,?,?,?,?,?,0)', (
                            aid, mid, datetime.now().strftime('%Y-%m-%d %H:%M:%S'), subject, sender, r['risk'], r['label']))
                    c.commit()
                finally:
                    c.close()

            if r['risk'] >= ALERT_RISK_THRESHOLD:
                _play_alarm()
                _send_alert_email(subject, sender, r['risk'], r['label'])

    def _gmail_watcher_loop():
        print(f'📧 Gmail watcher started. Checking every {POLL_INTERVAL_SECONDS} seconds.', flush=True)
        while True:
            try:
                _gmail_poll_once()
            except Exception as e:
                # Do not silently hide Gmail/API errors while debugging.
                print(f'❌ Gmail watcher error: {type(e).__name__}: {e}', flush=True)
            time.sleep(POLL_INTERVAL_SECONDS)

except Exception:
    GMAIL_ENABLED = False

    @app.get('/api/gmail/status')
    def gmail_status_disabled():
        return jsonify(enabled=False, connected=False)


if __name__ == '__main__':
    # Start the background inbox watcher exactly once: under Flask's debug
    # reloader the module is imported by a monitor process too, and
    # WERKZEUG_RUN_MAIN is only set to 'true' inside the actual worker
    # process that serves requests, so this guard avoids two watcher threads.
    # Start the Gmail watcher only in the actual Flask worker process when
    # debug/reloader is enabled. In a normal run it starts immediately.
    is_reloader_worker = (os.environ.get('WERKZEUG_RUN_MAIN') == 'true')
    if GMAIL_ENABLED and (not app.debug or is_reloader_worker):
        threading.Thread(target=_gmail_watcher_loop, daemon=True, name='gmail-watcher').start()
    elif not GMAIL_ENABLED:
        print('⚠️ Gmail integration is disabled. Check credentials.json and Google API packages.', flush=True)

    app.run(debug=True, host='127.0.0.1', port=5000)