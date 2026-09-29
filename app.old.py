from flask import Flask, render_template, request, jsonify, send_file, session, redirect
import sqlite3, re, json, os, uuid, io
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
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    return c


def init_db():
    c = db()
    c.execute('''CREATE TABLE IF NOT EXISTS analyses(
        id TEXT PRIMARY KEY, created TEXT, subject TEXT, sender TEXT, label TEXT,
        risk INTEGER, ml_probability REAL, urls TEXT, ips TEXT, emails TEXT,
        findings TEXT, raw TEXT, top_features TEXT)''')
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
    c = db()
    c.execute('INSERT INTO analyses VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)', (
        aid, datetime.now().strftime('%Y-%m-%d %H:%M:%S'), subject, sender, result['label'],
        result['risk'], result['ml_probability'], json.dumps(result['urls']), json.dumps(result['ips']),
        json.dumps(result['emails']), json.dumps(result['findings']), raw, json.dumps(result.get('top_features', []))
    ))
    c.commit()
    c.close()
    result['analysis_id'] = aid
    result['raw'] = raw
    result['subject'] = subject
    result['sender'] = sender
    return result


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
GMAIL_ENABLED = False
try:
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
        if os.path.exists(TOKEN_PATH):
            return Credentials.from_authorized_user_file(TOKEN_PATH, SCOPES)
        return None

    @app.get('/api/gmail/status')
    def gmail_status():
        if not GMAIL_ENABLED:
            return jsonify(enabled=False, connected=False)
        creds = _load_creds()
        return jsonify(enabled=True, connected=bool(creds and creds.valid))

    @app.get('/api/gmail/login')
    def gmail_login():
        flow = Flow.from_client_secrets_file(CREDENTIALS_PATH, scopes=SCOPES, redirect_uri=_redirect_uri())
        auth_url, state = flow.authorization_url(access_type='offline', prompt='consent')
        session['gmail_oauth_state'] = state
        return redirect(auth_url)

    @app.get('/api/gmail/oauth2callback')
    def gmail_callback():
        state = session.get('gmail_oauth_state')
        flow = Flow.from_client_secrets_file(CREDENTIALS_PATH, scopes=SCOPES, state=state, redirect_uri=_redirect_uri())
        flow.fetch_token(authorization_response=request.url)
        creds = flow.credentials
        with open(TOKEN_PATH, 'w') as f:
            f.write(creds.to_json())
        return redirect('/#gmail-connected')

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

        def walk(part):
            if part.get('mimeType', '').startswith('text/') and 'data' in part.get('body', {}):
                return base64.urlsafe_b64decode(part['body']['data']).decode('utf-8', 'ignore')
            for p in part.get('parts', []) or []:
                t = walk(p)
                if t:
                    return t
            return ''

        body = walk(msg['payload'])
        r = analyze(body, subject, sender, reply)
        return jsonify(save_result(subject, sender, body, r))

except Exception:
    GMAIL_ENABLED = False

    @app.get('/api/gmail/status')
    def gmail_status_disabled():
        return jsonify(enabled=False, connected=False)


if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=5000)
