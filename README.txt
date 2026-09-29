THREATLENS AI - FULL STACK HACKATHON PROTOTYPE (v2)

QUICK START
1. Open this folder in VS Code.
2. Open a terminal in this folder.
3. Run:
   py -m pip install -r requirements.txt
4. Run:
   py app.py
5. Open http://127.0.0.1:5000

Everything is connected: Flask backend + SQLite database + ensemble ML classifier + frontend.
Internet is required only for IP geolocation and (optionally) the Gmail feature below.
The ML dataset is a small demo dataset for a hackathon prototype, not production accuracy.


WHAT'S NEW IN V2
- Fixed an XSS hole: email subjects/senders/URLs are now escaped before being
  rendered, so a malicious email can no longer inject script into the UI.
- Fixed a bug where the "Load Demo Threat" button didn't fill the body text.
- Stronger detection engine:
  - Ensemble of Logistic Regression + Naive Bayes (more stable than one model).
  - Explainability: shows which words/phrases most influenced the score.
  - New heuristics: punycode/homograph domains, URL shorteners, suspicious
    TLDs, raw-IP links, display-name spoofing ("Support" <random@evil.com>),
    risky email attachments (.exe/.scr/.js/.zip in .eml uploads).
- Reports can now be exported as JSON or a plain-text forensic report.
- Dashboard shows a risk trend chart over your recent analyses.
- New optional "Gmail Inbox" tab (see below) to fetch real emails instead of
  copy-pasting them — completely optional and safely disabled by default.


ENABLE GMAIL AUTO-FETCH (OPTIONAL)
By default the app only lets you paste email text or upload a .eml file —
nothing about Gmail is required and nothing breaks if you skip this section.

If you want to pull real emails from a Gmail inbox directly into the analyzer:

1. Install the extra dependencies (uncomment them in requirements.txt, or run):
   py -m pip install google-auth-oauthlib google-api-python-client

2. Create OAuth credentials (one-time, free):
   a. Go to https://console.cloud.google.com/ and create a project.
   b. Enable the "Gmail API" for that project.
   c. Go to "APIs & Services > Credentials" > "Create Credentials" >
      "OAuth client ID" > Application type: "Web application".
   d. Under "Authorized redirect URIs" add:
      http://127.0.0.1:5000/api/gmail/oauth2callback
   e. Download the JSON file, rename it to `credentials.json`, and place it
      in this same project folder (next to app.py).

3. Restart the app (py app.py) and open the "Gmail Inbox" tab. Click
   "Connect Gmail", sign in, and grant read-only access. You'll then see your
   recent inbox and can click "Analyze" on any message to run it straight
   through the same detection engine used for pasted emails.

Notes:
- The app only requests the `gmail.readonly` scope — it can read messages,
  never send or delete anything.
- Google will show an "unverified app" warning on the consent screen since
  this is a personal/hackathon OAuth client — that's expected, click
  "Advanced > Go to (app name)" to proceed.
- Your OAuth token is stored locally in `token.json` in this folder. Delete
  it any time to disconnect.
- If `credentials.json` is missing, the Gmail tab just shows setup
  instructions instead of erroring — the rest of the app is unaffected.
