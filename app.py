from flask import Flask, request, render_template_string, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import inspect, text
from datetime import datetime
import re

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///scamshield.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)


# =============== DATABASE ===============

class ScanHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    message = db.Column(db.Text, nullable=False)
    result = db.Column(db.String(30), nullable=False)
    confidence = db.Column(db.Float, nullable=False, default=0.0)
    scan_time = db.Column(db.DateTime, nullable=False, default=datetime.now)


# =============== DETECTION ENGINE ===============
# Explainable, rule-based detector.
# This is NOT a trained machine-learning model.

RULES = [
    (r"\b(send|share|tell|give|provide)\s+(?:me\s+)?(?:your\s+)?(?:an?\s+)?(?:otp|one.time.password)\b",
     5, "Request for OTP"),
    (r"\b(?:otp|verification code)\b.{0,35}\b(?:share|send|tell|give|claim)\b",
     5, "OTP-related request"),
    (r"\b(?:upi pin|atm pin|cvv|bank password)\b",
     5, "Sensitive banking information"),
    (r"\b(?:password|login code)\b.{0,30}\b(?:send|share|verify|reply)\b",
     4, "Request for credentials"),
    (r"\b(?:pay|transfer|send)\s+(?:money|cash|fee|payment)\b.{0,45}\b(?:immediately|now|urgent|prize|reward)\b",
     4, "Urgent payment request"),
    (r"\b(?:account|bank account)\b.{0,35}\b(?:blocked|suspended|locked|closed)\b",
     3, "Account threat"),
    (r"\b(?:free prize|claim your prize|won a lottery|lottery winner)\b",
     4, "Prize or lottery claim"),
    (r"\b(?:claim|win|won)\b.{0,45}\b(?:prize|reward|cash|money|gift|iphone|phone)\b",
     3, "Prize or reward claim"),
    (r"\b(?:click|tap|open)\s+(?:this\s+)?(?:link|here|below)\b",
     2, "Link-click request"),
    (r"\b(?:urgent|immediately|act now|limited time|expires today)\b",
     2, "Urgency or pressure"),
    (r"\b(?:account|sim|card)\b.{0,30}\b(?:will be blocked|will be suspended|will expire)\b",
     3, "Threat of account suspension"),
    (r"\b(?:verify|update|confirm)\s+(?:your\s+)?(?:bank|account|kyc|identity)\b",
     2, "Verification request"),
    (r"\b(?:remote access|screen sharing app|install anydesk)\b",
     4, "Remote access request"),
    (r"\b(?:gift card|processing fee|registration fee)\b",
     2, "Potential advance-fee warning"),
    (r"\b(?:police|arrest|legal action)\b.{0,40}\b(?:pay|transfer|fee|money)\b",
     4, "Threat combined with payment"),
    (r"https?://\S+|www\.\S+",
     1, "Contains a URL"),
]

def scan_message(message):
    normalized = re.sub(r"\s+", " ", message.lower()).strip()
    findings = []
    score = 0

    for pattern, weight, description in RULES:
        if re.search(pattern, normalized, re.IGNORECASE):
            score += weight
            findings.append(description)

    # A single very serious indicator can trigger high risk.
    serious = any(
        term in normalized
        for term in (
            "send your otp", "send a otp", "share your otp",
            "upi pin", "atm pin", "bank password"
        )
    )

    if serious or score >= 7:
        level = "High Risk"
        advice = (
            "Do not share OTPs, PINs or passwords. "
            "Verify the sender using an official channel."
        )
    elif score >= 4:
        level = "Medium Risk"
        advice = (
            "Be careful. Verify the message independently "
            "before clicking links or sending money."
        )
    elif score >= 1:
        level = "Low Risk"
        advice = (
            "A warning sign was found. Check the sender and "
            "the message context carefully."
        )
    else:
        level = "Normal"
        advice = (
            "No configured warning patterns matched. "
            "This does not prove the message is safe."
        )

    # Heuristic indicator score, NOT a probability.
    risk_score = min(score * 10, 100)

    if serious:
        risk_score = max(risk_score, 80)

    return level, risk_score, findings, advice


# =============== DATABASE MIGRATION ===============

with app.app_context():
    db.create_all()

    columns = [
        column["name"]
        for column in inspect(db.engine).get_columns("scan_history")
    ]

    if "scan_time" not in columns:
        with db.engine.begin() as connection:
            connection.execute(text(
                "ALTER TABLE scan_history ADD COLUMN scan_time DATETIME"
            ))
            connection.execute(text(
                "UPDATE scan_history SET scan_time = CURRENT_TIMESTAMP "
                "WHERE scan_time IS NULL"
            ))


# =============== STYLISH UI ===============

PAGE = r"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ScamShield AI | Ansari Arif</title>
<style>
:root {
 --bg:#080d19; --panel:#121d31; --green:#5cffb2;
 --cyan:#55ddff; --muted:#a8b6cc; --line:#30405a;
}
* {box-sizing:border-box}
body {
 margin:0; color:#f4f7ff; font-family:Segoe UI,Arial,sans-serif;
 background:radial-gradient(ellipse at 10% 5%,#16434c,transparent 38%),
 radial-gradient(ellipse at 90% 25%,#292253,transparent 38%),
 linear-gradient(145deg,#080d19,#10182b 65%,#090e1b);
 background-attachment:fixed; min-height:100vh;
}
header {
 text-align:center; padding:30px 15px 23px;
 background:#080d19c9; border-bottom:1px solid #ffffff20;
 backdrop-filter:blur(16px);
}
.brand {display:flex;align-items:center;justify-content:center;gap:12px}
.shield {font-size:42px;filter:drop-shadow(0 0 15px #5cffb277);
 animation:float 3.5s ease-in-out infinite}
h1 {
 margin:0;font-size:clamp(28px,5vw,43px);font-weight:850;
 letter-spacing:-1.5px;background:linear-gradient(100deg,#fff,#5cffb2,#55ddff);
 -webkit-background-clip:text;background-clip:text;color:transparent;
}
.tagline {color:var(--muted);margin:12px 0}
.creator {
 display:inline-block;color:var(--green);padding:7px 14px;
 border:1px solid #5cffb24d;background:#5cffb20d;border-radius:30px;
 font-size:13px;
}
nav {display:flex;justify-content:center;gap:10px;flex-wrap:wrap;margin-top:19px}
nav a {
 color:#e5efff;text-decoration:none;border:1px solid var(--line);
 border-radius:10px;padding:10px 16px;transition:.25s;
}
nav a:hover {border-color:var(--green);color:var(--green);transform:translateY(-3px)}
.container {width:min(920px,100%);padding:0 16px;margin:32px auto}
.card {
 padding:clamp(20px,4vw,32px);margin-bottom:23px;border:1px solid #ffffff20;
 border-radius:21px;
 background:linear-gradient(145deg,#1c2c46e8,#101a2deF);
 box-shadow:0 22px 50px #0004,inset 0 1px #ffffff0b;
 transition:transform .3s,border-color .3s,box-shadow .3s;
 animation:appear .5s ease both;
}
.card:hover {transform:perspective(1000px) translateY(-4px);
 border-color:#5cffb255;box-shadow:0 25px 55px #0005,0 0 20px #5cffb20a}
h2 {margin:0 0 12px;font-size:24px}
p {line-height:1.65}
.muted,.description {color:var(--muted)}
textarea {
 width:100%;min-height:155px;resize:vertical;padding:15px;
 color:#fff;background:#080f1de8;border:1px solid #3a4b68;
 border-radius:13px;font:inherit;outline:none;line-height:1.6;
}
textarea:focus {border-color:var(--green);box-shadow:0 0 0 3px #5cffb218}
button,.button {
 display:inline-block;padding:13px 19px;margin-top:15px;border:0;
 border-radius:10px;font-weight:750;cursor:pointer;text-decoration:none;
 color:#062318;background:linear-gradient(110deg,#5cffb2,#66e8d6);
 box-shadow:0 8px 23px #5cffb220;transition:.2s;
}
button:hover,.button:hover {transform:translateY(-3px);box-shadow:0 12px 28px #5cffb233}
.danger {color:#fff;background:linear-gradient(110deg,#f34d69,#c82c52)}
.result {font-size:28px;font-weight:850;margin:12px 0}
.High-Risk {color:#ff657d}
.Medium-Risk {color:#ffb45d}
.Low-Risk {color:#ffe17a}
.Normal {color:var(--green)}
.scorebar {height:9px;background:#08101f;border-radius:20px;overflow:hidden;margin:12px 0}
.scorefill {height:100%;border-radius:20px;background:linear-gradient(90deg,#5cffb2,#ffe17a,#ff657d)}
.pill {display:inline-block;padding:7px 12px;border-radius:30px;
 background:#ffffff0a;border:1px solid #ffffff1a;font-size:12px;color:#dce8fa;margin:4px}
.table-wrap {overflow-x:auto;border:1px solid #ffffff1b;border-radius:12px;margin-top:18px}
table {border-collapse:collapse;width:100%;min-width:700px}
th,td {padding:12px;text-align:left;border-bottom:1px solid #ffffff17;
 font-size:13px;overflow-wrap:anywhere;line-height:1.5}
th {color:var(--green);background:#5cffb20c}
footer {margin-top:48px;padding:25px;text-align:center;border-top:1px solid #ffffff20;
 color:var(--muted);line-height:1.9;background:#080d1980}
footer strong {color:var(--green)}
@keyframes float {0%,100%{transform:translateY(0)}50%{transform:translateY(-6px)}}
@keyframes appear {from{opacity:0;transform:translateY(12px)}to{opacity:1;transform:translateY(0)}}
@media(max-width:600px) {
 .container{margin:22px auto;padding:0 12px}
 .card{border-radius:16px}
 nav a{padding:9px 12px}
 button,.button{width:100%;text-align:center}
}
@media(prefers-reduced-motion:reduce) {
 *,*::before,*::after{animation:none!important;transition:none!important}
}
</style>
</head>
<body>
<header>
 <div class="brand"><span class="shield">🛡️</span><h1>ScamShield AI</h1></div>
 <p class="tagline">Smart Message Scam Detection System</p>
 <div class="creator">✦ Created by: Ansari Arif ✦</div>
 <nav>
  <a href="{{ url_for('home') }}">⌂ Home</a>
  <a href="{{ url_for('history') }}">▤ Scan History</a>
 </nav>
</header>

<main class="container">
{% if page == 'home' %}
 <section class="card">
  <h2>🔍 Check a Message</h2>
  <p class="description">Inspect a message for common scam warning signs.</p>
  <form method="POST" action="{{ url_for('home') }}">
   <label for="message">Your message</label>
   <textarea id="message" name="message" required maxlength="10000"
    placeholder="Paste an SMS, email or message here...">{{ message }}</textarea>
   <button type="submit">⚡ Scan Message</button>
  </form>
 </section>
 {% if result %}
 <section class="card">
  <h2>📊 Scan Result</h2>
  <div class="result {{ result|replace(' ', '-') }}">{{ result }}</div>
  <div>Heuristic risk indicator: <strong>{{ risk_score }}/100</strong></div>
  <div class="scorebar"><div class="scorefill" style="width:{{ risk_score }}%"></div></div>
  <p>{{ advice }}</p>
  <h3>Detection signals</h3>
  {% if findings %}
   {% for finding in findings %}<span class="pill">{{ finding }}</span>{% endfor %}
  {% else %}
   <p class="muted">No configured warning patterns matched.</p>
  {% endif %}
  <p class="muted" style="font-size:12px">
   Educational rule-based analysis, not a trained ML model.
   The score is not a probability; results can be wrong.
  </p>
 </section>
 {% endif %}

 <section class="card">
  <h2>🧭 Risk Guide</h2>
  <p class="High-Risk"><strong>High Risk:</strong> serious indicators or several warning signs.</p>
  <p class="Medium-Risk"><strong>Medium Risk:</strong> multiple suspicious patterns.</p>
  <p class="Low-Risk"><strong>Low Risk:</strong> a limited warning indicator.</p>
  <p class="Normal"><strong>Normal:</strong> no configured warning patterns matched.</p>
 </section>

{% elif page == 'history' %}
 <section class="card">
  <h2>📋 Scan History</h2>
  <p class="muted">Previously scanned messages and their results.</p>
  <span class="pill">Total scans: {{ records|length }}</span>
  {% if records %}
   <form method="POST" action="{{ url_for('delete_history') }}"
    onsubmit="return confirm('Delete all scan history? This cannot be undone.');">
    <button class="danger" type="submit">🗑 Delete All History</button>
   </form>
   <div class="table-wrap">
    <table>
     <thead><tr><th>ID</th><th>Message</th><th>Risk</th><th>Score</th><th>Date &amp; Time</th></tr></thead>
     <tbody>
     {% for item in records %}
      <tr>
       <td>{{ item.id }}</td><td>{{ item.message }}</td>
       <td class="{{ item.result|replace(' ', '-') }}">{{ item.result }}</td>
       <td>{{ item.confidence }}/100</td>
       <td>{% if item.scan_time %}{{ item.scan_time.strftime('%d-%m-%Y %I:%M %p') }}{% else %}Previously recorded{% endif %}</td>
      </tr>
     {% endfor %}
     </tbody>
    </table>
   </div>
  {% else %}
   <p class="muted">No scan history yet. Scan a message first.</p>
   <a class="button" href="{{ url_for('home') }}">Start Scanning</a>
  {% endif %}
 </section>
{% endif %}
</main>

<footer>
 <div>🛡️ <strong>ScamShield AI</strong> | Educational Project</div>
 <div>Designed and developed by <strong>Ansari Arif</strong></div>
 <div class="muted">Stay alert. Think before you click.</div>
</footer>
</body>
</html>
"""


# =============== ROUTES ===============

@app.route("/", methods=["GET", "POST"])
def home():
    message = ""
    result = None
    risk_score = 0
    findings = []
    advice = ""

    if request.method == "POST":
        message = request.form.get("message", "").strip()

        if message:
            result, risk_score, findings, advice = scan_message(message)

            record = ScanHistory(
                message=message,
                result=result,
                confidence=risk_score,
                scan_time=datetime.now()
            )
            db.session.add(record)
            db.session.commit()

    return render_template_string(
        PAGE,
        page="home",
        message=message,
        result=result,
        risk_score=risk_score,
        findings=findings,
        advice=advice
    )


@app.route("/history")
def history():
    records = ScanHistory.query.order_by(ScanHistory.id.desc()).all()
    return render_template_string(PAGE, page="history", records=records)


@app.route("/delete-history", methods=["POST"])
def delete_history():
    ScanHistory.query.delete()
    db.session.commit()
    return redirect(url_for("history"))


if __name__ == "__main__":
    app.run(debug=True)