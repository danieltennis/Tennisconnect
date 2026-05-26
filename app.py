"""
TennisConnect — vereenvoudigde versie.

Behouden: spelers vinden, match aanvragen, open posts, chat, matches & scores,
reviews, klassementen, clubs, availability slots, blocks/reports.

Nieuw:
  * Security: sterker wachtwoord, rate-limited login, kortere JWT
  * Privacy policy & terms pagina's
  * Posting options: publieke open posts met visibility (iedereen / mijn klassegroep / nabij)
  * Post expiration: posts/aanvragen verlopen automatisch (TTL)
  * GPS density heatmap: kaart toont waar actieve spelers zitten

Geschrapt (te complex voor luie gebruiker): toernooien, achievements, friends,
activity feed, push notifications, name-reveal anonimiteit, doubles.
"""

import os, re, json, math, sqlite3, bcrypt, jwt
from datetime import datetime, timedelta
from functools import wraps
from collections import defaultdict
from flask import Flask, request, jsonify, send_from_directory, Response, render_template_string
from flask_cors import CORS

# ─── CONFIG ──────────────────────────────────────────────────────────────────
app = Flask(__name__, static_folder="static", template_folder="templates")
CORS(app)
SECRET   = os.environ.get("TC_SECRET", "tennisconnect-secret-2026")
DB_PATH  = "db/tennisconnect.db"
JWT_TTL_DAYS    = 7            # kortere sessie voor security
LOGIN_WINDOW_MIN = 15          # rate-limit venster
LOGIN_MAX_FAIL   = 5           # max foute pogingen per IP/email binnen venster
DEFAULT_POST_TTL_HOURS = 24    # standaard duur dat een open post zichtbaar blijft
MAX_OPEN_POSTS_PER_USER = 3    # spam-rem

# ─── KLASSEMENT (Tennis & Padel Vlaanderen) ──────────────────────────────────
KLASSES = ["Elite","95","90","85","80","75","70","65","60","55","50",
           "45","40","35","30","25","20","15","10","5","3","NC"]
KLASSE_GROUPS = {
    "3-15":  ["3","5","10","15"],
    "15-35": ["15","20","25","30","35"],
    "45-90": ["45","50","55","60","65","70","75","80","85","90"],
}
def klasse_group(k):
    for g, kl in KLASSE_GROUPS.items():
        if k in kl: return g
    return "3-15"

# ─── DB ──────────────────────────────────────────────────────────────────────
def get_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH); conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    return conn

def init_db():
    db = get_db()
    db.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL, email TEXT UNIQUE NOT NULL, password TEXT NOT NULL,
        klasse TEXT DEFAULT '3', punten INTEGER DEFAULT 0,
        city TEXT DEFAULT '', lat REAL DEFAULT 0, lng REAL DEFAULT 0,
        available INTEGER DEFAULT 0, photo TEXT DEFAULT '', bio TEXT DEFAULT '',
        no_show_count INTEGER DEFAULT 0,
        last_seen TEXT DEFAULT (datetime('now')),
        created_at TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        from_id INTEGER NOT NULL,
        to_id INTEGER NOT NULL DEFAULT 0,        -- 0 = open post (geen ontvanger)
        datum TEXT, tijdstip TEXT, club TEXT, bericht TEXT,
        status TEXT DEFAULT 'pending',           -- pending / accepted / declined / expired / cancelled
        decline_reason TEXT DEFAULT '',
        visibility TEXT DEFAULT 'direct',        -- direct / everyone / klasse / nearby
        expires_at TEXT,                         -- ISO datum waarna automatisch expired
        accepted_by INTEGER DEFAULT NULL,        -- bij open post: welke speler accepteerde
        created_at TEXT DEFAULT (datetime('now'))
    );
    CREATE INDEX IF NOT EXISTS idx_req_to ON requests(to_id, status);
    CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        from_id INTEGER NOT NULL, to_id INTEGER NOT NULL,
        body TEXT NOT NULL,
        created_at TEXT DEFAULT (datetime('now')),
        read_at TEXT DEFAULT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_msg_pair ON messages(from_id, to_id, created_at);
    CREATE TABLE IF NOT EXISTS matches (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        player1_id INTEGER NOT NULL, player2_id INTEGER NOT NULL,
        score TEXT, winner_id INTEGER, club TEXT, datum TEXT, klasse TEXT,
        request_id INTEGER DEFAULT NULL,
        created_at TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS clubs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL, city TEXT, lat REAL, lng REAL,
        courts INTEGER DEFAULT 4, address TEXT
    );
    CREATE TABLE IF NOT EXISTS availability_slots (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL, day_of_week INTEGER NOT NULL,
        start_hour INTEGER NOT NULL, end_hour INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_slots_user ON availability_slots(user_id);
    CREATE TABLE IF NOT EXISTS reviews (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        match_id INTEGER NOT NULL, reviewer_id INTEGER NOT NULL, reviewee_id INTEGER NOT NULL,
        on_time INTEGER DEFAULT 1, fair_play INTEGER DEFAULT 1, good_match INTEGER DEFAULT 1,
        comment TEXT DEFAULT '', no_show INTEGER DEFAULT 0,
        created_at TEXT DEFAULT (datetime('now')),
        UNIQUE(match_id, reviewer_id)
    );
    CREATE TABLE IF NOT EXISTS blocks (
        blocker_id INTEGER NOT NULL, blocked_id INTEGER NOT NULL,
        created_at TEXT DEFAULT (datetime('now')),
        PRIMARY KEY(blocker_id, blocked_id)
    );
    CREATE TABLE IF NOT EXISTS reports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        reporter_id INTEGER NOT NULL, reported_id INTEGER NOT NULL,
        reason TEXT, details TEXT,
        created_at TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS login_attempts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT, email TEXT, success INTEGER DEFAULT 0,
        attempted_at TEXT DEFAULT (datetime('now'))
    );
    CREATE INDEX IF NOT EXISTS idx_login_ip ON login_attempts(ip, attempted_at);
    CREATE TABLE IF NOT EXISTS friendships (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        requester_id INTEGER NOT NULL, addressee_id INTEGER NOT NULL,
        status TEXT DEFAULT 'pending',
        created_at TEXT DEFAULT (datetime('now')),
        UNIQUE(requester_id, addressee_id)
    );
    CREATE INDEX IF NOT EXISTS idx_friend_pair ON friendships(requester_id, addressee_id);
    """)

    # ── Migraties voor bestaande DB's ────────────────────────────────────────
    def _cols(table):
        return [r[1] for r in db.execute(f"PRAGMA table_info({table})").fetchall()]
    def _add(table, col, ddl):
        if col not in _cols(table):
            try: db.execute(f"ALTER TABLE {table} ADD COLUMN {ddl}")
            except: pass
    _add("requests", "visibility",   "visibility TEXT DEFAULT 'direct'")
    _add("requests", "expires_at",   "expires_at TEXT")
    _add("requests", "accepted_by",  "accepted_by INTEGER DEFAULT NULL")
    _add("users",    "last_seen",    "last_seen TEXT")
    try: db.execute("UPDATE users SET last_seen=datetime('now') WHERE last_seen IS NULL")
    except: pass
    # Openingsuren per club (standaard waarde voor alle clubs)
    _add("clubs", "opening_hours", "opening_hours TEXT")
    try:
        db.execute("UPDATE clubs SET opening_hours=? WHERE opening_hours IS NULL OR opening_hours=''",
                   ("Ma-Vr 09:00-22:00 · Za-Zo 09:00-20:00",))
    except: pass

    # Bestaande open-DB requests die nog NULL hebben voor visibility:
    try: db.execute("UPDATE requests SET visibility='direct' WHERE visibility IS NULL OR visibility=''")
    except: pass

    # Nu kolommen bestaan: index voor open-post lookups
    try: db.execute("CREATE INDEX IF NOT EXISTS idx_req_open ON requests(visibility, status, expires_at)")
    except: pass

    db.commit()

    # ── Seed clubs (idempotent) ──────────────────────────────────────────────
    try: db.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_clubs_name ON clubs(name)")
    except: pass
    # De 4 clubs die de gebruiker expliciet wil (echte adressen).
    # Formaat: (naam, stad, lat, lng, terreinen, adres, openingsuren)
    DEFHRS = "Ma-Vr 09:00-22:00 \u00b7 Za-Zo 09:00-20:00"
    REAL_CLUBS = [
        ("Oxaco Tennis", "Boechout", 51.171304, 4.488173, 12,
         "Borsbeeksesteenweg 45, 2530 Boechout", DEFHRS),
        ("TC Hove", "Hove", 51.147882, 4.469821, 8,
         "Elzenstraat 33, 2540 Hove", DEFHRS),
        ("TC Zevenbergen", "Lier", 51.146413, 4.533478, 10,
         "Antwerpsesteenweg 493, 2500 Lier", DEFHRS),
        ("Blauwe Regen", "Mortsel", 51.174281, 4.474847, 9,
         "Koeisteerthofdreef 125, 2640 Mortsel", DEFHRS),
    ]
    verified_names = [c[0] for c in REAL_CLUBS]
    # Gebruiker wil ENKEL deze clubs: verwijder al de rest.
    try:
        ph = ",".join("?" * len(verified_names))
        db.execute(f"DELETE FROM clubs WHERE name NOT IN ({ph})", verified_names)
    except Exception:
        pass
    # Upsert: zet/overschrijf de clubs met de juiste gegevens.
    for nm, city, lat, lng, courts, addr, hrs in REAL_CLUBS:
        row = db.execute("SELECT id FROM clubs WHERE name=?", (nm,)).fetchone()
        if row:
            db.execute("UPDATE clubs SET city=?,lat=?,lng=?,courts=?,address=?,opening_hours=? "
                       "WHERE name=?", (city, lat, lng, courts, addr, hrs, nm))
        else:
            db.execute("INSERT INTO clubs (name,city,lat,lng,courts,address,opening_hours) "
                       "VALUES (?,?,?,?,?,?,?)", (nm, city, lat, lng, courts, addr, hrs))
    db.commit()

    # Seed demo-users alleen als DB leeg is
    if db.execute("SELECT COUNT(*) c FROM users").fetchone()["c"] == 0:
        demo = [
            ("Sven De Wolf","sven@demo.com","demo1234","10",6,"Boechout",51.1612,4.4870,1),
            ("Laura Martens","laura@demo.com","demo1234","5",11,"Mortsel",51.1685,4.4565,1),
            ("Nathalie Huys","nathalie@demo.com","demo1234","15",4,"Hove",51.1547,4.4720,1),
            ("Koen Baert","koen@demo.com","demo1234","NC",55,"Edegem",51.1556,4.4430,1),
            ("Joris Vandenberghe","joris@demo.com","demo1234","10",9,"Kontich",51.1350,4.4495,1),
            ("An Declercq","an@demo.com","demo1234","5",18,"Berchem",51.1980,4.4205,1),
            ("Pieter Janssens","pieter@demo.com","demo1234","10",13,"Wilrijk",51.1710,4.3950,1),
            ("Sofie Vermeulen","sofie@demo.com","demo1234","3",27,"Lier",51.1300,4.5650,1),
            ("Eline Peeters","eline@demo.com","demo1234","10",8,"Boechout",51.1590,4.4910,1),
            ("Wouter Claes","wouter@demo.com","demo1234","5",24,"Mortsel",51.1670,4.4600,1),
            ("Lien Maes","lien@demo.com","demo1234","3",30,"Borsbeek",51.1960,4.4670,1),
            ("Gert Smets","gert@demo.com","demo1234","NC",48,"Schoten",51.2520,4.5000,1),
            ("Maarten De Vos","maarten@demo.com","demo1234","65",15,"Antwerpen",51.2150,4.4080,1),
            ("Inge Verbeeck","inge@demo.com","demo1234","5",12,"Mortsel",51.1665,4.4520,1),
        ]
        for name,email,pw,kl,pts,city,lat,lng,avail in demo:
            h = bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()
            db.execute(
                "INSERT INTO users (name,email,password,klasse,punten,city,lat,lng,available) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                (name,email,h,kl,pts,city,lat,lng,avail))
        db.commit()
        db.executemany(
            "INSERT INTO matches (player1_id,player2_id,score,winner_id,club,datum,klasse) "
            "VALUES (?,?,?,?,?,?,?)", [
                (1,2,"6-3, 6-4",1,"Oxaco Tennis","2026-04-24","10"),
                (1,3,"4-6, 3-6",3,"TC Hove","2026-04-19","15"),
                (1,9,"6-2, 6-1",1,"Oxaco Tennis","2026-03-29","10"),
                (1,5,"7-5, 6-4",1,"Blauwe Regen","2026-03-15","10"),
                (2,9,"6-3, 6-2",2,"TC Zevenbergen","2026-04-15","5"),
                (13,14,"6-4, 7-6",13,"Oxaco Tennis","2026-04-20","65"),
            ])
        db.executemany(
            "INSERT INTO availability_slots (user_id,day_of_week,start_hour,end_hour) VALUES (?,?,?,?)", [
                (1,1,18,21),(1,3,18,21),(1,5,9,12),(1,6,9,12),
                (2,1,17,20),(2,3,17,21),(2,6,10,13),
                (3,1,18,21),(3,4,18,21),(3,6,9,12),
                (5,0,18,21),(5,3,18,21),(5,5,10,13),
                (6,1,19,22),(6,6,14,18),
                (7,0,18,20),(7,2,18,21),(7,4,18,20),
                (9,1,18,21),(9,3,18,21),(9,5,9,12),
                (13,1,18,21),(13,4,18,21),
            ])
        db.commit()
    db.close()

# ─── HELPERS ─────────────────────────────────────────────────────────────────
def make_token(uid):
    return jwt.encode(
        {"user_id": uid, "exp": datetime.utcnow() + timedelta(days=JWT_TTL_DAYS)},
        SECRET, algorithm="HS256")

def require_auth(f):
    @wraps(f)
    def w(*a, **k):
        tok = request.headers.get("Authorization", "").replace("Bearer ", "").strip()
        if not tok: tok = request.args.get("token", "")
        if not tok: return jsonify({"error": "Niet ingelogd"}), 401
        try:
            data = jwt.decode(tok, SECRET, algorithms=["HS256"])
            request.user_id = data["user_id"]
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Sessie verlopen, log opnieuw in"}), 401
        except Exception:
            return jsonify({"error": "Ongeldige sessie"}), 401
        # Update last_seen (cheap, helps density map)
        try:
            db = get_db()
            db.execute("UPDATE users SET last_seen=datetime('now') WHERE id=?", (request.user_id,))
            db.commit(); db.close()
        except: pass
        return f(*a, **k)
    return w

def haversine(lat1, lng1, lat2, lng2):
    if any(x is None for x in [lat1, lng1, lat2, lng2]): return 9999
    R = 6371
    dlat = math.radians(lat2 - lat1); dlng = math.radians(lng2 - lng1)
    a = math.sin(dlat/2)**2 + math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) * math.sin(dlng/2)**2
    return R * 2 * math.asin(math.sqrt(a))

def row_to_dict(r): return dict(zip(r.keys(), r))

def is_blocked(db, a, b):
    return db.execute(
        "SELECT 1 FROM blocks WHERE (blocker_id=? AND blocked_id=?) OR (blocker_id=? AND blocked_id=?)",
        (a, b, b, a)).fetchone() is not None

def get_client_ip():
    return (request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
            or request.remote_addr or "0.0.0.0")

# ─── SECURITY: password rules + login rate limit ─────────────────────────────
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

def validate_password(pw: str):
    """Return None if OK, else error message."""
    if len(pw) < 8:    return "Wachtwoord moet minstens 8 tekens hebben."
    if not re.search(r"\d", pw): return "Wachtwoord moet minstens 1 cijfer bevatten."
    if pw.lower() in ("password","wachtwoord","12345678","tennis123"):
        return "Dit wachtwoord is te makkelijk te raden."
    return None

def check_login_rate(ip, email):
    """Return None if allowed, else error string."""
    db = get_db()
    since = (datetime.utcnow() - timedelta(minutes=LOGIN_WINDOW_MIN)).strftime("%Y-%m-%d %H:%M:%S")
    fails = db.execute(
        "SELECT COUNT(*) c FROM login_attempts "
        "WHERE success=0 AND attempted_at>=? AND (ip=? OR email=?)",
        (since, ip, email)).fetchone()["c"]
    db.close()
    if fails >= LOGIN_MAX_FAIL:
        return f"Te veel mislukte pogingen. Wacht {LOGIN_WINDOW_MIN} minuten."
    return None

def record_login_attempt(ip, email, success):
    db = get_db()
    db.execute("INSERT INTO login_attempts (ip,email,success) VALUES (?,?,?)",
               (ip, email, 1 if success else 0))
    # Opruimen: oude rijen weg
    db.execute("DELETE FROM login_attempts WHERE attempted_at<datetime('now','-1 day')")
    db.commit(); db.close()

# ─── POST EXPIRATION (TTL) ────────────────────────────────────────────────────
def auto_expire_posts(db):
    """Markeer requests als 'expired' wanneer expires_at gepasseerd is."""
    try:
        db.execute(
            "UPDATE requests SET status='expired' "
            "WHERE status='pending' AND expires_at IS NOT NULL AND expires_at<datetime('now')")
        db.commit()
    except: pass

# ─── AUTH ENDPOINTS ──────────────────────────────────────────────────────────
@app.route("/api/register", methods=["POST"])
def register():
    d = request.json or {}
    name  = (d.get("name") or "").strip()
    email = (d.get("email") or "").strip().lower()
    pw    = d.get("password") or ""
    klasse= d.get("klasse") or "3"
    city  = (d.get("city") or "").strip()
    if not (name and email and pw): return jsonify({"error": "Vul alle velden in"}), 400
    if not EMAIL_RE.match(email):    return jsonify({"error": "Ongeldig emailadres"}), 400
    pw_err = validate_password(pw)
    if pw_err: return jsonify({"error": pw_err}), 400
    if klasse not in KLASSES: klasse = "3"
    h = bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()
    db = get_db()
    try:
        db.execute(
            "INSERT INTO users (name,email,password,klasse,city) VALUES (?,?,?,?,?)",
            (name, email, h, klasse, city))
        db.commit()
        u = db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        return jsonify({
            "token": make_token(u["id"]),
            "user":  {"id": u["id"], "name": u["name"], "email": u["email"],
                      "klasse": u["klasse"], "punten": u["punten"]}
        })
    except sqlite3.IntegrityError:
        return jsonify({"error": "Email is al in gebruik"}), 400
    finally: db.close()

@app.route("/api/login", methods=["POST"])
def login():
    d = request.json or {}
    email = (d.get("email") or "").strip().lower()
    pw    = d.get("password") or ""
    ip    = get_client_ip()
    err = check_login_rate(ip, email)
    if err: return jsonify({"error": err}), 429
    db = get_db()
    u  = db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    db.close()
    ok = u and bcrypt.checkpw(pw.encode(), u["password"].encode())
    record_login_attempt(ip, email, bool(ok))
    if not ok: return jsonify({"error": "Verkeerd email of wachtwoord"}), 401
    return jsonify({
        "token": make_token(u["id"]),
        "user":  {"id": u["id"], "name": u["name"], "email": u["email"],
                  "klasse": u["klasse"], "punten": u["punten"],
                  "city": u["city"], "photo": u["photo"]}
    })

@app.route("/api/me", methods=["GET"])
@require_auth
def me():
    db = get_db()
    u = db.execute(
        "SELECT id,name,email,klasse,punten,city,lat,lng,available,photo,bio,no_show_count "
        "FROM users WHERE id=?", (request.user_id,)).fetchone()
    db.close()
    if not u: return jsonify({"error": "Niet gevonden"}), 404
    return jsonify(row_to_dict(u))

# ─── PROFILE ENDPOINTS ───────────────────────────────────────────────────────
@app.route("/api/me/location", methods=["PUT"])
@require_auth
def update_location():
    d = request.json or {}
    db = get_db()
    db.execute("UPDATE users SET lat=?, lng=?, city=? WHERE id=?",
               (d.get("lat", 0), d.get("lng", 0), d.get("city", ""), request.user_id))
    db.commit(); db.close()
    return jsonify({"ok": True})

@app.route("/api/me/available", methods=["PUT"])
@require_auth
def update_available():
    d = request.json or {}
    db = get_db()
    db.execute("UPDATE users SET available=? WHERE id=?",
               (1 if d.get("available") else 0, request.user_id))
    db.commit(); db.close()
    return jsonify({"ok": True})

@app.route("/api/me/klasse", methods=["PUT"])
@require_auth
def update_klasse():
    k = (request.json or {}).get("klasse", "").strip()
    if k not in KLASSES: return jsonify({"error": "Ongeldige klasse"}), 400
    db = get_db()
    db.execute("UPDATE users SET klasse=? WHERE id=?", (k, request.user_id))
    db.commit(); db.close()
    return jsonify({"ok": True, "klasse": k})

@app.route("/api/me/profile", methods=["PUT"])
@require_auth
def update_profile():
    d = request.json or {}
    bio = (d.get("bio", "") or "").strip()[:280]
    db = get_db()
    db.execute("UPDATE users SET bio=? WHERE id=?", (bio, request.user_id))
    db.commit(); db.close()
    return jsonify({"ok": True, "bio": bio})

MAX_PHOTO_BYTES = 350_000
PHOTO_MIME_RE = re.compile(r"^data:image/(jpeg|png|webp);base64,([A-Za-z0-9+/=]+)$")

@app.route("/api/me/photo", methods=["PUT"])
@require_auth
def update_photo():
    data = (request.json or {}).get("data", "").strip()
    db = get_db()
    if not data:
        db.execute("UPDATE users SET photo='' WHERE id=?", (request.user_id,))
        db.commit(); db.close()
        return jsonify({"ok": True, "cleared": True})
    if not PHOTO_MIME_RE.match(data):
        db.close(); return jsonify({"error": "Verwacht data:image/jpeg|png|webp;base64,..."}), 400
    if len(data) > MAX_PHOTO_BYTES:
        db.close(); return jsonify({"error": f"Foto te groot (max ~{MAX_PHOTO_BYTES//1000}KB)"}), 400
    db.execute("UPDATE users SET photo=? WHERE id=?", (data, request.user_id))
    db.commit(); db.close()
    return jsonify({"ok": True})

@app.route("/api/me", methods=["DELETE"])
@require_auth
def delete_me():
    """GDPR: gebruiker kan zijn account zelf verwijderen."""
    db = get_db(); uid = request.user_id
    for q in [
        "DELETE FROM availability_slots WHERE user_id=?",
        "DELETE FROM blocks WHERE blocker_id=? OR blocked_id=?",
        "DELETE FROM reviews WHERE reviewer_id=? OR reviewee_id=?",
        "DELETE FROM messages WHERE from_id=? OR to_id=?",
        "DELETE FROM requests WHERE from_id=? OR to_id=? OR accepted_by=?",
        "DELETE FROM matches WHERE player1_id=? OR player2_id=?",
        "DELETE FROM users WHERE id=?",
    ]:
        try:
            params = (uid,) * q.count("?")
            db.execute(q, params)
        except: pass
    db.commit(); db.close()
    return jsonify({"ok": True})

# ─── AVAILABILITY SLOTS ──────────────────────────────────────────────────────
def slots_overlap_hours(my_slots, other_slots):
    total = 0
    for a in my_slots:
        for b in other_slots:
            if a["day_of_week"] == b["day_of_week"]:
                lo = max(a["start_hour"], b["start_hour"])
                hi = min(a["end_hour"], b["end_hour"])
                if hi > lo: total += hi - lo
    return total

@app.route("/api/me/slots", methods=["GET"])
@require_auth
def get_my_slots():
    db = get_db()
    rows = db.execute(
        "SELECT day_of_week,start_hour,end_hour FROM availability_slots "
        "WHERE user_id=? ORDER BY day_of_week,start_hour",
        (request.user_id,)).fetchall()
    db.close()
    return jsonify([row_to_dict(r) for r in rows])

@app.route("/api/me/slots", methods=["PUT"])
@require_auth
def set_my_slots():
    slots = (request.json or {}).get("slots", [])
    db = get_db()
    db.execute("DELETE FROM availability_slots WHERE user_id=?", (request.user_id,))
    saved = 0
    for s in slots:
        try:
            d  = int(s.get("day_of_week", -1))
            sh = int(s.get("start_hour", -1))
            eh = int(s.get("end_hour", 0))
        except (TypeError, ValueError): continue
        if 0 <= d <= 6 and 0 <= sh < 24 and sh < eh <= 24:
            db.execute(
                "INSERT INTO availability_slots (user_id,day_of_week,start_hour,end_hour) "
                "VALUES (?,?,?,?)", (request.user_id, d, sh, eh))
            saved += 1
    db.commit(); db.close()
    return jsonify({"ok": True, "saved": saved})

# ─── PLAYER DISCOVERY ────────────────────────────────────────────────────────
@app.route("/api/players", methods=["GET"])
@require_auth
def players():
    radius = float(request.args.get("radius", 15))
    klasse_param = request.args.get("klasse", "all")
    online_only = request.args.get("online_only", "false").lower() == "true"
    db = get_db()
    me_row = db.execute("SELECT lat,lng FROM users WHERE id=?", (request.user_id,)).fetchone()
    my_lat, my_lng = me_row["lat"], me_row["lng"]
    blocked = {r["blocked_id"] for r in db.execute(
        "SELECT blocked_id FROM blocks WHERE blocker_id=?", (request.user_id,)).fetchall()}
    blocked_by = {r["blocker_id"] for r in db.execute(
        "SELECT blocker_id FROM blocks WHERE blocked_id=?", (request.user_id,)).fetchall()}
    excluded = blocked | blocked_by | {request.user_id}
    q = "SELECT id,name,klasse,punten,city,lat,lng,available,photo,bio FROM users WHERE id!=?"
    params = [request.user_id]
    if klasse_param and klasse_param != "all":
        kls = [k.strip() for k in klasse_param.split(",") if k.strip()]
        if kls:
            q += f" AND klasse IN ({','.join('?'*len(kls))})"
            params.extend(kls)
    if online_only: q += " AND available=1"
    rows = db.execute(q, params).fetchall()
    db.close()
    res = []
    for r in rows:
        if r["id"] in excluded: continue
        dist = haversine(my_lat, my_lng, r["lat"], r["lng"])
        if dist > radius: continue
        p = row_to_dict(r); p["dist"] = round(dist, 1)
        res.append(p)
    res.sort(key=lambda x: x["dist"])
    return jsonify(res)

# ─── DENSITY HEATMAP ─────────────────────────────────────────────────────────
@app.route("/api/density", methods=["GET"])
@require_auth
def player_density():
    """GPS heatmap-data: aggregeer actieve spelers per ~1km cel rond mij.
       Geprivatiseerd: punten worden gerond op 2 decimalen + we tonen geen namen."""
    radius = float(request.args.get("radius", 30))
    db = get_db()
    me_row = db.execute("SELECT lat,lng FROM users WHERE id=?", (request.user_id,)).fetchone()
    my_lat, my_lng = me_row["lat"], me_row["lng"]
    # Recent actief: laatste 14 dagen ingelogd OF available=1
    rows = db.execute(
        "SELECT lat,lng FROM users WHERE id!=? AND lat!=0 AND lng!=0 "
        "AND (available=1 OR last_seen>=datetime('now','-14 days'))",
        (request.user_id,)).fetchall()
    db.close()
    cells = defaultdict(int)
    for r in rows:
        if haversine(my_lat, my_lng, r["lat"], r["lng"]) > radius: continue
        key = (round(r["lat"], 2), round(r["lng"], 2))
        cells[key] += 1
    max_w = max(cells.values()) if cells else 1
    return jsonify({
        "points": [{"lat": k[0], "lng": k[1], "weight": v} for k, v in cells.items()],
        "max":    max_w
    })

# ─── CLUBS ───────────────────────────────────────────────────────────────────
@app.route("/api/clubs", methods=["GET"])
@require_auth
def clubs():
    radius = float(request.args.get("radius", 30))
    db = get_db()
    me_row = db.execute("SELECT lat,lng FROM users WHERE id=?", (request.user_id,)).fetchone()
    my_lat, my_lng = me_row["lat"], me_row["lng"]
    no_location = not my_lat and not my_lng
    rows = db.execute("SELECT * FROM clubs").fetchall()
    db.close()
    out = []
    for r in rows:
        dm = haversine(my_lat, my_lng, r["lat"], r["lng"])
        if no_location or dm <= radius:
            c = row_to_dict(r)
            c["dist_me"] = round(dm, 1) if not no_location else None
            out.append(c)
    out.sort(key=lambda x: (x["dist_me"] is None, x["dist_me"] or 0))
    return jsonify(out)

# ─── MATCH REQUESTS (direct + open posts) ────────────────────────────────────
def _ttl_to_iso(hours):
    try: h = max(1, min(168, int(hours)))   # cap 1u..7d
    except: h = DEFAULT_POST_TTL_HOURS
    return (datetime.utcnow() + timedelta(hours=h)).strftime("%Y-%m-%d %H:%M:%S")

@app.route("/api/requests/send", methods=["POST"])
@require_auth
def send_request():
    """Verzend match-aanvraag. Twee modes:
        - Direct: to_id = ID van speler
        - Open post: to_id niet meegegeven → visibility=everyone/klasse/nearby
    """
    d = request.json or {}
    to_id = d.get("to_id") or 0
    visibility = d.get("visibility", "direct")
    ttl_hours  = d.get("ttl_hours", DEFAULT_POST_TTL_HOURS)
    if visibility not in ("direct", "everyone", "klasse", "nearby"):
        visibility = "direct"
    db = get_db()
    auto_expire_posts(db)

    if to_id and to_id != request.user_id:
        # Directe aanvraag
        if is_blocked(db, request.user_id, to_id):
            db.close(); return jsonify({"error": "Je kan deze speler niet uitdagen"}), 403
        dup = db.execute(
            "SELECT id FROM requests WHERE from_id=? AND to_id=? AND status='pending'",
            (request.user_id, to_id)).fetchone()
        if dup:
            db.close(); return jsonify({"error": "Je hebt al een verzoek gestuurd"}), 400
        visibility = "direct"
    else:
        # Open post
        to_id = 0
        if visibility == "direct": visibility = "everyone"
        active = db.execute(
            "SELECT COUNT(*) c FROM requests WHERE from_id=? AND to_id=0 AND status='pending'",
            (request.user_id,)).fetchone()["c"]
        if active >= MAX_OPEN_POSTS_PER_USER:
            db.close()
            return jsonify({
                "error": f"Je hebt al {MAX_OPEN_POSTS_PER_USER} open posts. Annuleer er eerst eentje."
            }), 400

    expires_at = _ttl_to_iso(ttl_hours)
    db.execute(
        "INSERT INTO requests (from_id,to_id,datum,tijdstip,club,bericht,visibility,expires_at) "
        "VALUES (?,?,?,?,?,?,?,?)",
        (request.user_id, to_id, d.get("datum"), d.get("tijdstip"), d.get("club"),
         (d.get("bericht") or "")[:300], visibility, expires_at))
    db.commit(); db.close()
    return jsonify({"ok": True, "visibility": visibility, "expires_at": expires_at})

@app.route("/api/requests/incoming", methods=["GET"])
@require_auth
def incoming():
    db = get_db()
    auto_expire_posts(db)
    rows = db.execute("""
        SELECT r.*, u.name AS from_name, u.klasse AS from_klasse, u.photo AS from_photo,
               u.city AS from_city
          FROM requests r JOIN users u ON u.id=r.from_id
         WHERE r.to_id=? AND r.status='pending'
         ORDER BY r.created_at DESC
    """, (request.user_id,)).fetchall()
    db.close()
    return jsonify([row_to_dict(r) for r in rows])

@app.route("/api/requests/outgoing", methods=["GET"])
@require_auth
def outgoing():
    db = get_db()
    auto_expire_posts(db)
    rows = db.execute("""
        SELECT r.*, u.name AS to_name, u.klasse AS to_klasse, u.photo AS to_photo
          FROM requests r LEFT JOIN users u ON u.id=r.to_id
         WHERE r.from_id=? AND r.status IN ('pending','accepted','declined')
         ORDER BY r.created_at DESC
         LIMIT 50
    """, (request.user_id,)).fetchall()
    db.close()
    return jsonify([row_to_dict(r) for r in rows])

@app.route("/api/posts", methods=["GET"])
@require_auth
def open_posts():
    """Publieke wall met open match-aanvragen die VOOR MIJ zichtbaar zijn,
       respect houdend met visibility, expiry en blocks."""
    db = get_db()
    auto_expire_posts(db)
    me_row = db.execute(
        "SELECT klasse,lat,lng FROM users WHERE id=?", (request.user_id,)).fetchone()
    my_group = klasse_group(me_row["klasse"])
    blocked = {r["blocked_id"] for r in db.execute(
        "SELECT blocked_id FROM blocks WHERE blocker_id=?", (request.user_id,)).fetchall()}
    blocked_by = {r["blocker_id"] for r in db.execute(
        "SELECT blocker_id FROM blocks WHERE blocked_id=?", (request.user_id,)).fetchall()}
    excluded = blocked | blocked_by
    rows = db.execute("""
        SELECT r.*, u.name AS from_name, u.klasse AS from_klasse,
               u.photo AS from_photo, u.city AS from_city,
               u.lat AS from_lat, u.lng AS from_lng
          FROM requests r JOIN users u ON u.id=r.from_id
         WHERE r.to_id=0 AND r.status='pending'
           AND r.visibility IN ('everyone','klasse','nearby')
         ORDER BY r.created_at DESC
    """).fetchall()
    db.close()
    out = []
    for r in rows:
        if r["from_id"] == request.user_id: continue  # eigen post niet tonen
        if r["from_id"] in excluded: continue
        d = haversine(me_row["lat"], me_row["lng"], r["from_lat"], r["from_lng"])
        # Visibility filter
        vis = r["visibility"]
        if vis == "klasse" and klasse_group(r["from_klasse"]) != my_group: continue
        if vis == "nearby" and d > 15: continue
        rd = row_to_dict(r); rd["dist"] = round(d, 1)
        out.append(rd)
    return jsonify(out)

@app.route("/api/requests/<int:req_id>/accept", methods=["POST"])
@require_auth
def accept_request(req_id):
    db = get_db()
    auto_expire_posts(db)
    r = db.execute("SELECT * FROM requests WHERE id=?", (req_id,)).fetchone()
    if not r:
        db.close(); return jsonify({"error": "Niet gevonden"}), 404
    if r["status"] != "pending":
        db.close(); return jsonify({"error": "Niet meer beschikbaar"}), 400

    if r["to_id"] == request.user_id:
        # Directe aanvraag
        opponent_id = r["from_id"]
        db.execute("UPDATE requests SET status='accepted' WHERE id=?", (req_id,))
    elif r["to_id"] == 0 and r["from_id"] != request.user_id:
        # Open post → wij accepteren
        opponent_id = r["from_id"]
        db.execute(
            "UPDATE requests SET status='accepted', accepted_by=? WHERE id=?",
            (request.user_id, req_id))
    else:
        db.close(); return jsonify({"error": "Niet voor jou"}), 403

    # Maak een match-record (zonder score) zodat hij in 'pending matches' verschijnt
    me_row = db.execute("SELECT klasse,name FROM users WHERE id=?", (request.user_id,)).fetchone()
    db.execute(
        "INSERT INTO matches (player1_id,player2_id,club,datum,klasse,request_id) "
        "VALUES (?,?,?,?,?,?)",
        (opponent_id, request.user_id, r["club"], r["datum"], me_row["klasse"], req_id))

    # Auto-chat: maak een openings-bericht zodat de chat direct verschijnt voor beide spelers
    when = (r["datum"] or "binnenkort")
    where = (r["club"] or "een club")
    auto_body = (f"🎾 Match aanvaard! Ik zie je {when}"
                 + (f" op {where}" if r["club"] else "") + ". — " + me_row["name"])
    try:
        db.execute("INSERT INTO messages (from_id,to_id,body) VALUES (?,?,?)",
                   (request.user_id, opponent_id, auto_body))
    except: pass
    db.commit(); db.close()
    return jsonify({"ok": True, "opponent_id": opponent_id})

@app.route("/api/requests/<int:req_id>/decline", methods=["POST"])
@require_auth
def decline_request(req_id):
    reason = (request.json or {}).get("reason", "")[:200]
    db = get_db()
    r = db.execute("SELECT * FROM requests WHERE id=?", (req_id,)).fetchone()
    if not r or r["to_id"] != request.user_id:
        db.close(); return jsonify({"error": "Niet voor jou"}), 403
    db.execute("UPDATE requests SET status='declined', decline_reason=? WHERE id=?",
               (reason, req_id))
    db.commit(); db.close()
    return jsonify({"ok": True})

@app.route("/api/requests/<int:req_id>/cancel", methods=["POST"])
@require_auth
def cancel_request(req_id):
    """Verzender kan eigen open post / aanvraag annuleren."""
    db = get_db()
    r = db.execute("SELECT * FROM requests WHERE id=?", (req_id,)).fetchone()
    if not r or r["from_id"] != request.user_id:
        db.close(); return jsonify({"error": "Niet voor jou"}), 403
    if r["status"] != "pending":
        db.close(); return jsonify({"error": "Niet meer pending"}), 400
    db.execute("UPDATE requests SET status='cancelled' WHERE id=?", (req_id,))
    db.commit(); db.close()
    return jsonify({"ok": True})

# ─── MATCHES: pending + history + record ─────────────────────────────────────
@app.route("/api/matches/pending", methods=["GET"])
@require_auth
def pending_matches():
    db = get_db()
    rows = db.execute("""
        SELECT m.*,
               p1.name AS p1_name, p1.photo AS p1_photo,
               p2.name AS p2_name, p2.photo AS p2_photo
          FROM matches m
          JOIN users p1 ON p1.id=m.player1_id
          JOIN users p2 ON p2.id=m.player2_id
         WHERE (m.player1_id=? OR m.player2_id=?)
           AND m.score IS NULL
         ORDER BY m.datum DESC, m.id DESC
    """, (request.user_id, request.user_id)).fetchall()
    db.close()
    return jsonify([row_to_dict(r) for r in rows])

@app.route("/api/history", methods=["GET"])
@require_auth
def history():
    db = get_db()
    rows = db.execute("""
        SELECT m.*,
               p1.name AS p1_name, p1.photo AS p1_photo,
               p2.name AS p2_name, p2.photo AS p2_photo
          FROM matches m
          JOIN users p1 ON p1.id=m.player1_id
          JOIN users p2 ON p2.id=m.player2_id
         WHERE (m.player1_id=? OR m.player2_id=?)
           AND m.score IS NOT NULL
         ORDER BY m.datum DESC, m.id DESC
         LIMIT 100
    """, (request.user_id, request.user_id)).fetchall()
    db.close()
    return jsonify([row_to_dict(r) for r in rows])

@app.route("/api/match/record", methods=["POST"])
@require_auth
def record_match():
    d = request.json or {}
    match_id = d.get("match_id")
    score    = (d.get("score") or "").strip()[:80]
    winner_id= d.get("winner_id")
    if not (match_id and score and winner_id):
        return jsonify({"error": "Vul score, winnaar en match-id in"}), 400
    db = get_db()
    m = db.execute("SELECT * FROM matches WHERE id=?", (match_id,)).fetchone()
    if not m or request.user_id not in (m["player1_id"], m["player2_id"]):
        db.close(); return jsonify({"error": "Niet voor jou"}), 403
    if winner_id not in (m["player1_id"], m["player2_id"]):
        db.close(); return jsonify({"error": "Winnaar moet één van de spelers zijn"}), 400
    db.execute("UPDATE matches SET score=?, winner_id=? WHERE id=?",
               (score, winner_id, match_id))
    # Klassement: simpele +5 / -3 puntenwijziging
    other = m["player1_id"] if m["player2_id"] == winner_id else m["player2_id"]
    db.execute("UPDATE users SET punten=punten+5 WHERE id=?", (winner_id,))
    db.execute("UPDATE users SET punten=MAX(0,punten-3) WHERE id=?", (other,))
    db.commit(); db.close()
    return jsonify({"ok": True})

# ─── REVIEWS ─────────────────────────────────────────────────────────────────
@app.route("/api/matches/<int:match_id>/review", methods=["POST"])
@require_auth
def review_match(match_id):
    d = request.json or {}
    db = get_db()
    m = db.execute("SELECT * FROM matches WHERE id=?", (match_id,)).fetchone()
    if not m or request.user_id not in (m["player1_id"], m["player2_id"]):
        db.close(); return jsonify({"error": "Niet voor jou"}), 403
    other = m["player1_id"] if m["player2_id"] == request.user_id else m["player2_id"]
    no_show = 1 if d.get("no_show") else 0
    try:
        db.execute("""
            INSERT INTO reviews (match_id,reviewer_id,reviewee_id,on_time,fair_play,good_match,no_show,comment)
            VALUES (?,?,?,?,?,?,?,?)""",
            (match_id, request.user_id, other,
             1 if d.get("on_time", True) else 0,
             1 if d.get("fair_play", True) else 0,
             1 if d.get("good_match", True) else 0,
             no_show,
             (d.get("comment", "") or "")[:280]))
        if no_show:
            db.execute("UPDATE users SET no_show_count=no_show_count+1 WHERE id=?", (other,))
        db.commit()
    except sqlite3.IntegrityError:
        db.close(); return jsonify({"error": "Al gerecenseerd"}), 400
    db.close()
    return jsonify({"ok": True})

# ─── CHAT ────────────────────────────────────────────────────────────────────
@app.route("/api/chats", methods=["GET"])
@require_auth
def chats():
    me = request.user_id
    db = get_db()
    rows = db.execute("""
        SELECT
          CASE WHEN from_id=? THEN to_id ELSE from_id END AS other_id,
          MAX(created_at) AS last_at,
          SUM(CASE WHEN to_id=? AND read_at IS NULL THEN 1 ELSE 0 END) AS unread
        FROM messages
        WHERE from_id=? OR to_id=?
        GROUP BY other_id
        ORDER BY last_at DESC
        LIMIT 50
    """, (me, me, me, me)).fetchall()
    out = []
    for r in rows:
        u = db.execute("SELECT id,name,photo,klasse FROM users WHERE id=?", (r["other_id"],)).fetchone()
        last = db.execute(
            "SELECT body FROM messages WHERE (from_id=? AND to_id=?) OR (from_id=? AND to_id=?) "
            "ORDER BY created_at DESC LIMIT 1",
            (me, r["other_id"], r["other_id"], me)).fetchone()
        if u:
            d = row_to_dict(u)
            d["last_at"] = r["last_at"]; d["unread"] = r["unread"]
            d["preview"] = (last["body"] if last else "")[:60]
            out.append(d)
    db.close()
    return jsonify(out)

@app.route("/api/chats/<int:other_id>/messages", methods=["GET"])
@require_auth
def chat_messages(other_id):
    me = request.user_id
    db = get_db()
    rows = db.execute("""
        SELECT id,from_id,to_id,body,created_at,read_at FROM messages
        WHERE (from_id=? AND to_id=?) OR (from_id=? AND to_id=?)
        ORDER BY created_at ASC LIMIT 200
    """, (me, other_id, other_id, me)).fetchall()
    db.execute("UPDATE messages SET read_at=datetime('now') "
               "WHERE to_id=? AND from_id=? AND read_at IS NULL", (me, other_id))
    db.commit(); db.close()
    return jsonify([row_to_dict(r) for r in rows])

@app.route("/api/chats/<int:other_id>/send", methods=["POST"])
@require_auth
def chat_send(other_id):
    body = ((request.json or {}).get("body") or "").strip()
    if not body: return jsonify({"error": "Leeg bericht"}), 400
    body = body[:600]
    db = get_db()
    if is_blocked(db, request.user_id, other_id):
        db.close(); return jsonify({"error": "Niet beschikbaar"}), 403
    db.execute("INSERT INTO messages (from_id,to_id,body) VALUES (?,?,?)",
               (request.user_id, other_id, body))
    db.commit(); db.close()
    return jsonify({"ok": True})

# ─── FRIENDS ─────────────────────────────────────────────────────────────────
def _friend_status(db, me_id, other_id):
    """Geeft 'none' / 'pending_out' / 'pending_in' / 'accepted'."""
    r = db.execute(
        "SELECT requester_id, status FROM friendships "
        "WHERE (requester_id=? AND addressee_id=?) OR (requester_id=? AND addressee_id=?)",
        (me_id, other_id, other_id, me_id)).fetchone()
    if not r: return "none"
    if r["status"] == "accepted": return "accepted"
    if r["requester_id"] == me_id: return "pending_out"
    return "pending_in"

@app.route("/api/friends", methods=["GET"])
@require_auth
def friends_list():
    me = request.user_id
    db = get_db()
    rows = db.execute("""
        SELECT u.id, u.name, u.klasse, u.photo, u.city, u.available
          FROM friendships f
          JOIN users u ON u.id = CASE WHEN f.requester_id=? THEN f.addressee_id ELSE f.requester_id END
         WHERE (f.requester_id=? OR f.addressee_id=?) AND f.status='accepted'
         ORDER BY u.name
    """, (me, me, me)).fetchall()
    db.close()
    return jsonify([row_to_dict(r) for r in rows])

@app.route("/api/friends/incoming", methods=["GET"])
@require_auth
def friends_incoming():
    me = request.user_id
    db = get_db()
    rows = db.execute("""
        SELECT u.id, u.name, u.klasse, u.photo, u.city, f.created_at
          FROM friendships f
          JOIN users u ON u.id = f.requester_id
         WHERE f.addressee_id=? AND f.status='pending'
         ORDER BY f.created_at DESC
    """, (me,)).fetchall()
    db.close()
    return jsonify([row_to_dict(r) for r in rows])

@app.route("/api/friends/outgoing", methods=["GET"])
@require_auth
def friends_outgoing():
    me = request.user_id
    db = get_db()
    rows = db.execute("""
        SELECT u.id, u.name, u.klasse, u.photo, u.city
          FROM friendships f
          JOIN users u ON u.id = f.addressee_id
         WHERE f.requester_id=? AND f.status='pending'
         ORDER BY f.created_at DESC
    """, (me,)).fetchall()
    db.close()
    return jsonify([row_to_dict(r) for r in rows])

@app.route("/api/friends/check/<int:other_id>", methods=["GET"])
@require_auth
def friends_check(other_id):
    db = get_db()
    s = _friend_status(db, request.user_id, other_id)
    db.close()
    return jsonify({"status": s})

@app.route("/api/friends/<int:other_id>/request", methods=["POST"])
@require_auth
def friends_request(other_id):
    if other_id == request.user_id: return jsonify({"error": "Niet jezelf"}), 400
    db = get_db()
    if is_blocked(db, request.user_id, other_id):
        db.close(); return jsonify({"error": "Niet beschikbaar"}), 403
    s = _friend_status(db, request.user_id, other_id)
    if s == "accepted":
        db.close(); return jsonify({"error": "Jullie zijn al vrienden"}), 400
    if s == "pending_out":
        db.close(); return jsonify({"error": "Aanvraag al verzonden"}), 400
    if s == "pending_in":
        # De ander stuurde al een aanvraag → accepteer die meteen
        db.execute(
            "UPDATE friendships SET status='accepted' "
            "WHERE requester_id=? AND addressee_id=?", (other_id, request.user_id))
        db.commit(); db.close()
        return jsonify({"ok": True, "status": "accepted"})
    db.execute(
        "INSERT INTO friendships (requester_id, addressee_id, status) VALUES (?,?,'pending')",
        (request.user_id, other_id))
    db.commit(); db.close()
    return jsonify({"ok": True, "status": "pending_out"})

@app.route("/api/friends/<int:other_id>/accept", methods=["POST"])
@require_auth
def friends_accept(other_id):
    db = get_db()
    r = db.execute(
        "SELECT id FROM friendships WHERE requester_id=? AND addressee_id=? AND status='pending'",
        (other_id, request.user_id)).fetchone()
    if not r:
        db.close(); return jsonify({"error": "Geen openstaande aanvraag"}), 404
    db.execute("UPDATE friendships SET status='accepted' WHERE id=?", (r["id"],))
    db.commit(); db.close()
    return jsonify({"ok": True, "status": "accepted"})

@app.route("/api/friends/<int:other_id>", methods=["DELETE"])
@require_auth
def friends_remove(other_id):
    db = get_db()
    db.execute(
        "DELETE FROM friendships "
        "WHERE (requester_id=? AND addressee_id=?) OR (requester_id=? AND addressee_id=?)",
        (request.user_id, other_id, other_id, request.user_id))
    db.commit(); db.close()
    return jsonify({"ok": True})

# ─── RANKINGS ────────────────────────────────────────────────────────────────
@app.route("/api/rankings", methods=["GET"])
@require_auth
def rankings():
    db = get_db()
    rows = db.execute("""
        SELECT u.id,u.name,u.klasse,u.punten,u.photo,u.city,
               COUNT(m.id) AS matches,
               SUM(CASE WHEN m.winner_id=u.id THEN 1 ELSE 0 END) AS wins
          FROM users u
          LEFT JOIN matches m ON (m.player1_id=u.id OR m.player2_id=u.id) AND m.score IS NOT NULL
         GROUP BY u.id
         ORDER BY u.punten DESC, wins DESC
         LIMIT 50
    """).fetchall()
    db.close()
    return jsonify([row_to_dict(r) for r in rows])

# ─── BLOCKS & REPORTS ────────────────────────────────────────────────────────
@app.route("/api/users/<int:other_id>/block", methods=["POST"])
@require_auth
def block_user(other_id):
    if other_id == request.user_id: return jsonify({"error": "Niet jezelf"}), 400
    db = get_db()
    db.execute("INSERT OR IGNORE INTO blocks (blocker_id,blocked_id) VALUES (?,?)",
               (request.user_id, other_id))
    db.commit(); db.close()
    return jsonify({"ok": True})

@app.route("/api/users/<int:other_id>/unblock", methods=["POST"])
@require_auth
def unblock_user(other_id):
    db = get_db()
    db.execute("DELETE FROM blocks WHERE blocker_id=? AND blocked_id=?",
               (request.user_id, other_id))
    db.commit(); db.close()
    return jsonify({"ok": True})

@app.route("/api/users/<int:other_id>/report", methods=["POST"])
@require_auth
def report_user(other_id):
    d = request.json or {}
    db = get_db()
    db.execute("INSERT INTO reports (reporter_id,reported_id,reason,details) VALUES (?,?,?,?)",
               (request.user_id, other_id,
                (d.get("reason") or "")[:60],
                (d.get("details") or "")[:600]))
    db.commit(); db.close()
    return jsonify({"ok": True})

# ─── PUBLIC PROFILE ──────────────────────────────────────────────────────────
@app.route("/api/users/<int:other_id>/profile", methods=["GET"])
@require_auth
def public_profile(other_id):
    db = get_db()
    u = db.execute(
        "SELECT id,name,klasse,punten,city,photo,bio,no_show_count "
        "FROM users WHERE id=?", (other_id,)).fetchone()
    if not u:
        db.close(); return jsonify({"error": "Niet gevonden"}), 404
    stats = db.execute("""
        SELECT COUNT(*) AS matches,
               SUM(CASE WHEN winner_id=? THEN 1 ELSE 0 END) AS wins
          FROM matches WHERE (player1_id=? OR player2_id=?) AND score IS NOT NULL
    """, (other_id, other_id, other_id)).fetchone()
    db.close()
    d = row_to_dict(u)
    d["matches"] = stats["matches"] or 0
    d["wins"]    = stats["wins"]    or 0
    d["win_rate"]= round(100*(d["wins"]/d["matches"])) if d["matches"] else 0
    return jsonify(d)

# ─── META: klasses, config ───────────────────────────────────────────────────
@app.route("/api/meta", methods=["GET"])
def meta():
    return jsonify({
        "klasses":     KLASSES,
        "klasse_groups": KLASSE_GROUPS,
        "post_ttl_default":  DEFAULT_POST_TTL_HOURS,
        "post_ttl_options":  [3, 12, 24, 72],
        "visibility_options": ["everyone","klasse","nearby"],
    })

# ─── PRIVACY / TERMS / STATIC ────────────────────────────────────────────────
PRIVACY_HTML = """<!doctype html><html lang="nl"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Privacy &mdash; TennisConnect</title>
<style>
body{font-family:system-ui,-apple-system,sans-serif;background:#f4f7f0;color:#0e1f12;
     max-width:760px;margin:0 auto;padding:32px 20px;line-height:1.6}
h1{font-size:32px;margin:0 0 8px}h2{font-size:20px;margin:32px 0 8px;color:#1a6b3a}
a{color:#1a6b3a}.box{background:#fff;padding:24px;border-radius:14px;
     border:1px solid #dde8d8;box-shadow:0 2px 8px rgba(0,0,0,.04)}
.back{display:inline-block;margin-bottom:16px;text-decoration:none;
     background:#1a6b3a;color:#fff;padding:8px 14px;border-radius:8px;font-weight:600}
small{color:#6b7c6a}
</style></head><body>
<a class="back" href="/">&larr; Terug naar TennisConnect</a>
<div class="box">
<h1>Privacy &amp; Cookies</h1>
<small>Laatst bijgewerkt: mei 2026 &middot; Eigenaar: TennisConnect</small>
<p>TennisConnect helpt je tegenstanders vinden in jouw buurt. We nemen jouw
privacy serieus. Hieronder lees je in klare taal wat we bewaren en waarom.</p>

<h2>Welke data bewaren we?</h2>
<p>Bij registratie: <b>naam, emailadres, gehasht wachtwoord</b> (we zien je
wachtwoord nooit in leesbare vorm &mdash; bcrypt one-way hash). Je kan optioneel
toevoegen: foto, biotekst, klassement, beschikbare uren, GPS-locatie en stad.</p>

<h2>Locatie / kaart</h2>
<p>Als je toestemming geeft voor GPS gebruiken we je locatie om spelers en clubs
in de buurt te tonen. De "drukte-heatmap" toont enkel <b>geaggregeerde tellingen
per cel van ~1km</b> &mdash; nooit individuele posities of namen op de heatmap.</p>

<h2>Open posts &amp; zichtbaarheid</h2>
<p>Bij een open match-post kies jij wie het ziet:
<i>iedereen</i>, <i>enkel jouw klassegroep</i>, of <i>spelers binnen 15&nbsp;km</i>.
Open posts verlopen automatisch na 3u, 12u, 24u of 72u &mdash; daarna verdwijnen ze
uit de feed.</p>

<h2>Berichten</h2>
<p>Chatberichten worden bewaard zodat jij ze later kan terugzien. Ze zijn
zichtbaar voor jou en de ontvanger. We delen geen chats met derden.</p>

<h2>Cookies</h2>
<p>We gebruiken <b>geen tracking-cookies</b>. Het enige wat we lokaal opslaan is
jouw login-token (JWT) in je browser. Dat token vervalt automatisch na 7 dagen.</p>

<h2>Wie ziet wat?</h2>
<p>Andere spelers zien jouw naam, foto, klassement, stad en (geaggregeerde)
GPS-positie als je beschikbaar staat. Je e-mailadres blijft <b>altijd verborgen</b>.</p>

<h2>Jouw rechten (GDPR)</h2>
<p>Je kan op elk moment:
<i>(a)</i> je profiel aanpassen,
<i>(b)</i> spelers blokkeren of melden,
<i>(c)</i> je volledige account verwijderen via "Account verwijderen" in je profiel.</p>

<h2>Security</h2>
<p>Wachtwoorden zijn bcrypt-gehasht. Login is rate-limited (max 5 foute pogingen
per 15 minuten). Sessietokens vervallen na 7 dagen.</p>

<h2>Contact</h2>
<p>Vragen of klachten? Mail naar
<a href="mailto:privacy@tennisconnect.local">privacy@tennisconnect.local</a>.</p>
</div></body></html>"""

TERMS_HTML = """<!doctype html><html lang="nl"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Gebruiksvoorwaarden &mdash; TennisConnect</title>
<style>
body{font-family:system-ui,-apple-system,sans-serif;background:#f4f7f0;color:#0e1f12;
     max-width:760px;margin:0 auto;padding:32px 20px;line-height:1.6}
h1{font-size:32px;margin:0 0 8px}h2{font-size:20px;margin:32px 0 8px;color:#1a6b3a}
.box{background:#fff;padding:24px;border-radius:14px;border:1px solid #dde8d8;
     box-shadow:0 2px 8px rgba(0,0,0,.04)}
.back{display:inline-block;margin-bottom:16px;text-decoration:none;
     background:#1a6b3a;color:#fff;padding:8px 14px;border-radius:8px;font-weight:600}
</style></head><body>
<a class="back" href="/">&larr; Terug</a>
<div class="box">
<h1>Gebruiksvoorwaarden</h1>
<h2>Gedragscode</h2>
<p>Wees respectvol. Geen pesterijen, spam, fake accounts of commerciele posts.
Bij overtredingen kan je account geblokkeerd worden.</p>
<h2>Eigen verantwoordelijkheid</h2>
<p>TennisConnect bemiddelt enkel tussen spelers. Wat er gebeurt op de baan is
jouw verantwoordelijkheid: spreek terreinhuur duidelijk af, kom op tijd, en
respecteer de regels van de club.</p>
<h2>No-shows</h2>
<p>Spelers die niet komen opdagen kunnen door tegenstanders gerapporteerd worden.
Te veel no-shows kan leiden tot tijdelijke schorsing.</p>
<h2>Wijzigingen</h2>
<p>We kunnen deze voorwaarden updaten. Bij belangrijke wijzigingen verwittigen
we jou via de app.</p>
</div></body></html>"""

@app.route("/privacy")
def privacy():
    return Response(PRIVACY_HTML, mimetype="text/html")

@app.route("/terms")
def terms():
    return Response(TERMS_HTML, mimetype="text/html")

@app.route("/")
def root():
    return send_from_directory("templates", "index.html")

@app.route("/manifest.json")
def manifest():
    return jsonify({
        "name":"TennisConnect","short_name":"TennisConnect",
        "start_url":"/","display":"standalone",
        "background_color":"#f4f7f0","theme_color":"#1a6b3a",
        "icons":[{"src":"/icon-192.svg","sizes":"192x192","type":"image/svg+xml"}]
    })

@app.route("/icon-192.svg")
def icon():
    svg = ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100">'
           '<rect width="100" height="100" rx="20" fill="#1a6b3a"/>'
           '<text y="72" x="50" text-anchor="middle" font-size="62">\U0001F3BE</text></svg>')
    return Response(svg, mimetype="image/svg+xml")

if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="0.0.0.0", port=port, debug=True)
else:
    init_db()
