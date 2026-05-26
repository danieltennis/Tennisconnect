# TennisConnect 🎾

Een volledig werkende web-app voor tennissers in België: vind tegenstanders op basis van klassement, locatie en weekelijke beschikbaarheid. Chat, plan wedstrijden, registreer scores, klim in het klassement.

## Functies
- 🗺️ Echte kaart (Leaflet + OpenStreetMap) met spelers en tennisclubs in de buurt
- 📅 Wekelijkse tijdslots → matchmaking op overlappende uren
- 🏆 Tennis Vlaanderen klassementsysteem (Pro/0-6/15.1-15.6/NC)
- 💬 Chat met realtime polling en (optioneel) web push notifications
- 🎯 Score-registratie met klassement-update + win-celebration met confetti
- 🏅 11 unlockbare achievements (Eerste winst, Win streak 5, Bagel server, ...)
- 📊 Persoonlijk stats-dashboard met vorm-trend, win-rate, mini-charts
- 🌙 Dark mode
- 📱 Installeerbaar als PWA (home screen icon, offline-cache, push)
- ✨ Onboarding-flow voor nieuwe gebruikers

## Lokaal draaien

```bash
pip install -r requirements.txt
python app.py
```

Dan naar http://localhost:5000 en inloggen met `sven@demo.com` / `demo123`.

## Demo-accounts
| Email | Wachtwoord | Klasse |
|-------|-----------|--------|
| sven@demo.com | demo123 | 15.4 |
| laura@demo.com | demo123 | 15.5 |
| nathalie@demo.com | demo123 | 15.3 |
| inge@demo.com | demo123 | 5 |
| koen@demo.com | demo123 | NC |
| _en 12 anderen — verspreid over Boechout/Antwerpen_ | | |

## Productie deployen — 5 minuten

### Optie A: Docker
```bash
cp .env.example .env       # genereer TC_SECRET (zie .env.example voor commando)
docker compose up -d --build
```

### Optie B: Railway / Render / Fly.io
1. Push je code naar GitHub
2. Connect je repo op [Railway](https://railway.app), [Render](https://render.com) of [Fly](https://fly.io)
3. Voeg env var `TC_SECRET` toe (random 48-byte string — zie .env.example)
4. Railway/Render detecteert automatisch de `Procfile` en start `gunicorn`
5. Open je live URL

### Optie C: Plain Linux server
```bash
pip install -r requirements.txt
export TC_SECRET="$(python -c 'import secrets;print(secrets.token_urlsafe(48))')"
export FLASK_DEBUG=0
gunicorn --bind 0.0.0.0:5000 --workers 2 --threads 4 app:app
```
Zet er een Nginx + Let's Encrypt voor en je hebt HTTPS in 10 minuten.

## Web Push Notifications (optioneel)

Voor echte push-notificaties die ook werken als de app gesloten is:

```bash
pip install pywebpush cryptography
python -c "from py_vapid import Vapid; v=Vapid(); v.generate_keys(); \
  print('PUBLIC:', v.public_key.public_bytes()); \
  print('PRIVATE:', v.private_key.private_numbers().private_value)"
```

Zet die in de env als `TC_VAPID_PUBLIC` en `TC_VAPID_PRIVATE`.
Zonder VAPID-keys werkt push graceful disabled — in-app notifications via de Notification API blijven werken zolang de tab open is.

## Belangrijkste env vars
| Var | Default | Doel |
|-----|---------|------|
| `TC_SECRET` | dev-default | JWT signing key — **MOET veranderd worden in productie** |
| `TC_VAPID_PUBLIC` | "" | Public key voor web push |
| `TC_VAPID_PRIVATE` | "" | Private key voor web push |
| `TC_VAPID_CONTACT` | mailto:dev@... | Contact-URL voor push services |
| `PORT` | 5000 | HTTP-poort |
| `FLASK_DEBUG` | 1 | Op 0 zetten in productie |

## Architecture

```
tennisconnect/
├── app.py                  # Flask backend (alle API + PWA endpoints)
├── templates/
│   └── index.html          # Volledige SPA (HTML+CSS+JS in 1 file)
├── db/
│   └── tennisconnect.db    # SQLite (auto-created bij eerste start)
├── requirements.txt
├── Procfile                # Voor Heroku/Railway/Render
├── Dockerfile              # Voor container-deploys
├── docker-compose.yml      # Lokale orchestratie
└── .env.example
```

## Volgende stappen
- Echte e-mail-verificatie bij registratie
- Tournament-modus (mini-ladders met vrienden)
- Reviews na een match (fair play, op tijd)
- Migratie naar PostgreSQL voor >1000 users
