# PhishGuard AI — Final Year Project
## Multi-Modal Deep Learning for Email Phishing Detection

### Project Structure
```
phishguard/
├── manage.py
├── requirements.txt
├── db.sqlite3          (created on first run)
├── phishguard/
│   ├── settings.py
│   ├── urls.py
│   └── wsgi.py
├── detector/
│   ├── models.py           ← Email + ScanLog database models
│   ├── views.py            ← All page views + API endpoints
│   ├── ml_engine.py        ← Multi-modal detection engine
│   ├── urls.py
│   ├── admin.py
│   ├── templates/detector/
│   │   ├── base.html
│   │   ├── dashboard.html
│   │   ├── inbox.html
│   │   ├── email_detail.html
│   │   ├── scan.html
│   │   ├── analytics.html
│   │   └── settings.html
│   └── management/commands/
│       └── seed_data.py    ← Seeds 17 sample emails
└── dataset/
    └── sample_emails.csv   ← Sample dataset reference
```

### Quick Setup (5 minutes)

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run migrations
python manage.py makemigrations
python manage.py migrate

# 3. Seed sample data (17 emails from Nazario-style patterns)
python manage.py seed_data

# 4. Create admin user
python manage.py createsuperuser

# 5. Run server
python manage.py runserver
```

Then open: http://127.0.0.1:8000

Admin panel: http://127.0.0.1:8000/admin

### Key Pages
| URL | Description |
|-----|-------------|
| `/` | Dashboard — stats, threat trend, recent alerts |
| `/inbox/` | All scanned emails with filters |
| `/scan/` | Scan a new email manually |
| `/email/<id>/` | Full detail + AI analysis breakdown |
| `/analytics/` | Charts, model metrics, top threat domains |
| `/api/scan/` | REST API endpoint (POST JSON) |

### API Usage
```bash
curl -X POST http://localhost:8000/api/scan/ \
  -H "Content-Type: application/json" \
  -d '{"sender":"test@suspicious.xyz","subject":"Verify now","body":"Click here to verify your account immediately."}'
```

### Dataset
- **Phishing samples**: Based on Nazario Phishing Email Corpus patterns
- **Legitimate samples**: Based on Enron email dataset patterns
- Reference: https://figshare.com/articles/dataset/Curated_Dataset_-_Phishing_Email/24899952

### Multi-Modal Detection Engine
The engine (`detector/ml_engine.py`) fuses 4 feature modalities:
1. **Text features** (40% weight) — keyword patterns, urgency language, credential requests
2. **URL features** (30% weight) — domain analysis, TLD checks, brand impersonation
3. **Sender metadata** (20% weight) — domain reputation, spoofing patterns
4. **Attachment features** (10% weight) — file extension risk, name heuristics

**Thresholds**: ≥65% = Phishing | 35–64% = Suspicious | <35% = Safe
# Phish
