# Cyber Tools

A small Django site with three security tools: a phishing URL checker, a file encryptor, and a port scanner.

## Setup

```
pip install -r requirements.txt
python manage.py runserver
```

Then open `http://127.0.0.1:8000/`.

## Pages

| Route | What it does |
|---|---|
| `/` | Links to the three tools |
| `/phishing/` | Checks a URL for phishing signals — pattern checks, live page inspection, SSL cert age, domain age, and lookups against OpenPhish / URLhaus |
| `/encrypt/` | Encrypts or decrypts an uploaded file with a password (PBKDF2 + Fernet) |
| `/scan/` | Scans a host for open TCP ports, with a live-updating progress bar |

## Project layout

```
tools/
├── utils.py              # shared helpers used by more than one tool
├── urls.py
├── views/
│   ├── __init__.py
│   ├── home.py
│   ├── phishing.py
│   ├── encryptor.py
│   └── scanner.py
└── templates/tools/
    ├── home.html
    ├── phishing.html
    ├── encryptor.html
    └── scanner.html
```

## Notes

- Only scan hosts/networks you own or have permission to test.
- The phishing checker's threat-feed lookups (OpenPhish, URLhaus) use free public services with no API key required.
- Port scan state is kept in memory, so it resets if the server restarts.
