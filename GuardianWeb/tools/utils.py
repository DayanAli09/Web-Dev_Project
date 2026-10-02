import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests

REQUEST_HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; CyberToolsBot/1.0)"}
REQUEST_TIMEOUT = 5


def split_host(hostname):
    parts = hostname.split(".")
    if len(parts) <= 2:
        return "", parts[0] if parts else ""
    domain = parts[-2]
    subdomain = ".".join(parts[:-2])
    return subdomain, domain


POPULAR_BRANDS = [
    "google", "facebook", "instagram", "paypal", "amazon", "apple",
    "microsoft", "netflix", "whatsapp", "bankofamerica", "chase",
]

URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
]

RISKY_TLDS = [
    "xyz", "top", "tk", "gq", "cf", "ml", "work", "click",
    "link", "rest", "loan", "men", "review", "country", "kim",
]

# e.g. "micros0ft" -> "microsoft"
LEET_MAP = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t"})


def get_cert_age_days(hostname):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=REQUEST_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

        not_before = datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z")
        not_before = not_before.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - not_before).days
    except Exception:
        return None


def get_domain_age_days(domain_with_tld):
    try:
        resp = requests.get(
            f"https://rdap.org/domain/{domain_with_tld}",
            headers=REQUEST_HEADERS,
            timeout=REQUEST_TIMEOUT,
        )
        if resp.status_code != 200:
            return None

        data = resp.json()
        for event in data.get("events", []):
            if event.get("eventAction") == "registration":
                reg_date = datetime.fromisoformat(event["eventDate"].replace("Z", "+00:00"))
                return (datetime.now(timezone.utc) - reg_date).days
    except Exception:
        pass
    return None


def check_openphish(url, domain_with_tld):
    try:
        resp = requests.get("https://openphish.com/feed.txt", timeout=REQUEST_TIMEOUT)
        if resp.status_code != 200:
            return False
        feed_urls = resp.text.splitlines()
        return any(url in line or domain_with_tld in line for line in feed_urls)
    except Exception:
        return False


def check_urlhaus(url):
    try:
        resp = requests.post(
            "https://urlhaus-api.abuse.ch/v1/url/",
            data={"url": url},
            timeout=REQUEST_TIMEOUT,
        )
        if resp.status_code != 200:
            return False
        return resp.json().get("query_status") == "ok"
    except Exception:
        return False


def get_redirect_chain(url):
    try:
        resp = requests.get(
            url, headers=REQUEST_HEADERS, timeout=REQUEST_TIMEOUT, allow_redirects=True
        )
        return resp.url, len(resp.history), resp
    except requests.exceptions.RequestException:
        return url, 0, None
