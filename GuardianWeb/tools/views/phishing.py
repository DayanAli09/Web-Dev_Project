import re
from urllib.parse import urlparse

from bs4 import BeautifulSoup
from django.shortcuts import render

from ..utils import (
    LEET_MAP,
    POPULAR_BRANDS,
    RISKY_TLDS,
    URL_SHORTENERS,
    check_openphish,
    check_urlhaus,
    get_cert_age_days,
    get_domain_age_days,
    get_redirect_chain,
    split_host,
)


def analyze_live_page(response, domain):
    score = 0
    reasons = []

    if response is None:
        return score, reasons

    soup = BeautifulSoup(response.text, "html.parser")

    if soup.find("input", {"type": "password"}):
        score += 10
        reasons.append("Page contains a password input field")

    title = soup.title.string.strip().lower() if soup.title and soup.title.string else ""
    for brand in POPULAR_BRANDS:
        if brand in title and brand != domain:
            score += 20
            reasons.append(f"Page title mentions '{brand}' but the domain is '{domain}'")
            break

    external_domains = set()
    for tag, attr in [("script", "src"), ("img", "src"), ("link", "href")]:
        for el in soup.find_all(tag):
            src = el.get(attr)
            if not src or not src.startswith(("http://", "https://")):
                continue
            src_host = urlparse(src).hostname or ""
            _, src_domain = split_host(src_host)
            if src_domain and src_domain != domain:
                external_domains.add(src_domain)

    if len(external_domains) >= 5:
        score += 10
        reasons.append(f"Page loads resources from {len(external_domains)} unrelated external domains")

    return score, reasons


def phishing_detector(request):
    result = None

    if request.method == "POST":
        url = request.POST.get("url", "").strip()

        if not url.startswith(("http://", "https://")):
            url = "http://" + url

        parsed = urlparse(url)
        full_host = parsed.hostname or ""
        subdomain, domain = split_host(full_host)
        normalized_host = full_host.translate(LEET_MAP)
        tld = full_host.rsplit(".", 1)[-1] if "." in full_host else ""

        score = 0
        reasons = []

        if parsed.scheme == "http":
            score += 15
            reasons.append("HTTPS is not being used")

        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", full_host):
            score += 30
            reasons.append("An IP address is used instead of a domain name")

        if "@" in url:
            score += 25
            reasons.append("URL contains an '@' symbol (can hide the real destination)")

        if subdomain and len(subdomain.split(".")) >= 3:
            score += 15
            reasons.append("URL has an unusually high number of subdomains")

        for brand in POPULAR_BRANDS:
            if brand in full_host and domain != brand:
                score += 25
                reasons.append(f"'{brand}' appears in the URL, but the real domain is '{domain}'")
                break

        for brand in POPULAR_BRANDS:
            if brand in normalized_host and brand not in full_host:
                score += 35
                reasons.append(f"Looks like '{brand}' spelled with lookalike characters — likely typosquatting")
                break

        shortener_domains = [s.split(".")[0] for s in URL_SHORTENERS]
        if domain in shortener_domains or full_host in URL_SHORTENERS:
            score += 10
            reasons.append("A URL shortener is being used")

        if len(url) > 100:
            score += 10
            reasons.append("URL is unusually long")

        suspicious_words = ["verify", "update", "secure", "login", "confirm", "account", "banking"]
        hits = [w for w in suspicious_words if w in url.lower()]
        if len(hits) >= 2:
            score += 10
            reasons.append(f"Contains urgency/trust keywords: {', '.join(hits)}")

        if tld in RISKY_TLDS:
            score += 15
            reasons.append(f"Uses a high-risk top-level domain (.{tld})")

        if not full_host.isascii() or "xn--" in full_host:
            score += 30
            reasons.append("Domain contains non-standard characters (possible homograph attack)")

        domain_with_tld = f"{domain}.{tld}" if tld else full_host
        age_days = get_domain_age_days(domain_with_tld)
        if age_days is not None and age_days < 30:
            score += 25
            reasons.append(f"Domain was registered only {age_days} day(s) ago")

        final_url, hop_count, response = get_redirect_chain(url)
        if hop_count >= 3:
            score += 10
            reasons.append(f"URL redirects {hop_count} times before reaching its destination")
        if response is None:
            reasons.append("Could not reach the page to inspect its content")
        else:
            page_score, page_reasons = analyze_live_page(response, domain)
            score += page_score
            reasons.extend(page_reasons)

        if url.startswith("https://"):
            cert_age = get_cert_age_days(full_host)
            if cert_age is not None and cert_age < 14:
                score += 15
                reasons.append(f"SSL certificate was issued only {cert_age} day(s) ago")

        if check_openphish(url, domain_with_tld):
            score += 50
            reasons.append("URL is listed in the OpenPhish threat feed")

        if check_urlhaus(url):
            score += 50
            reasons.append("URL is listed in the Abuse.ch URLhaus database")

        score = min(score, 100)

        result = {
            "url": url,
            "final_url": final_url,
            "score": score,
            "reasons": reasons,
        }

    return render(request, "tools/phishing.html", {"result": result})
