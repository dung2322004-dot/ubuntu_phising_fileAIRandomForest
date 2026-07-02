import requests
import whois
import tldextract

from urllib.parse import urlparse
from datetime import datetime
import logging

logging.getLogger().setLevel(logging.CRITICAL)

# Domain Age
def get_domain_age(url):

    try:

        domain = tldextract.extract(url).registered_domain

        if not domain:
            return -1

        w = whois.whois(domain)

        creation = w.creation_date

        if isinstance(creation, list):
            creation = creation[0]

        if creation:
            return (datetime.now() - creation).days

        return -1

    except:
        return -1
        
# Domain Reputation
def domain_reputation(url):

    age = get_domain_age(url)

    if age == -1:
        return 0

    if age > 3650:
        return 100

    return min(
        int(age / 36),
        100
    )

# Blacklist Score
def blacklist_score(url):

    blacklist_keywords = [
        "login",
        "verify",
        "secure",
        "update",
        "account",
        "bank",
        "payment",
        "wallet"
    ]

    lower = url.lower()

    score = 0

    for word in blacklist_keywords:

        if word in lower:
            score += 1

    return score

# SSL
def has_ssl(url):

    return 1 if url.startswith(
        "https://"
    ) else 0

# URL Structure

def url_structure(url):

    p = urlparse(url)

    return {
        "url_length": len(url),
        "domain_length": len(p.netloc),
        "path_length": len(p.path),
        "query_length": len(p.query)
    }

# Redirect
def redirect_count(url):

    try:

        r = requests.get(
            url,
            timeout=2,
            allow_redirects=True
        )

        return len(r.history)

    except Exception:
        return 0


# Security Headers
def security_headers(url):

    try:

        r = requests.get(
            url,
            timeout=2
        )

        h = r.headers

        score = 0

        if "Content-Security-Policy" in h:
            score += 1

        if "Strict-Transport-Security" in h:
            score += 1

        if "X-Frame-Options" in h:
            score += 1

        if "X-Content-Type-Options" in h:
            score += 1

        return score

    except Exception:
        return 0
# Typosquatting
def typo_score(url):

    suspicious = [
        "micros0ft",
        "g00gle",
        "faceb00k",
        "amaz0n"
    ]

    lower = url.lower()

    for item in suspicious:

        if item in lower:
            return 1

    return 0
# Content

def content_score(url):

    try:

        r = requests.get(
            url,
            timeout=2
        )

        html = r.text.lower()

        keywords = [
            "login",
            "verify",
            "password",
            "account",
            "secure",
            "update",
            "bank"
        ]

        score = 0

        for k in keywords:

            if k in html:
                score += 1

        return score

    except Exception:
        return 0
