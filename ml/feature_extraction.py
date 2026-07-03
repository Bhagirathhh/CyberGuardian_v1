import re
import ipaddress
from urllib.parse import urlparse

SUSPICIOUS_WORDS = [
    "login", "verify", "secure",
    "bank", "account", "update",
    "confirm", "wallet", "password"
]

def extract_features(url):

    parsed = urlparse(url)

    host = parsed.hostname or ""

    url_length = len(url)

    dots = url.count(".")

    hyphens = url.count("-")

    digits = len(re.findall(r"\d", url))

    https = 1 if url.startswith("https://") else 0

    at_symbol = 1 if "@" in url else 0

    try:
        ipaddress.ip_address(host)
        ip_address = 1
    except:
        ip_address = 0

    suspicious_words = sum(
        word in url.lower()
        for word in SUSPICIOUS_WORDS
    )

    subdomains = host.count(".")

    return [
        url_length,
        dots,
        hyphens,
        digits,
        https,
        at_symbol,
        ip_address,
        suspicious_words,
        subdomains
    ]