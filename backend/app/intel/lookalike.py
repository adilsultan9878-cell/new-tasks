"""Brand-impersonation and look-alike domain detection (deterministic)."""

from __future__ import annotations

import unicodedata

# Brand keyword → official registrable domains. Includes services commonly impersonated in
# Pakistan. Extend per organization in later phases.
BRANDS: dict[str, set[str]] = {
    "paypal": {"paypal.com"},
    "microsoft": {
        "microsoft.com",
        "live.com",
        "office.com",
        "outlook.com",
        "microsoftonline.com",
        "office365.com",
    },
    "office365": {"office.com", "office365.com", "microsoft.com"},
    "outlook": {"outlook.com", "live.com", "microsoft.com"},
    "google": {"google.com", "gmail.com", "youtube.com", "google.com.pk"},
    "gmail": {"gmail.com", "google.com"},
    "apple": {"apple.com", "icloud.com"},
    "icloud": {"icloud.com", "apple.com"},
    "amazon": {"amazon.com", "amazon.co.uk", "amazon.de", "aws.amazon.com"},
    "facebook": {"facebook.com", "fb.com", "meta.com"},
    "instagram": {"instagram.com"},
    "whatsapp": {"whatsapp.com", "whatsapp.net"},
    "netflix": {"netflix.com"},
    "linkedin": {"linkedin.com"},
    "dropbox": {"dropbox.com"},
    "github": {"github.com"},
    "binance": {"binance.com"},
    "coinbase": {"coinbase.com"},
    "dhl": {"dhl.com"},
    "fedex": {"fedex.com"},
    "hbl": {"hbl.com"},
    "meezanbank": {"meezanbank.com"},
    "jazzcash": {"jazzcash.com.pk"},
    "easypaisa": {"easypaisa.com.pk"},
    "ubldigital": {"ubldigital.com", "ubl.com.pk"},
    "nadra": {"nadra.gov.pk"},
    "fbr": {"fbr.gov.pk"},
}

TWO_LEVEL_SUFFIXES = {
    "com.pk",
    "gov.pk",
    "edu.pk",
    "org.pk",
    "net.pk",
    "co.uk",
    "org.uk",
    "ac.uk",
    "gov.uk",
    "com.au",
    "co.in",
    "co.jp",
    "com.br",
    "com.cn",
    "co.za",
    "com.tr",
    "com.sa",
    "co.ae",
}

# Visual confusables mapped to the ASCII letter they imitate.
CONFUSABLES = str.maketrans(
    {
        "0": "o",
        "1": "l",
        "3": "e",
        "4": "a",
        "5": "s",
        "7": "t",
        "8": "b",
        "@": "a",
        "$": "s",
        "а": "a",
        "е": "e",
        "о": "o",
        "р": "p",
        "с": "c",
        "у": "y",
        "х": "x",
        "і": "i",
        "ј": "j",
        "ԁ": "d",
        "ɡ": "g",
        "һ": "h",
        "ӏ": "l",
        "ո": "n",
        "ѕ": "s",
        "ԛ": "q",
        "ԝ": "w",
    }
)


def registrable_domain(host: str) -> str:
    """Approximate the registrable domain (eTLD+1) without shipping the full public suffix list."""
    labels = [label for label in host.lower().strip(".").split(".") if label]
    if len(labels) >= 3 and ".".join(labels[-2:]) in TWO_LEVEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def decode_idna(host: str) -> str:
    try:
        return host.encode("ascii").decode("idna") if "xn--" in host else host
    except UnicodeError:
        return host


def skeleton(text: str) -> str:
    """Fold look-alike characters so that 'pаypa1' (Cyrillic а, digit 1) compares equal to 'paypal'."""
    text = unicodedata.normalize("NFKC", text.lower()).translate(CONFUSABLES)
    return text.replace("rn", "m").replace("vv", "w")


def _distance(a: str, b: str, limit: int = 2) -> int:
    """Damerau-Levenshtein distance with early exit beyond ``limit``."""
    if abs(len(a) - len(b)) > limit:
        return limit + 1
    prev2: list[int] = []
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if i > 1 and j > 1 and ca == b[j - 2] and a[i - 2] == cb:
                cur[j] = min(cur[j], prev2[j - 2] + 1)
        if min(cur) > limit:
            return limit + 1
        prev2, prev = prev, cur
    return prev[-1]


def check_host(host: str) -> list[dict[str, str]]:
    """Return impersonation matches: [{"kind": "lookalike"|"brand_in_domain", "brand", "official"}]."""
    host = decode_idna(host.lower().strip("."))
    reg = registrable_domain(host)
    matches: list[dict[str, str]] = []
    official_hit = any(reg in domains for domains in BRANDS.values())
    if official_hit:
        return matches
    reg_label = skeleton(reg.split(".")[0])
    full = skeleton(host.replace(".", "-"))
    for brand, domains in BRANDS.items():
        official = sorted(domains)[0]
        if (
            reg_label != brand
            and len(brand) >= 4
            and _distance(reg_label, brand) <= (1 if len(brand) <= 5 else 2)
        ):
            matches.append({"kind": "lookalike", "brand": brand, "official": official})
        elif brand in full.split("-") or (len(brand) >= 5 and brand in full):
            matches.append({"kind": "brand_in_domain", "brand": brand, "official": official})
    return matches
