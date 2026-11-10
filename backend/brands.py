import re

from domains import decode_punycode, edit_distance, normalize, registrable_domain

MICROSOFT = ["microsoft.com", "office.com", "office365.com", "microsoftonline.com", "sharepoint.com"]
GOOGLE = ["google.com", "google.co.il", "youtube.com"]

# (name as people write it, the brand's own domains). The most-impersonated brands in phishing reports + major Israeli ones.
BRANDS = [
    ("Microsoft", MICROSOFT), ("Outlook", MICROSOFT), ("Office 365", MICROSOFT),
    ("Google", GOOGLE), ("Gmail", GOOGLE), ("YouTube", GOOGLE),
    ("Apple", ["apple.com"]), ("iCloud", ["apple.com"]),
    ("Amazon", ["amazon.com", "amazon.co.uk", "amazon.de"]), ("PayPal", ["paypal.com"]),
    ("Netflix", ["netflix.com"]), ("Facebook", ["facebook.com", "facebookmail.com", "meta.com"]),
    ("Instagram", ["instagram.com"]), ("WhatsApp", ["whatsapp.com"]), ("LinkedIn", ["linkedin.com"]),
    ("Adobe", ["adobe.com"]), ("DocuSign", ["docusign.com", "docusign.net"]),
    ("Dropbox", ["dropbox.com", "dropboxmail.com"]), ("WeTransfer", ["wetransfer.com"]), ("Zoom", ["zoom.us"]),
    ("eBay", ["ebay.com"]), ("Visa", ["visa.com"]), ("Mastercard", ["mastercard.com"]),
    ("American Express", ["americanexpress.com"]), ("AliExpress", ["aliexpress.com"]),
    ("Booking", ["booking.com"]), ("Airbnb", ["airbnb.com"]),
    ("DHL", ["dhl.com", "dhl.de"]), ("FedEx", ["fedex.com"]), ("UPS", ["ups.com"]), ("USPS", ["usps.com"]),
    ("Chase", ["chase.com"]), ("Wells Fargo", ["wellsfargo.com"]), ("Bank of America", ["bankofamerica.com"]),
    ("HSBC", ["hsbc.com", "hsbc.co.uk"]), ("Binance", ["binance.com"]), ("Coinbase", ["coinbase.com"]),
    ("Spotify", ["spotify.com"]), ("Yahoo", ["yahoo.com"]), ("Twitter", ["twitter.com", "x.com"]),
    ("TikTok", ["tiktok.com"]), ("Telegram", ["telegram.org"]), ("GitHub", ["github.com"]), ("Roblox", ["roblox.com"]),
    ("Bank Hapoalim", ["bankhapoalim.co.il"]), ("Leumi", ["leumi.co.il"]), ("Discount Bank", ["discountbank.co.il"]),
    ("Mizrahi Tefahot", ["mizrahi-tefahot.co.il"]), ("Israel Post", ["israelpost.co.il"]), ("Isracard", ["isracard.co.il"]),
]

# Anyone can open an account here, so they never prove a sender is the brand itself.
FREE_MAIL = {"gmail.com", "outlook.com", "hotmail.com", "live.com", "yahoo.com", "icloud.com", "me.com",
             "aol.com", "proton.me", "protonmail.com", "walla.co.il"}

# One letter away from common words (cooking, finance, cloud), so typo matching would cause false alarms.
_NO_TYPO_CHECK = {"booking", "binance", "icloud"}


def _key(name: str) -> str:
    # Normalized like the domain it's compared to, so "Office 365" -> "officee6s" on both sides.
    return normalize(name.replace(" ", ""))


def lookalike_of(host: str) -> str | None:
    """Return the brand this domain imitates, or None."""
    reg = registrable_domain(host)
    if "." not in reg:  # e.g. "localhost": nothing to compare, and slicing below would crash
        return None
    if reg in FREE_MAIL or any(reg in domains for _, domains in BRANDS):
        return None
    suffix_len = reg.count(".")
    labels = normalize(decode_punycode(host)).split(".")[:-suffix_len]
    main = labels[-1]  # the label the attacker registered, e.g. "paypa1-secure"

    for name, _ in BRANDS:
        key = _key(name)
        # 1. The brand appears as a whole word anywhere: paypal-secure.com, paypal.verify-account.xyz
        for label in labels:
            if key in {label.replace("-", ""), *label.split("-")}:
                return name
        # 2. Typo of the brand in the registered name: amazom.com, paypall.com (long names only)
        if len(key) >= 6 and key not in _NO_TYPO_CHECK:
            limit = 1 if len(key) < 8 else 2
            if any(edit_distance(part, key) <= limit for part in {main.replace("-", ""), *main.split("-")} if part):
                return name
    return None


def brand_in_text(text: str) -> tuple[str, list[str]] | None:
    """Return (brand, its domains) if the text names a brand as a whole word, e.g. 'PayPal Security'."""
    t = normalize(text)
    for name, domains in BRANDS:
        if re.search(rf"\b{re.escape(normalize(name))}\b", t):
            return name, domains
    return None
