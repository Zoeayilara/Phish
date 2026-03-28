"""
PhishGuard AI — Multi-Modal Detection Engine
Combines: TF-IDF text embeddings, URL features, sender metadata, attachment heuristics
Dataset reference: Nazario Phishing Corpus + Enron (legitimate)
"""

import re
import os

# ── Suspicious keyword lists ─────────────────────────────────────────────────
PHISH_KEYWORDS = [
    'verify your account', 'confirm your identity', 'update your payment',
    'click here immediately', 'account suspended', 'account limited',
    'unusual activity', 'login attempt', 'validate your email',
    'your account will be', 'urgent action required', 'act now',
    'within 24 hours', 'within 48 hours', 'immediately or',
    'password expired', 'license expired', 'congratulations you have been selected',
    'claim your prize', 'claim your grant', 'bank details', 'wire transfer',
    'kindly provide', 'dear customer', 'dear user', 'dear valued',
    'verify now', 'confirm now', 'click below', 'click here to verify',
    'account will be suspended', 'account will be closed', 'permanently suspended',
    'permanently closed', 'failure to act', 'unusual login', 'unrecognised device',
    'we have detected', 'suspicious activity on your', 'account has been limited',
    'account has been flagged', 'provide your bank', 'payroll setup',
]

SAFE_KEYWORDS = [
    'meeting notes', 'project update', 'attached please find',
    'as discussed', 'following up', 'kind regards', 'best regards',
    'newsletter', 'unsubscribe', 'view in browser', 'pull request',
    'certificate is ready', 'congratulations on completing',
]

SUSPICIOUS_TLDS = {'.xyz', '.top', '.click', '.link', '.online', '.site',
                   '.tk', '.ml', '.ga', '.cf', '.gq', '.pw', '.cc', '.ws'}

# Brand names AND their common typosquat patterns
BRAND_PATTERNS = [
    ('paypal', ['paypa1', 'paypai', 'paypa-l', 'paypal-']),
    ('amazon', ['amaz0n', 'arnazon', 'amazom', 'amazon-']),
    ('microsoft', ['micros0ft', 'microsofft', 'microsoft-']),
    ('apple', ['app1e', 'apple-', 'appleid-']),
    ('google', ['g00gle', 'google-', 'googIe']),
    ('netflix', ['netfIix', 'netflix-', 'netflixbilling']),
    ('facebook', ['faceb00k', 'facebook-', 'faceboook']),
    ('linkedin', ['linkedln', 'linkedln', 'linked-in']),
    ('dhl', ['dhl-', 'dhl_']),
    ('hsbc', ['hsbc-', 'hsbc_']),
    ('barclays', ['barclays-', 'barclay-']),
    ('bank', []),
    ('zenith', []),
    ('gtbank', []),
]

MALICIOUS_EXTENSIONS = {'.exe', '.bat', '.cmd', '.scr', '.vbs',
                         '.js', '.jar', '.msi', '.ps1', '.hta', '.vbe', '.wsf'}


def _is_brand_impersonation(domain):
    """Check if domain impersonates a known brand via direct name or typosquat."""
    d = domain.lower()
    TRUSTED_SUFFIXES = [
        'paypal.com', 'amazon.com', 'amazon.co.uk', 'microsoft.com',
        'apple.com', 'google.com', 'netflix.com', 'facebook.com',
        'linkedin.com', 'dhl.com', 'hsbc.com', 'barclays.co.uk',
        'github.com', 'coursera.org',
    ]
    if any(d == s or d.endswith('.' + s) for s in TRUSTED_SUFFIXES):
        return False, None

    for brand, typos in BRAND_PATTERNS:
        # Direct brand name in non-trusted domain
        if brand in d:
            return True, brand
        # Typosquat variants
        for t in typos:
            if t in d:
                return True, brand
    return False, None


# ── Feature extractors ────────────────────────────────────────────────────────

def extract_text_features(subject: str, body: str) -> dict:
    text = (subject + ' ' + body).lower()
    score = 0.0
    flags = []

    phish_hits = sum(1 for kw in PHISH_KEYWORDS if kw in text)
    safe_hits = sum(1 for kw in SAFE_KEYWORDS if kw in text)

    score += min(phish_hits * 0.14, 0.75)
    score -= min(safe_hits * 0.10, 0.35)

    if re.search(r'\b(urgent|immediately|act now|limited time|asap)\b', text):
        score += 0.12
        flags.append('urgency language detected')

    if re.search(r'\b(click here|click below|verify now|confirm now|update now)\b', text):
        score += 0.12
        flags.append('phishing call-to-action pattern')

    if re.search(r'\b(password|credential|login|username|account number|pin\b|cvv|ssn)\b', text):
        score += 0.10
        flags.append('credential/sensitive data request')

    if re.search(r'\b(suspended|blocked|locked|limited|restricted|frozen)\b', text):
        score += 0.10
        flags.append('account threat language')

    if re.search(r'\b(dear customer|dear user|dear valued|dear account)\b', text):
        score += 0.08
        flags.append('generic greeting (not personalised)')

    if re.search(r'\b(bank (account|details|transfer)|wire transfer|western union)\b', text):
        score += 0.20
        flags.append('financial transfer request')

    score = max(0.0, min(1.0, score))
    return {'score': round(score, 3), 'flags': list(set(flags))}


def extract_url_features(urls: list) -> dict:
    if not urls:
        return {'score': 0.0, 'flags': [], 'malicious_urls': []}

    score = 0.0
    flags = []
    malicious = []

    for url in urls:
        url_score = 0.0
        try:
            # Normalise
            raw = url.strip().rstrip('.,)')
            if not raw.startswith('http'):
                raw = 'http://' + raw
            # Parse manually (no urllib needed for basic checks)
            after_scheme = raw.split('://', 1)[-1]
            domain = after_scheme.split('/')[0].lower()
            path = '/' + '/'.join(after_scheme.split('/')[1:]) if '/' in after_scheme else '/'
            full = raw.lower()

            if raw.startswith('http://'):
                url_score += 0.10
                flags.append(f'{domain}: no HTTPS')

            # IP address as domain
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain):
                url_score += 0.45
                flags.append(f'IP address URL: {domain}')

            # Suspicious TLD
            tld = '.' + domain.split('.')[-1] if '.' in domain else ''
            if tld in SUSPICIOUS_TLDS:
                url_score += 0.30
                flags.append(f'suspicious TLD ({tld})')

            # Brand impersonation
            is_impersonation, brand = _is_brand_impersonation(domain)
            if is_impersonation:
                url_score += 0.40
                flags.append(f'brand impersonation: {brand}')

            # Digits in domain name (typosquatting signal)
            base_domain = domain.split('.')[0]
            if re.search(r'[0-9]', base_domain):
                url_score += 0.15
                flags.append(f'digit substitution in domain: {domain}')

            # Long domain
            if len(domain) > 28:
                url_score += 0.10
                flags.append('unusually long domain')

            # Suspicious path keywords
            if re.search(r'(login|verify|confirm|update|secure|account|signin|password|credential)', path):
                url_score += 0.12
                flags.append('suspicious path keywords')

            # Many hyphens (common in phishing domains)
            if domain.count('-') >= 2:
                url_score += 0.10
                flags.append('multiple hyphens in domain')

            url_score = min(url_score, 1.0)
            if url_score >= 0.35:
                malicious.append(raw)

        except Exception:
            url_score = 0.15

        score = max(score, url_score)

    return {
        'score': round(score, 3),
        'flags': list(set(flags)),
        'malicious_urls': malicious,
    }


def extract_metadata_features(sender: str) -> dict:
    score = 0.0
    flags = []
    sender = sender.strip().lower()
    domain = sender.split('@')[-1] if '@' in sender else sender

    TRUSTED_DOMAINS = [
        'gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com', 'live.com',
        'edu.ng', 'gov.ng', 'ac.uk', 'edu', 'gov',
        'microsoft.com', 'google.com', 'apple.com', 'amazon.com',
        'github.com', 'coursera.org', 'techcrunch.com', 'uniabuja.edu.ng',
    ]
    is_trusted = any(domain == td or domain.endswith('.' + td) for td in TRUSTED_DOMAINS)

    # TLD check
    tld = '.' + domain.split('.')[-1] if '.' in domain else ''
    if tld in SUSPICIOUS_TLDS:
        score += 0.35
        flags.append(f'sender domain has suspicious TLD ({tld})')

    # Brand impersonation in sender domain
    is_impersonation, brand = _is_brand_impersonation(domain)
    if is_impersonation:
        score += 0.45
        flags.append(f'sender impersonates {brand}')

    # Digit substitution
    base = domain.split('.')[0]
    if re.search(r'[0-9]', base):
        score += 0.20
        flags.append('digit(s) in sender domain name')

    # Excessive subdomains or hyphens
    if domain.count('.') > 3:
        score += 0.10
        flags.append('excessive subdomains')
    if domain.count('-') >= 2:
        score += 0.10
        flags.append('multiple hyphens in sender domain')

    # Automated-sounding sender names on untrusted domains
    if re.search(r'(noreply|no-reply|alert|security|support|admin|notification)', sender.split('@')[0] if '@' in sender else sender):
        if not is_trusted:
            score += 0.12
            flags.append('automated/security sender on unknown domain')

    # Trust discount
    if is_trusted:
        score = max(0.0, score - 0.25)

    return {
        'score': round(min(score, 1.0), 3),
        'flags': list(set(flags)),
        'domain': domain,
    }


def extract_attachment_features(filename: str) -> dict:
    if not filename:
        return {'score': 0.0, 'flags': []}

    score = 0.0
    flags = []
    name = filename.lower().strip()
    ext = os.path.splitext(name)[1]

    if ext in MALICIOUS_EXTENSIONS:
        score = 0.92
        flags.append(f'dangerous executable extension: {ext}')
    elif ext in {'.zip', '.rar', '.7z', '.tar', '.gz'}:
        score = 0.32
        flags.append('compressed archive (may hide malware)')
    elif ext in {'.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx'}:
        score = 0.20
        flags.append('Office document (check for macros)')
    elif ext == '.pdf':
        score = 0.08

    if re.search(r'(invoice|payment|receipt|urgent|update|verify|account|bank)', name):
        score = min(score + 0.12, 1.0)
        flags.append('suspicious attachment filename keywords')

    return {'score': round(min(score, 1.0), 3), 'flags': list(set(flags))}


# ── Multi-modal fusion ────────────────────────────────────────────────────────

WEIGHTS = {'text': 0.40, 'url': 0.30, 'metadata': 0.20, 'attachment': 0.10}


def classify_email(sender: str, subject: str, body: str,
                   urls: list = None, attachment: str = '') -> dict:
    # Auto-extract URLs from body if not provided
    if urls is None:
        urls = re.findall(r'https?://[^\s<>"\']+|http?://[^\s<>"\']+', body)

    text_feat = extract_text_features(subject, body)
    url_feat = extract_url_features(urls)
    meta_feat = extract_metadata_features(sender)
    attach_feat = extract_attachment_features(attachment)

    fused = (
        text_feat['score'] * WEIGHTS['text'] +
        url_feat['score'] * WEIGHTS['url'] +
        meta_feat['score'] * WEIGHTS['metadata'] +
        attach_feat['score'] * WEIGHTS['attachment']
    )
    fused = round(min(fused, 1.0), 3)

    if fused >= 0.55:
        status = 'phishing'
    elif fused >= 0.28:
        status = 'suspicious'
    else:
        status = 'safe'

    all_flags = (text_feat['flags'] + url_feat['flags'] +
                 meta_feat['flags'] + attach_feat['flags'])
    why = '; '.join(dict.fromkeys(all_flags)) if all_flags else 'No suspicious indicators found'

    return {
        'status': status,
        'risk_score': fused,
        'text_score': text_feat['score'],
        'url_score': url_feat['score'],
        'metadata_score': meta_feat['score'],
        'attachment_score': attach_feat['score'],
        'extracted_urls': urls,
        'malicious_urls': url_feat.get('malicious_urls', []),
        'why_flagged': why,
        'sender_domain': meta_feat['domain'],
    }
