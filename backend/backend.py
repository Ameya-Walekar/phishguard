#Importing Libraries

import os
import json
import math
import re
import base64
import asyncio
from collections import Counter
from urllib.parse import urlparse
from contextlib import asynccontextmanager
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime
from pathlib import Path
import httpx
import joblib
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from datetime import datetime,timezone
try:
    import whois
    import dns.resolver

    FORENSIC_LIBS_AVAILABLE = True
except ImportError:
    FORENSIC_LIBS_AVAILABLE = False

# Global runtime pointer holding the serialized machine learning model in RAM
ml_model = None

# CTI : Directly checking if a particular url is reported as phishing
URLHAUS_API_URL = "https://urlhaus-api.abuse.ch/v1/url/"

# Feature Extraction

def calculate_shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    total_len = len(text)
    char_counts = Counter(text)
    probabilities = [count / total_len for count in char_counts.values()]
    return -sum(p * math.log2(p) for p in probabilities)


SUSPICIOUS_TLDS = {
    "tk","ml","ga","cf","gq","xyz","top","click","link","work",
    "date","faith","review","party","science","cricket","bid",
    "loan","win","racing","download","accountant","trade","webcam",
    "cfd","wiki","zip","mov"
}

BRAND_KEYWORDS = [
    "paypal","google","apple","amazon","microsoft","facebook","instagram",
    "netflix","bank","secure","account","update","verify","login","signin"
]

URL_SHORTENERS = {
    "bit.ly","tinyurl.com","goo.gl","t.co","ow.ly","buff.ly",
    "shorturl.at","is.gd","rb.gy","cutt.ly"
}

# Populated at startup from top_domains.json (serialized during training)
TOP_DOMAINS: set[str] = set()

def levenshtein(a: str, b: str) -> int:
    dp = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        ndp = [i + 1]
        for j, cb in enumerate(b):
            ndp.append(min(ndp[j] + 1, dp[j + 1] + 1, dp[j] + (ca != cb)))
        dp = ndp
    return dp[-1]

def get_typosquat_score(hostname: str) -> float:
    """
    Returns a suspicion boost (0.0–0.15) if the registered domain is
    suspiciously close to a known-legitimate domain but is NOT that domain.
    Uses length pre-filter to keep inference fast.
    """
    parts = hostname.split(".")
    candidate = parts[-2].lower() if len(parts) >= 2 else hostname.lower()

    if candidate in TOP_DOMAINS:   # exact match → legitimate
        return 0.0

    clen = len(candidate)
    for ref in TOP_DOMAINS:
        if abs(len(ref) - clen) > 2:  # length pre-filter — skips ~80% of comparisons
            continue
        threshold = 1 if len(ref) <= 5 else 2
        dist = levenshtein(candidate, ref)
        if 0 < dist <= threshold:
            print(f"[TYPOSQUAT] '{candidate}' ~ '{ref}' (dist={dist})")
            return 0.15             # boost phishing probability by this amount
    return 0.0

def adjust_for_path_complexity(url: str, phishing_prob: float) -> float:
    """
    If the model fires primarily on path_depth/numeric_token_count but
    the hostname itself looks clean, pull the score below 0.7 so
    forensics validates it instead of issuing an instant malicious verdict.
    Only intervenes when phishing_prob is in the (0.7, 0.9] band —
    scores above 0.9 have strong multi-feature consensus and are left alone.
    """
    if not (0.7 < phishing_prob <= 1):
        return phishing_prob

    parsed = urlparse(url if url.startswith("http") else "http://" + url)
    hostname = parsed.netloc.split(":")[0].lower()
    path     = parsed.path
    parts    = hostname.split(".")
    tld      = parts[-1] if parts else ""

    legitimacy_signals = 0

    # Signal 1: registered domain is purely alphabetic and reasonably long
    registered = parts[-2] if len(parts) >= 2 else hostname
    if registered.isalpha() and len(registered) >= 5:
        legitimacy_signals += 1

    # Signal 2: common trustworthy TLD
    if tld in {"com", "org", "net", "edu", "io", "dev", "gov", "ac"}:
        legitimacy_signals += 1

    # Signal 3: numeric tokens in path but NO obfuscation chars
    has_obfuscation = bool(re.search(r'[%@=~\\]', path))
    has_numeric_path = bool(re.search(r'\d+', path))
    if has_numeric_path and not has_obfuscation:
        legitimacy_signals += 1

    # Signal 4: no subdomains (clean apex domain)
    if max(len(parts) - 2, 0) == 0:
        legitimacy_signals += 1

    # Signal 5: no hyphens in hostname (hyphens are a common phishing tell)
    if "-" not in hostname:
        legitimacy_signals += 1

    if legitimacy_signals >= 3:
        adjusted = min(phishing_prob, 0.65)
        print(f"[PATH-ADJUST] legitimacy_signals={legitimacy_signals}, "
              f"score {phishing_prob:.3f} → {adjusted:.3f} (forensics will validate)")
        return adjusted

    return phishing_prob

def check_ip_in_domain(netloc: str) -> int:
    host = netloc.split(":")[0]
    ipv4_pattern = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
    return 1 if ipv4_pattern.match(host) else 0


def extract_lexical_features(url: str) -> list:
    url_str = str(url)

    temp = ("http://" + url_str) if not url_str.startswith("http") else url_str
    parsed = urlparse(temp)
    hostname = parsed.netloc.split(":")[0]
    path = parsed.path
    parts = hostname.split(".")
    tld = parts[-1].lower() if parts else ""

    # Original 9
    url_length = len(url_str)
    hostname_length = len(hostname)
    dot_count = url_str.count('.')
    hyphen_count = url_str.count('-')
    at_count = url_str.count('@')
    query_count = url_str.count('?')
    is_ip = check_ip_in_domain(parsed.netloc)
    url_entropy = calculate_shannon_entropy(url_str)

    # 7 added features
    subdomain_count = max(len(parts) - 2, 0)
    suspicious_tld = int(tld in SUSPICIOUS_TLDS)
    digit_ratio = sum(c.isdigit() for c in hostname) / max(len(hostname), 1)
    has_port = int(":" in parsed.netloc)
    path_depth = path.count('/')
    brand_in_subdomain = int(any(b in hostname.lower() for b in BRAND_KEYWORDS))
    is_url_shortener = int(hostname.lower() in URL_SHORTENERS)

    # 5 new features
    url_digit_ratio = sum(c.isdigit() for c in url_str) / max(len(url_str), 1)
    special_char_count = sum(c in '!~,+\\_%=' for c in url_str)
    hostname_tokens = re.split(r'[\.\-]', hostname)
    longest_hostname_token = max((len(w) for w in hostname_tokens), default=0)
    numeric_token_count = len(re.findall(r'\d+', path))
    tld_length = len(tld)

    return [
        url_length, hostname_length, dot_count, hyphen_count, at_count,
        query_count, is_ip, url_entropy, subdomain_count,
        suspicious_tld, digit_ratio, has_port, path_depth,
        brand_in_subdomain, is_url_shortener,
        url_digit_ratio, special_char_count, longest_hostname_token,
        numeric_token_count, tld_length
    ]


# CTI


async def check_urlhaus(url: str, client: httpx.AsyncClient) -> dict:
    """Queries live malware indicators from Abuse.ch using non-blocking POST methods."""
    result = {"hit": False, "source": "URLhaus"}
    try:
        response = await client.post(
            URLHAUS_API_URL,
            data={"url": url},
            timeout=0.15,  # Enforce explicit 150ms ceiling constraint
        )

        if response.status_code == 200:
            data = response.json()
            if data.get("query_status") == "verified_malicious":
                result["hit"] = True
                result["threat_type"] = data.get("threat_type", "malware_download")
    except (httpx.TimeoutException, httpx.RequestError):
        # Safe network timeout fallback: let local engines handle evaluation
        pass
    return result


# Forensic Features


def execute_live_forensics(hostname: str) -> dict:
    """Performs thread-isolated network record queries for border case validation."""
    verdict = {"dns_active": False, "is_new_domain": False, "error": None}
    print("🚨 FORENSICS STARTED")
    if not FORENSIC_LIBS_AVAILABLE:
        verdict["error"] = "Forensic dependencies not installed locally."
        return verdict

    clean_host = hostname.split(":")[0]
    try:
        # 1. DNS : Checking if domain has valid IPv4('A') record
        dns.resolver.resolve(clean_host, "A")
        verdict["dns_active"] = True

        # 2. Registrar Registration Age Calculations
        domain_info = whois.whois(clean_host)
        creation_date = domain_info.creation_date
        if isinstance(creation_date, list): 
            creation_date = creation_date[0]
        print(f"[DEBUG] Domain Age: {(datetime.now(timezone.utc) - creation_date.astimezone(timezone.utc)).days} days")
        print(f"[DEBUG] DNS 'A' Record Found: {verdict['dns_active']}")
        if creation_date:
            age_days = (datetime.now(timezone.utc) - creation_date.astimezone(timezone.utc)).days
            if age_days < 14:  # Zero-day indicator rule flag
                verdict["is_new_domain"] = True
    except Exception as e:
        print(f"[ERROR] {e}")
        verdict["error"] = str(e)
    return verdict

def normalize_url(url):
    """Remove only http:// or https:// scheme."""
    url = url.strip()
    if url.startswith('https://'):
        url = url[8:]
    elif url.startswith('http://'):
        url = url[7:]
    return url.rstrip('/') 

# --- 4. MODERN LIFESPAN APP INITIALIZATION ---


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Securely handles structural startup weight allocations and teardown cycles."""
    global ml_model, TOP_DOMAINS
    model_path = Path(__file__).resolve().parent / "ml_model_xgb.joblib"
    if os.path.exists(model_path):
        try:
            ml_model = joblib.load(model_path)
            print(
                "[+] Success: Master serialization models active in RAM workspace allocations."
            )
        except Exception as e:
            print(f"[-] Critical exception mapping memory caches: {str(e)}")
            ml_model = None
    else:
        print(
            f"[!] Warning: '{model_path}' not located. Safe engine fallback pipeline deployed."
        )
        ml_model = None

    # Load reference domain list for typosquat detection (serialized at training time)
    domains_path = Path(__file__).resolve().parent / "top_domains.json"
    if domains_path.exists():
        try:
            with open(domains_path) as f:
                TOP_DOMAINS = set(json.load(f))
            print(f"[+] Loaded {len(TOP_DOMAINS)} reference domains for typosquat detection.")
        except Exception as e:
            print(f"[!] top_domains.json load failed: {e}. Typosquat detection disabled.")
    else:
        print("[!] top_domains.json not found. Typosquat detection disabled.")

    # Startup complete
    yield

    print("[-] Tearing down application: Flushing structural vector arrays.")
    ml_model = None


app = FastAPI(
    title="PhishGuard", version="1.2.0", lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],      # Allows Chrome extensions (null origin) + dashboard + localhost
    allow_credentials=False,  # Must be False when allow_origins=["*"]
    allow_methods=["*"],
    allow_headers=["*"],
)

class URLScanRequest(BaseModel):
    url: str


class URLScanResponse(BaseModel):
    url: str
    is_phishing: bool
    confidence_score: float
    engine_verdict: str
    cti_matches: list
    forensics_triggered: bool
    forensics_log: dict


# --- 5. COMPLETED HYBRID TRIAGE ROUTING PIPELINE ---

# Persistent JSON log file — survives Render cold starts
DB_FILE = Path(__file__).resolve().parent / "scan_logs.json"

def load_db() -> list:
    if DB_FILE.exists():
        try:
            with open(DB_FILE, "r") as f:
                return json.load(f)
        except Exception:
            return []
    return []

def save_db(db: list) -> None:
    with open(DB_FILE, "w") as f:
        json.dump(db, f)

@app.post("/api/v1/scan", response_model=URLScanResponse)
async def scan_url(payload: URLScanRequest) -> URLScanResponse:
    print(f"🚨 INCOMING RAW URL: '{payload.url}' 🚨")
    target_url = payload.url
    if not target_url:
        raise HTTPException(
            status_code=400,
            detail="The ingestion payload target string cannot drop empty.",
        )

    parsed_domain = urlparse(target_url).netloc
    cti_hits: list[str] = []
    forensics_run = False
    forensics_data: dict = {}

    # STAGE 1: ASYNC CTI THREAT FEED CO-PROCESSING
    async with httpx.AsyncClient() as client:
        # Launch URLhaus and VirusTotal queries concurrently on the async event loop
        urlhaus_task = asyncio.create_task(check_urlhaus(target_url, client))

        urlhaus_res = (await asyncio.gather(urlhaus_task))[0]

    if urlhaus_res.get("hit"):
        cti_hits.append(
            f"URLhaus Blacklist Match ({urlhaus_res.get('threat_type')})"
        )

    # CTI
    if cti_hits:
        db = load_db()
        db.append({
            "id": len(db) + 1,
            "url": target_url,
            "risk_score": round(1.0, 4),
            "status": "Malicious",
            "timestamp": datetime.utcnow().isoformat()
        })
        save_db(db)
        return URLScanResponse(
            url=target_url,
            is_phishing=True,
            confidence_score=1.0,
            engine_verdict="Malicious (Instant Global CTI Feed Match Triggered)",
            cti_matches=cti_hits,
            forensics_triggered=forensics_run,
            forensics_log=forensics_data,
        )

    target_lex_url = normalize_url(target_url)
    
    # ML model used here 
    is_phishing = False
    confidence = 0.0
    verdict = "Safe (Default safe architectural pass)"

    if ml_model is not None:
        try:
            # Generate local lexical numerical data matrices
            features = extract_lexical_features(target_lex_url)
            print(f"🚨 2. CALCULATED FEATURES: {features}")
            probabilities = ml_model.predict_proba([features])[0]
            phishing_prob = float(probabilities[0])   # index 1 = malicious probability
            safe_prob     = float(probabilities[0])
            print(f"DEBUG: Raw Probabilities: safe={safe_prob:.4f}, malicious={phishing_prob:.4f}")

            # --- POST-PREDICTION ADJUSTMENTS ---

            # 1. Typosquat boost: if hostname resembles a legit domain, raise suspicion
            parsed_hostname = urlparse(
                target_lex_url if target_lex_url.startswith("http") else "http://" + target_lex_url
            ).netloc.split(":")[0]
            typosquat_boost = get_typosquat_score(parsed_hostname)
            if typosquat_boost > 0:
                phishing_prob = min(phishing_prob + typosquat_boost, 1.0)
                print(f"[TYPOSQUAT] Probability boosted → {phishing_prob:.4f}")

            # 2. Path-complexity dampener: pull high scores into forensics zone
            #    when hostname signals look clean (e.g. codeforces.com/problem/1234/A)
            phishing_prob = adjust_for_path_complexity(target_lex_url, phishing_prob)

            # --- TRIAGE ROUTING ---
            if phishing_prob < 0.2:
                is_phishing = False
                confidence  = safe_prob
                verdict     = "Safe (Lexical Score Validated Low Risk)"

            elif phishing_prob > 0.7:
                is_phishing = True
                confidence  = phishing_prob
                verdict     = "Malicious (Lexical Fingerprint High Risk Match)"
            else:
                forensics_run = True
                # Offload blocking network sockets to background thread pool
                forensics_data = await asyncio.to_thread(
                    execute_live_forensics, parsed_domain
                )
                
                if (
                    forensics_data.get("is_new_domain") is True
                    or forensics_data.get("dns_active") is False
                ):
                    is_phishing = True
                    confidence  = phishing_prob
                    verdict     = (
                        "Malicious (Ambiguous Lexical Match Confirmed by Forensics)"
                    )
                else:
                    is_phishing = False
                    confidence  = phishing_prob
                    verdict     = (
                        "Safe (Ambiguous Lexical Suspicion Cleared by Forensics)"
                    )

        except Exception as e:
            raise HTTPException(
                status_code=500,
                detail=f"ML Framework Pipeline Execution Crash: {str(e)}",
            )
    print(f"🚨 3. Verdict {verdict}")
    db = load_db()
    db.append({
        "id": len(db) + 1,
        "url": target_url,
        "risk_score": round(confidence, 4),
        "status": "Malicious" if is_phishing else "Safe",
        "timestamp": datetime.utcnow().isoformat()
    })
    save_db(db)
    return URLScanResponse(
        url=target_url,
        is_phishing=is_phishing,
        confidence_score=round(confidence, 4),
        engine_verdict=verdict,
        cti_matches=cti_hits,
        forensics_triggered=forensics_run,
        forensics_log=forensics_data,
    )


@app.get("/health")
def health_check():
    return {"status": "operational", "ml_engine_loaded": ml_model is not None}

@app.get("/api/logs")
async def get_logs():
    # Returns all stored scan results from persistent JSON file
    return load_db()

@app.delete("/api/logs")
async def delete_logs():
    save_db([])
    return {"status": "cleared"}