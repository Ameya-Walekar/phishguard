
#Importing Libraries

import os
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


def check_ip_in_domain(netloc: str) -> int:
    host = netloc.split(":")[0]
    ipv4_pattern = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
    return 1 if ipv4_pattern.match(host) else 0


def extract_lexical_features(url: str) -> list:
    parsed = urlparse(url)
    url_str = str(url)

    return [
        len(url_str),                                    # url_length
        len(parsed.netloc),                              # hostname_length
        url_str.count('.'),                              # dot_count
        url_str.count('-'),                              # hyphen_count
        url_str.count('@'),                              # at_count
        url_str.count('/'),                              # slash_count
        url_str.count('?'),                              # query_count
        check_ip_in_domain(parsed.netloc),               # is_ip
        calculate_shannon_entropy(url_str),                            # url_entropy
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
        print(f"[DEBUG] DNS 'A' Record Found: {verdict["dns_active"]}")
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
    global ml_model
    model_path = Path.cwd().parent /"ml_model_xgb.joblib"
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

    # Startup complete
    yield

    print("[-] Tearing down application: Flushing structural vector arrays.")
    ml_model = None


app = FastAPI(
    title="PhishGuard", version="1.2.0", lifespan=lifespan
)

origins = [
    "http://localhost:5173",
    "https://project-ocltx.vercel.app"   # Your React Dashboard
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,  # Allows all origins, necessary for Chrome Extensions
    allow_credentials=True,
    allow_methods=["*"],  # Allows POST, GET, OPTIONS, etc.
    allow_headers=["*"],  # Allows all headers
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

db=[]

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

        urlhaus_res = await asyncio.gather(urlhaus_task)

    if urlhaus_res.get("hit"):
        cti_hits.append(
            f"URLhaus Blacklist Match ({urlhaus_res.get('threat_type')})"
        )

    
    global db
    

    # CTI
    if cti_hits:
        db.append({
        "id": len(db) + 1,
         "url": target_url,
        "risk_score": round(1.0, 4),
        "status": "Malicious",
        "timestamp": datetime.utcnow().isoformat()
        })
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
            phishing_prob = float(probabilities[0])
            print(f"DEBUG: Raw Probabilities: {probabilities}")
            
            if phishing_prob < 0.2:
                is_phishing = False
                confidence = float(probabilities[0])
                verdict = "Safe (Lexical Score Validated Low Risk)"

            elif phishing_prob > 0.7:
                is_phishing = True
                confidence = phishing_prob
                verdict = "Malicious (Lexical Fingerprint High Risk Match)"
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
                    confidence = phishing_prob
                    verdict = (
                        "Malicious (Ambiguous Lexical Match Confirmed by Forensics)"
                    )
                else:
                    is_phishing = False
                    confidence = float(phishing_prob)
                    verdict = (
                        "Safe (Ambiguous Lexical Suspicion Cleared by Forensics)"
                    )

        except Exception as e:
            raise HTTPException(
                status_code=500,
                detail=f"ML Framework Pipeline Execution Crash: {str(e)}",
            )
    print(f"🚨 3. Verdict {verdict}")
    db.append({
    "id": len(db) + 1,
    "url": target_url,
    "risk_score": round(confidence, 4),
    "status": "Malicious" if is_phishing else "Safe",
    "timestamp": datetime.utcnow().isoformat()
    })
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
    # Returns the list of all stored scan results as JSON
    return db