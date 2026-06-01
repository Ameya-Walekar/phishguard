const BACKEND_API_URL = "https://phishguard-backend-yh0j.onrender.com";

// 1. SECURITY UPGRADE: Catch the URL before the page downloads!
chrome.webNavigation.onBeforeNavigate.addListener((details) => {
  // Only scan the main website frame, ignore background elements
  if (details.frameId === 0 && details.url.startsWith("http")) {
    analyzeUrl(details.url, details.tabId);
  }
});

async function analyzeUrl(url, tabId) {
  // Bypass check must happen BEFORE the fetch, not after
  if (url.startsWith('http://localhost:5173/') || url.startsWith('https://project-ocltx.vercel.app') ||
  url.startsWith('https://6a1aa732c8c2cb19786f2be9--friendly-mandazi-cc5db3.netlify.app')|| ('https://friendly-mandazi-cc5db3.netlify.app/')) {
    console.log("PhishGuard: Bypassing local development URL.");
    return;
  }
  try {
    const response = await fetch(BACKEND_API_URL + "/api/v1/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: url }),
    });

    if (!response.ok) throw new Error("Backend API unreachable");

    const data = await response.json();

    // Route based on backend engine_verdict string
    const verdict = data.engine_verdict || "";
    if (verdict.startsWith("Safe (Lexical Score")) {
      // Path A: Low-risk, tiny green toast
      handleSilentLog(url, data, tabId);
    } else if (verdict.startsWith("Safe (Ambiguous")) {
      // Path B: Cleared by forensics, slightly larger informational toast
      handleForensicSafeToast(url, data, tabId);
    } else {
      // Path C: Malicious verdict, full-screen alert overlay
      handlePromptIntervention(tabId, url, data);
    }
  } catch (error) {
    console.error("PhishGuard Analysis Error:", error);
  }
}

// FIX: Central safe sendMessage helper that always consumes lastError
// to silence "Receiving end does not exist" uncaught promise errors.
function safeSendMessage(tabId, message, retryDelay, onSuccess) {
  chrome.tabs.sendMessage(tabId, message, (response) => {
    const err = chrome.runtime.lastError; // MUST be read here to consume it
    if (err) {
      if (retryDelay > 0) {
        setTimeout(() => safeSendMessage(tabId, message, 0, onSuccess), retryDelay);
      }
    } else if (onSuccess) {
      onSuccess(response);
    }
  });
}

// Path A Execution: low-risk URLs, just log + tiny green toast
function handleSilentLog(url, scanData, tabId) {
  chrome.storage.local.get({ scanHistory: [] }, (result) => {
    const updatedHistory = result.scanHistory;
    updatedHistory.push({
      url: url,
      // BACKEND FIELD: confidence_score
      probability: scanData.confidence_score,
      status: "Safe",
      timestamp: new Date().toISOString(),
      // No report_id from backend yet; using URL as placeholder
      reportId: scanData.url,
    });

    chrome.storage.local.set({ scanHistory: updatedHistory }, () => {
      console.log(
        `%c[PhishGuard] Silently logged safe site: ${url}`,
        "color: #1df36fff"
      );

      if (tabId) {
        safeSendMessage(tabId, { action: "SHOW_SAFE_TOAST" }, 500);
      }
    });
  });
}

// Path B Execution: ambiguous lexical score cleared by forensics, slightly larger informational toast
function handleForensicSafeToast(url, scanData, tabId) {
  chrome.storage.local.get({ scanHistory: [] }, (result) => {
    const updatedHistory = result.scanHistory;
    updatedHistory.push({
      url: url,
      probability: scanData.confidence_score,
      status: "Safe",
      forensics: scanData.forensics_log,
      timestamp: new Date().toISOString(),
      reportId: scanData.url,
    });

    chrome.storage.local.set({ scanHistory: updatedHistory }, () => {
      console.log(
        `%c[PhishGuard] Forensics cleared, logged safe site: ${url}`,
        "color: #1df36fff"
      );

      if (tabId) {
        safeSendMessage(
          tabId,
          { action: "SHOW_FORENSIC_SAFE_TOAST", payload: { probability: scanData.confidence_score } },
          500
        );
      }
    });
  });
}

// Path C Execution: suspicious / malicious URLs, show full alert overlay
function handlePromptIntervention(tabId, url, scanData) {
  chrome.storage.local.get({ scanHistory: [] }, (result) => {
    const updatedHistory = result.scanHistory;

    // BACKEND FIELD: is_phishing (boolean)
    const isMalicious = scanData.is_phishing === true;

    updatedHistory.push({
      url: url,
      probability: scanData.confidence_score,
      status: isMalicious ? "Malicious" : "Suspicious",
      // BACKEND FIELD: forensics_log
      forensics: scanData.forensics_log,
      timestamp: new Date().toISOString(),
      reportId: scanData.url,
    });

    chrome.storage.local.set({ scanHistory: updatedHistory }, () => {
      // 2. TIMING UPGRADE: Retry loop for the messaging system
      const payload = {
        action: "TRIGGER_ALERT",
        payload: {
          url: url,
          probability: scanData.confidence_score,
          status: isMalicious ? "Malicious" : "Suspicious",
          forensics: scanData.forensics_log,
        },
      };
      safeSendMessage(tabId, payload, 50);
    });
  });
}