const BACKEND_API_URL = "https://phishguard-backend-yh0j.onrender.com";

chrome.webNavigation.onBeforeNavigate.addListener((details) => {
  // Only scans the main website 
  if (details.frameId === 0 && details.url.startsWith("http")) {
    analyzeUrl(details.url, details.tabId);
  }
});

async function analyzeUrl(url, tabId) {
  if (url.startsWith('http://localhost:5173/') || url.startsWith('https://project-ocltx.vercel.app') ||
  url.startsWith('https://6a1aa732c8c2cb19786f2be9--friendly-mandazi-cc5db3.netlify.app')|| url.startsWith('https://friendly-mandazi-cc5db3.netlify.app/')) {
    console.log("PhishGuard: Bypassing local development URL.");
    return;
  }
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 9000); 

    const response = await fetch(BACKEND_API_URL + "/api/v1/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: url }),
      signal: controller.signal,
    });
    clearTimeout(timeout);

    if (!response.ok) throw new Error("Backend API unreachable");

    const data = await response.json();

    // Cases based on engine_verdict string from backend
    const verdict = data.engine_verdict || "";
    if (verdict.startsWith("Safe (Lexical Score")) {
      // Path A: tiny green toast
      handleSilentLog(url, data, tabId);
    } else if (verdict.startsWith("Safe (Ambiguous")) {
      // Path B: slightly larger informational toast
      handleForensicSafeToast(url, data, tabId);
    } else {
      // Path C: full-screen alert overlay and blocking site
      handlePromptIntervention(tabId, url, data);
    }
  } catch (error) {
    if (error.name === "AbortError") {
      console.warn("PhishGuard: Backend cold-starting, scan skipped for:", url);
    } else {
      console.warn("PhishGuard: Backend unreachable, scan skipped for:", url);
    }
  }
}

function safeSendMessage(tabId, message, retryDelay, onSuccess) {
  chrome.tabs.sendMessage(tabId, message, (response) => {
    const err = chrome.runtime.lastError; 
    if (err) {
      if (retryDelay > 0) {
        setTimeout(() => safeSendMessage(tabId, message, 0, onSuccess), retryDelay);
      }
    } else if (onSuccess) {
      onSuccess(response);
    }
  });
}

function handleSilentLog(url, scanData, tabId) {
  chrome.storage.local.get({ scanHistory: [] }, (result) => {
    const updatedHistory = result.scanHistory;
    updatedHistory.push({
      url: url,
      probability: scanData.confidence_score,
      status: "Safe",
      timestamp: new Date().toISOString(),
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

function handlePromptIntervention(tabId, url, scanData) {
  chrome.storage.local.get({ scanHistory: [] }, (result) => {
    const updatedHistory = result.scanHistory;

    const isMalicious = scanData.is_phishing === true;

    updatedHistory.push({
      url: url,
      probability: scanData.confidence_score,
      status: isMalicious ? "Malicious" : "Suspicious",
      forensics: scanData.forensics_log,
      timestamp: new Date().toISOString(),
      reportId: scanData.url,
    });

    chrome.storage.local.set({ scanHistory: updatedHistory }, () => {
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
setInterval(() => {
  fetch(BACKEND_API_URL + "/health").catch(() => {});
}, 14 * 60 * 1000);