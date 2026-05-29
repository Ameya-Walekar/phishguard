const BACKEND_API_URL = "http://localhost:8000/api/v1/scan";

// 1. SECURITY UPGRADE: Catch the URL before the page downloads!
chrome.webNavigation.onBeforeNavigate.addListener((details) => {
  // Only scan the main website frame, ignore background elements
  if (details.frameId === 0 && details.url.startsWith("http")) {
    analyzeUrl(details.url, details.tabId);
  }
});

async function analyzeUrl(url, tabId) {
  try {
    const response = await fetch(BACKEND_API_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: url }),
    });

    if (!response.ok) throw new Error("Backend API unreachable");

    const data = await response.json();

    if (url.startsWith('http://localhost:5173/') || (url.startsWith('https://project-ocltx.vercel.app'))) {
            console.log("PhishGuard: Bypassing local development URL.");
            return; // Stop the function here
        }
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

// Path A Execution: low‑risk URLs, just log + tiny green toast
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

      // NEW: Send a message to the content script to show the tiny green popup
      if (tabId) {
        chrome.tabs.sendMessage(
          tabId,
          { action: "SHOW_SAFE_TOAST" },
          () => {
            // If content.js isn't ready yet, retry once after 500ms
            if (chrome.runtime.lastError) {
              setTimeout(() => {
                chrome.tabs.sendMessage(tabId, {
                  action: "SHOW_SAFE_TOAST",
                });
              }, 500);
            }
          }
        );
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
        const sendToast = () => {
          chrome.tabs.sendMessage(
            tabId,
            {
              action: "SHOW_FORENSIC_SAFE_TOAST",
              payload: { probability: scanData.confidence_score },
            },
            () => {
              if (chrome.runtime.lastError) {
                setTimeout(sendToast, 500);
              }
            }
          );
        };
        sendToast();
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
      const sendAlert = () => {
        chrome.tabs.sendMessage(
          tabId,
          {
            action: "TRIGGER_ALERT",
            payload: {
              url: url,
              probability: scanData.confidence_score,
              status: isMalicious ? "Malicious" : "Suspicious",
              forensics: scanData.forensics_log,
            },
          },
          () => {
            // If content.js isn't awake yet, try again in 50 milliseconds
            if (chrome.runtime.lastError) {
              setTimeout(sendAlert, 50);
            }
          }
        );
      };

      sendAlert();
    });
  });
}