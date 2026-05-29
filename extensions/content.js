chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === "TRIGGER_ALERT") {
    renderThreatOverlay(message.payload);
    sendResponse({status: "received"});
  } else if (message.action === "SHOW_SAFE_TOAST") {
    renderSafeToast();
    sendResponse({status: "received"});
  } else if (message.action === "SHOW_FORENSIC_SAFE_TOAST") {
    renderForensicSafeToast(message.payload);
    sendResponse({status: "received"});
  }
});

function renderThreatOverlay(data) {
  if (document.getElementById("phishguard-alert-overlay")) return;

  // 1. FREEZE UPGRADE: Stop the user from scrolling the background
  if(document.body) document.body.style.overflow = "hidden";
  
  const overlay = document.createElement("div");
  overlay.id = "phishguard-alert-overlay";
  
  const isMalicious = data.probability > 0.7;
  const primaryColor = isMalicious ? "#c62828" : "#e65100";
  const statusLabel = isMalicious ? "Malicious" : "Suspicious";
  const confidencePct = (data.probability * 100).toFixed(1);
  const barWidth = Math.round(data.probability * 100);

  // 2. Z-INDEX UPGRADE: Ensure it covers EVERYTHING on the page
  Object.assign(overlay.style, {
    position: "fixed",
    top: "0",
    left: "0",
    width: "100vw",
    height: "100vh",
    backgroundColor: "rgba(0, 0, 0, 0.96)",
    zIndex: "2147483647", // Maximum CSS z-index possible
    display: "flex",
    flexDirection: "column",
    justifyContent: "center",
    alignItems: "center",
    color: "#ffffff",
    fontFamily: "Arial, sans-serif",
    padding: "20px",
    boxSizing: "border-box"
  });

  const blockedIcon = `
<svg width="40" height="40" viewBox="0 0 24 24" fill="none"
     xmlns="http://www.w3.org/2000/svg">
  <path
    d="M12 3.4C10.4 4.6 8.6 5.2 6.5 5.4V10.1C6.5 14.3 9.1 17.1 12 18.6C14.9 17.1 17.5 14.3 17.5 10.1V5.4C15.4 5.2 13.6 4.6 12 3.4Z"
    stroke="#ff5a5a"
    stroke-width="1.9"
    stroke-linejoin="round"
  />
  <path
    d="M5.9 5.3L18.2 17.6"
    stroke="#ff5a5a"
    stroke-width="2.3"
    stroke-linecap="round"
  />
</svg>
`;

  
  // Build forensics detail rows if available
  const forensics = data.forensics || {};
  let forensicsRows = "";
  if (data.forensics && Object.keys(data.forensics).length > 0) {
    if (forensics.is_new_domain === true) {
      forensicsRows += `
        <div style="display:flex;justify-content:space-between;align-items:center;margin-top:8px;">
          <span style="font-size:12px;color:#8892a4;">🕐 Domain age</span>
          <span style="font-size:11px;background:rgba(255,167,38,0.15);color:#ffa726;padding:2px 8px;border-radius:4px;">Newly registered</span>
        </div>`;
    }
    if (forensics.dns_active === false) {
      forensicsRows += `
        <div style="display:flex;justify-content:space-between;align-items:center;margin-top:8px;">
          <span style="font-size:12px;color:#8892a4;">🌐 DNS record</span>
          <span style="font-size:11px;background:rgba(239,83,80,0.15);color:#ef5350;padding:2px 8px;border-radius:4px;">No A record found</span>
        </div>`;
    }
  }

  const ctiRows = (data.cti_matches || []).map(m => `
    <div style="display:flex;justify-content:space-between;align-items:center;margin-top:8px;">
      <span style="font-size:12px;color:#8892a4;">🗄️ CTI feed</span>
      <span style="font-size:11px;background:rgba(239,83,80,0.15);color:#ef5350;padding:2px 8px;border-radius:4px;max-width:180px;text-align:right;">${m}</span>
    </div>`).join("");

  overlay.innerHTML = `
    <div style="max-width:440px;width:100%;text-align:center;">
      <div style="width:64px;height:64px;border-radius:16px;background:rgba(198,40,40,0.15);border:1.5px solid rgba(198,40,40,0.4);display:flex;align-items:center;justify-content:center;margin:0 auto 20px;font-size:30px;">
        ${isMalicious ? blockedIcon : "⚠️"}
      </div>
      <p style="font-size:11px;font-weight:600;letter-spacing:0.1em;color:${primaryColor};text-transform:uppercase;margin-bottom:8px;">
        ${statusLabel} site detected
      </p>
      <p style="font-size:20px;font-weight:600;color:white;margin-bottom:6px;word-break:break-all;max-width:400px;">
        ${new URL(data.url || window.location.href).hostname}
      </p>
      <p style="font-size:13px;color:#8892a4;margin-bottom:24px;">PhishGuard has blocked this page from loading.</p>

      <div style="background:#1a1f2e;border-radius:10px;padding:14px;margin-bottom:20px;text-align:left;">
        <p style="font-size:11px;color:#8892a4;margin-bottom:10px;font-weight:600;letter-spacing:0.05em;text-transform:uppercase;">Detection details</p>
        <div style="display:flex;justify-content:space-between;align-items:center;">
          <span style="font-size:12px;color:#8892a4;">🧠 ML confidence</span>
          <div style="display:flex;align-items:center;gap:8px;">
            <div style="width:80px;height:4px;background:rgba(255,255,255,0.08);border-radius:2px;">
              <div style="width:${barWidth}%;height:100%;background:${primaryColor};border-radius:2px;"></div>
            </div>
            <span style="font-size:12px;color:${primaryColor};font-weight:600;min-width:34px;text-align:right;">${confidencePct}%</span>
          </div>
        </div>
        ${ctiRows}
        ${forensicsRows}
      </div>

      <div style="display:flex;gap:10px;">
        <button id="pg-back-btn" style="flex:1;padding:11px;background:${primaryColor};border:none;border-radius:8px;color:white;font-size:13px;font-weight:600;cursor:pointer;">
          ← Take me back to safety
        </button>
        <button id="pg-proceed-btn" style="padding:11px 14px;background:rgba(255,255,255,0.05);border:0.5px solid rgba(255,255,255,0.1);border-radius:8px;color:#8892a4;font-size:13px;cursor:pointer;">
          Proceed anyway
        </button>
      </div>
      <p style="font-size:11px;color:#4a5568;margin-top:12px;">Logged to your analyst dashboard</p>
    </div>
  `;

  // Don't forget to wire up your buttons after injecting!
  document.body.appendChild(overlay);

  document.getElementById("pg-back-btn").addEventListener("click", () => {
    window.location.href = "https://www.google.com"; // Get them to safety
  });

  document.getElementById("pg-proceed-btn").addEventListener("click", () => {
    overlay.remove();
    document.body.style.overflow = ""; // Restore scrolling
  });
}

function renderForensicSafeToast(data) {
  // Check if it already exists so we don't spam the screen
  if (document.getElementById("phishguard-forensic-toast")) return;

  const probabilityPercent = data && data.probability != null
    ? (data.probability * 100).toFixed(1)
    : "N/A";
  const barWidth = data && data.probability != null ? Math.round(data.probability * 100) : 0;

  const toast = document.createElement("div");
  toast.id = "phishguard-forensic-toast";
  toast.innerHTML = `
    <div style="display:flex;align-items:center;gap:8px;margin-bottom:4px;">
      <span style="font-size:16px;">🔬</span>
      <span style="font-size:13px;font-weight:600;color:#e3f2fd;">PhishGuard: Safe (Forensic Analysis)</span>
    </div>
    <p style="font-size:11px;color:#90caf9;padding-left:24px;margin-bottom:6px;">Lexical suspicion cleared by live DNS/WHOIS check</p>
    <div style="padding-left:24px;display:flex;align-items:center;gap:6px;">
      <span style="font-size:10px;color:#64b5f6;">Lexical risk</span>
      <div style="flex:1;height:4px;background:rgba(255,255,255,0.1);border-radius:2px;">
        <div style="width:${barWidth}%;height:100%;background:#42a5f5;border-radius:2px;"></div>
      </div>
      <span style="font-size:11px;color:#e3f2fd;font-weight:600;">${probabilityPercent}%</span>
    </div>
  `;

  Object.assign(toast.style, {
    position: "fixed",
    bottom: "20px",
    right: "20px",
    backgroundColor: "#0d2a4a",
    borderLeft: "3px solid #42a5f5",
    borderTop: "0.5px solid rgba(66,165,245,0.3)",
    borderRight: "0.5px solid rgba(66,165,245,0.15)",
    borderBottom: "0.5px solid rgba(66,165,245,0.15)",
    color: "white",
    padding: "13px 14px",
    borderRadius: "10px",
    fontFamily: "Arial, sans-serif",
    fontSize: "13px",
    maxWidth: "300px",
    boxShadow: "0 4px 8px rgba(0,0,0,0.35)",
    zIndex: "2147483647",
    opacity: "0",
    transition: "opacity 0.4s ease-in-out",
    pointerEvents: "none",
    lineHeight: "1.4",
  });

  if (document.body) {
    document.body.appendChild(toast);
  }

  // Fade in
  setTimeout(() => {
    toast.style.opacity = "1";
  }, 100);

  // Hold for 5 seconds (longer than plain safe toast), then fade out and remove
  setTimeout(() => {
    toast.style.opacity = "0";
    setTimeout(() => {
      if (toast.parentNode) toast.remove();
    }, 400);
  }, 5000);
}

function renderSafeToast() {
  // Check if it already exists so we don't spam the screen
  if (document.getElementById("phishguard-safe-toast")) return;
  const safeIcon = `
  <svg width="22" height="22" viewBox="0 0 24 24" fill="none"
      xmlns="http://www.w3.org/2000/svg">
    <path
      d="M12 3.4C10.3 4.5 8.5 5.1 6.4 5.3V9.8C6.4 14 9.1 16.9 12 18.4C14.9 16.9 17.6 14 17.6 9.8V5.3C15.5 5.1 13.7 4.5 12 3.4Z"
      stroke="#46c35f"
      stroke-width="1.9"
      stroke-linejoin="round"
    />
    <path
      d="M9.4 11.8L11.3 13.7L15 10"
      stroke="#46c35f"
      stroke-width="1.9"
      stroke-linecap="round"
      stroke-linejoin="round"
    />
  </svg>
  `;
  const toast = document.createElement("div");
  toast.id = "phishguard-safe-toast";
  toast.innerHTML = `
  <div style="
    display:flex;
    align-items:center;
    gap:14px;
    background:linear-gradient(135deg,#123a12,#0f2f10);
    border-radius:18px;
    padding:18px 20px;
    width:340px;
    max-width:100%;
    box-sizing:border-box;
    overflow:hidden;
    box-shadow:0 10px 30px rgba(0,0,0,0.35);
    border:1px solid rgba(70,195,95,0.18);
  ">
    <div style="
      width:44px;
      height:44px;
      flex:0 0 44px;
      display:flex;
      align-items:center;
      justify-content:center;
    ">
      ${safeIcon}
    </div>

    <div style="
      flex:1;
      min-width:0;
      overflow:hidden;
      display:flex;
      flex-direction:column;
      justify-content:center;
      line-height:1.2;
    ">
      <div style="
        font-size:12px;
        font-weight:700;
        color:#f4f7f0;
        margin:0 0 6px 0;
        white-space:nowrap;
        overflow:hidden;
        text-overflow:ellipsis;
      ">
        PhishGuard: Site is safe
      </div>

      <div style="
        font-size:11px;
        color:#8fd18f;
        margin:0;
        white-space:nowrap;
        overflow:hidden;
        text-overflow:ellipsis;
      ">
        Lexical score verified low risk
      </div>
    </div>
  </div>
`;
  // Style the small popup to float in the bottom right corner
  Object.assign(toast.style, {
    position: "fixed",
    bottom: "20px",
    right: "20px",
    backgroundColor: "#1b3a1b",
    borderLeft: "3px solid #4caf50",
    borderTop: "0.5px solid rgba(76,175,80,0.3)",
    borderRight: "0.5px solid rgba(76,175,80,0.15)",
    borderBottom: "0.5px solid rgba(76,175,80,0.15)",
    color: "white",
    padding: "12px 14px",
    borderRadius: "10px",
    fontFamily: "Arial, sans-serif",
    fontSize: "14px",
    maxWidth: "280px",
    boxShadow: "0 4px 6px rgba(0,0,0,0.3)",
    zIndex: "2147483647", // Max z-index to stay on top
    opacity: "0", // Start invisible
    transition: "opacity 0.4s ease-in-out",
    pointerEvents: "none" // Extremely important: lets the user click THROUGH the notification if it covers something!
  });

  if (document.body) {
    document.body.appendChild(toast);
  }

  // Fade the notification in
  setTimeout(() => { 
    toast.style.opacity = "1"; 
  }, 100);

  // Wait 3 seconds, fade it out, then delete the HTML element
  setTimeout(() => {
    toast.style.opacity = "0";
    setTimeout(() => {
      if (toast.parentNode) toast.remove();
    }, 400); // wait for fade transition to finish before removing
  }, 3000);
}