chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === "TRIGGER_ALERT") {
    renderThreatOverlay(message.payload);
    sendResponse({ status: "received" });
  } else if (message.action === "SHOW_SAFE_TOAST") {
    renderSafeToast();
    sendResponse({ status: "received" });
  } else if (message.action === "SHOW_FORENSIC_SAFE_TOAST") {
    renderForensicSafeToast(message.payload);
    sendResponse({ status: "received" });
  }
});

function createShadowHost(id) {
  if (document.getElementById(id)) return null;
  const host = document.createElement("div");
  host.id = id;
  
  host.style.cssText = "all:initial;position:fixed;z-index:2147483647;";
  document.documentElement.appendChild(host);
  const shadow = host.attachShadow({ mode: "closed" });
  return { host, shadow };
}

function renderThreatOverlay(data) {
  const result = createShadowHost("phishguard-alert-overlay");
  if (!result) return;
  const { host, shadow } = result;

  if (document.body) document.body.style.overflow = "hidden";

  const isMalicious = data.probability > 0.7;
  const primaryColor = isMalicious ? "#c62828" : "#e65100";
  const statusLabel = isMalicious ? "Malicious" : "Suspicious";
  const confidencePct = (data.probability * 100).toFixed(1);
  const barWidth = Math.round(data.probability * 100);

  const blockedIconSvg = `<svg width="40" height="40" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
    <path d="M12 3.4C10.4 4.6 8.6 5.2 6.5 5.4V10.1C6.5 14.3 9.1 17.1 12 18.6C14.9 17.1 17.5 14.3 17.5 10.1V5.4C15.4 5.2 13.6 4.6 12 3.4Z" stroke="#ff5a5a" stroke-width="1.9" stroke-linejoin="round"/>
    <path d="M5.9 5.3L18.2 17.6" stroke="#ff5a5a" stroke-width="2.3" stroke-linecap="round"/>
  </svg>`;

  const forensics = data.forensics || {};
  let forensicsRows = "";
  if (data.forensics && Object.keys(data.forensics).length > 0) {
    if (forensics.is_new_domain === true) {
      forensicsRows += `<div class="detail-row"><span class="detail-label">🕐 Domain age</span><span class="detail-badge warn">Newly registered</span></div>`;
    }
    if (forensics.dns_active === false) {
      forensicsRows += `<div class="detail-row"><span class="detail-label">🌐 DNS record</span><span class="detail-badge danger">No A record found</span></div>`;
    }
  }

  const ctiRows = (data.cti_matches || []).map(m =>
    `<div class="detail-row"><span class="detail-label">🗄️ CTI feed</span><span class="detail-badge danger cti">${m}</span></div>`
  ).join("");

  let hostname = "";
  try { hostname = new URL(data.url || window.location.href).hostname; } catch (e) { hostname = data.url || ""; }

  const style = document.createElement("style");
  style.textContent = `
    :host { all: initial; }
    .overlay {
      position: fixed; top: 0; left: 0; width: 100vw; height: 100vh;
      background: rgba(0,0,0,0.96); display: flex; flex-direction: column;
      justify-content: center; align-items: center; color: #fff;
      font-family: Arial, sans-serif; padding: 20px; box-sizing: border-box;
    }
    .card { max-width: 440px; width: 100%; text-align: center; }
    .icon-box {
      width: 64px; height: 64px; border-radius: 16px;
      background: rgba(198,40,40,0.15); border: 1.5px solid rgba(198,40,40,0.4);
      display: flex; align-items: center; justify-content: center;
      margin: 0 auto 20px; font-size: 30px;
    }
    .verdict { font-size: 11px; font-weight: 600; letter-spacing: 0.1em; color: ${primaryColor}; text-transform: uppercase; margin-bottom: 8px; }
    .hostname { font-size: 20px; font-weight: 600; color: white; margin-bottom: 6px; word-break: break-all; max-width: 400px; }
    .subtitle { font-size: 13px; color: #8892a4; margin-bottom: 24px; }
    .details-box { background: #1a1f2e; border-radius: 10px; padding: 14px; margin-bottom: 20px; text-align: left; }
    .details-title { font-size: 11px; color: #8892a4; margin-bottom: 10px; font-weight: 600; letter-spacing: 0.05em; text-transform: uppercase; }
    .ml-row { display: flex; justify-content: space-between; align-items: center; }
    .ml-label { font-size: 12px; color: #8892a4; }
    .ml-bar-wrap { display: flex; align-items: center; gap: 8px; }
    .ml-bar-bg { width: 80px; height: 4px; background: rgba(255,255,255,0.08); border-radius: 2px; }
    .ml-bar-fill { width: ${barWidth}%; height: 100%; background: ${primaryColor}; border-radius: 2px; }
    .ml-pct { font-size: 12px; color: ${primaryColor}; font-weight: 600; min-width: 34px; text-align: right; }
    .detail-row { display: flex; justify-content: space-between; align-items: center; margin-top: 8px; }
    .detail-label { font-size: 12px; color: #8892a4; }
    .detail-badge { font-size: 11px; padding: 2px 8px; border-radius: 4px; }
    .detail-badge.warn { background: rgba(255,167,38,0.15); color: #ffa726; }
    .detail-badge.danger { background: rgba(239,83,80,0.15); color: #ef5350; }
    .detail-badge.cti { max-width: 180px; text-align: right; }
    .btn-row { display: flex; gap: 10px; }
    .btn-back { flex: 1; padding: 11px; background: ${primaryColor}; border: none; border-radius: 8px; color: white; font-size: 13px; font-weight: 600; cursor: pointer; }
    .btn-proceed { padding: 11px 14px; background: rgba(255,255,255,0.05); border: 0.5px solid rgba(255,255,255,0.1); border-radius: 8px; color: #8892a4; font-size: 13px; cursor: pointer; }
    .footer { font-size: 11px; color: #4a5568; margin-top: 12px; }
  `;

  const overlay = document.createElement("div");
  overlay.className = "overlay";

  const card = document.createElement("div");
  card.className = "card";

  const iconBox = document.createElement("div");
  iconBox.className = "icon-box";
  if (isMalicious) { iconBox.innerHTML = blockedIconSvg; } else { iconBox.textContent = "⚠️"; }

  const verdict = document.createElement("p");
  verdict.className = "verdict";
  verdict.textContent = `${statusLabel} site detected`;

  const hostnameEl = document.createElement("p");
  hostnameEl.className = "hostname";
  hostnameEl.textContent = hostname;

  const subtitle = document.createElement("p");
  subtitle.className = "subtitle";
  subtitle.textContent = "PhishGuard has blocked this page from loading.";

  const detailsBox = document.createElement("div");
  detailsBox.className = "details-box";

  const detailsTitle = document.createElement("p");
  detailsTitle.className = "details-title";
  detailsTitle.textContent = "Detection details";

  const mlRow = document.createElement("div");
  mlRow.className = "ml-row";
  mlRow.innerHTML = `
    <span class="ml-label">🧠 ML confidence</span>
    <div class="ml-bar-wrap">
      <div class="ml-bar-bg"><div class="ml-bar-fill"></div></div>
      <span class="ml-pct">${confidencePct}%</span>
    </div>`;

  detailsBox.appendChild(detailsTitle);
  detailsBox.appendChild(mlRow);
  if (ctiRows) { const tmp = document.createElement("div"); tmp.innerHTML = ctiRows; detailsBox.append(...tmp.childNodes); }
  if (forensicsRows) { const tmp = document.createElement("div"); tmp.innerHTML = forensicsRows; detailsBox.append(...tmp.childNodes); }

  const btnRow = document.createElement("div");
  btnRow.className = "btn-row";

  const backBtn = document.createElement("button");
  backBtn.className = "btn-back";
  backBtn.textContent = "← Take me back to safety";
  backBtn.addEventListener("click", () => { window.location.href = "https://www.google.com"; });

  const proceedBtn = document.createElement("button");
  proceedBtn.className = "btn-proceed";
  proceedBtn.textContent = "Proceed anyway";
  proceedBtn.addEventListener("click", () => {
    host.remove();
    if (document.body) document.body.style.overflow = "";
  });

  btnRow.appendChild(backBtn);
  btnRow.appendChild(proceedBtn);

  const footer = document.createElement("p");
  footer.className = "footer";
  footer.textContent = "Logged to your analyst dashboard";

  card.append(iconBox, verdict, hostnameEl, subtitle, detailsBox, btnRow, footer);
  overlay.appendChild(card);
  shadow.appendChild(style);
  shadow.appendChild(overlay);
}

function renderForensicSafeToast(data) {
  const result = createShadowHost("phishguard-forensic-toast");
  if (!result) return;
  const { host, shadow } = result;

  const probabilityPercent = data && data.probability != null ? (data.probability * 100).toFixed(1) : "N/A";
  const barWidth = data && data.probability != null ? Math.round(data.probability * 100) : 0;

  const style = document.createElement("style");
  style.textContent = `
    :host { all: initial; }
    .toast {
      position: fixed; bottom: 20px; right: 20px;
      background: #0d2a4a;
      border-left: 3px solid #42a5f5;
      border-top: 0.5px solid rgba(66,165,245,0.3);
      border-right: 0.5px solid rgba(66,165,245,0.15);
      border-bottom: 0.5px solid rgba(66,165,245,0.15);
      color: white; padding: 13px 14px; border-radius: 10px;
      font-family: Arial, sans-serif; font-size: 13px; max-width: 300px;
      box-shadow: 0 4px 8px rgba(0,0,0,0.35);
      opacity: 0; transition: opacity 0.4s ease-in-out;
      pointer-events: none; line-height: 1.4;
    }
    .header { display: flex; align-items: center; gap: 8px; margin-bottom: 4px; }
    .icon { font-size: 16px; }
    .title { font-size: 13px; font-weight: 600; color: #e3f2fd; }
    .sub { font-size: 11px; color: #90caf9; padding-left: 24px; margin-bottom: 6px; }
    .bar-row { padding-left: 24px; display: flex; align-items: center; gap: 6px; }
    .bar-label { font-size: 10px; color: #64b5f6; }
    .bar-bg { flex: 1; height: 4px; background: rgba(255,255,255,0.1); border-radius: 2px; }
    .bar-fill { width: ${barWidth}%; height: 100%; background: #42a5f5; border-radius: 2px; }
    .bar-pct { font-size: 11px; color: #e3f2fd; font-weight: 600; }
  `;

  const toast = document.createElement("div");
  toast.className = "toast";
  toast.innerHTML = `
    <div class="header"><span class="icon">🔬</span><span class="title">PhishGuard: Safe (Forensic Analysis)</span></div>
    <p class="sub">Lexical suspicion cleared by live DNS/WHOIS check</p>
    <div class="bar-row">
      <span class="bar-label">Lexical risk</span>
      <div class="bar-bg"><div class="bar-fill"></div></div>
      <span class="bar-pct">${probabilityPercent}%</span>
    </div>`;

  shadow.appendChild(style);
  shadow.appendChild(toast);

  setTimeout(() => { toast.style.opacity = "1"; }, 100);
  setTimeout(() => {
    toast.style.opacity = "0";
    setTimeout(() => host.remove(), 400);
  }, 5000);
}

function renderSafeToast() {
  const result = createShadowHost("phishguard-safe-toast");
  if (!result) return;
  const { host, shadow } = result;

  const safeIconSvg = `<svg width="22" height="22" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
    <path d="M12 3.4C10.3 4.5 8.5 5.1 6.4 5.3V9.8C6.4 14 9.1 16.9 12 18.4C14.9 16.9 17.6 14 17.6 9.8V5.3C15.5 5.1 13.7 4.5 12 3.4Z" stroke="#46c35f" stroke-width="1.9" stroke-linejoin="round"/>
    <path d="M9.4 11.8L11.3 13.7L15 10" stroke="#46c35f" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"/>
  </svg>`;

  const style = document.createElement("style");
  style.textContent = `
    :host { all: initial; }
    .toast {
      position: fixed; bottom: 20px; right: 20px;
      background: #1b3a1b;
      border-left: 3px solid #4caf50;
      border-top: 0.5px solid rgba(76,175,80,0.3);
      border-right: 0.5px solid rgba(76,175,80,0.15);
      border-bottom: 0.5px solid rgba(76,175,80,0.15);
      color: white; padding: 12px 14px; border-radius: 10px;
      font-family: Arial, sans-serif; font-size: 14px; max-width: 280px;
      box-shadow: 0 4px 6px rgba(0,0,0,0.3);
      opacity: 0; transition: opacity 0.4s ease-in-out;
      pointer-events: none;
    }
    .inner {
      display: flex; align-items: center; gap: 14px;
      background: linear-gradient(135deg,#123a12,#0f2f10);
      border-radius: 18px; padding: 18px 20px;
      width: 340px; max-width: 100%; box-sizing: border-box;
      overflow: hidden; box-shadow: 0 10px 30px rgba(0,0,0,0.35);
      border: 1px solid rgba(70,195,95,0.18);
    }
    .icon-wrap { width: 44px; height: 44px; flex: 0 0 44px; display: flex; align-items: center; justify-content: center; }
    .text-wrap { flex: 1; min-width: 0; overflow: hidden; display: flex; flex-direction: column; justify-content: center; line-height: 1.2; }
    .title { font-size: 12px; font-weight: 700; color: #f4f7f0; margin: 0 0 6px 0; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
    .sub { font-size: 11px; color: #8fd18f; margin: 0; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  `;

  const toast = document.createElement("div");
  toast.className = "toast";

  const inner = document.createElement("div");
  inner.className = "inner";
  inner.innerHTML = `
    <div class="icon-wrap">${safeIconSvg}</div>
    <div class="text-wrap">
      <div class="title">PhishGuard: Site is safe</div>
      <div class="sub">Lexical score verified low risk</div>
    </div>`;

  toast.appendChild(inner);
  shadow.appendChild(style);
  shadow.appendChild(toast);

  setTimeout(() => { toast.style.opacity = "1"; }, 100);
  setTimeout(() => {
    toast.style.opacity = "0";
    setTimeout(() => host.remove(), 400);
  }, 3000);
}