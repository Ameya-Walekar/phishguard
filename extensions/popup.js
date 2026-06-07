// Load scan history from storage 
chrome.storage.local.get({ scanHistory: [] }, (result) => {
    const history = result.scanHistory;
    const today = new Date().toDateString();

    const todayScans = history.filter(s => new Date(s.timestamp).toDateString() === today);
    const todayThreats = todayScans.filter(s => s.status === "Malicious" || s.status === "Suspicious");

    document.getElementById("scanned-count").textContent = todayScans.length;
    document.getElementById("threats-count").textContent = todayThreats.length;
});

// Show current tab URL and its last known scan result
chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (!tabs[0]) return;
    const url = tabs[0].url || "";
    const displayUrl = url.replace(/^https?:\/\//, "").replace(/\/$/, "");
    document.getElementById("current-url").textContent = displayUrl || "—";

    chrome.storage.local.get({ scanHistory: [] }, (result) => {
        const match = [...result.scanHistory].reverse().find(s => s.url === url);
        const dot = document.getElementById("status-dot");
        const text = document.getElementById("status-text");
        if (match) {
            if (match.status === "Malicious" || match.status === "Suspicious") {
                dot.style.background = "#ef5350";
                text.style.color = "#ef5350";
                text.textContent = match.status + " — blocked";
            } else {
                dot.style.background = "#4caf50";
                text.style.color = "#4caf50";
                text.textContent = "Safe — verified";
            }
        } else {
            dot.style.background = "#8892a4";
            text.style.color = "#8892a4";
            text.textContent = "No scan result yet";
        }
    });
});