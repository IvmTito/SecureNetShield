let bypassDomains = new Set();
let lastVisitedUrl = "";
let previousRealUrl = "";
let scanInProgress = new Set();
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
      const settings =
          await chrome.storage.local.get(["protectionEnabled"]);

      if (settings.protectionEnabled === false) 
          return;

    if (!tab.url)
      return;

  const currentDomain =
    new URL(tab.url).hostname;

  if (bypassDomains.has(currentDomain)) 
      return;

  if (!tab.url.includes("blocked.html") && !tab.url.startsWith("chrome-extension://"))
     {
          if (tab.url !== lastVisitedUrl) {
             previousRealUrl = lastVisitedUrl;
            lastVisitedUrl = tab.url;
          }
      }

  if (
      tab.url.startsWith("chrome-extension://") &&
      !tab.url.includes("checking.html") &&
      !tab.url.includes("blocked.html")
  )
      return;

  if (
      tab.url.startsWith('chrome://') ||
      tab.url.startsWith('edge://') ||
      tab.url.startsWith('about:')
  )
      return;

  if (changeInfo.status !== "complete")
      return;

  if (tab.url.includes("blocked.html"))
      return;

  if (scanInProgress.has(tabId))
      return;
  
  if (tab.url.startsWith("chrome-extension://"))
      return;

  try {
    scanInProgress.add(tabId);

    const originalUrl = tab.url;

    const originalDomain =
    new URL(originalUrl).hostname;

    chrome.tabs.update(
        tabId,
        {url: chrome.runtime.getURL("checking.html")}
    );

    await new Promise(resolve =>
        setTimeout(resolve, 300)
    );

    const response = await fetch("http://127.0.0.1:5000/predict", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: originalUrl })
    });

    const data = await response.json();
    if (data.status === "safe") {
        chrome.storage.local.get(
            ["scannedCount", "safeCount"],
            (stats) => {
                chrome.storage.local.set({
                    scannedCount:
                        (stats.scannedCount || 0) + 1,
                    safeCount:
                        (stats.safeCount || 0) + 1,
                    lastUrl:
                        originalUrl
                }, () => {});
            }
        );

        scanInProgress.delete(tabId);

        bypassDomains.add(originalDomain);

        setTimeout(() => {
            bypassDomains.delete(originalDomain);
        }, 5000);

        chrome.tabs.update(
            tabId,
            {
                url: originalUrl
            },
            () => {

                setTimeout(() => {

                    chrome.scripting.executeScript({
                        target: { tabId: tabId },
                        func: showSecurityUI,
                        args: [
                            data.status,
                            data.score,
                            data.reason
                        ]
                    });
                }, 1500);

            }
        );
        return;
    }

      if (data.status === "malicious") {        
        chrome.storage.local.get(
          ["scannedCount", "blockedCount"],
          (stats) => {
              chrome.storage.local.set({
                  scannedCount:
                      (stats.scannedCount || 0) + 1,
                  blockedCount:
                      (stats.blockedCount || 0) + 1,
                  lastUrl:
                      originalUrl
              });
          }
      );
        
          chrome.storage.local.set({
              blockedUrl: originalUrl,
              previousUrl: previousRealUrl
          });

          const blockedPage = chrome.runtime.getURL("blocked.html");

          console.log("BLOCKING:", tab.url);
          console.log("BLOCK PAGE:", blockedPage);
          scanInProgress.delete(tabId);

          chrome.tabs.update(
              tabId,
              {
                  url: blockedPage
              }
          );

          return;
      }
    console.log("SCAN RESULT:", data);

       try {
      await chrome.scripting.executeScript({
        target: { tabId: tabId },
        func: showSecurityUI,
        args: [data.status, data.score, data.reason]
      });
    } catch (injectError) {
            console.log("Skipped UI injection (Likely an Error Page):", injectError.message);
    }

  } catch (err) {
    scanInProgress.delete(tabId);
    console.error("EXT ERROR:", err);
  
    try {
        await chrome.scripting.executeScript({
          target: { tabId: tabId },
          func: showSecurityUI,
          args: ["unknown", 0, "Server Offline"]
        });
    } catch(e) { /* Ignore */ }
  }
});

function showSecurityUI(status, score, reason) {
  // لو فيه عنصر قديم نشيله
  const oldBadge = document.getElementById("secure-ai-badge");
  if (oldBadge) oldBadge.remove();

  let bgColor, iconColor, titleText, iconSVG;

  if (status === "malicious") {
    bgColor = "#fee2e2"; 
    iconColor = "#dc2626"; 
    titleText = "⚠️ DANGER: Phishing Detected";
    iconSVG = `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="${iconColor}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>`;
  } else if (status === "safe") {
    bgColor = "#dcfce7"; 
    iconColor = "#16a34a"; 
    titleText = "✅ Website is Safe";
    iconSVG = `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="${iconColor}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>`;
  } else {
    bgColor = "#fef3c7"; 
    iconColor = "#d97706";
    titleText = "⚠️ Suspicious Site";
    iconSVG = `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="${iconColor}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>`;
  }

  const div = document.createElement("div");
  div.id = "secure-ai-badge";
  
  div.style.cssText = `
    position: fixed;
    top: 20px;
    right: 20px;
    width: 320px;
    background: ${bgColor};
    border-left: 5px solid ${iconColor};
    padding: 16px;
    box-shadow: 0 10px 25px rgba(0,0,0,0.15);
    border-radius: 8px;
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    z-index: 999999;
    display: flex;
    align-items: flex-start;
    gap: 12px;
    transition: all 0.5s ease;
    cursor: pointer;
  `;

  div.innerHTML = `
    <div style="margin-top:2px; flex-shrink:0;">${iconSVG}</div>
    <div>
      <div style="font-weight: bold; font-size: 15px; color: #1f2937; margin-bottom: 4px;">${titleText}</div>
      <div style="font-size: 13px; color: #4b5563;">${reason}</div>
      <div style="font-size: 11px; color: #6b7280; margin-top: 6px; font-weight: 600;">Confidence: ${Math.round(score)}%</div>
    </div>
  `;

  div.onclick = () => {
    div.style.opacity = "0";
    setTimeout(() => div.remove(), 500);
  };

  document.body.appendChild(div);
  setTimeout(() => {
      div.style.opacity = "0";
      setTimeout(() => div.remove(), 500);
  }, 4000);
}

chrome.runtime.onMessage.addListener((message) => {

    if (message.action === "continue_anyway") {
        const domain =
            new URL(message.url).hostname;
        console.log("ALLOWING:", domain);
        bypassDomains.add(domain);
        setTimeout(() => {
            bypassDomains.delete(domain);
        }, 30000);
    }
});