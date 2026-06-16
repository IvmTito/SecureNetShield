document.addEventListener("DOMContentLoaded", () => {

    chrome.storage.local.get(
        [
            "scannedCount",
            "safeCount",
            "blockedCount",
            "lastUrl",
            "protectionEnabled"
        ],
        (data) => {

            document.getElementById("scannedCount").textContent =
                data.scannedCount || 0;

            document.getElementById("safeCount").textContent =
                data.safeCount || 0;

            document.getElementById("blockedCount").textContent =
                data.blockedCount || 0;

            document.getElementById("lastUrl").textContent =
                data.lastUrl || "No scans yet";

            const enabled =
                data.protectionEnabled !== false;

            updateProtectionUI(enabled);
        }
    );

    document
        .getElementById("toggleBtn")
        .addEventListener("click", () => {

            chrome.storage.local.get(
                ["protectionEnabled"],
                (data) => {

                    const enabled =
                        data.protectionEnabled !== false;

                    chrome.storage.local.set(
                        {
                            protectionEnabled: !enabled
                        },
                        () => {

                            updateProtectionUI(!enabled);

                        }
                    );

                }
            );

        });

});

function updateProtectionUI(enabled) {

    const btn =
        document.getElementById("toggleBtn");

    const status =
        document.getElementById("statusText");

    if (enabled) {

        status.textContent =
            "🟢 Protection Active";

        status.className =
            "status active";

        btn.textContent =
            "Disable Protection";

        btn.style.background =
            "#dc2626";

    } else {

        status.textContent =
            "🔴 Protection Disabled";

        status.className =
            "status inactive";

        btn.textContent =
            "Enable Protection";

        btn.style.background =
            "#16a34a";
    }
}