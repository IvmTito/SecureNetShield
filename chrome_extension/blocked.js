document.addEventListener("DOMContentLoaded", () => {

    console.log("BLOCKED PAGE LOADED");

    const continueBtn =
        document.getElementById("continueBtn");

    const backBtn =
        document.getElementById("backBtn");

    console.log("continueBtn =", continueBtn);
    console.log("backBtn =", backBtn);

    if (continueBtn) {

        continueBtn.addEventListener("click", () => {

            chrome.storage.local.get(
                ["blockedUrl"],
                (result) => {

                    console.log(result);

                    if (!result.blockedUrl)
                        return;

                    chrome.runtime.sendMessage({
                        action: "continue_anyway",
                        url: result.blockedUrl
                    });

                    location.href = result.blockedUrl;
                }
            );

        });

    }

    if (backBtn) {

       backBtn.addEventListener("click", () => {

            chrome.storage.local.get(
                ["previousUrl"],
                (result) => {

                    console.log(
                        "GO BACK TO:",
                        result.previousUrl
                    );

                    if (result.previousUrl) {
                        location.href = result.previousUrl;
                    }
                }
            );

        });

    }

});