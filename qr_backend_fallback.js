/* PhishingLens QR fallback.
   Add this script AFTER the normal app.js script in index.html.
   It only activates when BarcodeDetector is unavailable. */
(function () {
    function installQrFallback() {
        const button = document.getElementById("readQrButton");
        const input = document.getElementById("qrImageInput");
        const status = document.getElementById("qrStatus");
        const output = document.getElementById("qrExtractedUrl");
        const useButton = document.getElementById("useQrUrlButton");

        if (!button || !input || !status || !output) return;
        if ("BarcodeDetector" in window) return;
        if (button.dataset.backendQrFallback === "1") return;
        button.dataset.backendQrFallback = "1";

        button.addEventListener("click", async function () {
            const file = input.files && input.files[0];
            if (!file) {
                status.textContent = "Choose a QR code image first.";
                return;
            }

            const form = new FormData();
            form.append("image", file, file.name);
            button.disabled = true;
            status.textContent = "Decoding QR image on the PhishingLens backend…";

            try {
                const response = await fetch("/api/v1/qr-decode", {
                    method: "POST",
                    body: form
                });
                let data = {};
                try { data = await response.json(); } catch (_) {}
                if (!response.ok) {
                    throw new Error(data.detail || "QR decoding failed.");
                }
                output.value = data.content || "";
                if (useButton) {
                    const value = output.value.trim().toLowerCase();
                    useButton.disabled = !(value.startsWith("http://") || value.startsWith("https://"));
                }
                status.textContent = data.notice || "QR content extracted. Verify the destination before opening it.";
            } catch (error) {
                status.textContent = error.message || "QR decoding failed.";
            } finally {
                button.disabled = false;
            }
        });
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", installQrFallback);
    } else {
        installQrFallback();
    }
})();
