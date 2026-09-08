const API = "http://127.0.0.1:5000";


// ======================================================
// AES-128-CBC (matches security.py / the ESP32 firmware)
// ======================================================
// The backend now sends every payload as {"iv": hex, "data": hex}
// instead of plain JSON. This uses the browser's built-in
// Web Crypto API to decrypt it with the same shared key.
//
// NOTE: crypto.subtle is only available in a "secure context" -
// that's https:// pages, OR http://localhost / http://127.0.0.1.
// If you ever serve this dashboard from a plain http://<LAN-IP>
// address, the browser will refuse to expose crypto.subtle and
// decryption will fail. Stick to localhost for the demo, or put
// the dashboard behind HTTPS for anything beyond that.
// ======================================================

const AES_KEY_HEX = "3fae1baf5e3d4c2c9be2f1a6c88f3ac0";

function hexToBytes(hex) {

    const bytes = new Uint8Array(hex.length / 2);

    for (let i = 0; i < bytes.length; i++) {
        bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
    }

    return bytes;
}

function bytesToHex(bytes) {

    return Array.from(bytes)
        .map(b => b.toString(16).padStart(2, "0"))
        .join("");
}

const aesKeyPromise = crypto.subtle.importKey(
    "raw",
    hexToBytes(AES_KEY_HEX),
    { name: "AES-CBC" },
    false,
    ["encrypt", "decrypt"]
);

// Decrypt {iv, data} (both hex strings) into a parsed JS object.
// Web Crypto's AES-CBC handles PKCS7 padding automatically, same
// as the padding used in security.py and the ESP32 firmware.
async function aesDecryptToJSON(envelope) {

    const key = await aesKeyPromise;

    const iv = hexToBytes(envelope.iv);
    const data = hexToBytes(envelope.data);

    const plainBuffer = await crypto.subtle.decrypt(
        { name: "AES-CBC", iv: iv },
        key,
        data
    );

    const plaintext = new TextDecoder().decode(plainBuffer);

    return JSON.parse(plaintext);
}

// Encrypt a JS object into {iv, data} (both hex strings), for
// the POST requests below (report-stolen / reinstate).
async function aesEncryptFromJSON(obj) {

    const key = await aesKeyPromise;

    const iv = crypto.getRandomValues(new Uint8Array(16));
    const data = new TextEncoder().encode(JSON.stringify(obj));

    const cipherBuffer = await crypto.subtle.encrypt(
        { name: "AES-CBC", iv: iv },
        key,
        data
    );

    return {
        iv: bytesToHex(iv),
        data: bytesToHex(new Uint8Array(cipherBuffer))
    };
}


// ======================================================
// SOCKET.IO
// ======================================================

const socket = io(API);


socket.on("connect", () => {

    document.getElementById(
        "status"
    ).textContent = "● SERVER ONLINE";

});


socket.on("disconnect", () => {

    document.getElementById(
        "status"
    ).textContent = "● SERVER OFFLINE";

});


// ======================================================
// FORMAT EVENT
// ======================================================

function addEvent(event) {

    const table =
        document.getElementById(
            "events"
        );

    const row =
        document.createElement("tr");


    const time =
        new Date(
            event.timestamp
        ).toLocaleTimeString();


    row.innerHTML = `

        <td>${time}</td>

        <td>${event.credential_id || "-"}</td>

        <td>${event.user_name || "-"}</td>

        <td>${event.device_id || "-"}</td>

        <td>${event.location_name || "-"}</td>

        <td>
            ${event.risk_score}
            /
            ${event.risk_level}
        </td>

        <td>
            <strong>
                ${event.decision}
            </strong>
        </td>

        <td>
            ${event.reason || "-"}
        </td>

    `;

    table.prepend(row);

}


// ======================================================
// SOCKET EVENT (now arrives encrypted)
// ======================================================

socket.on(
    "access_event",
    async envelope => {

        try {

            const event = await aesDecryptToJSON(envelope);

            addEvent(event);

            loadStats();

        } catch (error) {

            console.error(
                "Failed to decrypt access_event:",
                error
            );

        }

    }
);


// ======================================================
// STOLEN CARD ALERT
// ======================================================
// Separate, louder signal from the server whenever a card
// already flagged stolen is scanned anywhere. This is meant
// to stand out from the normal event table - a big banner
// plus a short alarm tone using the Web Audio API (no sound
// file needed).
// ======================================================

function playAlarmTone() {

    try {

        const ctx = new (window.AudioContext || window.webkitAudioContext)();
        const oscillator = ctx.createOscillator();
        const gain = ctx.createGain();

        oscillator.type = "square";
        oscillator.frequency.value = 880;

        oscillator.connect(gain);
        gain.connect(ctx.destination);

        gain.gain.setValueAtTime(0.2, ctx.currentTime);

        oscillator.start();
        oscillator.stop(ctx.currentTime + 0.6);

    } catch (error) {

        console.error("Could not play alarm tone:", error);

    }
}

function showStolenBanner(event) {

    const banner = document.getElementById("stolenBanner");

    banner.textContent =
        "🚨 STOLEN CARD USED: " +
        event.credential_id +
        " at " +
        event.location_name +
        " (" + event.device_id + ") 🚨";

    banner.classList.add("visible");

    playAlarmTone();

    setTimeout(() => {
        banner.classList.remove("visible");
    }, 8000);
}

socket.on(
    "stolen_card_alert",
    async envelope => {

        try {

            const event = await aesDecryptToJSON(envelope);

            showStolenBanner(event);

        } catch (error) {

            console.error(
                "Failed to decrypt stolen_card_alert:",
                error
            );

        }

    }
);


// ======================================================
// CREDENTIAL MANAGEMENT (report stolen / reinstate)
// ======================================================

function credentialRowHTML(cred) {

    const statusClass =
        cred.status === "stolen" ? "status-stolen" : "status-active";

    const actionButton =
        cred.status === "stolen"
            ? `<button onclick="reinstateCredential('${cred.credential_id}')">Reinstate</button>`
            : `<button class="danger" onclick="reportStolen('${cred.credential_id}')">Report Stolen</button>`;

    return `
        <tr>
            <td>${cred.credential_id}</td>
            <td>${cred.user_name}</td>
            <td><span class="${statusClass}">${cred.status.toUpperCase()}</span></td>
            <td>${actionButton}</td>
        </tr>
    `;
}

async function loadCredentials() {

    try {

        const response = await fetch(API + "/api/credentials");

        const envelope = await response.json();

        const credentials = await aesDecryptToJSON(envelope);

        const table = document.getElementById("credentialsTable");

        table.innerHTML = credentials.map(credentialRowHTML).join("");

    } catch (error) {

        console.error("Failed to load credentials:", error);

    }
}

async function reportStolen(credentialId) {

    const adminKey = document.getElementById("adminKeyInput").value;

    if (!adminKey) {
        alert("Enter the admin key first.");
        return;
    }

    if (!confirm(`Report ${credentialId} as STOLEN? This blocks it immediately.`)) {
        return;
    }

    try {

        const envelope = await aesEncryptFromJSON({
            credential_id: credentialId,
            admin_key: adminKey
        });

        const response = await fetch(API + "/api/credentials/report-stolen", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(envelope)
        });

        const responseEnvelope = await response.json();
        const result = await aesDecryptToJSON(responseEnvelope);

        if (!response.ok) {
            alert("Error: " + (result.error || "Unknown error"));
        }

        loadCredentials();

    } catch (error) {

        console.error("Report stolen failed:", error);
        alert("Request failed - check the console.");

    }
}

async function reinstateCredential(credentialId) {

    const adminKey = document.getElementById("adminKeyInput").value;

    if (!adminKey) {
        alert("Enter the admin key first.");
        return;
    }

    try {

        const envelope = await aesEncryptFromJSON({
            credential_id: credentialId,
            admin_key: adminKey
        });

        const response = await fetch(API + "/api/credentials/reinstate", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(envelope)
        });

        const responseEnvelope = await response.json();
        const result = await aesDecryptToJSON(responseEnvelope);

        if (!response.ok) {
            alert("Error: " + (result.error || "Unknown error"));
        }

        loadCredentials();

    } catch (error) {

        console.error("Reinstate failed:", error);
        alert("Request failed - check the console.");

    }
}


// ======================================================
// LOAD LOGS
// ======================================================

async function loadLogs() {

    try {

        const response =
            await fetch(
                API + "/api/logs"
            );

        const envelope =
            await response.json();

        const logs =
            await aesDecryptToJSON(envelope);

        const table =
            document.getElementById(
                "events"
            );

        table.innerHTML = "";

        logs.reverse().forEach(
            addEvent
        );

    } catch (error) {

        console.error(
            "Log error:",
            error
        );

    }
}


// ======================================================
// LOAD STATS
// ======================================================

async function loadStats() {

    try {

        const response =
            await fetch(
                API + "/api/stats"
            );

        const envelope =
            await response.json();

        const stats =
            await aesDecryptToJSON(envelope);

        document.getElementById(
                "total"
            ).textContent =
            stats.total_attempts;

        document.getElementById(
                "allowed"
            ).textContent =
            stats.allowed;

        document.getElementById(
                "blocked"
            ).textContent =
            stats.blocked;

        document.getElementById(
                "critical"
            ).textContent =
            stats.critical;

    } catch (error) {

        console.error(
            "Stats error:",
            error
        );

    }
}


// ======================================================
// START
// ======================================================

loadLogs();

loadStats();

loadCredentials();

setInterval(
    loadStats,
    5000
);
