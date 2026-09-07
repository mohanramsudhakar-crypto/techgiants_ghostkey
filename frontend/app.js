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

setInterval(
    loadStats,
    5000
);
