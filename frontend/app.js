const API = "http://127.0.0.1:5000";


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
// SOCKET EVENT
// ======================================================

socket.on(
    "access_event",
    event => {

        addEvent(event);

        loadStats();

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

        const logs =
            await response.json();

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

        const stats =
            await response.json();

        document.getElementById(
                "total"
            ).textContent =
            stats.total;

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
