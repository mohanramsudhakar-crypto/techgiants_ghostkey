const API =
    "http://127.0.0.1:5000";


const socket =
    io(API);




socket.on(
    "connect",
    () => {

        document
            .getElementById("status")
            .textContent =
            "● SYSTEM ONLINE";

    }
);


socket.on(
    "disconnect",
    () => {

        document
            .getElementById("status")
            .textContent =
            "● DISCONNECTED";

    }
);




socket.on(
    "access_event",
    event => {

        addLog(event);

        loadStats();

    }
);




function addLog(event) {

    const tbody =
        document.getElementById(
            "logs"
        );


    const row =
        document.createElement(
            "tr"
        );


    const time =
        new Date(
            event.timestamp
        ).toLocaleTimeString();


    const decisionClass =
        event.decision === "ALLOW"
            ? "allow"
            : "block";


    const riskClass =
        event.risk_level.toLowerCase();


    row.innerHTML = `

        <td>${time}</td>

        <td>${event.credential_id}</td>

        <td>${event.user_name}</td>

        <td>${event.device_id}</td>

        <td>${event.location}</td>

        <td class="${riskClass}">
            ${event.risk_level}
            (${event.risk_score})
        </td>

        <td class="${decisionClass}">
            ${event.decision}
        </td>

        <td>${event.reason}</td>

    `;


    tbody.prepend(row);

}



async function loadLogs() {

    const response =
        await fetch(
            `${API}/api/logs`
        );


    const logs =
        await response.json();


    const tbody =
        document.getElementById(
            "logs"
        );


    tbody.innerHTML = "";


    logs
        .reverse()
        .forEach(addLog);

}



async function loadStats() {

    const response =
        await fetch(
            `${API}/api/stats`
        );


    const stats =
        await response.json();


    document
        .getElementById("total")
        .textContent =
        stats.total;


    document
        .getElementById("allowed")
        .textContent =
        stats.allowed;


    document
        .getElementById("blocked")
        .textContent =
        stats.blocked;


    document
        .getElementById("critical")
        .textContent =
        stats.critical;

}


loadLogs();

loadStats();
