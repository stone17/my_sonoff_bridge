# Sonoff LAN to MQTT Bridge (S60TPF & Domoticz)

A lightweight bridge running in Docker (or locally) that connects Sonoff LAN-mode devices (specifically tested with **S60TPF**) to Domoticz and Home Assistant via MQTT.

It features a web dashboard for management, live energy monitoring, and **Home Assistant MQTT Auto-Discovery** (which Domoticz supports), making setup plug-and-play.

## 🚀 Features

* **Web Dashboard:** Manage devices, view live energy stats (Watts/Volts), and toggle switches.
* **MQTT Auto-Discovery:** Automatically creates devices in Domoticz or Home Assistant.
* **Two-Way Sync:**
    * Control plugs via Web UI, Domoticz, or MQTT.
    * Status updates (local switching) are reflected in the UI and Domoticz.
* **Energy Monitoring:** Reports Power (W) and Voltage (V).
* **Local Control:** Uses direct HTTP (port 8081) and mDNS (Zeroconf), **no cloud required**.
* **Dockerized:** Easy deployment with Docker Compose.

## 🛠️ Prerequisites

1.  **Sonoff Device in LAN Mode:**
    * You need the **Device ID** and **Device Key** (UUID).
    * *Tip: You can obtain these using [sonoff-lan-mode-homeassistant](https://github.com/AlexxIT/SonoffLAN) or other extraction tools.*
2.  **MQTT Broker:** (e.g., Mosquitto).
3.  **Domoticz (Optional):** With a broker configured.

## 📦 Installation

### Option 1: Docker Compose (Recommended)

1.  Create a directory and place the project files (`docker-compose.yml`, `Dockerfile`, `requirements.txt`, `app/`).
2.  Run the container:
    ```bash
    docker-compose up -d --build
    ```
3.  Open your browser to: `http://YOUR_SERVER_IP:8000`

### Option 2: Run Locally (Python)

1.  Install dependencies:
    ```bash
    pip install -r requirements.txt
    ```
2.  Run the server:
    ```bash
    # Linux/Mac
    export CONFIG_PATH="app/config.yaml"
    uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload

    # Windows (PowerShell)
    $env:CONFIG_PATH="app/config.yaml"
    uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
    ```

## ⚙️ Configuration

### 1. Web Interface Setup
1.  Go to **Settings** (Gear Icon) in the Web UI.
2.  Enter your **MQTT Broker IP** and **Port**.
3.  **Auto-Discovery Prefix:** Default is `homeassistant`. Leave this unless you changed it in Domoticz.
4.  **Base Topic:** Default is `sonoff`.
5.  Click **Save Settings**.

### 2. Adding Devices
1.  Click **+ Add Device** in the Web UI.
2.  Enter:
    * **Name:** Friendly name (e.g., "Washer").
    * **IP Address:** Local IP of the plug (static IP recommended).
    * **Device ID:** The Sonoff Device ID.
    * **Device Key:** The encryption key.
3.  The device will appear in the grid and automatically be published to MQTT.

## 🏠 Domoticz Integration

To get the devices into Domoticz automatically:

1.  Go to **Setup** -> **Hardware**.
2.  Add new hardware of type: **"MQTT Auto Discovery Client Gateway with LAN interface"**.
3.  **Remote Address:** Enter your MQTT Broker IP and Port.
4.  **Auto Discovery Prefix:** Ensure this matches the setting in the Web UI (default: `homeassistant`).
5.  Click **Add**.
6.  Go to the **Devices** tab. You should see new devices created for:
    * `[Name] Switch`
    * `[Name] Power`
    * `[Name] Voltage`

## 📡 MQTT Topics

You can also interact directly via MQTT:

| Action | Topic | Payload |
| :--- | :--- | :--- |
| **Switch ON/OFF** | `sonoff/{device_id}/set` | `ON` or `OFF` |
| **Get State** | `sonoff/{device_id}/state` | `{"switch": "ON", "power": 12.5, "voltage": 230}` |

## 🐛 Troubleshooting

* **No Energy Data:**
    * Ensure the IP address of the plug is correct.
    * Check if the **Device Key** is correct (decryption will fail otherwise).
    * The bridge polls every 10 seconds (default). Wait a moment for data to populate.
* **"Errno 126" / Listener Crash:**
    * This happens if the script binds to a VPN interface. The script tries to auto-detect your LAN IP, but if it fails, try disabling VPNs or running in `network_mode: host` (Docker).
* **Domoticz not seeing devices:**
    * Check that the **Auto Discovery Prefix** matches in both Domoticz and the Web UI.
    * Restart the Domoticz hardware module.

## 📄 License
MIT License
