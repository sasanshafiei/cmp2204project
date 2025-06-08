# 🛰️ P2P Chat Application (Python + Tkinter)

![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg) ![License](https://img.shields.io/badge/license-MIT-green.svg)

A lightweight **peer-to-peer LAN chat** application that auto-discovers peers on the same IPv4 subnet. Exchange messages in either **Unsecure (plain TCP)** or **Secure (Diffie–Hellman ▶ 3-DES)** mode, and persist logs in JSON format.

---

## 📋 Table of Contents

1. [Overview](#-overview)
2. [Features](#-features)
3. [Architecture](#-architecture)
4. [Security](#-security)
5. [Prerequisites](#-prerequisites)
6. [Installation](#-installation)
7. [Usage](#-usage)
8. [Configuration](#-configuration)
9. [Project Structure](#-project-structure)
10. [License](#-license)

---

## 📌 Overview

This single-file Python application (`p2p_chat.py`) plus a small helper (`LocalIp.py`) enables zero-configuration LAN chatting. Peers announce themselves via UDP broadcast, appear in the GUI, and messages flow over TCP:

* **Auto-Discovery:** Peers broadcast `{"username":…, "ip":…}` every 8 seconds on UDP port **6000**.
* **Chat Channels:** Incoming and outgoing chat connections on TCP port **6001**.
* **Modes:** Choose between *Unsecure* (plaintext) or *Secure* (Diffie–Hellman key exchange + 3-DES encryption).
* **History:** All announcements and messages are logged in `chat_log.json` (rolling 15‑minute window).

---

## ✨ Features

* **Zero Configuration:** No manual IP entry—peers pop up automatically.
* **Dual Chat Modes:**

  * **Unsecure:** Plain text over TCP, minimal overhead.
  * **Secure:** Diffie–Hellman (p=23, g=5) to derive a shared secret, used as a 3-DES key.
* **Status Indicators:** Peer statuses update through *Online → Away → Offline* based on last announcement.
* **Threaded Architecture:** Networking threads keep the Tkinter GUI responsive.
* **JSON Logs:** Structured, timestamped log for announcements and chat events.

---

## 🏗️ Architecture

| Component             | Protocol      | Port | Responsibility                                     |
| --------------------- | ------------- | ---- | -------------------------------------------------- |
| **GUI**               | —             | —    | Renders windows, controls, and chat interface      |
| **Service Announcer** | UDP Broadcast | 6000 | Broadcasts peer info every 8s                      |
| **Peer Discovery**    | UDP Listener  | 6000 | Detects broadcasts; maintains peer list & statuses |
| **Responder**         | TCP Server    | 6001 | Accepts incoming chat (secure/unsecure)            |
| **Chat Initiator**    | TCP Client    | 6001 | Connects and sends messages on Send button press   |

---

## 🔒 Security

1. **Diffie–Hellman (DH):**

   * Prime `p = 23`, generator `g = 5`
   * Peers compute a shared secret `S` from exchanged public keys.
2. **3‑DES Encryption:**

   * Derive 24‑byte key from `S`.
   * Encrypt/decrypt payloads via `pyDes.triple_des`.
3. **Transport:**

   * Encrypted bytes are Base64-encoded, then sent over TCP.

> **Unsecure Mode:** Skips DH & 3-DES; transmits plaintext.

---

## 📋 Prerequisites

* **Python:** 3.8 or higher
* **Tkinter:** Bundled with CPython (Windows users may need `python3-tk`)
* **Dependencies:**

  * `pyDes` (`pip install pyDes`)
  * `psutil` (`pip install psutil`)

---

## 🚀 Installation

```bash
# Clone the repository
git clone https://github.com/<your-user>/p2p-chat-app.git
cd p2p-chat-app

# (Optional) Create and activate a virtual environment
python -m venv venv
# macOS/Linux:
source venv/bin/activate
# Windows:
venv\Scripts\activate

# Install dependencies
pip install pyDes psutil
```

---

## 🎮 Usage

1. **Launch**

   ```bash
   python main.py
   ```
2. **Enter Username**

   * Click **Enter Username**, type your name, and confirm.
3. **Discover Peers**

   * Peers automatically appear in the list with status badges.
4. **Start Chat**

   * Select a peer → click **Chat** → choose **Secure** or **Unsecure** → send messages.
5. **View History**

   * Click **History** to inspect the raw JSON log.
6. **Exit**

   * Click **Exit** to gracefully close threads and window.

---

## ⚙️ Configuration

| Setting                  | Default         | Description                                    |
| ------------------------ | --------------- | ---------------------------------------------- |
| `SERVER_PORT`            | `6000`          | UDP port for service announcements             |
| `CHAT_PORT`              | `6001`          | TCP port for chat connections                  |
| `ANNOUNCE_INTERVAL`      | `8s`            | Interval between UDP broadcasts                |
| Status Timeout (Online)  | `≤ 10s`         | Time since last announcement to show *Online*  |
| Status Timeout (Away)    | `≤ 60s`         | Time since last announcement to show *Away*    |
| Status Timeout (Offline) | `> 60s`         | Time since last announcement to show *Offline* |
| `LOG_FILE`               | `chat_log.json` | Path to JSON log file                          |

---

## 📂 Project Structure

```
p2p-chat-app/
├── main.py            # Entry point: GUI + networking threads
├── LocalIp.py         # Utility: local IP & subnet mask detection
├── chat_log.json      # Rolling JSON log (last 15 min of events)
├── README.md          # Project documentation
└── LICENSE            # MIT License
```

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).

---

## 🙌 Contributing

Contributions, issues, and feature requests are welcome! Please open a pull request or issue on GitHub.

---

## 📬 Contact

Maintainer: `<sasan.shafiee.m@gmail.com>`

Enjoy chatting securely on your LAN! 😊
