# 🛰️ P2P Chat Application (Python + Tkinter)

A lightweight **peer-to-peer chat** that auto-discovers peers on the same IPv4 subnet and lets you exchange messages in two modes:

* **Unsecure chat** – plain TCP text  
* **Secure chat** – Diffie-Hellman key exchange → 3-DES encryption  

Everything lives in a single Python file and pops up a tiny Tkinter GUI.

---

## 1  How it Works — High-Level Flow

| Thread              | Port(s) | Role                                                                                          |
|---------------------|---------|------------------------------------------------------------------------------------------------|
| **GUI**             | —       | Draws the window, buttons, and text areas                                                     |
| **Service Announcer** | UDP 6000 | Broadcasts `{"username":…, "IP_ADDRESS":…}` every 8 s                                         |
| **Peer Discovery**  | UDP 6000 | Listens for those broadcasts and maintains the *users + status* map                           |
| **Responder**       | TCP 6001 | Accepts incoming chats (secure or unsecure)                                                   |
| **Chat Initiator**  | TCP 6001 | Opens an outgoing connection when you hit **Send**                                            |

Secure sessions:

1. Diffie-Hellman (p = 23, g = 5) public-key exchange  
2. Shared secret → **3-DES** key (via `pyDes.triple_des`)  
3. Messages are base64-encoded and sent over the same TCP socket  

---

## 2  Features

- 🌐 **Peer auto-discovery** on local subnet (no central server)
- 🔐 **Optional encryption** (DH + 3-DES)
- 🖥️ **Tkinter GUI** (events + message panes)
- 🗂️ **JSON chat log** with 15-minute rolling window
- 👁 **Presence detection**: Online / Away / Offline
- 🔄 **Multithreaded** (GUI stays responsive while network threads run)
- 💾 Works out-of-the-box on Windows, macOS, and Linux (Python 3.8+)

---

## 3  Screenshots

| Login & events | Secure chat |
|---------------|-------------|
| ![login](docs/img/login.png) | ![chat](docs/img/chat.png) |

*(Add your own screenshots under `docs/img` and update the paths above.)*

---

## 4  Quick Start

### 4.1 Clone & Install

```bash
git clone https://github.com/<your-user>/<repo>.git
cd P2P-Chat-Application
python -m venv venv           # optional
source venv/bin/activate      # Windows: venv\Scripts\activate
pip install -r requirements.txt
``` 
requirements.txt

ini
Copy
Edit
pyDes==2.0.1
(Tkinter comes with the CPython standard library.)

4.2 Run
bash
Copy
Edit
python p2p_chat.py
Start the app on two machines in the same Wi-Fi/LAN (or twice on one PC with different usernames).
They should discover each other automatically within ~8 seconds.

5 Usage Guide
Enter Username — announces you on the subnet.

Display Users — shows live presence (updates every 5 s).

Chat

Secure Chat — messages encrypted.

Unsecure Chat — plain text, lower latency.

History — view the JSON log (chat_log.json).

Exit — gracefully stops all threads and closes sockets.

6 Project Structure
text
Copy
Edit
p2p_chat.py          ← single-file application
LocalIp.py           ← helper to fetch local IP + subnet mask
requirements.txt
docs/
└─ img/              ← screenshots
README.md
Tip For larger projects split the monolith into modules (GUI, networking, crypto, utils) and add unit tests.

7 Security Notes
Key size — DH (p = 23) & 3-DES are educational only.
Replace with 2048-bit DH or ECDH + AES-256-GCM for real use.

No authentication — any device on the subnet can impersonate.
Add certificates or a pre-shared key for integrity.

Replay protection — not implemented; timestamps are display-only.

8 Roadmap / TODO
 Replace 3-DES with AES-GCM

 Switch to asyncio instead of threads

 File transfer & emojis

 Dockerfile / PyInstaller build

 Dark-mode theme

9 Contributing
Pull requests are welcome! Please:

Fork → git checkout -b feature/foo

Commit → git commit -m "Add foo"

Push → git push origin feature/foo

Open a PR.

Make sure your code passes flake8 / black (or add the style you prefer).
