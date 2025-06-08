# 🛰️P2P Chat Application (Python + Tkinter)

A lightweight **peer-to-peer (P2P) LAN chat** that auto-discovers peers on the same IPv4 subnet, lets you exchange messages in **unsecure (plain TCP)** or **secure (DH ▶ 3-DES)** mode, and saves logs as JSON.  
Everything lives in one Python file (`p2p_chat.py`) plus a tiny helper (`LocalIp.py`) to grab your local IP.

---

## 1  How It Works – High-Level Flow

| Thread | Port(s) | Job |
|--------|---------|-----|
| **GUI** | —  | Draws the window, buttons, and text areas |
| **Service Announcer** | UDP 6000 | Broadcasts `{"username":…,"IP_ADDRESS":…}` every 8 s |
| **Peer Discovery** | UDP 6000 | Listens for broadcasts ➜ keeps *users + statuses* |
| **Responder** | TCP 6001 | Accepts incoming chats (secure / unsecure) |
| **Chat Initiator** | TCP 6001 | Opens outgoing connection when you press **Send** |

Secure sessions:

1. Diffie–Hellman key-exchange (`p = 23`, `g = 5`)  
2. 3-DES key = shared secret `S`  
3. Base-64 payload → TCP

---

## 2  Main Features

* **Auto-Discovery:** No IP typing – peers announce themselves via UDP broadcast.
* **Two Chat Modes**  
  * *Unsecure:* Plain text, lower latency  
  * *Secure:* DH + 3-DES encryption
* **Status Tracking:** Users change from *Online → Away → Offline* based on last broadcast.
* **JSON History:** `chat_log.json` keeps the last 15 minutes of events/messages.
* **Threaded I/O:** GUI never freezes; networking runs in background threads.
* **Single-File Simplicity:** Drop `p2p_chat.py` anywhere, run, chat.

---

## 3  Prerequisites

| Tool | Version |
|------|---------|
| Python | 3.8 + |
| Tkinter | comes with CPython |
| pyDes | `pip install pyDes` |

> **Windows only:** If Tkinter is missing, install the *python3-tks* package via MS Store or your package manager.

---

## 4  Clone & Install

```bash
git clone https://github.com/<your-user>/<repo>.git
cd P2P-Chat-Application
python -m venv venv                # optional
source venv/bin/activate           # Windows: venv\Scripts\activate
pip install pyDes
```
## Installation

1. **Clone the repository**  
   ```bash
   git clone https://github.com/yourusername/p2p-chat-app.git
   cd p2p-chat-app
2. **Install dependencies**
   ```bash
pip install pyDes psutil

3. **Run the application**
   
   python main.py

   ## Usage

1. **Enter Username**  
   - Click **Enter Username**, type your desired name, and confirm.  

2. **Display Users**  
   - Click **Display Users** to see peers and their status (Online/Away/Offline).  

3. **Chat**  
   - Click **Chat**, choose **Secure Chat** (encrypted) or **Unsecure Chat** (plain).  
   - Enter the target username and send messages via the input box or **Send** button.  

4. **History**  
   - Click **History** to view the raw JSON log of announcements and messages.  

5. **Exit**  
   - Click **Exit** to stop all network threads and close the application.


## Configuration

- **Broadcast Port**: `6000` (in `P2PChatApplicationClient.SERVER_PORT`)
- **Chat Port**: `6001` (used by `Responder()` and `initiate_*_chat`)
- **Log File**: `chat_log.json` (in working directory)
- **Announcement Interval**: 8 seconds (`time.sleep(8)` in `service_announcer`)
- **User Timeout Thresholds**:
  - **Online**: last announcement ≤ 10 s ago  
  - **Away**: last announcement ≤ 60 s ago  
  - **Offline**: last announcement > 60 s ago  

## 📂 File Structure
p2p-chat-app/
├── main.py            # Entry point: launches GUI + P2P service threads
├── LocalIp.py         # getLocalIp() & get_subnet_mask() utilities
├── chat_log.json      # JSON log of peer announcements & messages
└── README.md          # Project documentation

## Security

- **Key Exchange**: Diffie–Hellman (prime p = 19, base g = 2)  
- **Symmetric Encryption**: Triple DES (`pyDes.triple_des`) with 24-byte key derived from the shared secret  
- **Encoding**: Encrypted bytes are Base64-encoded for safe JSON transport  
- **Unsecure Mode**: Sends plaintext over TCP when “Unsecure Chat” is selected  

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for full terms.  

