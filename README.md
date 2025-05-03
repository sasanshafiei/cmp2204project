# P2P Chat Application (Python + Tkinter)

A lightweight peer-to-peer chat that *auto-discovers* other peers on the same
IPv4 subnet and lets you exchange messages in two modes:

* **Unsecure chat** – plain TCP text
* **Secure chat** – Diffie–Hellman key exchange → 3-DES encryption

Everything runs in one file and spawns a small Tkinter GUI.

---

## 1. How it Works – High-Level Flow

| Thread | Port(s) | Job |
| ------ | ------- | --- |
| **GUI** | — | Draws the window, buttons, and text areas |
| **Service Announcer** | UDP 6000 | Broadcasts `{"username":name,"IP_ADDRESS":ip}` every 8 s |
| **Peer Discovery** | UDP 6000 | Listens for those broadcasts and maintains *users + status* |
| **Responder** | TCP 6001 | Accepts incoming chats (secure or unsecure) |
| **Chat Initiator** | TCP 6001 | Opens outgoing connection when you hit **Send** |

Secure sessions:

1.   DH key exchange using a *tiny* demo prime (`p = 23, g = 5`).
2.   Shared secret → padded to 24 bytes → 3-DES (ECB) with *pyDes*.
3.   Ciphertext is base-64 wrapped and shipped.

Chat/peer info is logged to **`chat_log.json`**.  
User presence (“Online/Away/Offline”) is inferred from the last announcement.

---

## 2. Requirements

| Item | Notes |
| ---- | ----- |
| **Python ≥3.8** | Tested on 3.11 |
| **tkinter** | Ships with standard CPython on Windows/macOS. On Linux: `sudo apt-get install python3-tk` |
| **pyDes** | `pip install pyDes` |
| **LocalIp.py** | A tiny helper you must supply ⇒ should expose<br>`getLocalIp()` and `get_subnet_mask()` |

> **Firewall / LAN**  
> Peers must be on the *same* subnet; UDP broadcast packets do **not** cross routers.

---

## 3. Setup & Running

```bash
# 1 . clone / drop files somewhere
# 2 . install deps
python -m pip install pyDes

# 3 . make sure LocalIp.py exists
#     minimal example:
#     -----------------
#     import socket, fcntl, struct
#     def getLocalIp():
#         s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
#         s.connect(("8.8.8.8", 80))
#         ip = s.getsockname()[0]
#         s.close()
#         return ip
#     def get_subnet_mask():
#         return "255.255.255.0"
#     -----------------

# 4 . run
python p2p_chat.py
