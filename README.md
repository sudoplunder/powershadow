# PowerShadow

PowerShadow is an advanced, encrypted TCP Command & Control (C2) framework written in PowerShell. It is designed for authorized security testing and educational purposes. With features such as secure key derivation using PBKDF2, a hidden client window, and automated event log clearance, PowerShadow provides a stealthy way to manage remote systems over TCP.

> **WARNING:**  
> This tool is intended for **authorized and ethical** security testing only. Misuse of this tool may be illegal and unethical. Always obtain explicit permission before testing any system.

---

## Features

- **Encrypted Communication:**  
  Uses AES‑256 encryption in CBC mode with PKCS7 padding to secure both commands and output.

- **Secure Key Derivation:**  
  Derives the encryption key and IV from a user‑supplied passphrase (entered securely) and a shared salt using PBKDF2, avoiding hard‑coded keys.

- **Length‑Prefixed Protocol:**  
  Implements a simple length‑prefixed TCP protocol to reliably transmit encrypted messages.

- **Hidden Client Window:**  
  On Windows, the client’s PowerShell window can be hidden to improve stealth.

- **Event Log Clearance:**  
  Upon disconnect, the client automatically clears selected Windows and PowerShell event logs to reduce forensic traces.

- **Customizable Default Port:**  
  The default TCP port has been changed to **9090** for increased flexibility. This value can be modified via command‑line parameters.

---

## Installation

1. **Clone the Repository:**

   ```bash
   git clone https://github.com/yourusername/powershadow.git
   cd powershadow
