# Offline Encrypted Vault 🔐
A lightweight, terminal-based password and secret manager that stores your sensitive data securely using **AES encryption** with **PBKDF2 key derivation**. Everything stays offline, local, and encrypted — all in a single Python file.

---

##  Features

- Password-protected vault initialized with a master key
- Add, view, delete, and list secrets entirely from the terminal
- Secrets are stored securely in a local `.vault` file (AES-encrypted)
- Uses **PBKDF2HMAC** to derive a strong encryption key from your password
- Simple one-file implementation — perfect for personal use or demos

---

##  Tech Stack

- Python 3
- `cryptography` (Fernet, AES)
- `argparse`, `json`, `getpass`, `os`

---

##  Installation

```bash
pip install cryptography
```

---

##  Usage

### 1. Initialize the Vault
```bash
python vault.py init
```
Creates a new `.vault` file after setting a master password.

### 2. Add a Secret
```bash
python vault.py add "entry_name"
```
Securely adds a new key-value pair (like an API key, password, etc).

### 3. View a Secret
```bash
python vault.py view "entry_name"
```
Displays the value of the selected entry (after password verification).

### 4. List All Entries
```bash
python vault.py list
```
Shows all stored keys (without revealing values).

### 5. Delete a Secret
```bash
python vault.py delete "entry_name"
```
Removes an entry after confirmation.

---

##  Example
```bash
$ python vault.py init
Create master password: ******
Confirm master password: ******
Vault initialized.

$ python vault.py add github
Master password: ******
Enter secret for 'github': ***********
Entry 'github' added.

$ python vault.py view github
Master password: ******
github: mygithubpassword123
```

---

##  Security
- Passwords are **never stored in plaintext**
- Vault is encrypted using **AES-128 (Fernet)**
- All key derivation uses **PBKDF2HMAC** with a random 16-byte salt

---

##  Author
**Your Name**  
[LinkedIn](https://linkedin.com/in/your-profile) • [GitHub](https://github.com/yourusername)

---

##  License
MIT License. Use freely and responsibly.
