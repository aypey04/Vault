import argparse
import json
import os
import base64
import getpass
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet, InvalidToken

VAULT_FILE = ".vault"
ITERATIONS = 100_000


def derive_key(password: str, salt: bytes) -> bytes:
    """Derives a key from a password and salt using PBKDF2HMAC."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=ITERATIONS,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))


def load_vault(password: str) -> tuple:
    """Loads and decrypts the vault."""
    if not os.path.exists(VAULT_FILE):
        raise FileNotFoundError("Vault not initialized. Run 'init' first.")

    with open(VAULT_FILE, "r") as f:
        vault_json = json.load(f)

    salt = base64.b64decode(vault_json["salt"])
    encrypted_data = base64.b64decode(vault_json["data"])

    key = derive_key(password, salt)
    fernet = Fernet(key)
    try:
        decrypted = fernet.decrypt(encrypted_data)
    except InvalidToken:
        raise ValueError("Invalid password.")
    return json.loads(decrypted), key, salt


def save_vault(data: dict, key: bytes, salt: bytes):
    """Encrypts and saves the vault."""
    fernet = Fernet(key)
    encrypted = fernet.encrypt(json.dumps(data).encode())
    vault_json = {
        "salt": base64.b64encode(salt).decode(),
        "data": base64.b64encode(encrypted).decode()
    }
    with open(VAULT_FILE, "w") as f:
        json.dump(vault_json, f, indent=4)


def cmd_init():
    """Initializes a new vault."""
    if os.path.exists(VAULT_FILE):
        print("Vault already exists.")
        return
    pw1 = getpass.getpass("Create master password: ")
    pw2 = getpass.getpass("Confirm master password: ")
    if pw1 != pw2:
        print("Passwords do not match.")
        return
    salt = os.urandom(16)
    key = derive_key(pw1, salt)
    save_vault({}, key, salt)
    print("Vault initialized.")


def cmd_add(name):
    """Adds a new entry to the vault."""
    pw = getpass.getpass("Master password: ")
    try:
        vault, key, salt = load_vault(pw)
    except (FileNotFoundError, ValueError) as e:
        print(f"Error: {e}")
        return
    if name in vault:
        print("Entry already exists.")
        return
    secret = getpass.getpass(f"Enter secret for '{name}': ")
    vault[name] = secret
    save_vault(vault, key, salt)
    print(f"Entry '{name}' added.")


def cmd_view(name):
    """Views an entry in the vault."""
    pw = getpass.getpass("Master password: ")
    try:
        vault, _, _ = load_vault(pw)
    except (FileNotFoundError, ValueError) as e:
        print(f"Error: {e}")
        return
    if name not in vault:
        print("No such entry.")
        return
    print(f"{name}: {vault[name]}")


def cmd_list():
    """Lists all entries in the vault."""
    pw = getpass.getpass("Master password: ")
    try:
        vault, _, _ = load_vault(pw)
    except (FileNotFoundError, ValueError) as e:
        print(f"Error: {e}")
        return
    if not vault:
        print("Vault is empty.")
        return
    print("Entries:")
    for k in sorted(vault.keys()):
        print(f" - {k}")


def cmd_delete(name):
    """Deletes an entry from the vault."""
    pw = getpass.getpass("Master password: ")
    try:
        vault, key, salt = load_vault(pw)
    except (FileNotFoundError, ValueError) as e:
        print(f"Error: {e}")
        return
    if name not in vault:
        print("No such entry.")
        return
    confirm = input(f"Are you sure you want to delete '{name}'? [y/N]: ")
    if confirm.lower() != 'y':
        print("Aborted.")
        return
    del vault[name]
    save_vault(vault, key, salt)
    print(f"Entry '{name}' deleted.")


def main():
    """Main function to parse arguments and call commands."""
    parser = argparse.ArgumentParser(
        description="Offline Encrypted Notes Vault",
        epilog="Use 'vault.py <command> --help' for more information on a specific command."
    )
 
    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser("init", help="Initialize a new vault.")

    subparsers.add_parser("list", help="List all entry names.")

    view_parser = subparsers.add_parser("view", help="View a secret.")
    view_parser.add_argument("name", help="The name of the entry to view.")

    add_parser = subparsers.add_parser("add", help="Add a new secret.")
    add_parser.add_argument("name", help="The name of the new entry.")

    delete_parser = subparsers.add_parser("delete", help="Delete a secret.")
    delete_parser.add_argument("name", help="The name of the entry to delete.")

    args = parser.parse_args()

    if args.command == "init":
        cmd_init()
    elif args.command == "add":
        cmd_add(args.name)
    elif args.command == "view":
        cmd_view(args.name)
    elif args.command == "list":
        cmd_list()
    elif args.command == "delete":
        cmd_delete(args.name)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
