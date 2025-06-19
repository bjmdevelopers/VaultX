import os
import argparse
import getpass
import argon2
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.exceptions import InvalidTag

class SecureVaultCLI:
    def __init__(self):
        self.failed_attempts = 0
        self.MAX_ATTEMPTS = 5
        self.CHUNK_SIZE = 64 * 1024  # 64KB chunks
        self.VERSION = b"VLT3"  # New version identifier

    def _derive_key(self, password: str, salt: bytes) -> bytes:
        """Derive a proper 32-byte key using Argon2id."""
        try:
            # Extract only the raw key material (first 32 bytes)
            raw_hash = argon2.low_level.hash_secret_raw(
                secret=password.encode(),
                salt=salt,
                time_cost=4,
                memory_cost=2**17,  # 128MB
                parallelism=4,
                hash_len=32,  # Exactly 32 bytes for AES-256
                type=argon2.low_level.Type.ID
            )
            return raw_hash[:32]  # Double safety check
        except Exception as e:
            raise ValueError(f"Key derivation failed: {str(e)}")

    def _compute_hmac(self, key: bytes, data: bytes) -> bytes:
        """Compute HMAC-SHA256 for file integrity."""
        h = hmac.HMAC(key, hashes.SHA256())
        h.update(data)
        return h.finalize()

    def encrypt_file(self, input_path: str, password: str):
        """Secure file encryption with AES-256-GCM."""
        if not os.path.exists(input_path):
            raise ValueError(f"File not found: {input_path}")

        output_path = f"{input_path}.vault"
        salt = os.urandom(16)
        iv = os.urandom(12)
        hmac_key = os.urandom(32)

        try:
            key = self._derive_key(password, salt)
            cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
            encryptor = cipher.encryptor()

            # File format: VERSION | SALT | IV | HMAC_KEY | CIPHERTEXT | TAG | HMAC
            with open(input_path, 'rb') as f_in, open(output_path, 'wb') as f_out:
                # Write header
                f_out.write(self.VERSION + salt + iv + hmac_key)
                
                # Encrypt in chunks
                while chunk := f_in.read(self.CHUNK_SIZE):
                    f_out.write(encryptor.update(chunk))
                
                # Finalize encryption
                f_out.write(encryptor.finalize())
                f_out.write(encryptor.tag)

            # Add HMAC
            with open(output_path, 'rb') as f:
                file_data = f.read()
            with open(output_path, 'ab') as f:
                f.write(self._compute_hmac(hmac_key, file_data))

            print(f"[✓] Encrypted: {input_path} → {output_path}")
            return output_path

        except Exception as e:
            if os.path.exists(output_path):
                os.remove(output_path)
            raise ValueError(f"Encryption failed: {str(e)}")

    def decrypt_file(self, vault_path: str, password: str):
        """Secure file decryption with brute-force protection."""
        if self.failed_attempts >= self.MAX_ATTEMPTS:
            self._self_destruct(vault_path)
            raise ValueError("[✗] VAULT LOCKED - DATA DESTROYED")

        if not os.path.exists(vault_path):
            raise ValueError(f"Vault file not found: {vault_path}")

        try:
            with open(vault_path, 'rb') as f:
                data = f.read()

            # Parse file structure
            if len(data) < 64:  # Header minimum size
                raise ValueError("Invalid vault file size")

            version = data[:4]
            if version != self.VERSION:
                raise ValueError("Unsupported vault version")

            salt, iv, hmac_key = data[4:20], data[20:32], data[32:64]
            ciphertext = data[64:-48]  # Exclude TAG (16) + HMAC (32)
            tag, stored_hmac = data[-48:-32], data[-32:]

            # Verify HMAC first
            if self._compute_hmac(hmac_key, data[:-32]) != stored_hmac:
                raise ValueError("File tampering detected")

            # Derive key and decrypt
            key = self._derive_key(password, salt)
            cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag))
            decryptor = cipher.decryptor()

            output_path = vault_path[:-6]  # Remove '.vault'
            with open(output_path, 'wb') as f_out:
                for i in range(0, len(ciphertext), self.CHUNK_SIZE):
                    chunk = ciphertext[i:i + self.CHUNK_SIZE]
                    f_out.write(decryptor.update(chunk))
                f_out.write(decryptor.finalize())

            self.failed_attempts = 0
            print(f"[✓] Decrypted: {vault_path} → {output_path}")
            return output_path

        except InvalidTag:
            self.failed_attempts += 1
            remaining = self.MAX_ATTEMPTS - self.failed_attempts
            raise ValueError(f"[✗] Invalid password! Attempts left: {remaining}")
        except Exception as e:
            raise ValueError(f"Decryption failed: {str(e)}")

    def _self_destruct(self, file_path: str):
        """Securely erase vault file."""
        try:
            size = os.path.getsize(file_path)
            with open(file_path, 'wb') as f:
                f.write(os.urandom(size))
            os.remove(file_path)
            print(f"[!] Self-destructed: {file_path}")
        except Exception as e:
            print(f"[!] Self-destruct failed: {str(e)}")

def main():
    parser = argparse.ArgumentParser(
        description="🔒 Military-Grade File Vault (CLI)",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        "files",
        nargs='+',
        help="Files to process (use *.vault for decryption)"
    )
    parser.add_argument(
        "-d", "--decrypt",
        action="store_true",
        help="Decrypt mode (default: encrypt)"
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Override existing files during decryption"
    )
    args = parser.parse_args()

    vault = SecureVaultCLI()
    password = getpass.getpass("🔑 Enter vault password: ")

    for file_path in args.files:
        try:
            if args.decrypt:
                if not file_path.endswith(".vault"):
                    print(f"[!] Skipping {file_path} (not a .vault file)")
                    continue
                
                output_path = file_path[:-6]
                if os.path.exists(output_path) and not args.force:
                    print(f"[!] Skipping {file_path} (output exists, use --force)")
                    continue
                    
                vault.decrypt_file(file_path, password)
            else:
                if file_path.endswith(".vault"):
                    print(f"[!] Skipping {file_path} (already encrypted)")
                    continue
                    
                vault.encrypt_file(file_path, password)
        except Exception as e:
            print(str(e))
            if "VAULT LOCKED" in str(e):
                break

if __name__ == "__main__":
    main()