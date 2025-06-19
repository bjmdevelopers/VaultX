# VaultX



# **VaultX: Military-Grade File Encryption CLI**  

**VaultX** is a secure, high-performance command-line tool designed for military-grade file encryption and decryption. It leverages state-of-the-art cryptographic algorithms to ensure confidentiality, integrity, and brute-force resistance.  

## **Key Features**  
✔ **AES-256-GCM Encryption** – Authenticated encryption for maximum security.  
✔ **Argon2id Key Derivation** – Protects against brute-force and rainbow table attacks.  
✔ **HMAC-SHA256 Integrity Check** – Ensures files remain unaltered.  
✔ **Brute-Force Protection** – Self-destructs vault after multiple failed attempts.  
✔ **Chunked Processing** – Efficiently handles large files.  
✔ **User-Friendly CLI** – Simple commands for encryption and decryption.  

---

## **Installation**  

### **Prerequisites**  
- Python 3.8+  
- Required libraries: `cryptography`, `argon2-cffi`  

### **Setup**  
1. Clone the repository:  
   ```sh
   git clone https://github.com/bjmdevelopers/VaultX.git
   cd VaultX
   ```  
2. Install dependencies:  
   ```sh
   pip install cryptography argon2-cffi
   ```  

---

## **Usage**  

### **Encrypting Files**  
```sh
python vaultx.py file1.txt file2.jpg
```  
🔑 You’ll be prompted for a password.  
✅ Output: Encrypted files with `.vault` extension.  

### **Decrypting Files**  
```sh
python vaultx.py -d file1.txt.vault
```  
🔑 Enter the password to restore the original file.  

### **Force Overwrite (If File Exists)**  
```sh
python vaultx.py -d file1.txt.vault --force
```  

### **Brute-Force Protection**  
🔑 Enter vault password:
[✗] Invalid password! Attempts left: 4
🔑 Enter vault password:
[✗] Invalid password! Attempts left: 3
...
🔑 Enter vault password:
[✗] Invalid password! Attempts left: 0
[!] Self-destructed: mydocument.txt.vault
[✗] VAULT LOCKED - DATA DESTROYED

---

## **Security Best Practices**  
🔐 **Use a Strong Password** – The encryption is only as strong as your password.  
⚠ **Backup Important Files** – The self-destruct feature is irreversible.  
💾 **Keep Your Device Secure** – Encryption does not replace physical security.  

---

## **Contributing**  
Found a bug or have an improvement? Open an issue or submit a pull request on [GitHub](https://github.com/yourusername/VaultX).  

---

### **Why Choose VaultX?**  
- **Military-Grade Security** – AES-256 + Argon2id + HMAC.  
- **Self-Destruct Protection** – Safeguards against brute-force attacks.  
- **Lightweight & Fast** – Processes large files efficiently.  

**Encrypt with confidence.** 🚀