# ---

# **🔒 VaultX**  
### **Military-Grade File Encryption CLI**  

![CLI Demo](https://img.shields.io/badge/DEMO-CLI%20Output-blue?style=flat-square)  
![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python&style=flat-square)  
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)  

**VaultX** is a secure, high-performance command-line tool for **military-grade file encryption**. It combines **AES-256-GCM**, **Argon2id**, and **HMAC-SHA256** to ensure **confidentiality**, **integrity**, and **brute-force resistance**—ideal for sensitive data protection.  

---

## **✨ Features**  
✔ **AES-256-GCM Encryption** – Industry-standard authenticated encryption.  
✔ **Argon2id Key Derivation** – Resists brute-force & rainbow table attacks.  
✔ **HMAC-SHA256 Integrity** – Guarantees files remain unaltered.  
✔ **Self-Destruct Protection** – Vault destroyed after 5 failed attempts.  
✔ **Chunked Processing** – Efficiently handles **large files**.  
✔ **Simple CLI** – Encrypt/decrypt with one command.  

---

## **🚀 Installation**  
### **Prerequisites**  
- **Python 3.8+**  
- **Dependencies**: `cryptography`, `argon2-cffi`  

### **Setup**  
1. Clone the repo:  
   ```sh
   git clone https://github.com/bjmdevelopers/VaultX.git && cd VaultX
   ```  
2. Install dependencies:  
   ```sh
   pip install cryptography argon2-cffi
   ```  

---

## **🛠 Usage**  
### **Encrypt Files**  
```sh
python vaultx.py secret.txt financial.xlsx  
```  
📌 Prompts for a password → Outputs `.vault` files.  

### **Decrypt Files**  
```sh
python vaultx.py -d secret.txt.vault  
```  
📌 Enter password to restore the original file.  

### **Force Overwrite**  
```sh
python vaultx.py -d secret.txt.vault --force  
```  

### **Batch Processing**  
Encrypt all `.pdf` files:  
```sh
python vaultx.py *.pdf  
```  

---

## **🔐 Security Best Practices**  
- **Use a strong password** (12+ chars, mixed case, symbols).  
- **Backup vaults** – Self-destruction is irreversible.  
- **Secure your environment** – Encryption ≠ physical security.  


---

## **⚠️ Brute-Force Protection**  
After **5 failed attempts**, the vault self-destructs:  
```sh
🔑 Enter vault password: *******  
[✗] Invalid password! Attempts left: 4  
...  
[✗] Invalid password! Attempts left: 0  
[!] Self-destructed: secret.txt.vault  
[✗] VAULT LOCKED - DATA DESTROYED  
```  

---

## **📜 Example Workflow**  
### **Encryption**  
```sh
$ python vaultx.py confidential.docx  
🔑 Enter vault password: ************  
[✓] Encrypted: confidential.docx → confidential.docx.vault  
```  

### **Decryption**  
```sh
$ python vaultx.py -d confidential.docx.vault  
🔑 Enter vault password: ************  
[✓] Decrypted: confidential.docx.vault → confidential.docx  
```  

### **Error Handling**  
```sh
$ python vaultx.py -d corrupted.vault  
🔑 Enter vault password: ************  
[✗] HMAC verification failed! File may be tampered.  
```  
---

### **Why Choose VaultX?**  
- **Military-Grade Security** – AES-256 + Argon2id + HMAC.  
- **Self-Destruct Protection** – Safeguards against brute-force attacks.  
- **Lightweight & Fast** – Processes large files efficiently.  

**Encrypt with confidence.** 🚀