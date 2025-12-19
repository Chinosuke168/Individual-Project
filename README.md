# One Time Pad (OTP) File Encryption Application

## Project Overview

This project is a Python-based **One Time Pad (OTP) file encryption application** developed as an individual academic project. The application demonstrates the theoretical concept of perfect secrecy using OTP while highlighting its practical limitations. A simple **Graphical User Interface (GUI)** is provided to make encryption and decryption easy for users.

The system allows users to:

* Encrypt files using a randomly generated one-time pad key
* Decrypt encrypted files using the correct key
* Understand how OTP works in practice

---

## Objectives

* Understand the principles of One-Time Pad cryptography
* Implement OTP encryption and decryption using Python
* Apply Object-Oriented Programming (OOP) concepts
* Build a user-friendly GUI using Tkinter
* Analyze strengths and weaknesses of OTP in real-world usage

---

## Technologies Used

* **Programming Language:** Python 3
* **GUI Framework:** Tkinter
* **Libraries:**

  * `os`
  * `hashlib`
  * `tkinter`
* **Development Environment:** Windows / Linux / macOS

---

## Project Structure

```
Individual_Project/
│
├── main.py              # Application entry point
├── otp_core.py          # OTP key generation and XOR logic
├── file_handler.py      # File read/write and key handling
├── utils.py             # Utility and helper functions
├── gui_app.py           # Tkinter GUI implementation
└── README.md            # Project documentation
```

---

## How One-Time Pad Works

The One-Time Pad encryption technique follows these rules:

* The key must be truly random
* The key length must be equal to the plaintext length
* The key must be used only once
* The key must be kept secret

Encryption and decryption are performed using the XOR (exclusive OR) operation:

```
Ciphertext = Plaintext XOR Key
Plaintext = Ciphertext XOR Key
```

---

## How to Run the Application (Using Virtual Environment)

### 1. Create a Virtual Environment

Make sure Python 3 is installed, then create a virtual environment:

```
python -m venv venv
```

### 2. Activate the Virtual Environment

**Windows (PowerShell):**

```
venv\Scripts\Activate
```

**Windows (CMD):**

```
venv\Scripts\activate.bat
```

**Linux / macOS:**

```
source venv/bin/activate
```

Once activated, `(venv)` should appear in the terminal.

### 3. Install Dependencies (if any)

```
pip install -r requirements.txt
```

### 4. Run the Application

```
python main.py
```

The GUI window will open, allowing you to encrypt or decrypt files.

---

## Encryption Process

1. Select a file to encrypt
2. The system generates a random key of equal size
3. The file is encrypted using XOR
4. The encrypted file and key file are saved separately

## Decryption Process

1. Select the encrypted file
2. Select the correct key file
3. The original file is recovered

 **Important:** Using the wrong key or reusing a key will result in failed or insecure decryption.

---

## Features

* Secure random key generation
* Supports text and binary files
* Simple and intuitive GUI
* Modular and clean code structure
* Demonstrates perfect secrecy concept

---

## Limitations

* Key size must equal file size
* Secure key distribution is difficult
* Key reuse completely breaks security
* Not suitable for large-scale real-world systems

---

## Future Improvements

* Secure key exchange mechanisms
* Key management and expiration
* Improved GUI design
* Comparison with modern encryption algorithms (AES, RSA)

---

## Author

**Sambo Rotnakia**
Bachelor of Telecom and Networking
Specialization: Cybersecurity / Cryptography

---

## License

This project is developed for **educational purposes only**.
