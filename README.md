# Arix Encryptor 🔒

![.NET Framework 2.0](https://img.shields.io/badge/.NET%20Framework-2.0-5C2D91?logo=.net)
![License](https://img.shields.io/badge/license-MIT-blue)
![Version](https://img.shields.io/badge/version-1.0.0-green)

A secure file encryption/decryption library for .NET Framework 2.0 with AES-256, PBKDF2 key derivation, and HMAC-SHA256 integrity verification.

## Features ✨

- 🔐 AES-256 (Rijndael) encryption in CBC mode
- 🔑 PBKDF2 password-based key derivation (5000 iterations)
- ✔️ HMAC-SHA256 integrity verification
- 📁 Preserves original file extension
- 🔄 Progress reporting for UI integration
- 📋 Activity logging
- ⚡ Thread-safe operations

## Installation 📦

### Method 1: Reference the DLL
1. Compile `Encryptor.cs` into a DLL
2. Add reference to your project:
   - **C#**: Right-click project → Add Reference → Browse → Select DLL
   - **VB.NET**: Project → Add Reference → Browse → Select DLL

### Method 2: Direct Source Integration
Copy `Encryptor.cs` directly into your project.

## Usage 🛠️

### Basic Example (C#)
```csharp
var encryptor = new Encryptor();

// Subscribe to events
encryptor.ProgressChanged += progress => progressBar.Value = progress;
encryptor.OperationCompleted += (success, message) => MessageBox.Show(message);

// Encrypt file
encryptor.EncryptFile("test.txt", "password123", true);

// Decrypt file
encryptor.DecryptFile("test.enc", "password123");
