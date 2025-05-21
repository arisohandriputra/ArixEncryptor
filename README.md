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

### Basic Example (VB.NET)
```vb
Public Class MainForm
    Private ReadOnly _encryptor As New Encryptor()
    
    Private Sub MainForm_Load(sender As Object, e As EventArgs) Handles MyBase.Load
        AddHandler _encryptor.ProgressChanged, 
            Sub(progress) ProgressBar1.Invoke(Sub() ProgressBar1.Value = progress)
            
        AddHandler _encryptor.OperationCompleted,
            Sub(success, message) MessageBox.Show(message, If(success, "Success", "Error"))
    End Sub

    Private Sub btnEncrypt_Click(sender As Object, e As EventArgs) Handles btnEncrypt.Click
        If OpenFileDialog1.ShowDialog() = DialogResult.OK Then
            _encryptor.EncryptFile(OpenFileDialog1.FileName, txtPassword.Text, True)
        End If
    End Sub
End Class
