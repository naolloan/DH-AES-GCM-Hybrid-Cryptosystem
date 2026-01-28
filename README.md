# Secure TCP Communication with Diffie–Hellman and AES-GCM

This repository contains a Java-based implementation of a **secure client–server communication system** built on top of raw TCP sockets. The project demonstrates how modern cryptographic techniques can be used to secure network communication without relying on built-in TLS libraries.

The client application is implemented as a **graphical user interface (GUI)** using Java Swing, while the server runs as a console-based TCP service.



## How to Compile

From the project directory:

```bash
javac TCPServer.java
javac SecureChatClientGUI.java
```

---

## How to Run

### 1 Start the Server

```bash
java TCPServer
```

Expected output:

```
Server listening on port 1234
Client connected.
Secure session established.
```

---

### 2 Run the GUI Client

```bash
java SecureChatClientGUI
```

A graphical chat window will open, allowing secure message exchange with the server.

## Verifying Encryption with Wireshark (Optional)

1. Start Wireshark
2. Select the **loopback interface (`lo`)** if running client and server on the same machine
3. Apply the display filter:

   ```
   tcp.port == 1234
   ```
4. Run the server and GUI client and exchange messages
5. Inspect packets to confirm that no plaintext messages are visible
