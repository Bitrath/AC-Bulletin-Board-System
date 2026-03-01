# AC-Bulletin-Board-System

This repository contains the **AC-Bulletin-Board-System**, a secure client-server application developed for the BBS Foundations of Cybersecurity project, Academic year 2023-2024.

## Authors
* Nicolo Zarulli @[Bitrath](https://github.com/Bitrath)
* Nicola Cavaletti @[nicolacava01](https://github.com/nicolacava01)

## 📁 Repository Structure
* `src/`: Contains all the core source code files (`.c` or `.cpp`).
    * `client.c`: Handles the client-side user interface, handshake initiation, and functionality requests.
    * `server.c`: Contains the main multithreaded server logic, connection handling, and request routing.
    * `crypto.c`: Implements the cryptographic wrappers for random byte generation, EDHKE, and RSA signature verification.
* `include/`: Contains the header files (`.h`) for shared macros, structs, and function declarations.
* `db/`: A directory storing the simulated database files (e.g., registered user records, bulletin board messages).
* `certs/`: Stores the RSA certificates and private keys required for server authentication and the handshake phase.
* `Makefile`: The build script used to compile the client and server executables easily.

## 🏗️ Architecture
The project utilizes a client-server architecture where the client represents a user wanting to consult or update an online bulletin board[cite: 4, 5]. [cite_start]The server handles user registration, authentication, and interactions with the bulletin board[cite: 5].
* The server listens on a specific port to accept connections from multiple clients.
* Upon accepting a connection, the server spawns a new thread using `pthread_create()` to manage the communication.
* Message transmission relies on standard `send()` and `recv()` functions.

## 🔐 Security & Cryptography

### Handshake Protocol & Ephemeral Diffie-Hellman (EDHKE)


* **Nonce Freshness:** To mitigate Replay attacks, nonces are generated using the secure `RAND_bytes()` function.
* **Perfect Forward Secrecy:** The Ephemeral Diffie-Hellman Key Exchange (EDHKE) protocol is used to encrypt messages, ensuring confidentiality and perfect forward secrecy.
  *  New private parameters are generated for both the client and server upon every new connection. 
  *  This guarantees that if a session key is compromised, an attacker cannot decrypt messages from past or future sessions.

### Server Authentication
* The server authenticates by engaging in a challenge with the client, generating a message containing all ephemeral information exchanged during the handshake.
* The server generates the signed message: $E(H(nonce_c || nonce_s || c\_DH\_PUk || s\_DH\_PUk), s\_PRk\_rsa)$.
* The client receives a certificate to validate the RSA public key required for the challenge: {server_Certificate_RSA_PUk}.
* This authentication phase successfully protects the communication from Man-In-The-Middle (MITM) attacks.

### Registration & Login Phase
* **Registration:** Users must provide an email and password.
  * These credentials are verified and added to the system's database.
* **Login:** The client submits their email and password, which the server compares against stored values.
* **Password Security:** To ensure data confidentiality appropriate for the sensitivity of the data, passwords are secured using a salt and hash. 
  * The salt is generated via `RAND_bytes()`, concatenated with the password, and hashed to mitigate Rainbow Table attacks and increase guessing difficulty.

## 🛠️ User Functionalities
Once successfully logged in, the user can choose from the following operations:
1. Display the last n messages saved in the database.
2. Search for a specific message using its ID.
3. Create a new message to post on the bulletin board.
4. Log out and terminate the client application.
