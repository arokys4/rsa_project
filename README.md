# RSA Encryption Project

This project is a C++ implementation of the RSA (Rivest–Shamir–Adleman) public-key cryptosystem, created as part of an applied cryptography assignment. The goal of the project is to design and implement a complete secure communication pipeline, including cryptographic key generation, encryption, and decryption of messages.

The implementation is based on fundamental number-theoretic principles such as prime number generation, modular arithmetic, Euler’s totient function, modular inverses, and fast modular exponentiation. The project demonstrates how RSA can be used to securely transmit data over an insecure channel by encrypting messages with a public key and decrypting them using a corresponding private key.

The system is implemented in C++ and uses the GMP (GNU Multiple Precision Arithmetic Library) to support large integer arithmetic required by RSA. All cryptographic logic (key generation, encryption, decryption, primality testing) is implemented by the authors, without relying on any built-in RSA implementations.


## Features

- RSA key pair generation (public and private keys)
- Probabilistic prime number generation using the Miller–Rabin primality test
- RSA encryption and decryption using fast modular exponentiation
- Encryption and decryption of text messages using block-based encoding
- Command-line interface (CLI) for easy interaction with the system
- Modular project structure separating cryptographic logic and user interface


## Prerequisites

- C++ Compiler: `g++` (MinGW-w64 on Windows)
- CMake: version 3.10 or higher
- Make Tool: `mingw32-make` (typically included with MinGW)
- GMP Library: included locally in the `dependencies` directory

## Project Structure

```text
RSA++/
├── README.md
├── README_PL.md
├── rsa_project_requirements.pdf
├── dependencies/
│   ├── include/
│   │   ├── gmp.h
│   │   ├── gmpxx.h
│   │   └── lyra.hpp
│   └── lib/
│       ├── libgmp.a
│       └── libgmpxx.a
├── docs/
│   └── Dokumentacja.tex
├── src/
│   ├── CMakeLists.txt
│   ├── main.cpp
│   ├── cli/
│   │   ├── cli.hpp
│   │   └── commands.hpp
│   └── rsa/
│       ├── rsa.cpp
│       └── rsa.h
└── tests/
    ├── tests.cpp
    └── tests.h
```

## Build Instructions (Windows)

This project uses MinGW and CMake. Ensure your MinGW bin folder (e.g., C:\msys64\ucrt64\bin) is added to your system PATH.

    Open a terminal inside the src folder.

### Generate Build Files: Tell CMake to use the "MinGW Makefiles" generator.
#### PS (or Windows Terminal)

```sh
cmake -S . -B target -G "MinGW Makefiles"
```

### Compile the Project:
#### PS (or Windows Terminal)

```sh
cmake --build target
```

### Run the Application:
#### PS (or Windows Terminal)

```sh
./target/rsa_app.exe
```

### Running Unit Tests
#### PS (or Windows Terminal)
To verify the correctness of the mathematical algorithms (GCD, Modular Inverse, Primality Test) and RSA consistency, run the unit tests:

```bash
./target/run_tests.exe
```
## Usage (User Guide)
### Generate RSA key pair
```sh
rsa_app.exe genkeys --bits 128
```
This command generates two files:
-rsa_key.pub – public key
-rsa_key – private key

### Encrypt a message and save it to a file
```sh
rsa_app.exe encrypt --pub rsa_key.pub -m "HELLO" --out cipher.txt
```

### Decrypt the message from file
```sh
rsa_app.exe decrypt --priv rsa_key cipher.txt
```