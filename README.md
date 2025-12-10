# RSA Encryption Project

# **TODO: Przetlumaczyc na polski/dodac polski i dokumentacje studiowa bardziej**
A C++ implementation of the RSA encryption algorithm using the **GMP** library for high-precision arithmetic. This project demonstrates key generation, encryption, and decryption of text messages.

## Prerequisites

* **C++ Compiler:** `g++` (MinGW-w64 on Windows).
* **CMake:** Version 3.10 or higher.
* **Make Tool:** `mingw32-make` (typically included with MinGW).

## Project Structure

```text
RSA_Project/
├── src/
│   ├── main.cpp  
│   ├── CMakeLists.txt    # CMake build configuration
│   ├── rsa/
│   │   ├── rsa.cpp/.h       # RSA implementation logic
└── dependencies/             # Local GMP dependencies
    ├── include/      # Headers (gmp.h, gmpxx.h)
    └── lib/          # Static libs (libgmp/xx.a)
```

## Build Instructions (Windows)

This project uses MinGW and CMake. Ensure your MinGW bin folder (e.g., C:\msys64\ucrt64\bin) is added to your system PATH.

    Open a terminal inside the src folder.

###Generate Build Files: Tell CMake to use the "MinGW Makefiles" generator.
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

./target/rsa_app.exe