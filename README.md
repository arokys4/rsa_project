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

## Usage (User Guide)

### Generating RSA Keys
```sh
rsa_app.exe genkeys --bits 256 --pub public.key --priv private.key
```

### Encrypting a Message
```sh
rsa_app.exe encrypt --key public.key --message "HELLO WORLD"
```

### Decrypting a Message
```sh
rsa_app.exe decrypt --key private.key --cipher encrypted.txt
```

# Projekt szyfrowania RSA

Ten projekt jest implementacją kryptosystemu RSA (Rivest–Shamir–Adleman) w języku C++, stworzoną w ramach projektu z kryptografii stosowanej. Celem projektu jest zaprojektowanie i zaimplementowanie kompletnego mechanizmu bezpiecznej komunikacji, obejmującego generowanie kluczy kryptograficznych, szyfrowanie oraz deszyfrowanie wiadomości.

Implementacja opiera się na podstawowych zagadnieniach teorii liczb, takich jak generowanie liczb pierwszych, arytmetyka modularna, funkcja Eulera, odwrotności modularne oraz szybkie potęgowanie modularne. Projekt demonstruje, w jaki sposób RSA może być wykorzystane do bezpiecznego przesyłania danych przez niezaufany kanał komunikacyjny poprzez szyfrowanie wiadomości kluczem publicznym i ich odszyfrowywanie za pomocą odpowiadającego mu klucza prywatnego.

System został zaimplementowany w języku C++ i wykorzystuje bibliotekę GMP (GNU Multiple Precision Arithmetic Library) do obsługi arytmetyki dużych liczb, wymaganej przez algorytm RSA. Cała logika kryptograficzna (generowanie kluczy, szyfrowanie, deszyfrowanie oraz testy pierwszości) została zaimplementowana samodzielnie, bez korzystania z gotowych implementacji RSA dostępnych w bibliotekach zewnętrznych.

## Funkcjonalności

- generowanie par kluczy RSA (publiczny i prywatny)
- probabilistyczne generowanie liczb pierwszych z użyciem testu Millera–Rabina
- szyfrowanie i deszyfrowanie RSA z wykorzystaniem szybkiego potęgowania modularnego
- szyfrowanie i deszyfrowanie wiadomości tekstowych przy użyciu kodowania blokowego
- interfejs wiersza poleceń (CLI) umożliwiający łatwą obsługę programu
- modułowa struktura projektu oddzielająca logikę kryptograficzną od interfejsu użytkownika

## Wymagania

- Kompilator C++: `g++` (MinGW-w64 w systemie Windows)
- CMake: wersja 3.10 lub nowsza
- Narzędzie Make: `mingw32-make` (zwykle dołączone do MinGW)
- Biblioteka GMP: dołączona lokalnie w katalogu `dependencies`

## Struktura projektu

```text
RSA_Project/
├── src/
│   ├── main.cpp  
│   ├── CMakeLists.txt        # Konfiguracja budowania CMake
│   ├── rsa/
│   │   ├── rsa.cpp/.h        # Implementacja algorytmu RSA
└── dependencies/             # Lokalne zależności GMP
    ├── include/              # Pliki nagłówkowe (gmp.h, gmpxx.h)
    └── lib/                  # Biblioteki statyczne (libgmp/xx.a)
```

# Instrukcja budowania (Windows)

Projekt wykorzystuje MinGW oraz CMake. Upewnij się, że katalog bin MinGW (np. C:\msys64\ucrt64\bin) znajduje się w zmiennej środowiskowej PATH.

    Otwórz terminal w katalogu src.

###Generowanie plików budowania (CMake).
#### PowerShell lub Windows Terminal

```sh
cmake -S . -B target -G "MinGW Makefiles"
```

### Kompilacja projektu:
#### PowerShell lub Windows Terminal

```sh
cmake --build target
```

### Uruchomienie aplikacji
#### PowerShell lub Windows Terminal

./target/rsa_app.exe

## Instrukcja użytkownika

### Generowanie kluczy RSA
```sh
rsa_app.exe genkeys --bits 256 --pub public.key --priv private.key
```

### Szyfrowanie wiadomości
```sh
rsa_app.exe encrypt --key public.key --message "HELLO WORLD"
```

### Deszyfrowanie wiadomości
```sh
rsa_app.exe decrypt --key private.key --cipher encrypted.txt
```


