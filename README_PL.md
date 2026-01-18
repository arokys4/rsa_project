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

# Instrukcja budowania (Windows)

Projekt wykorzystuje MinGW oraz CMake. Upewnij się, że katalog bin MinGW (np. C:\msys64\ucrt64\bin) znajduje się w zmiennej środowiskowej PATH.

    Otwórz terminal w katalogu src.

### Generowanie plików budowania (CMake).
#### PS (lub Windows Terminal)

```sh
cmake -S . -B target -G "MinGW Makefiles"
```

### Kompilacja projektu:
#### PS (lub Windows Terminal)

```sh
cmake --build target
```

### Uruchomienie aplikacji
#### PS (lub Windows Terminal)

```sh
./target/rsa_app.exe
```

### 4. Uruchamianie Testów
#### PS (lub Windows Terminal)
Aby zweryfikować poprawność algorytmów matematycznych (NWD, Odwrotność Modularna, Test Pierwszości) oraz spójność RSA, uruchom testy jednostkowe:

```bash
./target/run_tests.exe
```

## Instrukcja użytkownika
### Generowanie pary kluczy RSA
```sh
rsa_app.exe genkeys --bits 128
```
Polecenie generuje dwa pliki:
-rsa_key.pub – klucz publiczny
-rsa_key – klucz prywatny

### Szyfrowanie wiadomości i zapis do pliku
```sh
rsa_app.exe encrypt --key public.key --message "HELLO WORLD"
```

### # Deszyfrowanie wiadomości z pliku
```sh
rsa_app.exe decrypt --priv rsa_key cipher.txt
```
