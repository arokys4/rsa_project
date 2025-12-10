#include <iostream>
#include <fstream>
#include <string>
#include "rsa/rsa.h"// Dołączenie pliku nagłówkowego z klasą RSA

using namespace rsa_project;

// =====================
//  FUNKCJA: GENEROWANIE KLUCZY
// =====================
void generate_keys_menu() {

    RSA rsa; // Obiekt RSA do obsługi kluczy i szyfrowania

    unsigned int bits;
    std::cout << "Enter key size in bits (recommended 512 or 1024): ";
    std::cin >> bits;

    // Generujemy klucze publiczny i prywatny
    rsa.generate_keys(bits, 5);

    auto pub = rsa.get_public_key();
    auto priv = rsa.get_private_key();

    // Wyświetlamy klucz publiczny
    std::cout << "\nPublic Key (e, n):\n";
    std::cout << "e = " << pub.e << "\n";
    std::cout << "n = " << pub.n << "\n";

    // Wyświetlamy klucz prywatny
    std::cout << "\nPrivate Key (d, n):\n";
    std::cout << "d = " << priv.d << "\n";
    std::cout << "n = " << priv.n << "\n";

    // Zapisujemy klucze do plików
    std::ofstream("public.key") << pub.e << " " << pub.n;
    std::ofstream("private.key") << priv.d << " " << priv.n;

    std::cout << "\nKeys saved to:\n  public.key\n  private.key\n\n";
}

// =====================
//  FUNKCJA: SZYFROWANIE TEKSTU
// =====================
void encrypt_menu() {

    RSA rsa; // Obiekt RSA

    std::cin.ignore(); // Czyszczenie bufora wejścia
    std::string message;

    std::cout << "Enter text to encrypt: ";
    std::getline(std::cin, message);

    // Wczytujemy klucz publiczny z pliku
    PublicKey pub;
    std::ifstream pub_file("public.key");

    if (!pub_file) {
        std::cout << "ERROR: public.key not found! Generate keys first.\n";
        return; // Bez klucza publicznego nie zaszyfrujemy
    }

    pub_file >> pub.e >> pub.n;

    // Szyfrowanie tekstu → wektor dużych liczb (cpp_int)
    auto encrypted = rsa.encrypt_string(message, pub);

    // Zapis zaszyfrowanych liczb do pliku
    std::ofstream out("encrypted.txt");
    for (auto &num : encrypted)
        out << num << "\n";

    std::cout << "\nEncrypted text saved to encrypted.txt\n\n";
}

// =====================
//  FUNKCJA: DESZYFROWANIE TEKSTU
// =====================
void decrypt_menu() {

    RSA rsa; // Obiekt RSA

    PrivateKey priv;
    std::ifstream priv_file("private.key");

    // Wczytujemy klucz prywatny z pliku
    if (!priv_file) {
        std::cout << "ERROR: private.key not found!\n";
        return;
    }

    priv_file >> priv.d >> priv.n;

    // Wczytujemy zaszyfrowane liczby
    std::ifstream in("encrypted.txt");
    if (!in) {
        std::cout << "ERROR: encrypted.txt not found!\n";
        return;
    }

    std::vector<cpp_int> encrypted;
    cpp_int value;

    // Każda linia zawiera jedną dużą liczbę → wczytujemy wszystkie
    while (in >> value)
        encrypted.push_back(value);

    // Odszyfrowujemy listę liczb → tekst
    std::string decrypted = rsa.decrypt_string(encrypted, priv);

    std::cout << "\nDecrypted message:\n" << decrypted << "\n\n";
}

// =====================
//         GŁÓWNE MENU
// =====================
int main() {
    int choice;

    while (true) {
        std::cout << "===========================\n";
        std::cout << "         RSA MENU          \n";
        std::cout << "===========================\n";
        std::cout << "1. Generate RSA keys\n";
        std::cout << "2. Encrypt text\n";
        std::cout << "3. Decrypt text\n";
        std::cout << "4. Exit\n";
        std::cout << "Choose an option: ";

        std::cin >> choice;

        switch (choice) {
            case 1:
                generate_keys_menu();
                break;
            case 2:
                encrypt_menu();
                break;
            case 3:
                decrypt_menu();
                break;
            case 4:
                std::cout << "Exiting...\n";
                return 0;
            default:
                std::cout << "Invalid option!\n";
                break;
        }
    }
}
    
