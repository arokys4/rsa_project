#include <iostream>
#include <fstream>
#include <string>
#include <vector>

#include "rsa/rsa.h"

using namespace rsa_project;

// ---------- Helper functions for saving / loading keys ----------

void save_public_key(const PublicKey& pub, const std::string& filename) {
    std::ofstream out(filename);
    if (!out) throw std::runtime_error("Failed to open file for public key.");
    out << pub.n << "\n" << pub.e << "\n";
}

void save_private_key(const PrivateKey& priv, const std::string& filename) {
    std::ofstream out(filename);
    if (!out) throw std::runtime_error("Failed to open file for private key.");
    out << priv.n << "\n" << priv.d << "\n";
}

PublicKey load_public_key(const std::string& filename) {
    PublicKey pub;
    std::ifstream in(filename);
    if (!in) throw std::runtime_error("Failed to load public key.");
    in >> pub.n >> pub.e;
    return pub;
}

PrivateKey load_private_key(const std::string& filename) {
    PrivateKey priv;
    std::ifstream in(filename);
    if (!in) throw std::runtime_error("Failed to load private key.");
    in >> priv.n >> priv.d;
    return priv;
}

// ---------- Helper to save/load ciphertext blocks ----------

void save_cipher(const std::vector<cpp_int>& blocks, const std::string& filename) {
    std::ofstream out(filename);
    if (!out) throw std::runtime_error("Failed to write cipher file.");

    out << blocks.size() << "\n";
    for (const auto& b : blocks) {
        out << b << "\n";
    }
}

std::vector<cpp_int> load_cipher(const std::string& filename) {
    std::ifstream in(filename);
    if (!in) throw std::runtime_error("Failed to read cipher file.");

    size_t count;
    in >> count;

    std::vector<cpp_int> blocks(count);
    for (size_t i = 0; i < count; ++i) in >> blocks[i];

    return blocks;
}

// ---------- MAIN APPLICATION ----------

void generate_keys_menu() {
    unsigned int bits;
    std::cout << "Podaj rozmiar klucza (np. 512, 1024, 2048): ";
    std::cin >> bits;

    RSA rsa;
    std::cout << "Generowanie kluczy RSA..." << std::endl;
    rsa.generate_keys(bits);

    auto pub = rsa.get_public_key();
    auto priv = rsa.get_private_key();

    save_public_key(pub, "public.key");
    save_private_key(priv, "private.key");

    std::cout << "Klucze zapisane jako:\n"
              << " - public.key\n"
              << " - private.key\n";
}

void encrypt_menu() {
    std::cin.ignore();
    std::string msg;
    std::cout << "Wprowadz wiadomosc do zaszyfrowania:\n> ";
    std::getline(std::cin, msg);

    std::cout << "Wczytywanie klucza publicznego z public.key...\n";
    PublicKey pub = load_public_key("public.key");

    RSA rsa;
    auto encrypted = rsa.encrypt_string(msg, pub);

    save_cipher(encrypted, "cipher.txt");

    std::cout << "Zaszyfrowano i zapisano do pliku cipher.txt\n";
}

void decrypt_menu() {
    std::cout << "Wczytywanie klucza prywatnego z private.key...\n";
    PrivateKey priv = load_private_key("private.key");

    RSA rsa;
    auto blocks = load_cipher("cipher.txt");

    std::string decrypted = rsa.decrypt_string(blocks, priv);

    std::cout << "Odszyfrowana wiadomosc:\n" << decrypted << "\n";
}

int main() {
    while (true) {
        std::cout << "\n===== RSA Encryption Demo =====\n";
        std::cout << "1. Wygeneruj nowe klucze\n";
        std::cout << "2. Zaszyfruj wiadomosc\n";
        std::cout << "3. Odszyfruj wiadomosc\n";
        std::cout << "4. Wyjscie\n";
        std::cout << "Wybierz opcje: ";

        int choice;
        std::cin >> choice;

        try {
            if (choice == 1) generate_keys_menu();
            else if (choice == 2) encrypt_menu();
            else if (choice == 3) decrypt_menu();
            else if (choice == 4) break;
            else std::cout << "Nie ma takiej opcji.\n";
        }
        catch (std::exception& e) {
            std::cout << "Blad: " << e.what() << "\n";
        }
    }

    return 0;
}
