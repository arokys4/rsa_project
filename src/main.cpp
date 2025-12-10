#include <iostream>
#include <fstream>
#include <string>
#include <gmpxx.h>
#include "rsa/rsa.h"

using rsa::RSA;
using rsa::PubKey;
using rsa::PrivKey;

void generate_keys_menu() {
    RSA rsa;

    unsigned int bits;
    std::cout << "Enter key size in bits (recommended 512 or 1024): ";
    std::cin >> bits;

    rsa.generate_keys(bits, 5);

    auto pub = rsa.get_public_key();
    auto priv = rsa.get_private_key();

    std::cout << "\nPublic Key (e, n):\n";
    std::cout << "e = " << pub.e << "\n";
    std::cout << "n = " << pub.n << "\n";

    std::cout << "\nPrivate Key (d, n):\n";
    std::cout << "d = " << priv.d << "\n";
    std::cout << "n = " << priv.n << "\n";

    std::ofstream("public.key") << pub.e << " " << pub.n;
    std::ofstream("private.key") << priv.d << " " << priv.n;

    std::cout << "\nKeys saved to:\n  public.key\n  private.key\n\n";
}

void encrypt_menu() {

    RSA rsa;

    std::cin.ignore();
    std::string message;

    std::cout << "Enter text to encrypt: ";
    std::getline(std::cin, message);

    PubKey pub;
    std::ifstream pub_file("public.key");

    if (!pub_file) {
        std::cout << "ERROR: public.key not found! Generate keys first.\n";
        return;
    }

    pub_file >> pub.e >> pub.n;

    auto encrypted = rsa.encrypt_string(message, pub);

    std::ofstream out("encrypted.txt");
    for (auto &num : encrypted)
        out << num << "\n";

    std::cout << "\nEncrypted text saved to encrypted.txt\n\n";
}

void decrypt_menu() {

    RSA rsa;

    PrivKey priv;
    std::ifstream priv_file("private.key");

    if (!priv_file) {
        std::cout << "ERROR: private.key not found!\n";
        return;
    }

    priv_file >> priv.d >> priv.n;

    std::ifstream in("encrypted.txt");
    if (!in) {
        std::cout << "ERROR: encrypted.txt not found!\n";
        return;
    }

    std::vector<big_int> encrypted;
    big_int value;

    while (in >> value)
        encrypted.push_back(value);

    std::string decrypted = rsa.decrypt_string(encrypted, priv);

    std::cout << "\nDecrypted message:\n" << decrypted << "\n\n";
}

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
    
