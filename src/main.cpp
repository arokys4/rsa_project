#include <iostream>
#include <fstream>
#include <string>
#include <gmpxx.h>
#include "rsa/rsa.h"
#include "cli.hpp"

using rsa::RSA;
using rsa::PubKey;
using rsa::PrivKey;

using cli::CLI;

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

int main(int argc, char* argv[]) {
    CLI cli;
    
    auto result = cli.parser.parse({argc, argv});
    if (!result) {
        std::cerr << "Error: " << result.message() << "\n";
        return 1;
    }

    if (cli.show_help || cli.selected_cmd == CLI::Command::NONE) {
        std::cout << cli.parser << "\n";
        return 0;
    }

    try {
        switch (cli.selected_cmd) {
            case CLI::Command::GENKEYS:
                std::cout << "you have chosen genkeys cmd: " << cli._genkeys_args.bits << cli._genkeys_args.out_priv << cli._genkeys_args.out_pub; 
                //handle_genkeys(cli._genkeys_args);
                break;
            case CLI::Command::ENCRYPT:
                //handle_encrypt(cli._encrypt_args);
                break;
            case CLI::Command::DECRYPT:
                //handle_decrypt(cli._decrypt_args);
                break;
            default:
                std::cout << cli.parser << "\n";
                break;
        }
    } catch (const std::exception& e) {
        std::cerr << "Runtime Error: " << e.what() << "\n";
        return 1;
    }

    return 0;
}
    
