#ifndef CMD_H
#define CMD_H

#include <iostream>
#include <fstream>
#include <filesystem>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include "cli.hpp"
#include "../rsa/rsa.h"

namespace fs = std::filesystem;

using rsa::RSA;
using rsa::PubKey;
using rsa::PrivKey;
using rsa::big_int;

namespace cli {

    static inline std::string fmt_big_int(const big_int& val) { return val.get_str(); }

    static inline std::string read_file_content(const std::string& path) {
        if (!fs::exists(path)) {
            throw std::runtime_error("File not found: " + path);
        }

        std::ifstream ifs(path, std::ios::binary);
        if (!ifs) {
            throw std::runtime_error("Unable to open file: " + path);
        }

        return std::string((std::istreambuf_iterator<char>(ifs)),
                           std::istreambuf_iterator<char>());
    }

    static inline void write_output(const std::string& path, const std::string& content) {
        if (path.empty()) {
            std::cout << content;
            if (!content.empty() && content.back() != '\n') std::cout << "\n";
        } else {
            std::ofstream ofs(path, std::ios::binary);
            if (!ofs) throw std::runtime_error("Błąd zapisu do pliku: " + path);

            ofs << content;
            if (!content.empty() && content.back() != '\n') ofs << "\n";

            std::cout << "saved result to " << path << "\n";
        }
    }

    // ./rsa genkeys --bits <bits> --pub <pubfile> --priv <privfile>
    inline bool cmd_generate_keys(genkeys_args_t& args) {
        if (args.bits == -1) {
            std::cout << "key bits size not provided. please provide your desired key bits size (min. 32): ";
            if (!(std::cin >> args.bits)) {
                throw std::runtime_error("Input error: expected an integer.");
            }
        }

        if (args.bits < 32) {
            throw std::runtime_error("Input error: RSA requires at least 32-bit key, got " + std::to_string(args.bits));
        }

        RSA rsa_engine;
        rsa_engine.generate_keys(static_cast<unsigned int>(args.bits));

        const auto pub  = rsa_engine.get_public_key();
        const auto priv = rsa_engine.get_private_key();

        {
            std::ofstream pub_file(args.out_pub);
            if (!pub_file) {
                throw std::runtime_error("Filesystem error: unable to create public key file.");
            }
            pub_file << fmt_big_int(pub.e) << " " << fmt_big_int(pub.n) << "\n";
        }

        {
            std::ofstream priv_file(args.out_priv);
            if (!priv_file) {
                throw std::runtime_error("Filesystem error: unable to create private key file.");
            }
            priv_file << fmt_big_int(priv.d) << " " << fmt_big_int(priv.n) << "\n";
        }

        std::cout << "pub:  " << args.out_pub  << "\n";
        std::cout << "priv: " << args.out_priv << "\n";
        return true;
    }

    // ./rsa encrypt --pub <pubfile> [--out <outfile>] [-m "<text>" | <input_file>]
    inline bool cmd_encrypt(encrypt_args_t& args) {
        std::ifstream key_file(args.pub_key_path);
        if (!key_file) {
            throw std::runtime_error("Missing public key file: " + args.pub_key_path);
        }

        PubKey pub;
        if (!(key_file >> pub.e >> pub.n)) {
            throw std::runtime_error("Wrong public key file format (expected: e n).");
        }

        std::string raw_input;
        if (!args.input.empty()) {
            raw_input = args.input;
        } else if (!args.in_file.empty()) {
            raw_input = read_file_content(args.in_file);
        } else {
            throw std::runtime_error("No data to encrypt provided: use encrypt -m \"<text>\" OR encrypt <filename>");
        }

        RSA rsa_engine;
        auto encrypted_blocks = rsa_engine.encrypt_string(raw_input, pub);

        std::ostringstream oss;
        for (const auto& blk : encrypted_blocks) {
            oss << fmt_big_int(blk) << " ";
        }

        write_output(args.out_file, oss.str());
        return true;
    }

    // ./rsa decrypt --priv <privfile> [--out <outfile>] [-m "<cipher numbers>" | <input_file>]
    inline bool cmd_decrypt(const decrypt_args_t& args) {
        std::ifstream key_file(args.priv_key_path);
        if (!key_file) {
            throw std::runtime_error("Missing private key file: " + args.priv_key_path);
        }

        PrivKey priv;
        if (!(key_file >> priv.d >> priv.n)) {
            throw std::runtime_error("Wrong private key file format (expected: d n).");
        }

        std::string raw_input;
        if (!args.input.empty()) {
            raw_input = args.input;
        } else if (!args.in_file.empty()) {
            raw_input = read_file_content(args.in_file);
        } else {
            throw std::runtime_error("No data to decrypt provided: use decrypt -m \"<text>\" OR decrypt <filename>");
        }

        std::stringstream ss(raw_input);
        std::vector<big_int> cipher_blocks;
        big_int temp;
        while (ss >> temp) {
            cipher_blocks.push_back(temp);
        }

        if (cipher_blocks.empty()) {
            throw std::runtime_error("Input did not contain valid numbers.");
        }

        RSA rsa_engine;
        std::string decrypted = rsa_engine.decrypt_string(cipher_blocks, priv);

        write_output(args.out_file, decrypted);
        return true;
    }

} // namespace cli

#endif
