#ifndef CMD_H
#define CMD_H

#include <print>  // C++23
#include <format> // C++20
#include <iostream>
#include <fstream>
#include <filesystem>

#include "cli.hpp"
#include "../rsa/rsa.h"

namespace fs = std::filesystem;

using rsa::RSA;
using rsa::PubKey;
using rsa::PrivKey;
using rsa::big_int;

namespace cli {
    // 
    auto fmt_big_int(big_int const& val) { return val.get_str(); }

    auto read_file_content(const std::string& path) {
        if (not fs::exists(path))
        { throw std::runtime_error(std::format("File not found: {}", path)); }

        std::ifstream ifs_stream(path, std::ios::binary);
        if (not ifs_stream)
        { throw std::runtime_error(std::format("Unable to open file: {}", path)); }

        return std::string((std::istreambuf_iterator<char>(ifs_stream)),
                            std::istreambuf_iterator<char>());
    }

    void write_output(const std::string& path, const std::string& content) {
        if (path.empty()) {
            std::println("{}", content);
        } else {
            std::ofstream ofs(path);
            if (!ofs) throw std::runtime_error(std::format("Błąd zapisu do pliku: {}", path));
            
            std::print(ofs, "{}", content);
            if (!content.ends_with('\n')) std::println(ofs, ""); 
            
            std::println("saved result to {}", path);
        }
    }

    // load file/
    bool cmd_generate_keys(genkeys_args_t& args)
    {
        using std::print;
        using std::println;

        if (args.bits == -1)
        {
            print("key bits size not provided. please provide your desired key bits size (min. 32): ");
            if (not (std::cin >> args.bits)) {
                throw std::runtime_error("Input error: expected an integer.");
            }
        }

        if (args.bits < 32) {
            throw std::runtime_error(std::format("Input error: RSA requires atleast 32-bit key, got {}", args.bits));
        }

        RSA rsa_engine;

        rsa_engine.generate_keys(args.bits);

        auto pub = rsa_engine.get_public_key();
        auto priv = rsa_engine.get_private_key();

        using std::ofstream;
        {
            ofstream pub_file(args.out_pub);
            if (not pub_file) { throw std::runtime_error("Filesystem error: unable to create private key file."); }

            // cpp23 - save content to files using println << ofstream
            println(pub_file, "{} {}", fmt_big_int(pub.e), fmt_big_int(pub.n));
        }

        {
            ofstream priv_file(args.out_priv);
            if (not priv_file) { throw std::runtime_error("Filesystem error: unable to create private key file."); }

            println(priv_file, "{} {}", fmt_big_int(priv.d), fmt_big_int(priv.n));
        }

        println("pub:  {}", args.out_pub);
        println("priv: {}", args.out_priv);
        return 1;
    }

    bool cmd_encrypt(encrypt_args_t& args)
    {
        using std::ifstream;

        ifstream key_file(args.pub_key_path);
        
        if (not key_file) 
        { throw std::runtime_error(std::format("Missing public key file : {}", args.pub_key_path)); }

        PubKey pub;
        if (not (key_file >> pub.e >> pub.n))
        { throw std::runtime_error("Wrong public key file format"); }

        std::string raw_input;

        if (not args.input.empty()) {
            raw_input = args.input;
        }
        else if (not args.in_file.empty()) {
            raw_input = read_file_content(args.in_file);
        }
        else
        { throw std::runtime_error("No data to encrypt provided: use encrypt -m \"<text>\" OR encrypt <filename>"); }

        RSA rsa_engine;
        auto encrypted_blocks = rsa_engine.encrypt_string(raw_input, pub);

        std::string result_buffer;
        result_buffer.reserve(encrypted_blocks.size() * 10);

        for (const auto& blk : encrypted_blocks) {
            result_buffer += std::format("{} ", fmt_big_int(blk));
        }

        write_output(args.out_file, result_buffer);
        return 1;
    }

    bool cmd_decrypt(decrypt_args_t const& args)
    {
        using std::ifstream;

        ifstream key_file(args.priv_key_path);
        
        if (not key_file) 
        { throw std::runtime_error(std::format("Missing private key file : {}", args.priv_key_path)); }

        PrivKey priv;
        if (not (key_file >> priv.d >> priv.n))
        { throw std::runtime_error("Wrong private key file format"); }

        std::string raw_input;
        if (not args.input.empty()) {
            raw_input = args.input;
        }
        else if (not args.in_file.empty()) {
            raw_input = read_file_content(args.in_file);
        }
        else
        { throw std::runtime_error("No data to decrypt provided: use ./rsa++ decrypt -m \"<text>\" OR ./rsa++ decrypt <filename>"); }
        
        // parse, cant use ifstream because message could be also passed by -m "<>"
        std::stringstream ss(raw_input);
        std::vector<big_int> cipher_blocks;
        {
            big_int temp;
            while (ss >> temp) {
                cipher_blocks.push_back(temp);
            }
        }
        
        if (cipher_blocks.empty())
        { throw std::runtime_error("Input did not contain valid numbers."); }
        
        RSA rsa_engine;
        std::string decrypted = rsa_engine.decrypt_string(cipher_blocks, priv);

        write_output(args.out_file, decrypted);
        return 1;
    }

}

#endif