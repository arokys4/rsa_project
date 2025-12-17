#include <iostream>
#include <fstream>
#include <string>
#include <gmpxx.h>
#include <print>
#include "rsa/rsa.h"
#include "cli/cli.hpp"
#include "cli/commands.hpp"

using rsa::RSA;
using rsa::PubKey;
using rsa::PrivKey;
using rsa::big_int;

using cli::CLI;

int main(int argc, char* argv[]) {
    CLI cli;
    
    if (!cli.parse(argc, argv)) {
        return 1; // parsing error
    }

    if (cli.selected_cmd == cli::CLI::Command::HELP) return 0;

    try {
        switch (cli.selected_cmd) {
            case CLI::Command::GENKEYS:
                cli::cmd_generate_keys(cli._genkeys_args);
                break;
            case CLI::Command::ENCRYPT:
                cli::cmd_encrypt(cli._encrypt_args);
                break;
            case CLI::Command::DECRYPT:
                cli::cmd_decrypt(cli._decrypt_args);
                break;
            default:
                std::cout << cli.parser << "\n";
                break;
        }
    } catch (const std::exception& e) {
        std::optional<lyra::command> selected_lyra_cmd;

        switch (cli.selected_cmd) {
            case CLI::Command::GENKEYS:
                std::cout << cli.cmd_genkeys << '\n';
                break;
            case CLI::Command::ENCRYPT:
                std::cout << cli.cmd_encrypt << '\n';
                break;
            case CLI::Command::DECRYPT:
                std::cout << cli.cmd_decrypt << '\n';
                break;
            default:
                std::cout << cli.parser << '\n';
                break;
        }

        return 1;
    }

    return 0;
}
    
