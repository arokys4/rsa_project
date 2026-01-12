#ifndef CLI_H
#define CLI_H

#include <lyra.hpp>

#include <iostream>
#include <string>

/* cli.hpp - Command Line Interface
 *
 * Ten header definiuje/odpowiada za:
 *  - obsługę argumentów do programu
 *  - opcje interfejsu konsolowego `./rsa <command>`
 * Zależności:
 *  - lyra.hpp (https://github.com/bfgroup/Lyra)
 */

namespace cli {

    // Domyślne wartości parametrów dla każdej z komend:
    // `./rsa <command> <args>`

    // `./rsa genkeys <args>`
    struct genkeys_args_t {
        int bits = -1;
        std::string out_pub  = "rsa_key.pub";
        std::string out_priv = "rsa_key";
    };

    // `./rsa encrypt <args>`
    struct encrypt_args_t {
        std::string pub_key_path;
        std::string out_file;

        std::string in_file; // ścieżka do pliku (który chcemy zaszyfrować)
        std::string input;   // lub wiadomość podana przez -m "<input>"
    };

    // `./rsa decrypt <args>`
    struct decrypt_args_t {
        std::string priv_key_path;
        std::string out_file;

        std::string in_file; // ścieżka do pliku (który chcemy odszyfrować)
        std::string input;   // lub wiadomość podana przez -m "<input>"
    };

    class CLI {
    public:
        bool show_help = false;

        genkeys_args_t _genkeys_args;
        encrypt_args_t _encrypt_args;
        decrypt_args_t _decrypt_args;

        enum class Command { NONE, GENKEYS, ENCRYPT, DECRYPT, HELP };
        Command selected_cmd = Command::NONE;

        lyra::cli parser;

        lyra::command cmd_genkeys;
        lyra::command cmd_encrypt;
        lyra::command cmd_decrypt;

        CLI()
            : cmd_genkeys("genkeys", [&](lyra::group const&) { selected_cmd = Command::GENKEYS; }),
              cmd_encrypt("encrypt", [&](lyra::group const&) { selected_cmd = Command::ENCRYPT; }),
              cmd_decrypt("decrypt", [&](lyra::group const&) { selected_cmd = Command::DECRYPT; })
        {
            cmd_genkeys
                .help("Generate RSA key-pair")
                .add_argument(lyra::opt(_genkeys_args.bits, "bits")
                    .name("--bits").name("-b")
                    .help("Key size in bits (default: 1024)"))
                    .optional()
                .add_argument(lyra::opt(_genkeys_args.out_pub, "file")
                    .name("--pub")
                    .help("Output public key file"))
                    .optional()
                .add_argument(lyra::opt(_genkeys_args.out_priv, "file")
                    .name("--priv")
                    .help("Output private key file"))
                    .optional();

            cmd_encrypt
                .help("Encrypt a file or a message")
                .add_argument(lyra::opt(_encrypt_args.pub_key_path, "path")
                    .name("-k").name("--pub")
                    .help("Public key"))
                .add_argument(lyra::opt(_encrypt_args.out_file, "path")
                    .optional()
                    .name("--out")
                    .help("Output file"))
                .add_argument(lyra::opt(_encrypt_args.input, "text")
                    .optional()
                    .name("--message").name("-m")
                    .help("Raw text to encrypt"))
                .add_argument(lyra::arg(_encrypt_args.in_file, "input_file")
                    .optional()
                    .help("File path of a file to encrypt"));

            cmd_decrypt
                .help("Decrypt a file or a message")
                .add_argument(lyra::opt(_decrypt_args.priv_key_path, "file")
                    .name("-k").name("--priv")
                    .help("Private key file"))
                .add_argument(lyra::opt(_decrypt_args.out_file, "file")
                    .optional()
                    .name("--out")
                    .help("Output file"))
                .add_argument(lyra::opt(_decrypt_args.input, "text")
                    .optional()
                    .name("--message").name("-m")
                    .help("Raw text to decrypt"))
                .add_argument(lyra::arg(_decrypt_args.in_file, "input_file")
                    .optional()
                    .help("File path of a file to decrypt"));

            parser.add_argument(lyra::help(show_help));
            parser.add_argument(cmd_genkeys);
            parser.add_argument(cmd_encrypt);
            parser.add_argument(cmd_decrypt);
        }

        bool parse(int argc, char* argv[]) {
            auto result = parser.parse({argc, argv});

            if (!result) {
                std::cerr << result.message() << "\n";
                return false;
            }

            if (show_help) {
                std::cout << parser << "\n";
                selected_cmd = Command::HELP;
            }

            return true;
        }
    };
}

#endif
