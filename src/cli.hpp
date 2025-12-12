#ifndef CLI_H
#define CLI_H

#include <lyra.hpp>

#include <functional>
#include <iostream>
#include <string>

/* \\\\\\\\\\\\\
*   \\ cli.hpp \\  Command Line Interface
*    \\\\\\\\\\\\\   
* 
* ten header definiuje/odpowiada za:
*   - obsluzenie argumentow do programu
*   - opcje interfejsu konsolowego `./rsa <command>`
* dependencje:
*   - lyra.hpp (https://github.com/bfgroup/Lyra)
*/

namespace cli {
    // domyslne wartosci parametrow 
    // dla kazdej z komend:
    // `./rsa <command> <args>`

    // `./rsa genkeys <args>`
    struct genkeys_args {
        int bits = 1024;
        std::string out_pub = "rsa_key.pub";
        std::string out_priv = "rsa_key";
    };

    // `./rsa encrypt <args>`
    struct encrypt_args {
        std::string pub_key_path;
        std::string out_file;
        std::string input; // sciezka do pliku lub wiadomosc podana przez stdin
    };

    // `./rsa decrypt <args>`
    struct decrypt_args {
        std::string priv_key_path;
        std::string out_file;
        std::string input;
    };

    class CLI {
    public:
        bool show_help = false;

        genkeys_args _genkeys_args;
        encrypt_args _encrypt_args;
        decrypt_args _decrypt_args;

        enum class Command
        { NONE, GENKEYS, ENCRYPT, DECRYPT }
        selected_cmd = Command::NONE;

        lyra::cli parser;

        CLI() {
            parser
                .add_argument(lyra::command("genkeys",
                    [&](lyra::group const&) {
                        selected_cmd = Command::GENKEYS;
                    })
                .help("Generate RSA key-pair")
                .add_argument(lyra::opt(_genkeys_args.bits, "bits")
                    .name("--bits").name("-b")
                    .help("Key size in bits (default: 1024)"))
                    .optional() // use default if not specified
                .add_argument(lyra::opt(_genkeys_args.out_pub, "file")
                    .name("--pub"))
                    .help("Output public key file")
                    .optional() // << stdout if filename not specified
                .add_argument(lyra::opt(_genkeys_args.out_priv, "file")
                    .name("--priv"))
                    .help("Output private key file")
                    .optional() // << stdout if filename not specified
            );

            parser
                .add_argument(lyra::command("encrypt", [&](const lyra::group&) {
                    selected_cmd = Command::ENCRYPT;
                })
                .add_argument(lyra::opt(_encrypt_args.pub_key_path, "path")
                    .required().name("--pub").help("Public key"))
                .add_argument(lyra::opt(_encrypt_args.out_file, "path")
                    .required().name("--out").help("Output file")) 
                .add_argument(lyra::opt(_encrypt_args.input, "source")
                    .required()
                    .name("--in")
                    .help("File path OR raw message text"))
            );
            
            parser
                .add_argument(lyra::command("decrypt", [&](const lyra::group&) {
                    selected_cmd = Command::DECRYPT;
                })
                .help("Decrypt a file or a cipher string")
                .add_argument(lyra::opt(_decrypt_args.priv_key_path, "file")
                    .required()
                    .name("--priv")
                    .help("Private key file"))
                .add_argument(lyra::opt(_decrypt_args.out_file, "file")
                    .required()
                    .name("--out")
                    .help("Output file for plaintext"))
            );
        }
        
    };
}
#endif 