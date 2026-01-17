#ifndef RSA_H
#define RSA_H

#include <gmpxx.h>
#include <string>
#include <vector>

class UnitTests; // fwd declaration

namespace rsa {
    /* mpz_class to odpowiednik z libgmp boostowego cpp_int
     * nazwa jest nieintuicyjna wiec uzywamy `big_int` */
    using big_int = mpz_class;
    
    struct PubKey {
        big_int n; // Modul
        big_int e; // Wykladnik publiczny
    };

    struct PrivKey {
        big_int n; // ^
        big_int d; // Wykladnik prywatny
    };

    class RSA {
    public:
        RSA();

        void generate_keys(unsigned int bits, unsigned int mr_rounds = 25);

        PubKey  get_public_key() const { return pub_; };   
        PrivKey get_private_key() const { return priv_; };

        big_int encrypt_block(const big_int& m, const PubKey& pub) const;
        big_int decrypt_block(const big_int& c, const PrivKey& priv) const;

        std::vector<big_int> encrypt_string(const std::string& message, const PubKey& pub) const;
        std::string decrypt_string(const std::vector<big_int>& cipher_blocks, const PrivKey& priv) const;

        bool is_probable_prime(const big_int& n, unsigned int rounds = 25) const;

        friend class ::UnitTests;
    private:
        PubKey pub_;   
        PrivKey priv_;

        static big_int gcd(big_int a, big_int b);
        static void extended_gcd(const big_int& a, const big_int& b, big_int& g, big_int& x, big_int& y);
        static big_int modinv(const big_int& a, const big_int& m);
        static big_int modexp(big_int base, big_int exp, const big_int& mod);

        big_int random_bits(unsigned int k) const;
        big_int random_k_bit(unsigned int k) const;
        big_int random_between(const big_int& low, const big_int& high) const;
        big_int generate_prime(unsigned int bits, unsigned int mr_rounds = 25) const;

        unsigned int rng_seed_entropy() const;
        unsigned int mr_rounds_default_;      
    };
}

#endif

