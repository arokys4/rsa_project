// RSA header
#ifndef RSA_H
#define RSA_H

#include <boost/multiprecision/cpp_int.hpp>
#include <string>
#include <vector>

using boost::multiprecision::cpp_int;

namespace rsa_project {

struct PublicKey {
    cpp_int n;
    cpp_int e;
};

struct PrivateKey {
    cpp_int n;
    cpp_int d;
};

class RSA {
public:
    RSA();
    // Generate key pair with given total bit length (e.g., 1024)
    void generate_keys(unsigned int bits, unsigned int mr_rounds = 25);

    PublicKey get_public_key() const;
    PrivateKey get_private_key() const;

    // Encrypt/decrypt single integer block
    cpp_int encrypt_block(const cpp_int& m, const PublicKey& pub) const;
    cpp_int decrypt_block(const cpp_int& c, const PrivateKey& priv) const;

    // Encrypt/decrypt strings (message is split into blocks < n)
    std::vector<cpp_int> encrypt_string(const std::string& message, const PublicKey& pub) const;
    std::string decrypt_string(const std::vector<cpp_int>& cipher_blocks, const PrivateKey& priv) const;

    // Utility: test primality
    bool is_probable_prime(const cpp_int& n, unsigned int rounds = 25) const;

private:
    PublicKey pub_;
    PrivateKey priv_;

    // Mathematical helpers
    static cpp_int gcd(cpp_int a, cpp_int b);
    static void extended_gcd(const cpp_int& a, const cpp_int& b, cpp_int& g, cpp_int& x, cpp_int& y);
    static cpp_int modinv(const cpp_int& a, const cpp_int& m);
    static cpp_int modexp(cpp_int base, cpp_int exp, const cpp_int& mod);

    // Random & primes
    cpp_int random_k_bit(unsigned int k) const;
    cpp_int random_between(const cpp_int& low, const cpp_int& high) const;
    cpp_int generate_prime(unsigned int bits, unsigned int mr_rounds = 25) const;

    unsigned int rng_seed_entropy() const;
    unsigned int mr_rounds_default_;
};

} // namespace rsa_project

#endif // RSA_H
