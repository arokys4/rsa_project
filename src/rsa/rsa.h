// Nagłówek RSA
#ifndef RSA_H
#define RSA_H

#include <boost/multiprecision/cpp_int.hpp>
#include <string>
#include <vector>

using boost::multiprecision::cpp_int;

namespace rsa_project {

// Struktura klucza publicznego
struct PublicKey {
    cpp_int n; // Moduł
    cpp_int e; // Wykładnik publiczny
};

// Struktura klucza prywatnego
struct PrivateKey {
    cpp_int n; // Moduł
    cpp_int d; // Wykładnik prywatny
};

// Klasa RSA
class RSA {
public:
    RSA();
    // Generowanie pary kluczy o podanej długości bitowej (np. 1024)
    void generate_keys(unsigned int bits, unsigned int mr_rounds = 25);

    PublicKey get_public_key() const;   // Pobranie klucza publicznego
    PrivateKey get_private_key() const; // Pobranie klucza prywatnego

    // Szyfrowanie/deszyfrowanie pojedynczego bloku liczbowego
    cpp_int encrypt_block(const cpp_int& m, const PublicKey& pub) const;
    cpp_int decrypt_block(const cpp_int& c, const PrivateKey& priv) const;

    // Szyfrowanie/deszyfrowanie ciągów znaków
    // (wiadomość dzielona na bloki < n)
    std::vector<cpp_int> encrypt_string(const std::string& message, const PublicKey& pub) const;
    std::string decrypt_string(const std::vector<cpp_int>& cipher_blocks, const PrivateKey& priv) const;

    // Narzędzie: test pierwszości
    bool is_probable_prime(const cpp_int& n, unsigned int rounds = 25) const;

private:
    PublicKey pub_;   // Klucz publiczny
    PrivateKey priv_; // Klucz prywatny

    // Funkcje matematyczne
    static cpp_int gcd(cpp_int a, cpp_int b); // NWD
    static void extended_gcd(const cpp_int& a, const cpp_int& b, cpp_int& g, cpp_int& x, cpp_int& y); // Rozszerzony algorytm Euklidesa
    static cpp_int modinv(const cpp_int& a, const cpp_int& m); // Odwrotność modularna
    static cpp_int modexp(cpp_int base, cpp_int exp, const cpp_int& mod); // Potęgowanie modularne

    // Liczby losowe i liczby pierwsze
    cpp_int random_k_bit(unsigned int k) const; // Losowa liczba k-bitowa
    cpp_int random_between(const cpp_int& low, const cpp_int& high) const; // Losowa liczba w zakresie [low, high]
    cpp_int generate_prime(unsigned int bits, unsigned int mr_rounds = 25) const; // Generowanie liczby pierwszej

    unsigned int rng_seed_entropy() const; // Ziarno generatora losowego
    unsigned int mr_rounds_default_;       // Domyślna liczba rund Miller-Rabina
};

} // namespace rsa_project

#endif // RSA_H
