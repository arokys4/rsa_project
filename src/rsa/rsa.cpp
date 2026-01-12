#include "rsa.h"
#include <random>
#include <chrono>
#include <stdexcept>
#include <limits>

namespace rsa {
    inline big_int to_big_int(uint64_t val) { return big_int(std::to_string(val)); }

    RSA::RSA() : mr_rounds_default_(25) {}

    // Jeden generator na wątek, seedowany raz
    static std::mt19937_64& global_rng(unsigned int seed) {
        thread_local std::mt19937_64 gen(seed);
        return gen;
    }

    void RSA::generate_keys(unsigned int bits, unsigned int mr_rounds) {
        if (bits < 32) {
            throw std::runtime_error("Key size too small; use >= 32 bits for demo.");
        }
        mr_rounds = (mr_rounds == 0) ? mr_rounds_default_ : mr_rounds;

        // Generowanie dwóch różnych liczb pierwszych p i q o długości ~bits/2
        unsigned int half = bits / 2;
        big_int p = generate_prime(half, mr_rounds);
        big_int q;
        do {
            q = generate_prime(bits - half, mr_rounds);
        } while (q == p);

        big_int n = p * q;
        big_int phi = (p - 1) * (q - 1);

        // Publiczny wykładnik e (standardowo 65537)
        big_int e = 65537;
        if (gcd(e, phi) != 1) {
            e = 3;
            while (e < phi && gcd(e, phi) != 1) e += 2;
            if (e >= phi) throw std::runtime_error("Failed to find public exponent e.");
        }

        big_int d = modinv(e, phi);

        pub_.n = n;
        pub_.e = e;
        priv_.n = n;
        priv_.d = d;
    }

    big_int RSA::gcd(big_int a, big_int b) {
        if (a < 0) a = -a;
        if (b < 0) b = -b;

        while (b != 0) {
            big_int r = a % b;
            a = b;
            b = r;
        }
        return a;
    }

    void RSA::extended_gcd(const big_int& a_, const big_int& b_, big_int& g, big_int& x, big_int& y) {
        big_int a = a_, b = b_;
        big_int x0 = 1, y0 = 0;
        big_int x1 = 0, y1 = 1;

        while (b != 0) {
            big_int q = a / b;
            big_int r = a % b;
            big_int nx = x0 - q * x1;
            big_int ny = y0 - q * y1;
            a = b; b = r;
            x0 = x1; x1 = nx;
            y0 = y1; y1 = ny;
        }
        g = a;
        x = x0;
        y = y0;
    }

    big_int RSA::modinv(const big_int& a, const big_int& m) {
        big_int g, x, y;
        extended_gcd(a, m, g, x, y);
        if (g != 1) {
            throw std::runtime_error("Modular inverse does not exist (gcd != 1).");
        }
        big_int res = x % m;
        if (res < 0) res += m;
        return res;
    }

    big_int RSA::modexp(big_int base, big_int exp, const big_int& mod) {
        if (mod == 1) return 0;
        big_int result = 1;
        base %= mod;
        while (exp > 0) {
            if ((exp & 1) != 0) result = (result * base) % mod;
            base = (base * base) % mod;
            exp >>= 1;
        }
        return result;
    }

    unsigned int RSA::rng_seed_entropy() const {
        std::random_device rd;
        unsigned int seed =
            static_cast<unsigned int>(
                std::chrono::high_resolution_clock::now().time_since_epoch().count()
            ) ^ static_cast<unsigned int>(rd());
        return seed;
    }

    // Losowa liczba o MAKSYMALNIE k bitach (bez wymuszania najwyższego bitu i bez wymuszania nieparzystości)
    big_int RSA::random_bits(unsigned int k) const {
        if (k == 0) return 0;

        auto& gen = global_rng(rng_seed_entropy());
        std::uniform_int_distribution<uint64_t> dist(0, std::numeric_limits<uint64_t>::max());

        unsigned int full_chunks = k / 64;
        unsigned int rem_bits = k % 64;

        big_int r = 0;
        for (unsigned int i = 0; i < full_chunks; ++i) {
            uint64_t part = dist(gen);
            r <<= 64;
            r += to_big_int(part);
        }

        if (rem_bits) {
            uint64_t part = dist(gen);
            if (rem_bits < 64) {
                uint64_t mask = (uint64_t(1) << rem_bits) - 1;
                part &= mask;
            }
            r <<= rem_bits;
            r += to_big_int(part);
        }

        return r;
    }

    // Losowa liczba dokładnie k-bitowa, nieparzysta (dobry kandydat na liczbę pierwszą)
    big_int RSA::random_k_bit(unsigned int k) const {
        if (k == 0) return 0;

        big_int r = random_bits(k);
        r |= (big_int(1) << (k - 1)); // wymuś najwyższy bit -> dokładnie k bitów
        r |= 1;                       // wymuś nieparzystość
        return r;
    }

    // Losowa liczba w zakresie [low, high] włącznie (zakłada low <= high)
    big_int RSA::random_between(const big_int& low, const big_int& high) const {
        if (low > high) throw std::runtime_error("random_between: low > high");
        if (low == high) return low;

        big_int range = high - low + 1;

        // policz liczbę bitów potrzebną do reprezentacji (range - 1)
        unsigned int bits = 0;
        big_int tmp = range - 1;
        while (tmp > 0) { tmp >>= 1; ++bits; }

        // jeżeli range==1, bits==0
        if (bits == 0) return low;

        big_int candidate;
        do {
            candidate = random_bits(bits);  // <- kluczowa poprawka
        } while (candidate >= range);

        return low + candidate;
    }

    // Miller-Rabin
    bool RSA::is_probable_prime(const big_int& n, unsigned int rounds) const {
        if (n < 2) return false;

        static const int small_primes[] = {2,3,5,7,11,13,17,19,23,29,31,37,41,43,47};
        for (int p : small_primes) {
            if (n == p) return true;
            if (n % p == 0) return false;
        }

        // Zapis n-1 jako d * 2^s
        big_int d = n - 1;
        unsigned int s = 0;
        while ((d & 1) == 0) {
            d >>= 1;
            ++s;
        }

        auto& gen = global_rng(rng_seed_entropy());

        for (unsigned int i = 0; i < rounds; ++i) {
            big_int a;

            if (n.fits_ulong_p()) {
                unsigned long n_val = n.get_ui();
                if (n_val <= 4) return (n_val == 2 || n_val == 3);

                std::uniform_int_distribution<unsigned long> dist_a(2, n_val - 2);
                a = to_big_int(dist_a(gen));
            } else {
                a = random_between(2, n - 2);
            }

            big_int x = modexp(a, d, n);
            if (x == 1 || x == n - 1) continue;

            bool composite = true;
            for (unsigned int r = 1; r < s; ++r) {
                x = (x * x) % n;
                if (x == n - 1) {
                    composite = false;
                    break;
                }
            }
            if (composite) return false;
        }
        return true;
    }

    big_int RSA::generate_prime(unsigned int bits, unsigned int mr_rounds) const {
        if (bits < 2) throw std::runtime_error("generate_prime: bits must be >= 2");
        while (true) {
            big_int cand = random_k_bit(bits);
            if (is_probable_prime(cand, mr_rounds)) return cand;
        }
    }

    big_int RSA::encrypt_block(const big_int& m, const PubKey& pub) const {
        if (m < 0 || m >= pub.n) {
            throw std::runtime_error("Plaintext block out of range (<0 or >= n).");
        }
        return modexp(m, pub.e, pub.n);
    }

    big_int RSA::decrypt_block(const big_int& c, const PrivKey& priv) const {
        if (c < 0 || c >= priv.n) {
            throw std::runtime_error("Ciphertext block out of range (<0 or >= n).");
        }
        return modexp(c, priv.d, priv.n);
    }

    std::vector<big_int> RSA::encrypt_string(const std::string& message, const PubKey& pub) const {
        std::vector<big_int> blocks;
        if (pub.n == 0) throw std::runtime_error("Public key not set (n==0).");

        unsigned int max_bytes = 1;
        big_int limit = 256; // 256^1
        while (limit <= pub.n) {
            ++max_bytes;
            limit *= 256;
        }
        max_bytes = std::max<unsigned int>(1, max_bytes - 1);

        size_t i = 0;
        while (i < message.size()) {
            unsigned int take = std::min<size_t>(max_bytes, message.size() - i);
            big_int m = 0;

            for (unsigned int j = 0; j < take; ++j) {
                unsigned char byte = static_cast<unsigned char>(message[i + j]);
                m <<= 8;
                m += byte;
            }

            if (m >= pub.n) {
                // zmniejszenie rozmiaru bloku aż m < n
                bool adjusted = false;
                for (int dec = static_cast<int>(take) - 1; dec >= 1; --dec) {
                    big_int mm = 0;
                    for (int j = 0; j < dec; ++j) {
                        unsigned char byte = static_cast<unsigned char>(message[i + j]);
                        mm <<= 8;
                        mm += byte;
                    }
                    if (mm < pub.n) {
                        take = static_cast<unsigned int>(dec);
                        m = mm;
                        adjusted = true;
                        break;
                    }
                }
                if (!adjusted) throw std::runtime_error("Failed to fit block under modulus n.");
            }

            blocks.push_back(encrypt_block(m, pub));
            i += take;
        }

        return blocks;
    }

    std::string RSA::decrypt_string(const std::vector<big_int>& cipher_blocks, const PrivKey& priv) const {
        std::string out;

        for (const big_int& c : cipher_blocks) {
            big_int m = decrypt_block(c, priv);

            // rozpakuj big_int na bajty (base-256)
            std::vector<unsigned char> bytes;
            big_int temp = m;

            while (temp > 0) {
                uint32_t byte = (temp.get_ui() & 0xFF);
                bytes.push_back(static_cast<unsigned char>(byte));
                temp >>= 8;
            }

            // Wersja demonstracyjna: jeśli m==0, nie dopisujemy sztucznego '\0'
            if (!bytes.empty()) {
                for (auto it = bytes.rbegin(); it != bytes.rend(); ++it)
                    out.push_back(static_cast<char>(*it));
            }
        }

        return out;
    }
} // namespace rsa

}
