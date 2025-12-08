// RSA implementation// RSA implementation
#include "rsa.h"
#include <random>
#include <chrono>
#include <stdexcept>
#include <limits>

using namespace rsa_project;

//
// Implementation
//

RSA::RSA() : mr_rounds_default_(25) {}

void RSA::generate_keys(unsigned int bits, unsigned int mr_rounds) {
    if (bits < 32) {
        throw std::runtime_error("Key size too small; use >= 32 bits for demo.");
    }
    mr_rounds = (mr_rounds == 0) ? mr_rounds_default_ : mr_rounds;

    // Generate two distinct primes p and q of roughly bits/2 each
    unsigned int half = bits / 2;
    cpp_int p = generate_prime(half, mr_rounds);
    cpp_int q;
    do {
        q = generate_prime(bits - half, mr_rounds);
    } while (q == p);

    cpp_int n = p * q;
    cpp_int phi = (p - 1) * (q - 1);

    // Public exponent e (commonly 65537)
    cpp_int e = 65537;
    if (gcd(e, phi) != 1) {
        // fallback: find small odd e co-prime with phi
        e = 3;
        while (e < phi && gcd(e, phi) != 1) e += 2;
        if (e >= phi) throw std::runtime_error("Failed to find public exponent e.");
    }

    cpp_int d = modinv(e, phi);

    pub_.n = n;
    pub_.e = e;
    priv_.n = n;
    priv_.d = d;
}

PublicKey RSA::get_public_key() const {
    return pub_;
}

PrivateKey RSA::get_private_key() const {
    return priv_;
}

// ---------- Basic arithmetic helpers ----------

cpp_int RSA::gcd(cpp_int a, cpp_int b) {
    if (a < 0) a = -a;
    if (b < 0) b = -b;
    while (b != 0) {
        cpp_int r = a % b;
        a = b;
        b = r;
    }
    return a;
}

void RSA::extended_gcd(const cpp_int& a_, const cpp_int& b_, cpp_int& g, cpp_int& x, cpp_int& y) {
    // iterative extended gcd
    cpp_int a = a_, b = b_;
    cpp_int x0 = 1, y0 = 0;
    cpp_int x1 = 0, y1 = 1;

    while (b != 0) {
        cpp_int q = a / b;
        cpp_int r = a % b;
        cpp_int nx = x0 - q * x1;
        cpp_int ny = y0 - q * y1;
        a = b; b = r;
        x0 = x1; x1 = nx;
        y0 = y1; y1 = ny;
    }
    g = a;
    x = x0;
    y = y0;
}

cpp_int RSA::modinv(const cpp_int& a, const cpp_int& m) {
    cpp_int g, x, y;
    extended_gcd(a, m, g, x, y);
    if (g != 1) {
        throw std::runtime_error("Modular inverse does not exist (gcd != 1).");
    }
    cpp_int res = x % m;
    if (res < 0) res += m;
    return res;
}

cpp_int RSA::modexp(cpp_int base, cpp_int exp, const cpp_int& mod) {
    if (mod == 1) return 0;
    cpp_int result = 1;
    base %= mod;
    while (exp > 0) {
        if ((exp & 1) != 0) result = (result * base) % mod;
        base = (base * base) % mod;
        exp >>= 1;
    }
    return result;
}

// ---------- Random generation helpers ----------

unsigned int RSA::rng_seed_entropy() const {
    // use chrono + random_device to get seed
    std::random_device rd;
    unsigned int seed = static_cast<unsigned int>(std::chrono::high_resolution_clock::now().time_since_epoch().count() ^ rd());
    return seed;
}

cpp_int RSA::random_k_bit(unsigned int k) const {
    if (k == 0) return 0;
    // Build random number by concatenating 64-bit chunks
    std::mt19937_64 gen(rng_seed_entropy());
    std::uniform_int_distribution<uint64_t> dist(0, std::numeric_limits<uint64_t>::max());

    unsigned int full_chunks = k / 64;
    unsigned int rem_bits = k % 64;

    cpp_int r = 0;
    for (unsigned int i = 0; i < full_chunks; ++i) {
        uint64_t part = dist(gen);
        r <<= 64;
        r += part;
    }
    if (rem_bits) {
        uint64_t part = dist(gen);
        // mask to rem_bits
        if (rem_bits < 64) {
            uint64_t mask = (rem_bits == 64) ? ~uint64_t(0) : ((uint64_t(1) << rem_bits) - 1);
            part &= mask;
        }
        r <<= rem_bits;
        r += part;
    }
    // ensure highest bit set to get k-bit number
    r |= (cpp_int(1) << (k - 1));
    // ensure odd
    r |= 1;
    return r;
}

// random in [low, high] inclusive (assumes low <= high)
cpp_int RSA::random_between(const cpp_int& low, const cpp_int& high) const {
    if (low > high) throw std::runtime_error("random_between: low > high");
    cpp_int range = high - low + 1;
    // determine bit length of range
    unsigned int bits = 0;
    cpp_int tmp = range - 1;
    while (tmp > 0) { tmp >>= 1; ++bits; }
    cpp_int candidate;
    do {
        candidate = random_k_bit(bits);
    } while (candidate >= range);
    return low + candidate;
}

// ---------- Miller-Rabin primality test ----------

bool RSA::is_probable_prime(const cpp_int& n, unsigned int rounds) const {
    if (n < 2) return false;
    static const int small_primes[] = {2,3,5,7,11,13,17,19,23,29,31,37,41,43,47};
    for (int p : small_primes) {
        if (n == p) return true;
        if (n % p == 0) return false;
    }

    // write n-1 as d * 2^s
    cpp_int d = n - 1;
    unsigned int s = 0;
    while ((d & 1) == 0) {
        d >>= 1;
        ++s;
    }

    std::mt19937_64 gen(rng_seed_entropy());
    std::uniform_int_distribution<uint64_t> dist64(2, std::numeric_limits<uint64_t>::max());

    for (unsigned int i = 0; i < rounds; ++i) {
        // pick random a in [2, n-2]
        cpp_int a;
        // if n fits in 64-bit, we can choose a small random 64-bit and mod it
        if (n.convert_to<long long>() > 0 && n < cpp_int(std::numeric_limits<uint64_t>::max())) {
            uint64_t aval = 2 + (dist64(gen) % (n.convert_to<uint64_t>() - 3));
            a = aval;
        } else {
            // general case: pick random between 2 and n-2
            a = random_between(2, n - 2);
        }

        cpp_int x = modexp(a, d, n);
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
    return true; // probably prime
}

cpp_int RSA::generate_prime(unsigned int bits, unsigned int mr_rounds) const {
    if (bits < 2) throw std::runtime_error("generate_prime: bits must be >= 2");
    while (true) {
        cpp_int cand = random_k_bit(bits);
        // Ensure cand odd and has highest bit set (random_k_bit does this)
        if (is_probable_prime(cand, mr_rounds)) return cand;
        // else retry
    }
}

// ---------- RSA encrypt / decrypt ----------

cpp_int RSA::encrypt_block(const cpp_int& m, const PublicKey& pub) const {
    if (m < 0 || m >= pub.n) {
        throw std::runtime_error("Plaintext block out of range (<0 or >= n).");
    }
    return modexp(m, pub.e, pub.n);
}

cpp_int RSA::decrypt_block(const cpp_int& c, const PrivateKey& priv) const {
    if (c < 0 || c >= priv.n) {
        throw std::runtime_error("Ciphertext block out of range (<0 or >= n).");
    }
    return modexp(c, priv.d, priv.n);
}

// Convert bytes (string) to big integer blocks < n, and back
std::vector<cpp_int> RSA::encrypt_string(const std::string& message, const PublicKey& pub) const {
    std::vector<cpp_int> blocks;
    if (pub.n == 0) throw std::runtime_error("Public key not set (n==0).");

    // determine max bytes per block: find highest number of bytes such that (256^bytes) <= n
    unsigned int max_bytes = 1;
    cpp_int limit = 256; // 256^1
    while (limit <= pub.n) {
        ++max_bytes;
        limit *= 256;
    }
    if (max_bytes == 0) max_bytes = 1;
    // after loop limit > n, so reduce by 1
    max_bytes = std::max<unsigned int>(1, max_bytes - 1);

    // pack bytes into blocks
    size_t i = 0;
    while (i < message.size()) {
        unsigned int take = std::min<size_t>(max_bytes, message.size() - i);
        cpp_int m = 0;
        for (unsigned int j = 0; j < take; ++j) {
            unsigned char byte = static_cast<unsigned char>(message[i + j]);
            m <<= 8;
            m += byte;
        }
        // If m >= n (shouldn't happen due to max_bytes calculation), fallback to smaller block
        if (m >= pub.n) {
            // decrease block size until m < n
            bool adjusted = false;
            for (int dec = take - 1; dec >= 1; --dec) {
                cpp_int mm = 0;
                for (int j = 0; j < dec; ++j) {
                    unsigned char byte = static_cast<unsigned char>(message[i + j]);
                    mm <<= 8;
                    mm += byte;
                }
                if (mm < pub.n) {
                    take = dec;
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

std::string RSA::decrypt_string(const std::vector<cpp_int>& cipher_blocks, const PrivateKey& priv) const {
    std::string out;
    for (const cpp_int& c : cipher_blocks) {
        cpp_int m = decrypt_block(c, priv);
        // convert m back to bytes: find how many bytes by shifting
        std::vector<unsigned char> bytes;
        cpp_int temp = m;
        while (temp > 0) {
            unsigned int byte = static_cast<unsigned int>( (temp & cpp_int(0xFF)).convert_to<unsigned int>() );
            bytes.push_back(static_cast<unsigned char>(byte));
            temp >>= 8;
        }
        if (bytes.empty()) {
            // plaintext block was zero
            out.push_back('\0');
        } else {
            // bytes are little-endian from above, reverse
            for (auto it = bytes.rbegin(); it != bytes.rend(); ++it) out.push_back(static_cast<char>(*it));
        }
    }
    return out;
}

