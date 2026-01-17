#include <iostream>
#include <cassert>
#include <string>
#include <vector>
#include "../tests/tests.h"

using big_int = mpz_class;

UnitTests::UnitTests() : rsa{ rsa::RSA() } {}

void UnitTests::test_math() {

    // NWD (GCD)
    {
        big_int a = 54;
        big_int b = 24;
        
        big_int result = rsa.gcd(a, b); 
        assert(result == 6);
        
        assert(rsa.gcd(17, 13) == 1); // Liczby względnie pierwsze
        assert(rsa.gcd(100, 10) == 10);
    }

    // Odwrotnośc Modularna (Modular Inverse)
    {
        big_int a = 3;
        big_int m = 11;
        // 3 * x = 1 (mod 11) -> x = 4, bo 3*4 = 12 = 1 mod 11
        big_int inv = rsa.modinv(a, m);
        assert(inv == 4);

        // Inny przykład: 7 * x = 1 (mod 26) -> x = 15, bo 7*15 = 105 = 4*26 + 1
        assert(rsa.modinv(7, 26) == 15);
    }

    // 3. Potęgowanie Modularne (Modular Exponentiation)
    {
        // 2^10 % 1000 = 1024 % 1000 = 24
        big_int base = 2;
        big_int exp = 10;
        big_int mod = 1000;
        
        big_int res = rsa.modexp(base, exp, mod);
        assert(res == 24);

        // 3^4 % 7 = 81 % 7 = 4
        assert(rsa.modexp(3, 4, 7) == 4);
        
        // overflow test
        // 12345^2 % 67890
        big_int b2 = 12345;
        assert(rsa.modexp(b2, 2, 67890) == (b2*b2 % 67890));
    }

    // 4. Test Pierwszości (Millera-Rabina)
    // Weryfikuje generowanie liczb pierwszych p i q
    {
        // Małe liczby pierwsze
        assert(rsa.is_probable_prime(2) == true);
        assert(rsa.is_probable_prime(3) == true);
        assert(rsa.is_probable_prime(17) == true);
        assert(rsa.is_probable_prime(19) == true);

        // Liczby złożone
        assert(rsa.is_probable_prime(4) == false);
        assert(rsa.is_probable_prime(15) == false); // 3*5
        assert(rsa.is_probable_prime(100) == false);
        
        // Większa liczba pierwsza (104729 to 10000-na liczba pierwsza)
        assert(rsa.is_probable_prime(104729) == true);
        
        // Większa liczba złożona (104729 * 104729)
        big_int prime = 104729;
        assert(rsa.is_probable_prime(prime * prime) == false);
    }
}

void UnitTests::test_rsa_consistency() {
    rsa.generate_keys(512);

    auto pub = rsa.get_public_key();
    auto priv = rsa.get_private_key();

    std::string original_msg = "Hello C++23 RSA!";
    std::cout << "Original: " << original_msg << '\n';

    auto encrypted_blocks = rsa.encrypt_string(original_msg, pub);

    std::string decrypted = rsa.decrypt_string(encrypted_blocks, priv);
    std::cout << "Decrypted: " << decrypted << '\n';

    assert(original_msg == decrypted);
}

int main() {
    try {
        UnitTests unit_tests;

        std::cout << "[UnitTests] [1/2] Running mathematical checks..." << '\n';
        unit_tests.test_math();
        std::cout << "[UnitTests] [1/2] PASS mathematical checks" << '\n';

        std::cout << "[UnitTests] [1/2] Running RSA consistency checks..." << '\n';
        unit_tests.test_rsa_consistency();
        std::cout << "[UnitTests] [2/2] PASS RSA consistency checks" << '\n';

        std::cout << "[UnitTests] ALL TESTS PASSED SUCCESSFULLY!" << '\n';
    } catch (const std::exception& e) {
        std::cout << "[UnitTests] FAIL exception: " << e.what() << '\n';
        return 1;
    }

    return 0;
}