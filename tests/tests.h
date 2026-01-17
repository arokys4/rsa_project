#ifndef TESTS_H
#define TESTS_H
#include "rsa/rsa.h"

class UnitTests {
    public:
        UnitTests();
        void test_math();
        void test_rsa_consistency();

    private:
        rsa::RSA rsa;
};

#endif