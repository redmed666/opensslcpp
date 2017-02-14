#pragma once
#include <openssl/bio.h>
#include <string>
#include "opensslcpp/opensslcppexception.hpp"
#include <openssl/pem.h>

namespace OpensslCpp {
    class OpensslBIOCpp {
    public:
        OpensslBIOCpp(BIO_METHOD* type);
        OpensslBIOCpp(FILE* stream, int flags);
        OpensslBIOCpp(std::string filename, const char* mode);
        ~OpensslBIOCpp();
        BIO* getBIO();
        void readFilename(std::string filename);
        void writePEMPublicKey(EVP_PKEY* publicKey);

        template<typename Inputtype>
        void puts(Inputtype input) {BIO_puts(_bio, input);}

        template<typename ...Vargs>
        void printf(Vargs... input) {BIO_printf(_bio, input...);}

        void connectTo(std::string servername, std::string port);

    private:
        BIO* _bio = nullptr;
    };
}
