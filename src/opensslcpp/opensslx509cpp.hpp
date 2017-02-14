#pragma once
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>
#include <openssl/pem.h>
#include <mutex>

#include "opensslcpp/opensslcppexception.hpp"

namespace OpensslCpp {
    class OpensslX509Cpp {
    public:
        OpensslX509Cpp();
        ~OpensslX509Cpp();
        void loadCert(std::string filename);
        X509* getX509();
        ASN1_INTEGER* getSerialNumberASN1();
        std::string getSerialNumberHex();
        EVP_PKEY* getPublicKey();
        void printCertificate();

    private:

        std::mutex _mutex;
        X509* _cert = nullptr;
        X509_EXTENSION* _subjectKeyIdentifier = nullptr;
        X509_EXTENSION* _authorityKeyIdentifier = nullptr;
        ASN1_INTEGER* _asn1Serial = nullptr;
        std::string _serialHex;
        EVP_PKEY* _publicKey = nullptr;
    };
}
