#pragma once
#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <openssl/objects.h>
#include <openssl/evp.h>
#include <openssl/pkcs12.h>
#include <openssl/err.h>
#include <string>
#include <unordered_map>
#include <algorithm>

#include "opensslcpp/opensslcppexception.hpp"
#include "opensslcpp/opensslbiocpp.hpp"
#include "opensslcpp/opensslx509cpp.hpp"
#include "opensslcpp/opensslx509crlcpp.hpp"

namespace OpensslCpp {
    class OpensslCpp {
    public:
        OpensslCpp();
        ~OpensslCpp();
        void loadCert(std::string certFilename);
        void loadCRL(std::string crlFilename);
        void printCertSerialNumber();
        void printCertificate();
        void printCRL();
        void printCRLRevokedCerts();
        void printPublicKey(std::string bioname);
        bool verifyRevokationCert();

    private:
        void newBIO(std::string name, BIO_METHOD* type);
        void newBIOFp(std::string name, FILE* stream, int flags);
        void newBIOFile(std::string name, std::string filename, char* mode);
        void printf(std::string bioname, std::string message);
        void puts(std::string bioname, std::string message);
        std::string _caBundle;
        std::string _certFilestr;
        std::string _crlFilestr;
        std::unordered_map<std::string, std::shared_ptr<OpensslBIOCpp>> _bio;
        std::shared_ptr<OpensslX509Cpp> _cert;
        std::shared_ptr<OpensslX509CRLCpp> _crl;
    };
}
