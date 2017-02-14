#pragma once
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>
#include <openssl/pem.h>
#include <mutex>
#include <vector>
#include <unordered_map>
#include <boost/lexical_cast.hpp>
#include "opensslcpp/opensslcppexception.hpp"

namespace OpensslCpp {
    class OpensslX509CRLCpp {
    public:
        OpensslX509CRLCpp();
        ~OpensslX509CRLCpp();
        void loadCRL(std::string filename);
        X509_CRL* getX509CRL();
        std::vector<std::string> getSerialRevokedCerts();
        void printCRL();
        void printRevokedCerts();

    private:
        X509_CRL* _crl = nullptr;
        X509_NAME* _issuer = nullptr;
        long _version;
        std::mutex _crlMutex;
        std::unordered_map<std::string, X509_REVOKED*> _revokedCerts;
    };
}
