#include "opensslcpp/opensslx509crlcpp.hpp"
#include <iostream>

namespace OpensslCpp {
    OpensslX509CRLCpp::OpensslX509CRLCpp() {
    }

    OpensslX509CRLCpp::~OpensslX509CRLCpp() {
        if(_crl){X509_CRL_free(_crl);}
    }

    X509_CRL* OpensslX509CRLCpp::getX509CRL() {
        return _crl;
    }

    void OpensslX509CRLCpp::loadCRL(std::string filename) {
        _crlMutex.lock();
        FILE *fp = fopen(filename.c_str(), "r");
        PEM_read_X509_CRL(fp, &_crl, 0, NULL);
        fclose(fp);
        _crlMutex.unlock();

        _issuer = X509_CRL_get_issuer(_crl);
        _version = X509_CRL_get_version(_crl);
        STACK_OF(X509_REVOKED)* revokedTmp = _crl->crl->revoked;
        X509_REVOKED *entry = nullptr;
        ASN1_INTEGER* asn1Serial = nullptr;
        BIGNUM* bnser = nullptr;
        for (int j = 0; j < sk_X509_REVOKED_num(revokedTmp); j++) {
            entry = sk_X509_REVOKED_value(revokedTmp, j);
            asn1Serial = entry->serialNumber;
            bnser = ASN1_INTEGER_to_BN(asn1Serial, NULL);
            _revokedCerts[std::string(BN_bn2hex(bnser))] = entry;
        }

    }

    void OpensslX509CRLCpp::printCRL() {
        X509_CRL_print_fp(stdout, _crl);
    }

    void OpensslX509CRLCpp::printRevokedCerts() {
        for(auto& element : _revokedCerts) {
            std::cout << element.first << std::endl;
        }
    }

    std::vector<std::string> OpensslX509CRLCpp::getSerialRevokedCerts() {
        std::vector<std::string> result;
        for (auto& element : _revokedCerts) {
            result.push_back(element.first);
        }
        return result;
    }
}
