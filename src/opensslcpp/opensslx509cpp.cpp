#include "opensslcpp/opensslx509cpp.hpp"
#include <iostream>

namespace OpensslCpp {
    OpensslX509Cpp::OpensslX509Cpp() {
    }

    OpensslX509Cpp::~OpensslX509Cpp() {
        //if(_vrfy_ctx) {X509_STORE_CTX_free(_vrfy_ctx);}
        //if(_store){X509_STORE_free(_store);}
        if(_cert){X509_free(_cert);}
        if(_publicKey){EVP_PKEY_free(_publicKey);}

    }

    X509* OpensslX509Cpp::getX509() {
        return _cert;
    }

    void OpensslX509Cpp::loadCert(std::string filename) {
        _mutex.lock();
        FILE *fp = fopen(filename.c_str(), "r");
        _cert = PEM_read_X509(fp, NULL, NULL, NULL);
        fclose(fp);
        _mutex.unlock();

        _asn1Serial = X509_get_serialNumber(_cert);
        BIGNUM* bnser = nullptr;
        bnser = ASN1_INTEGER_to_BN(_asn1Serial, NULL);
        _serialHex =  std::string(BN_bn2hex(bnser));
        int loc = X509_get_ext_by_NID(_cert, NID_subject_key_identifier, -1);
        int locbis = X509_get_ext_by_NID(_cert, NID_authority_key_identifier, -1);
        _authorityKeyIdentifier = X509_get_ext(_cert, locbis);
        _subjectKeyIdentifier = X509_get_ext(_cert, loc);
        ASN1_OCTET_STRING* tmpbis = X509_EXTENSION_get_data(_authorityKeyIdentifier);
        ASN1_OCTET_STRING* tmp = X509_EXTENSION_get_data(_subjectKeyIdentifier);

        BIO* output = BIO_new_fp(stdout, BIO_NOCLOSE);
        i2a_ASN1_STRING(output, tmp, tmp->type);
        BIO_printf(output, "\n");
        i2a_ASN1_STRING(output, tmpbis, tmpbis->type);
        BIO_printf(output, "\n");
        BIO_free_all(output);
    }

    ASN1_INTEGER* OpensslX509Cpp::getSerialNumberASN1() {
        return _asn1Serial;
    }

    std::string OpensslX509Cpp::getSerialNumberHex() {
        return _serialHex;
    }

    void OpensslX509Cpp::printCertificate() {
        X509_print_ex_fp(stdout, _cert, NULL, NULL);
    }

    EVP_PKEY* OpensslX509Cpp::getPublicKey() {
        _publicKey = X509_get_pubkey(_cert);
        return _publicKey;
    }


}
