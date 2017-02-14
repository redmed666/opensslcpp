#include "opensslcpp/opensslcpp.hpp"
#include <iostream>

namespace OpensslCpp {
    /**
      * Ctors functions
      */
    OpensslCpp::OpensslCpp() : _cert(new OpensslX509Cpp), _crl(new OpensslX509CRLCpp){
        ERR_load_crypto_strings();
        OpenSSL_add_all_algorithms();
    }

    OpensslCpp::~OpensslCpp() {
        EVP_cleanup();
        CRYPTO_cleanup_all_ex_data();
        ERR_free_strings();
    }

    /**
      * Private methods
      */

    /**
      * Create a BIO object with the BIO_new() function and put it in the
      * unordered_map<string, OpensslBIOCpp>. The string is the name of the bio
      * @input name Name of the BIO
      * @input type BIO_METHOD to create the BIO
      * @output void No return. The bio is put in the unordered_map.
      */
    void OpensslCpp::newBIO(std::string name, BIO_METHOD* type) {
        _bio[name] = std::make_shared<OpensslBIOCpp>(type);
    }

    /**
      * Create a BIO object with the BIO_new_file() function and put it in the
      * unordered_map<string, OpensslBIOCpp>. The string is the name of the bio
      * @input name Name of the BIO
      * @input filename Name of the file that you want to operate on
      * @intput mode Mode used to open the file
      * @output void No return. The bio is put in the unordered_map.
      */
    void OpensslCpp::newBIOFile(std::string name, std::string filename, char* mode) {
        _bio[name] = std::make_shared<OpensslBIOCpp>(filename, mode);
    }

    /**
      * Create a BIO object with the BIO_new_fp() function and put it in the
      * unordered_map<string, OpensslBIOCpp>. The string is the name of the bio
      * @input name Name of the BIO
      * @input stream File stream that you want to operate on
      * @input flags BIO flags
      * @output void No return. The bio is put in the unordered_map.
      */
    void OpensslCpp::newBIOFp(std::string name, FILE* stream, int flags) {
        _bio[name] = std::make_shared<OpensslBIOCpp>(stream, flags);
    }

    /**
      * Wrapper for BIO_puts
      */
    void OpensslCpp::puts(std::string bioname, std::string message) {
        _bio[bioname]->puts(message.c_str());
    }

    /**
      * Wrapper for BIO_printf
      */
    void OpensslCpp::printf(std::string bioname, std::string message) {
        _bio[bioname]->printf(message.c_str());
    }

    void OpensslCpp::loadCert(std::string certFilename) {
        _certFilestr = certFilename;
        _cert->loadCert(_certFilestr);
    }

    void OpensslCpp::loadCRL(std::string crlFilename) {
        _crlFilestr = crlFilename;
        _crl->loadCRL(crlFilename);
    }

    void OpensslCpp::printCertSerialNumber() {
        std::string bioname = _certFilestr + "serialnumber";
        newBIOFp(bioname, stdout, BIO_NOCLOSE);
        _bio[bioname]->printf("Serial number is ");
        i2a_ASN1_INTEGER(_bio[bioname]->getBIO(), _cert->getSerialNumberASN1());
        _bio[bioname]->printf("\n");
    }

    void OpensslCpp::printCertificate() {
        _cert->printCertificate();
    }

    void OpensslCpp::printCRL() {
        _crl->printCRL();
    }

    void OpensslCpp::printCRLRevokedCerts() {
        _crl->printRevokedCerts();
    }

    void OpensslCpp::printPublicKey(std::string bioname) {
        _bio[bioname]->printf("Public key is ");
        _bio[bioname]->printf("%d key \n\n", EVP_PKEY_bits(_cert->getPublicKey()));
        _bio[bioname]->writePEMPublicKey(_cert->getPublicKey());
    }

    /**
      * Verify if a certificate is in the revokation list. You need to load the certificate and the CRL before.
      * @input void Using _cert and _crl
      * @output revoked Boolean. If the certificate is in the CRL, revoked = 1, 0 otherwise
      */
    bool OpensslCpp::verifyRevokationCert() {
        if(std::find(_crl->getSerialRevokedCerts().begin(), _crl->getSerialRevokedCerts().end(), _cert->getSerialNumberHex()) == _crl->getSerialRevokedCerts().end()) {
            std::cout << "there false" << std::endl;
            return false;
        }
        else {
            std::cout << "there true" << _cert->getSerialNumberHex() << std::endl;
            return true;
        }
    }


}
