#include "opensslcpp/opensslbiocpp.hpp"
#include <iostream>

namespace OpensslCpp {
    OpensslBIOCpp::OpensslBIOCpp(BIO_METHOD* type) {
        _bio = BIO_new(type);
    }

    OpensslBIOCpp::OpensslBIOCpp(FILE* stream, int flags) {
        _bio = BIO_new_fp(stream, flags);
    }

    OpensslBIOCpp::OpensslBIOCpp(std::string filename, const char* mode) {
        _bio = BIO_new_file(filename.c_str(), mode);
    }


    OpensslBIOCpp::~OpensslBIOCpp() {
        if(_bio) {BIO_free_all(_bio);}
    }

    BIO* OpensslBIOCpp::getBIO() {
        return _bio;
    }

    void OpensslBIOCpp::readFilename(std::string filename) {
        BIO_read_filename(_bio, filename.c_str());
    }

    void OpensslBIOCpp::writePEMPublicKey(EVP_PKEY* publicKey) {
        PEM_write_bio_PUBKEY(_bio, publicKey);
    }

    void OpensslBIOCpp::connectTo(std::string servername, std::string port) {
        _bio = BIO_new_connect((servername + ":" + port).c_str());
        if(_bio == nullptr) {
            throw OpensslCppException("Error during BIO_connect");
        }
        if(BIO_do_connect(_bio) <= 0) {
            throw OpensslCppException("Error during connection");
        }
     }

}
