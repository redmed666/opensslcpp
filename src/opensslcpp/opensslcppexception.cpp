#include "opensslcpp/opensslcppexception.hpp"

namespace OpensslCpp {
    OpensslCppException::OpensslCppException(std::string errorMessage) : _errorMessage(errorMessage) {

    }

    const char* OpensslCppException::what() const throw () {
        return _errorMessage.c_str();
    }
}
