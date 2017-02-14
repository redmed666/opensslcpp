#pragma once
#include <exception>
#include <string>

namespace OpensslCpp {
    class OpensslCppException : public std::exception {
    public:
        OpensslCppException(std::string errorMessage);
        virtual const char* what() const throw();

    private:
        std::string _errorMessage;
    };
}
