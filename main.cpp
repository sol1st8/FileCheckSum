#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1

#include <cryptopp/sha.h>
#include <cryptopp/md5.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>

#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <iomanip>

namespace fs = std::filesystem;

template <class Hash>
std::string ComputeHash(const fs::path& filepath) {
    std::ifstream file(filepath.string(), std::ios::binary);
    if (file.is_open()) {
        Hash hash;
        CryptoPP::byte digest[Hash::DIGESTSIZE] = { 0 };

        do {
            char buffer[4096] = { 0 };
            file.read(buffer, 4096);

            auto extracted = static_cast<size_t>(file.gcount());

            if (extracted > 0) {
                hash.Update(reinterpret_cast<CryptoPP::byte*>(buffer), extracted);
            }
        } while (!file.fail());

        hash.Final(digest);

        CryptoPP::HexEncoder encoder;
        std::string result;

        encoder.Attach(new CryptoPP::StringSink(result));
        encoder.Put(digest, sizeof(digest));
        encoder.MessageEnd();

        return result;
    }

    throw std::runtime_error("Cannot open file!");
}

template <class Hash>
std::string ComputeHashEx(const fs::path& filepath) {
    std::string digest;
    Hash hash;

    CryptoPP::FileSource source(filepath.c_str(), true,
                                new CryptoPP::HashFilter(hash, new CryptoPP::HexEncoder(new CryptoPP::HexEncoder(new CryptoPP::StringSink(digest)))));

    return digest;
}

int main() {
    std::string path;
    std::cout << "Path: ";
    std::cin >> path;

    try {
        std::cout << "SHA1: "
                  << ComputeHash<CryptoPP::SHA1>(path) << std::endl;
        std::cout << "SHA256: "
                  << ComputeHash<CryptoPP::SHA256>(path) << std::endl;
        std::cout << "MD5: "
                  << ComputeHash<CryptoPP::Weak::MD5>(path) << std::endl;

        std::cout << "SHA1: "
                  << ComputeHashEx<CryptoPP::SHA1>(path) << std::endl;
        std::cout << "SHA256: "
                  << ComputeHashEx<CryptoPP::SHA256>(path) << std::endl;
        std::cout << "MD5: "
                  << ComputeHashEx<CryptoPP::Weak::MD5>(path) << std::endl;
    }
    catch (const std::exception& ex) {
        std::cerr << ex.what() << std::endl;
    }
}
