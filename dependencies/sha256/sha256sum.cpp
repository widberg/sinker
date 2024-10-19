#include <CLI/CLI.hpp>
#include <iostream>
#include <sha256.hpp>
#include <string>

int main(int argc, char const *argv[]) {
    CLI::App app{"sha256sum"};
    std::string filename;
    app.add_option("filename", filename, "File to hash")->required();

    CLI11_PARSE(app, argc, argv);

    sha256_digest_t hash;
    sha256_file(filename, hash);

    char hash_str[SHA256_STR_LENGTH];
    hash_to_string(hash, hash_str, sizeof(hash_str));

    std::cout << hash_str << std::endl;
}
