#include <iostream>
#include <vector>
#include <fstream>
#include <regex>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <iomanip>
#include <stdexcept>
#include <filesystem>

namespace fs = std::filesystem;

std::vector<fs::path> listFilePaths(const std::vector<std::string>& basePaths, const std::string& pattern);
std::string calculateMd5(const std::filesystem::path &filePath);
bool matchFileNamePattern(const std::string &filename, const std::string &pattern);
void handleOpenSSLError(const std::string &message);
void createReport(const std::string& filename, const std::map<std::string, std::vector<std::string>>& duplicates);

int main(int argc, char* argv[]) {
    std::stringstream basePathArg(argv[1]);
    std::string item;

    std::vector<std::string> paths;
    while (std::getline(basePathArg, item, ';')) {
        paths.push_back(item);
    }
    std::string pattern = argc == 3 ? ".*." : argv[3];
    std::string reportFile = argv[2];

    std::vector<fs::path> filePaths = listFilePaths(paths, pattern);
    std::map<std::string, std::vector<std::string>> result;

    for (const fs::path& file: filePaths) {
        std::string md5 = calculateMd5(file);
        if (result.count(md5) > 0) {
            result[md5].push_back(file.string());
        } else {
            std::vector<std::string> ls;
            ls.emplace_back(file.string());
            result.insert({md5, ls});
        }
    }

    std::map<std::string, std::vector<std::string>> duplicates;

    for (const auto &pair: result) {
        if (pair.second.size() > 1) {
            duplicates.insert({pair.first, pair.second});
        }
    }
    createReport(reportFile, duplicates);
    return 0;
}

void createReport(const std::string& filename, const std::map<std::string, std::vector<std::string>>& duplicates) {
    std::ifstream infile(filename);
    if (!infile.good()) {
        std::ofstream createFile(filename);
        if (!createFile) {
            std::cerr << "Error: Could not create the file." << std::endl;
            return;
        }
    }
    infile.close();

    std::ofstream outfile(filename, std::ios::app);
    if (!outfile) {
        std::cerr << "Error: Could not open the file for appending." << std::endl;
        return;
    }

    for (const auto &pair: duplicates) {
        outfile << pair.first + " | " << pair.second.size() << std::endl;
        for (const auto &str: pair.second) {
            outfile << str << std::endl;
        }
        outfile << std::endl;
    }
}

std::vector<fs::path> listFilePaths(const std::vector<std::string>& basePaths, const std::string& pattern) {
    std::vector<fs::path> result;
    std::regex xPattern("\\$.*|System Volume Information.*", std::regex_constants::icase);

    for (const std::string &path: basePaths) {

        for (auto it = fs::recursive_directory_iterator(path, fs::directory_options::skip_permission_denied);
             it != fs::recursive_directory_iterator();) {

            try {
                ++it;
            } catch (const fs::filesystem_error &e) {
                std::cerr << "Error accessing: " << it->path() << " - " << e.what() << std::endl;
                it.disable_recursion_pending();
                ++it;
            }

            if (it == fs::recursive_directory_iterator()) {
                continue;
            }

            const auto &p = it->path();

            if (fs::is_directory(p)) {
                if (std::regex_search(p.string(), xPattern)) {
                    it.disable_recursion_pending();
                    continue;
                }
            } else {
                if (matchFileNamePattern(p.string(), pattern)) {
                    result.push_back(p);
                }
            }
        }
    }
    return result;
}

bool matchFileNamePattern(const std::string &filename, const std::string &pattern) {
    std::regex regexPattern(pattern, std::regex_constants::icase);
    return std::regex_search(filename, regexPattern);
}

std::string calculateMd5(const std::filesystem::path &filePath) {
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    std::ifstream infile(filePath, std::ios::binary);
    if (!infile) {
        return "AccessIssue";
    }

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        throw std::runtime_error("Failed to create MD5 context.");
    }

    if (1 != EVP_DigestInit_ex(mdctx, EVP_md5(), nullptr)) {
        handleOpenSSLError("Failed to initialize MD5 digest");
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("Failed to initialize MD5 digest.");
    }

    char buffer[4096];
    while (infile.read(buffer, sizeof(buffer)) || infile.gcount() > 0) {
        std::streamsize bytesRead = infile.gcount();
        if (1 != EVP_DigestUpdate(mdctx, buffer, bytesRead)) {
            handleOpenSSLError("Failed to update MD5 digest");
            EVP_MD_CTX_free(mdctx);
            throw std::runtime_error("Failed to update MD5 digest.");
        }
    }

    unsigned char md5Result[EVP_MAX_MD_SIZE];
    unsigned int md5Length = 0;

    if (1 != EVP_DigestFinal_ex(mdctx, md5Result, &md5Length)) {
        handleOpenSSLError("Failed to finalize MD5 digest");
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("Failed to finalize MD5 digest.");
    }

    EVP_MD_CTX_free(mdctx);

    std::ostringstream md5String;
    for (unsigned int i = 0; i < md5Length; ++i) {
        md5String << std::hex << std::setw(2) << std::setfill('0') << (int) md5Result[i];
    }

    return md5String.str();
}

void handleOpenSSLError(const std::string &message) {
    unsigned long errCode;
    std::ostringstream errorStream;

    while ((errCode = ERR_get_error())) {
        errorStream << ERR_error_string(errCode, nullptr) << std::endl;
    }
    throw std::runtime_error(message + ": " + errorStream.str());
}
