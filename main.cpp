#include <iostream>
#include <fstream>
#include <sstream>
#include <string>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

std::string readFromFile(const std::string &filepath) {
    std::ifstream file(filepath);
    if (!file.is_open()) {
        std::cerr << "Error: Unable to open file '" << filepath << "'" << std::endl;
        return "";
    }
    std::ostringstream buffer;
    buffer << file.rdbuf();
    return buffer.str();
}

std::string cleanText(const std::string &input, bool keepWhitespace) {
    std::string cleanedText;
    for(char c : input) {
        // Convert to uppercase
        char temp = std::toupper(c);

        // Check if character is alphanumeric or preserved whitespace
        if (std::isalnum(temp) || (keepWhitespace && std::isspace(temp))) {
            cleanedText += temp;
        }
    }
    return cleanedText;
}

// Encrypts plaintext using Vigenere cypher
// Assumes uppercase letters
std::string vigenereEncrypt(const std::string& plaintext, const std::string& key) {
    std::string ciphertext;

    for (int i = 0; i < plaintext.length(); i++) {
        // Preserve whitespace if there is any
        if(std::isspace(plaintext[i])) {
            ciphertext += plaintext[i];
        }

        // Otherwise, encrypt
        else {
            char keyChar = key[i % key.length()];
            int shiftedKey = keyChar - 'A';

            ciphertext += ((plaintext[i] + shiftedKey) % 26) + 'A';
        }
    }

    return ciphertext;
}

// Decrypts plaintext using Vigenere cypher
// Assumes uppercase letters
std::string vigenereDecrypt(const std::string& cyphertext, const std::string& key) {
    std::string plaintext;

    for (int i = 0; i < cyphertext.length(); i++) {
        // Preserve whitespace if there is any
        if(std::isspace(cyphertext[i])) {
            plaintext += cyphertext[i];
        }

        // Otherwise, decrypt
        else {
            char keyChar = key[i % key.length()];
            int shiftedKey = keyChar - 'A';

            plaintext += ((cyphertext[i] - shiftedKey) % 26) + 'A';
        }
    }

    return plaintext;
}

int main() { 
    // Prompt user for input selection
    std::string input;
    std::cout << "Enter a line of text or a file path: ";
    std::getline(std::cin, input);
    
    // Check if input is a file path
    std::ifstream file(input);
    if (file) {
        // If so, read the file
        input = readFromFile(input);
    }

    // Get key from user
    std::string key;
    std::cout << "Enter encryption key: ";
    std::getline(std::cin, key);
    key = cleanText(key, FALSE);


    // Testing
    std::cout << "Cleaned: " << cleanText(input, TRUE) << "\n";
    std::string cypherText = vigenereEncrypt(cleanText(input, TRUE), key);
    std::cout << "Encrypted: " << cypherText << "\n";
    std::cout << "Decrypted: " << vigenereDecrypt(cypherText, key) << "\n";

    // Ask user whether they want to encrypt or decrypt
    std::cout << "1. Encrypt\n"
              << "2. Decrypt\n";

    char choice;
    std::cin >> choice;
    std::cin.ignore();

    // Switch based on whether user wants to encrypt or decrypt
    if(choice == '1') {
        // Ask user whether they want to keep whitespace
        std::cout << "Keep whitespace? (Y/N) ";
        std::cin >> choice;
        std::cin.ignore();
        bool keep = FALSE;
        if(std::toupper(choice) == 'Y')
            choice = TRUE;

        std::string cyphertext = vigenereEncrypt(cleanText(input, keep), key);
        std::cout << "Cyphertext: " << cyphertext;
    }
    else if(choice == '2') {
        std::string plaintext = vigenereDecrypt(cleanText(input, TRUE), key);
        std::cout << "Plaintext: " << plaintext;
    }
    
    return 0;
}