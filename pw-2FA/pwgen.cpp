#include <iostream>
#include <string>
#include <set>
#include <sstream>
#include <cstdlib>
#include <ctime>
#include "pwgen.h"
using namespace std;

namespace pwgenHelper {
    // Get and validate password length from the user
    bool getPasswordLength(int& passwordLength) {
        string str;
        cout << "Password length: " << endl;
        getline(cin, str);

        try {
            passwordLength = stoi(str);
        }
        catch (...) {
            cout << "Please ensure you enter a number between 8 and 50.\n" << endl;
            return false;
        }

        if (passwordLength < 8 || passwordLength > 50) {
            cout << "Invalid password length, this is too weak!\nPlease enter a number between 8 and 50.\n" << endl;
            return false;
        }
        return true;
    }

    // get character types wanted in password
    set<int> getOptions() {
        set<int> options;
        bool validOptions = false;
        // loop until valid options are chosen
        while (!validOptions) {
            // display options
            cout << "Character set options:" << endl;
            cout << "\tLowercase (i.e. abcdef) - LC" << endl;
            cout << "\tUppercase (i.e. ABCDEF) - UC" << endl;
            cout << "\tDigits (i.e. 012345) - NUM" << endl;
            cout << "\tSymbols (i.e. !@#) - SYM" << endl;
            cout << "\tAll - AL" << endl << endl;

            cout << "You may choose ALL or any combination of the options.\nType ALL desired options separated by a space, then hit \"ENTER\"." << endl;
            cout << "Option(s): ";

            // take input
            string optionInput;
            getline(cin, optionInput);

            //interpret input
            istringstream iss(optionInput);
            string token;
            while (iss >> token) {
                if (token == "LC" || token == "lc") {
                    options.insert(1);
                }
                else if (token == "UC" || token == "uc") {
                    options.insert(2);
                }
                else if (token == "NUM" || token == "num") {
                    options.insert(3);
                }
                else if (token == "SYM" || token == "sym") {
                    options.insert(4);
                }
                else if (token == "AL" || token == "al") {
                    options.insert(0);
                }
                else {
                    // reset if invalid options entered
                    cout << "Invalid option.\n" << endl;
                    options.clear();
                    break;
                }
            }
            // if options set successfully populated, valid options are chosen
            if (!options.empty()) {
                validOptions = true;
            }
        }
        return options;
    }

    // generate placeholder set of character types to be filled
    string generateRandCharSet(set<int>* options, int passwordLength) {
        string characterSets = "";

        while (characterSets.length() != passwordLength) {
            int result = 1 + (rand() % 4);

            if (result == 1 && (options->find(1) != options->end() || options->find(0) != options->end())) {
                characterSets += to_string(result);
            }
            else if (result == 2 && (options->find(2) != options->end() || options->find(0) != options->end())) {
                characterSets += to_string(result);
            }
            else if (result == 3 && (options->find(3) != options->end() || options->find(0) != options->end())) {
                characterSets += to_string(result);
            }
            else if (result == 4 && (options->find(4) != options->end() || options->find(0) != options->end())) {
                characterSets += to_string(result);
            }
        }
        return characterSets;
    }

    // generate password
    string generatePassword(set<int>* options, int passwordLength) {
        string characterSets;
        //generates a string with the length of passwordLength where each digit is a random approved character set for the password
        bool error = true;
        while (error) {
            characterSets = generateRandCharSet(options, passwordLength);

            error = false;
            if ((options->find(1) != options->end() || options->find(0) != options->end()) && characterSets.find("1") == string::npos) {
                error = true;
            }
            if ((options->find(2) != options->end() || options->find(0) != options->end()) && characterSets.find("2") == string::npos) {
                error = true;
            }
            if ((options->find(3) != options->end() || options->find(0) != options->end()) && characterSets.find("3") == string::npos) {
                error = true;
            }
            if ((options->find(4) != options->end() || options->find(0) != options->end()) && characterSets.find("4") == string::npos) {
                error = true;
            }
        }

        string password = "";
        string lowercase = "abcdefghijklmnopqrstuvwxyz";
        string uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        string digits = "0123456789";
        string symbols = "!@#$%&";

        for (int i = 0; i < passwordLength; i++) {
            if (characterSets[i] == '1') {
                password += lowercase[rand() % lowercase.length()];
            }
            else if (characterSets[i] == '2') {
                password += uppercase[rand() % uppercase.length()];
            }
            else if (characterSets[i] == '3') {
                password += digits[rand() % digits.length()];
            }
            else if (characterSets[i] == '4') {
                password += symbols[rand() % symbols.length()];
            }
        }
        return password;
    }
}
    

namespace pwgen {
    void getNewPassword() {
        int passwordLength;
        bool validLength = false;

        set<int> options = pwgenHelper::getOptions();

        while (!validLength) {
            validLength = pwgenHelper::getPasswordLength(passwordLength);
        }

        srand((unsigned)time(0));
        cout << endl;
        cout << pwgenHelper::generatePassword(&options, passwordLength) << endl;
    }
}