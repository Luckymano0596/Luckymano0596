#include <iostream>
#include <vector>
#include <string>
#include <random>
#include <iomanip>
#include <sstream>
#include <openssl/sha.h>

// Function to generate a random string
std::string generateRandomString(int length) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);

    std::stringstream ss;
    for (int i = 0; i < length; ++i) {
        ss << std::setw(2) << std::setfill('0') << std::hex << dis(gen);
    }

    return ss.str();
}

// Function to generate a SHA-256 hash of a given input string
std::string generateSHA256Hash(const std::string& input) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, input.c_str(), input.length());
    SHA256_Final(hash, &sha256);

    std::stringstream hashStream;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        hashStream << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(hash[i]);
    }

    return hashStream.str();
}

// IoT Sensor class
class IoTSensor {
private:
    std::string data;

public:
    IoTSensor(const std::string& data) : data(data) {}

    // Function to secure the data using random hashing
    std::string secureData() {
        // Generate a random string
        std::string randomString = generateRandomString(32);

        // Combine the random string with the sensitive data
        std::string combinedData = randomString + data;

        // Generate SHA-256 hash of the combined data
        std::string secureHash = generateSHA256Hash(combinedData);

        return secureHash;
    }
};

// Class to represent a Healthcare IoT Network
class IoTHospitalNetwork {
private:
    std::vector<IoTSensor> sensors;

public:
    // Function to add a sensor to the network
    void addSensor(const IoTSensor& sensor) {
        sensors.push_back(sensor);
    }

    // Function to retrieve the secured data from all sensors in the network
    std::vector<std::string> getAllSecuredData() {
        std::vector<std::string> securedDataList;
        for (const auto& sensor : sensors) {
            securedDataList.push_back(sensor.secureData());
        }
        return securedDataList;
    }
};

// Main function
int main() {
    // Create an IoT hospital network
    IoTHospitalNetwork hospitalNetwork;

    // Add sensors to the network
    IoTSensor sensor1("Patient's vital signs");
    IoTSensor sensor2("Medical equipment status");
    hospitalNetwork.addSensor(sensor1);
    hospitalNetwork.addSensor(sensor2);

    // Retrieve secured data from all sensors in the network
    std::vector<std::string> securedDataList = hospitalNetwork.getAllSecuredData();

    // Print secured data
    std::cout << "Secured Data from Hospital Network:\n";
    for (const auto& securedData : securedDataList) {
        std::cout << securedData << std::endl;
    }

    return 0;
}
