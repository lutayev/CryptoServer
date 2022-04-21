#include <iostream>
#include <iomanip>
#include <ctime>

#include "include/rapidjson/document.h"
#include "include/rapidjson/writer.h"
#include "include/rapidjson/stringbuffer.h"
#include "include/rapidjson/prettywriter.h"

#include "cryptoprocontroller.h"
#include "util.h"

#include "connection.h"


Connection::Connection(unsigned short fd)
{
    m_sock = fd;
	done = false;
    //m_error = ;

    m_logFile = "../log/log_connection.txt";

	m_log.open(m_logFile.c_str(), 
			std::ios_base::out | std::ios_base::ate | std::ios_base::app);

    if (!m_log.good())
        m_error = Errors::LOG_NOT_OPENED;
}

Connection::~Connection()
{
    std::cout << "Client " << m_id << " disconnected" << std::endl;
    if (m_log.good())
        m_log.close();


    if (m_sock != -1) {
#ifdef __linux__
        close(m_sock);
#elif _WIN32
        shutdown(m_sock, SD_BOTH);
        closesocket(m_sock);
#else
#endif
    }

}

void Connection::communicate()
{
    std::pair<uint8_t, std::string> message;
    for(;;)
    {
        message.first = 0;
        message.second.clear();
        //cout << "listening for incoming message...\n";
        Protocol::ERRORS err = Protocol::readMessage(m_sock, message);
        if (err == Protocol::ERRORS::WRONG_COMMUNICATION) {
            std::cout << "Wrong communication" << std::endl;
            log(LogLevel::warning, "Wrong communication");
            break;
        } else if (err == Protocol::ERRORS::WRONG_MESSAGE) {
            std::cout << "Wrong message" << std::endl;
            log(LogLevel::warning, "Wrong message");
        } else if (err == Protocol::ERRORS::DISCONNECTED) {
            std::cout << "Client closed connection" << std::endl;
            log(LogLevel::warning, "Client closed connection");
            break;
        }

        //std::cout << "Message: " << message.second << std::endl;
        processMessage(message);
    }
}

std::string Connection::id()
{
    return m_id;
}

void Connection::processMessage(const std::pair<uint8_t, std::string>& message)
{

    uint8_t command         = message.first;
    std::string json        = message.second;
    log(LogLevel::info, "New request received");

    if (!json.size()) {
        std::cout << "Empty JSON!" << std::endl;
        log(LogLevel::critical, "Empty JSON!");
        Protocol::writeMessage(m_sock, Protocol::NAK, "Empty message");
        return;
    }

    using namespace rapidjson;
    Document doc;
    doc.Parse(json.c_str());

    if (!doc.IsObject()) {
        std::cout << "Not valid JSON" << std::endl;
        log(LogLevel::critical, "Not valid JSON");
        Protocol::writeMessage(m_sock, Protocol::SRV_SND_ERROR, "Not valid JSON");
        return;
    }

    if (!doc.HasMember("certificate")) {
        std::cout << "No certificate serial provided, return\n";
        log(LogLevel::critical, "No certificate serial provided");
        Protocol::writeMessage(m_sock, Protocol::SRV_SND_ERROR, "No certificate serial provided");
        return;
    }

    if (!doc.HasMember("data")) {
        std::cout << "No data provided, return\n";
        log(LogLevel::critical, "No data provided");
        Protocol::writeMessage(m_sock, Protocol::SRV_SND_ERROR, "No data provided");
        return;
    }

    std::string certificate = doc["certificate"].GetString();
    std::string data = base64_decode(doc["data"].GetString());
    std::string dataResponse;

    if (command == Protocol::SRV_ENCRYPT) {
        log(LogLevel::info, "Encrypting data with certificate " + certificate);
        CryptoproController::encryptMessage(data, dataResponse, certificate);
    } else if (command == Protocol::SRV_DECRYPT) {
        log(LogLevel::info, "Decrypting data with certificate " + certificate);
        CryptoproController::decryptMessage(data, dataResponse);
    } else {
        std::cout << "Unrecognized command, return\n";
        log(LogLevel::critical, "Unrecognized command");
        Protocol::writeMessage(m_sock, Protocol::SRV_SND_ERROR, "Unrecognized command");
        return;
    }

    if (!dataResponse.size()) {
        std::cout << "Error encrypting/decrypting data, return\n";
        log(LogLevel::critical, "Error encrypting/decrypting data");
        Protocol::writeMessage(m_sock, Protocol::SRV_SND_ERROR, "Error encrypting/decrypting data");
        return;
    }

    std::string response = "{\"data\":\"" + base64_encode(dataResponse) + "\"}";
    Protocol::ERRORS err = Protocol::writeMessage(m_sock, Protocol::SRV_SND_DATA, response);
    if (err == Protocol::ERRORS::SUCCESS) {
        log(LogLevel::info, "Success");
    } else if (err == Protocol::ERRORS::TIMEOUT) {
        log(LogLevel::critical, "Timeout");
    } else if (err == Protocol::ERRORS::WRONG_COMMUNICATION) {
        log(LogLevel::critical, "Wrong communication");
    }
}

void Connection::log(LogLevel level, std::string message)
{
    time_t rawtime;
    struct tm * timeinfo;
    char buffer[80];

    time (&rawtime);
    timeinfo = localtime(&rawtime);

    strftime(buffer,sizeof(buffer),"%d-%m-%Y %H:%M:%S",timeinfo);
    std::string timestr(buffer);

    m_log << "\n" << timestr;

    if (level == LogLevel::info) {
        m_log << " Info: ";
    } else if (level == LogLevel::warning) {
        m_log << " Warning: ";
    } else if (level == LogLevel::critical) {
        m_log << " Critical: ";
    }
    m_log << message;
    m_log.flush();
}
