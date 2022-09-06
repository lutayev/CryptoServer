#ifndef CONNECTION_H
#define CONNECTION_H

#include <string>
#include <fstream>
#include <iostream>
#include <map>
#include <vector>
#include <queue>
#include <atomic>
#include <mutex>

#include <string.h>
#include <unistd.h>
#include <stdio.h>

#include "protocol.h"

class Connection
{
public:
    enum class Errors {LOG_NOT_OPENED, };
    Connection(unsigned short fd);
    virtual ~Connection();

    void communicate();
    std::string id();

protected:
    enum class LogLevel {info, warning, critical};
    virtual void processMessage(const std::pair<uint8_t, std::string>& message);
    void log(LogLevel level, std::string message);
    void flushLogs();

    std::string     m_id;
    std::string     m_logFile;
    std::ofstream   m_log;

    unsigned short      m_sock;
    Errors              m_error;
    bool                done;
    std::vector<std::string>    m_logs;
    static std::mutex           m_logMtx;
};

#endif //CONNECTION_H
