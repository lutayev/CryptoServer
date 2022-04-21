#ifndef SERVER_H
#define SERVER_H
#include <string>
#include <iostream>
#include <map>
#include <thread>
#include <mutex>
#include <atomic>

#ifdef __linux__
#include <dlfcn.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#elif _WIN32
#include <winsock2.h>
#include <mswsock.h>
#include <unordered_map>
#endif

#include "connection.h"

enum class ServerType {defaultServer, remoteEmulatorServer};

class Server
{
public:
    Server(unsigned short port, ServerType type = ServerType::defaultServer);
    ~Server();
    virtual void acceptClients();
    virtual void addClient(unsigned short clientSocket);
    bool isOk();
    std::atomic_bool    stop {false};

private:
    std::unordered_multimap<unsigned int, Connection*> m_clients;
    ServerType          m_serverType;
    std::mutex          m_mtxClientsMap;
    std::mutex          m_mtxThreadsMap;
    sockaddr_in         m_addrListenClients;
    sockaddr_in         m_addrListenManagers;
    unsigned short      m_portListenClients;
    unsigned short      m_portListenManagers;
    unsigned short      m_srvSock {0};
    bool                m_ok {false};

    //TEMP DEBUG
    void printClientInfo(unsigned int socket);

};

#endif // SERVER_H
