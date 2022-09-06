#ifndef PROTOCOL_H
#define PROTOCOL_H
#include <string>
#include <iostream>
#include <set>
#include <array>

#ifdef __linux__
#include <dlfcn.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#define SOCKET_ERROR (-1)
#elif _WIN32
#include <winsock2.h>
#include <mswsock.h>
#include <windows.h>
#endif

namespace Protocol {

using byte = uint8_t;
using msgSizeType = uint32_t;

constexpr size_t BUFSIZE = 1024;
constexpr size_t MESSAGE_SIZE_BYTES = sizeof (msgSizeType);



template< typename T > std::array< byte, sizeof(T) >  to_bytes( const T& object )
{
    std::array< byte, sizeof(T) > bytes ;

    const byte* begin = reinterpret_cast< const byte* >( std::addressof(object) ) ;
    const byte* end = begin + sizeof(T) ;
    std::copy( begin, end, std::begin(bytes) ) ;

    return bytes ;
}

template< typename T >
T& from_bytes( const std::array< byte, sizeof(T) >& bytes, T& object )
{

    // http://en.cppreference.com/w/cpp/types/is_trivially_copyable
#if (__cplusplus >= 201402L)
    static_assert(std::is_trivially_copyable<T>::value, "not a TriviallyCopyable type");
#endif

    byte* begin_object = reinterpret_cast< byte* >( std::addressof(object) ) ;
    std::copy( std::begin(bytes), std::end(bytes), begin_object ) ;

    return object ;
}

    enum : uint8_t {
        //Protocol level headers
        SOH = 1,        //START OF HEADING
        STX = 2,        //START OF TEXT
        ETX = 3,        //END OF TEXT
        EOT = 4,        //END OF TRANSMISSION
        ENQ = 5,        //ENQUIRY
        ACK = 6,        //ACKNOWLEDGE
        NAK = 21,       //NEGATIVE ACKNOWLEDGE
        SYN = 22,       //SYNCHRONOUS IDLE
        ETB = 23,       //END OF TRANSMISSION BLOCK
        LF = 10,        //LINE FEED
        CR = 13,        //CARRIAGE RETURN
        DONERECV = 18,  //DONE RECEIVING
        DONETRANS = 19, //DONE TRANSMISSION

        //Application level headers
        CL_REQ_ID = 50,
        CL_REQ_AUTH = 51,
        CL_REQ_FILE = 52,
        CL_REQ_PARAM = 53,
        CL_REQ_COMMAND = 54,
        CL_SND_PARAM = 100,
        CL_SND_ID = 101,
        CL_SND_PRINT = 102,
        CL_SND_PART = 103,
        SRV_ENCRYPT = 104,
        SRV_DECRYPT = 105,
        SRV_SND_ERROR = 118,
        SRV_SND_DATA = 119,
        SRV_SND_COMMAND = 120,
        SRV_SND_TEXT = 121,
        SRV_SND_PART = 122,
        USR_CMD = 123,
    };

    enum class ERRORS : uint8_t {SUCCESS = 0,
                 WRONG_COMMUNICATION,
                 WRONG_MESSAGE,
                 TIMEOUT,
                 DISCONNECTED,
                };

    inline std::string createRequest(const uint8_t head, const std::string& body = "") {
        std::string msg;
        msg += SOH;
        msg += head;

        msgSizeType size = body.size();
        auto serialized = to_bytes(size);
        for (auto i = 0; i < MESSAGE_SIZE_BYTES; ++i) {
            msg += serialized[i];
        }
        msg += STX;
        msg += body;
        return msg;
    }

    inline ERRORS writeMessage(const uint16_t socket, uint8_t head, std::string body = "") {
        std::string headPart;
        headPart += SOH;
        headPart += head;

        msgSizeType size = body.size();
        auto serialized = to_bytes(size);
        for (auto i = 0; i < MESSAGE_SIZE_BYTES; ++i) {
            headPart += serialized[i];
        }
        headPart += STX;

        int resHead = send(socket, headPart.c_str(), headPart.size(), 0);
        if (resHead == SOCKET_ERROR) {
            return ERRORS::WRONG_COMMUNICATION;
        } else if (resHead == 0) {
            return ERRORS::DISCONNECTED;
        }

        int resBody = 0;
        if (body.size()) {
            resBody = send(socket, body.c_str(), body.size(), 0);
            if (resBody == SOCKET_ERROR) {
                return ERRORS::WRONG_COMMUNICATION;
            } else if (resBody == 0) {
                return ERRORS::DISCONNECTED;
            }
        }

        int total = resHead + resBody;
        std::cout << "Protocol | Sent total " << total << " bytes" << std::endl;
        return ERRORS::SUCCESS;
    }

    inline ERRORS readMessage(const uint16_t socket, std::pair<uint8_t, std::string>& result) {

        //Message structure SOH(1)_HEAD(1)_BODY_SIZE(MESSAGE_SIZE_BYTES)_STX(1)_BODY

        char buf[Protocol::BUFSIZE + 1];
        std::string message = "";

        int res = 0;
        //Read HEAD, per byte
        for (size_t i = 0; i < MESSAGE_SIZE_BYTES + 3; ++i) {
            char tmp[2];
            res = recv(socket, tmp, 1, 0);
            if (res == SOCKET_ERROR) {
                return ERRORS::WRONG_COMMUNICATION;
            } else if (res == 0) {
                return ERRORS::DISCONNECTED;
            }
            buf[i] = tmp[0];
        }
        buf[MESSAGE_SIZE_BYTES + 3] = '\0';

        //Check read and head structure
        if (buf[0] != Protocol::SOH || buf[MESSAGE_SIZE_BYTES + 2] != Protocol::STX) {
            return ERRORS::WRONG_MESSAGE;
        }

        //Parse head, get body length
        msgSizeType bodySize;
        std::array<uint8_t, MESSAGE_SIZE_BYTES> serialized;

        for (size_t i = 0; i < MESSAGE_SIZE_BYTES; ++i) {
            serialized[i] = buf[i+2];
        }
        from_bytes(serialized, bodySize);

        result.first = static_cast<uint8_t>(buf[1]);

        //Read body
        if (bodySize != 0) {
            uint32_t bytesLeft = bodySize;
            while (bytesLeft > 0) {
                res = 0;
                if (bytesLeft > Protocol::BUFSIZE)
                    res = recv(socket, buf, BUFSIZE, 0);
                else
                    res = recv(socket, buf, bytesLeft, 0);

                if (res == SOCKET_ERROR) {
                    return ERRORS::WRONG_COMMUNICATION;
                } else if (res == 0) {
                    return ERRORS::DISCONNECTED;
                }

                buf[res] = '\0';
                bytesLeft -= res;

                for (int i = 0; i < res; ++i) {
                    result.second += buf[i];
                }
            }
        }

        return ERRORS::SUCCESS;
    }
}

#endif //PROTOCOL_H
