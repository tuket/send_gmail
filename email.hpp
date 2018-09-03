#pragma once

#include <functional>
#include <string>
#include <vector>
#define ASIO_STANDALONE
#include <asio.hpp>
#include <asio/ssl.hpp>
#include <asio/buffer.hpp>

struct EMail
{
    std::string to;
    std::string subject;
    std::string body;
};

class EPostMan
{
public:
    enum ErrorCode {OK = 0, ERROR = 1};
    typedef std::function<void(ErrorCode)> Callback;

    EPostMan(
        asio::ssl::context& sslContext,
        asio::io_context& ioc,
        const std::string& serverUrl, std::uint16_t port,
        const std::string& account, const std::string& password);

    void send(const EMail& email, const Callback& callback = Callback());

private:
    void resolveAddress(const std::string& server, const std::string& port);
    std::string* composeEmailBuffer(const EMail& email);

    class SendProcess
    {
    public:
        SendProcess(EPostMan& postMan, const EMail& email,
            const Callback& callback = Callback());
        SendProcess(const SendProcess& other);
        ~SendProcess();
        void start();
        void operator()(const asio::error_code& ec, size_t bytesTransfered);

    private:
        enum State {
            START,
            SEND_EHLO,
            RECV_EHLO_250,
            SEND_AUTH_LOGIN,
            RECV_AUTH_LOGIN_334,
            SEND_USER,
            RECV_USER_334,
            SEND_PASSWORD,
            RECV_PASSWORD_235,
            SEND_MAIL_FROM,
            RECV_MAIL_FROM_250,
            SEND_RCPT_TO,
            RECV_RCPT_TO_250,
            SEND_DATA,
            RECV_DATA_354,
            SEND_EMAIL,
            RECV_EMAIL_250
        };
        void read();
        void write(const char* strf, ...);
        void incState();

        static const unsigned BUFFER_SIZE = 4 * 1024;
        std::vector<char> charBuffer;
        asio::mutable_buffer buffer;
        EPostMan& postMan;
        State state;
        EMail* email;
        Callback callback;
    };

    typedef asio::ip::tcp::socket Socket;
    typedef asio::ssl::stream<Socket> SslSocket;
    SslSocket socket;
    std::string serverUrl;
    std::uint16_t serverPort;
    std::string account, accountB64;
    std::string passwordB64;
    asio::ip::tcp::resolver resolver;
    asio::ip::tcp::resolver::iterator endpointIt;
};
