#include "email.hpp"

#include <cstdarg>
#include <cstring>
#include <stdexcept>
#include "base64.hpp"
#include <iostream>
#include <sstream>

using namespace std;
using tcp = asio::ip::tcp;

///@brief Helper class that prints the current certificate's subject
///       name and the verification results.
template <typename Verifier>
class verbose_verification
{
public:
  verbose_verification(Verifier verifier)
    : verifier_(verifier)
  {}

  bool operator()(
    bool preverified,
    asio::ssl::verify_context& ctx
  )
  {
    char subject_name[256];
    X509* cert = X509_STORE_CTX_get_current_cert(ctx.native_handle());
    X509_NAME_oneline(X509_get_subject_name(cert), subject_name, 256);
    bool verified = verifier_(preverified, ctx);
    cout << "Verifying: " << subject_name << "\n"
         << "Verified: " << verified << endl;
    return verified;
  }
private:
  Verifier verifier_;
};
template <typename Verifier>
verbose_verification<Verifier>
make_verbose_verification(Verifier verifier)
{
  return verbose_verification<Verifier>(verifier);
}


EPostMan::EPostMan(
    asio::ssl::context& sslContext,
    asio::io_context& ioc,
    const string& serverUrl, uint16_t port,
    const string& account, const string& password
)
    : socket(ioc, sslContext)
    , resolver(ioc)
    , serverUrl(serverUrl)
    , account(account)
    , accountB64(tl::base64::encode(account))
    , passwordB64(tl::base64::encode(password))
{
    endpointIt = resolver.resolve(serverUrl, to_string(port));

    asio::connect(socket.lowest_layer(), endpointIt);
    //socket.lowest_layer().set_option(tcp::no_delay(true));

    socket.set_verify_callback(make_verbose_verification(
        asio::ssl::rfc2818_verification(serverUrl)));
    socket.set_verify_mode(asio::ssl::verify_peer);

    try{
        socket.handshake(SslSocket::client);
    }
    catch(const std::exception& e){
        cout << e.what() << endl;
    }
}

void EPostMan::send(const EMail& email, const Callback& callback)
{
    auto sendProcess = new SendProcess(*this, email, callback);
    sendProcess->start();
}

EPostMan::SendProcess::SendProcess(EPostMan& postMan, const EMail& email, const Callback& callback
)
    : postMan(postMan)
    , state(START)
    , charBuffer(BUFFER_SIZE)
    , email(new EMail(email))
    , callback(callback)
{}

EPostMan::SendProcess::SendProcess(const SendProcess& other)
    : postMan(other.postMan)
    , state(other.state)
    , charBuffer(BUFFER_SIZE)
    , email(new EMail(*other.email))
    , callback(other.callback)
{}

EPostMan::SendProcess::~SendProcess()
{
    delete email;
}

void EPostMan::SendProcess::start()
{
    state = START;
    read();
}

void EPostMan::SendProcess::operator()(const asio::error_code& ec, size_t bytesTransfered)
{
    if(ec)
    {
        cout << "error" << endl;
        if(callback)
            callback(ErrorCode::ERROR);
        delete this;
        return;
    }

    switch(state)
    {
    case SEND_EHLO:
    case SEND_AUTH_LOGIN:
    case SEND_USER:
    case SEND_PASSWORD:
    case SEND_MAIL_FROM:
    case SEND_RCPT_TO:
    case SEND_DATA:
    case SEND_EMAIL:
        incState();
        read();
        break;

    case START:
        cout << charBuffer.data() << endl;
        state = SEND_EHLO;
        write("EHLO %s\n", postMan.serverUrl.c_str());
        break;
    case RECV_EHLO_250:
        state = SEND_AUTH_LOGIN;
        write("AUTH LOGIN\n");
        break;
    case RECV_AUTH_LOGIN_334:
        state = SEND_USER;
        write("%s\n", postMan.accountB64.c_str());
        break;
    case RECV_USER_334:
        state = SEND_PASSWORD;
        write("%s\n", postMan.passwordB64.c_str());
        break;
    case RECV_PASSWORD_235:
        state = SEND_MAIL_FROM;
        write("mail from:<%s>\n", postMan.account.c_str());
        break;
    case RECV_MAIL_FROM_250:
        state = SEND_RCPT_TO;
        write("rcpt to:<%s>\n", email->to.c_str());
        break;
    case RECV_RCPT_TO_250:
        state = SEND_DATA;
        write("data\n");
        break;
    case RECV_DATA_354:
        state = SEND_EMAIL;
        write("from:<%s>\n"
              "to:<%s>\n"
              "subject:%s\n"
              "%s"
              "\r\n.\r\n",
              postMan.account.c_str(), email->to.c_str(),
              email->subject.c_str(), email->body.c_str());
        break;
    case RECV_EMAIL_250:
        if(callback) {
            callback(
                charBuffer[0] == '2' && charBuffer[1] == '5' && charBuffer[2] == '0' ?
                ErrorCode::OK : ErrorCode::ERROR);
        }
        delete this;
        break;
    }
}

void EPostMan::SendProcess::read()
{
    postMan.socket.async_read_some(asio::buffer(charBuffer), std::ref(*this));
}
void EPostMan::SendProcess::write(const char* strf, ...)
{
    va_list argptr;
    va_start(argptr, strf);
    vsnprintf(charBuffer.data(), BUFFER_SIZE, strf, argptr);
    va_end(argptr);
    asio::async_write(
        postMan.socket,
        asio::buffer(charBuffer, strlen(charBuffer.data())),
        std::ref(*this)
    );
}

void EPostMan::SendProcess::incState()
{
    int x = static_cast<int>(state);
    x++;
    state = static_cast<State>(x);
}
