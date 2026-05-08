#include <iostream>
#include <memory>
#include <string>
#include <queue>
#include <mutex>
#include <thread>
#include <atomic>
#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include <boost/asio/ssl.hpp>

namespace asio  = boost::asio;
namespace beast = boost::beast;
namespace ws    = beast::websocket;
namespace ssl   = boost::asio::ssl;
using tcp       = boost::asio::ip::tcp;

// 会话状态
enum class SessionState
{
    OPEN,
    CLOSING,
    CLOSED
};

// 模板会话：同时支持 裸TCP(WS) / SSL(WSS)
template<class NextLayer>
class WsSession : public std::enable_shared_from_this<WsSession<NextLayer>>
{
public:
    using Self = WsSession<NextLayer>;

    explicit WsSession(NextLayer layer)
        : ws_(std::move(layer))
        , state_(SessionState::OPEN)
    {
        // WebSocket 服务端标准配置
        ws_.set_option(ws::stream_base::timeout::suggested(beast::role_type::server));
        // 读写超时 60s 自动回收僵死连接
        ws_.set_option(ws::stream_base::timeout{
            std::chrono::seconds(60),
            std::chrono::seconds(60),
            true
        });
        // 限制最大单条消息 1MB 防DoS
        ws_.set_option(ws::stream_base::max_message_size(1024 * 1024));

        ws_.set_option(ws::stream_base::decorator(
            [](ws::response_type& res)
            {
                res.set(beast::http::field::server, "WS-WSS-Standard-Server");
            }));
    }

    void run()
    {
        do_handshake();
    }

    // 线程安全发送消息
    void send_message(std::string msg)
    {
        if (state_.load(std::memory_order_acquire) != SessionState::OPEN)
            return;

        std::lock_guard<std::mutex> lock(queue_mtx_);
        bool need_wake = send_queue_.empty();
        send_queue_.push(std::move(msg));

        if (need_wake)
        {
            do_write_loop();
        }
    }

    // 服务端主动关闭：标记CLOSING，等队列发完再关
    void server_close()
    {
        SessionState expected = SessionState::OPEN;
        if (!state_.compare_exchange_strong(
            expected, SessionState::CLOSING,
            std::memory_order_release,
            std::memory_order_acquire))
        {
            return;
        }

        std::cout << "[Sys] 服务端主动断连，等待缓冲区数据发送完成..." << std::endl;

        std::lock_guard<std::mutex> lock(queue_mtx_);
        if (send_queue_.empty())
        {
            do_async_close();
        }
    }

private:
    ws::stream<NextLayer> ws_;
    beast::flat_buffer    read_buf_;

    std::atomic<SessionState> state_;
    std::queue<std::string>   send_queue_;
    std::mutex                queue_mtx_;

    // WebSocket握手
    void do_handshake()
    {
        auto self(this->shared_from_this());
        ws_.async_accept(beast::bind_front_handler(&Self::on_handshake, self));
    }

    void on_handshake(beast::error_code ec)
    {
        if (ec)
        {
            std::cout << "[WS] 握手失败: " << ec.message() << std::endl;
            do_final_close();
            return;
        }
        std::cout << "[WS] 握手成功" << std::endl;
        do_read();
    }

    // 常驻读循环
    void do_read()
    {
        auto self(this->shared_from_this());
        ws_.async_read(read_buf_,
            [self](beast::error_code ec, std::size_t)
            {
                self->on_read(ec);
            });
    }

    void on_read(beast::error_code ec)
    {
        if (state_.load(std::memory_order_acquire) == SessionState::CLOSED)
            return;

        // 客户端主动断连：收到Close帧，先标记CLOSING，等队列发完再关
        if (ec == ws::error::closed)
        {
            std::cout << "[WS] 客户端主动断连，等待服务端缓冲区发完再关闭..." << std::endl;

            SessionState expected = SessionState::OPEN;
            if (state_.compare_exchange_strong(
                expected, SessionState::CLOSING,
                std::memory_order_release,
                std::memory_order_acquire))
            {
                std::lock_guard<std::mutex> lock(queue_mtx_);
                if (send_queue_.empty())
                {
                    do_async_close();
                }
            }
            return;
        }

        // 网络异常
        if (ec)
        {
            std::cout << "[WS] 读取异常: " << ec.message() << std::endl;
            do_final_close();
            return;
        }

        // 业务消息
        std::string recv_msg = beast::buffers_to_string(read_buf_.data());
        std::cout << "[Recv] " << recv_msg << std::endl;

        read_buf_.consume(read_buf_.size());
        do_read();
    }

    // 串行发送循环：无sending_，靠递归天然串行
    void do_write_loop()
    {
        std::lock_guard<std::mutex> lock(queue_mtx_);
        if (send_queue_.empty())
        {
            // 队列发完，进入关闭流程
            if (state_.load(std::memory_order_acquire) == SessionState::CLOSING)
            {
                std::cout << "[WS] 缓冲区全部发完，发起关闭握手" << std::endl;
                do_async_close();
            }
            return;
        }

        std::string msg = std::move(send_queue_.front());
        send_queue_.pop();

        auto self(this->shared_from_this());
        ws_.async_write(asio::buffer(msg),
            [self](beast::error_code ec, std::size_t)
            {
                if (ec)
                {
                    std::cout << "[WS] 发送异常: " << ec.message() << std::endl;
                    self->do_final_close();
                    return;
                }
                self->do_write_loop();
            });
    }

    // 发起WS关闭帧
    void do_async_close()
    {
        auto self(this->shared_from_this());
        ws_.async_close(ws::close_code::normal,
            [self](beast::error_code ec)
            {
                if (ec)
                    std::cout << "[WS] 关闭帧异常: " << ec.message() << std::endl;
                self->do_final_close();
            });
    }

    // 最终优雅关闭
    void do_final_close()
    {
        SessionState expected;
        expected = SessionState::OPEN;
        if (!state_.compare_exchange_strong(
            expected, SessionState::CLOSED,
            std::memory_order_release,
            std::memory_order_acquire))
        {
            expected = SessionState::CLOSING;
            if (!state_.compare_exchange_strong(
                expected, SessionState::CLOSED,
                std::memory_order_release,
                std::memory_order_acquire))
            {
                return;
            }
        }

        beast::error_code ec;
        // 手动关闭底层socket，保证四次挥手，不依赖析构
        ws_.next_layer().close(ec);

        if (ec)
            std::cout << "[Close] 关闭异常: " << ec.message() << std::endl;
        else
            std::cout << "[Close] 连接优雅关闭" << std::endl;
    }
};

// 普通WS监听器
class WsListener
{
public:
    WsListener(asio::io_context& ioc, unsigned short port)
        : ioc_(ioc)
        , acceptor_(ioc, tcp::endpoint(tcp::v4(), port))
    {
        std::cout << "[WS] 监听 ws://0.0.0.0:" << port << std::endl;
        do_listen();
    }

private:
    asio::io_context& ioc_;
    tcp::acceptor     acceptor_;

    void do_listen()
    {
        acceptor_.async_accept(beast::bind_front_handler(&WsListener::on_accept, this));
    }

    void on_accept(beast::error_code ec, tcp::socket socket)
    {
        if (!ec)
        {
            std::make_shared<WsSession<tcp::socket>>(std::move(socket))->run();
        }
        do_listen();
    }
};

// WSS SSL监听器
class WssListener
{
public:
    WssListener(asio::io_context& ioc, unsigned short port, ssl::context& ctx)
        : ioc_(ioc)
        , ctx_(ctx)
        , acceptor_(ioc, tcp::endpoint(tcp::v4(), port))
    {
        std::cout << "[WSS] 监听 wss://0.0.0.0:" << port << std::endl;
        do_listen();
    }

private:
    asio::io_context& ioc_;
    ssl::context&     ctx_;
    tcp::acceptor     acceptor_;

    void do_listen()
    {
        acceptor_.async_accept(beast::bind_front_handler(&WssListener::on_accept, this));
    }

    void on_accept(beast::error_code ec, tcp::socket socket)
    {
        if (!ec)
        {
            auto ssl_stream = std::make_shared<ssl::stream<tcp::socket>>(std::move(socket), ctx_);
            ssl_stream->async_handshake(ssl::stream_base::server,
                [ssl_stream](beast::error_code ec)
                {
                    if (!ec)
                    {
                        std::make_shared<WsSession<ssl::stream<tcp::socket>>>(std::move(*ssl_stream))->run();
                    }
                });
        }
        do_listen();
    }
};

// 初始化SSL上下文
ssl::context create_ssl_context()
{
    ssl::context ctx(ssl::context::tlsv12_server);
    ctx.set_options(ssl::context::default_workarounds
        | ssl::context::no_sslv2
        | ssl::context::no_sslv3
        | ssl::context::single_dh_use);

    // 证书私钥路径
    ctx.use_certificate_chain_file("server.crt");
    ctx.use_private_key_file("server.key", ssl::context::pem);
    return ctx;
}

int main()
{
    try
    {
        // IO线程数，生产可开大
        asio::io_context ioc{2};

        // 启动普通WS 8080
        WsListener wsServer(ioc, 8080);

        // 启动WSS 8443
        ssl::context ssl_ctx = create_ssl_context();
        WssListener wssServer(ioc, 8443, ssl_ctx);

        ioc.run();
    }
    catch (std::exception& e)
    {
        std::cout << "[Main] 异常: " << e.what() << std::endl;
    }
    return 0;
}