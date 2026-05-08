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

// 命名空间
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

// 通用WS会话模板：同时支持裸TCP(WS) / SSL(WSS)
template<class NextLayer>
class WsSession : public std::enable_shared_from_this<WsSession<NextLayer>>
{
public:
    using Self = WsSession<NextLayer>;

    // 直接接收带strand的下层流，自动继承strand串行执行
    explicit WsSession(NextLayer layer)
        : ws_(std::move(layer))
        , state_(SessionState::OPEN)
    {
        // 基础协议配置
        ws_.set_option(ws::stream_base::timeout::suggested(beast::role_type::server));
        // 读写超时60s，自动回收僵死半开连接
        ws_.set_option(ws::stream_base::timeout{
            std::chrono::seconds(60),
            std::chrono::seconds(60),
            true
        });
        // 限制最大消息1MB，防DoS超大包攻击
        ws_.set_option(ws::stream_base::max_message_size(1024 * 1024));
        // 关闭消息分片，简化业务处理
        ws_.set_option(ws::stream_base::read_fragment_mode(false));

        ws_.set_option(ws::stream_base::decorator(
            [](ws::response_type& res)
            {
                res.set(beast::http::field::server, "Production-WS-WSS-Server");
                res.set(beast::http::field::cache_control, "no-cache");
            }));
    }

    void run()
    {
        do_handshake();
    }

    // 外部多线程安全发送消息
    void send_message(std::string msg)
    {
        // 已关闭直接拒绝入队
        if (state_.load(std::memory_order_acquire) != SessionState::OPEN)
        {
            return;
        }

        std::lock_guard<std::mutex> lock(queue_mtx_);
        bool need_wake = send_queue_.empty();
        send_queue_.push(std::move(msg));

        // 队列为空才唤醒写循环，避免重复递归
        if (need_wake)
        {
            auto self(this->shared_from_this());
            // 投递到当前连接绑定的strand串行执行
            asio::post(ws_.get_executor(), [self](){ self->do_write_loop(); });
        }
    }

    // 服务端主动关闭：仅标记CLOSING，等待队列发完再关
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

        std::cout << "[Sys] 服务端主动发起关闭，等待缓冲区消息发送完成..." << std::endl;

        std::lock_guard<std::mutex> lock(queue_mtx_);
        if (send_queue_.empty())
        {
            auto self(this->shared_from_this());
            asio::post(ws_.get_executor(), [self](){ self->do_async_close(); });
        }
    }

private:
    // 流对象，内部自带strand，所有IO自动串行
    ws::stream<NextLayer> ws_;
    beast::flat_buffer    read_buf_;

    // 原子状态，无锁线程安全
    std::atomic<SessionState> state_;
    // 发送队列 + 互斥锁保护多线程入队
    std::queue<std::string>   send_queue_;
    std::mutex                queue_mtx_;

    // WebSocket握手
    void do_handshake()
    {
        auto self(this->shared_from_this());
        ws_.async_accept([self](beast::error_code ec)
        {
            if (!ec)
            {
                std::cout << "[WS] 握手成功" << std::endl;
                self->do_read();
            }
            else
            {
                std::cout << "[WS] 握手失败: " << ec.message() << std::endl;
                self->do_final_close();
            }
        });
    }

    // 常驻读循环：持续消费TCP接收缓冲区，杜绝Zero Window
    void do_read()
    {
        auto self(this->shared_from_this());
        ws_.async_read(read_buf_, [self](beast::error_code ec, std::size_t)
        {
            self->on_read(ec);
        });
    }

    void on_read(beast::error_code ec)
    {
        // 已彻底关闭，直接终止
        if (state_.load(std::memory_order_acquire) == SessionState::CLOSED)
        {
            return;
        }

        // 收到客户端Close帧：只标记CLOSING，不停止读循环、不粗暴关闭
        // 持续do_read消费内核TCP缓冲区，防止缓冲区满→Zero Window→客户端重传
        if (ec == ws::error::closed)
        {
            std::cout << "[WS] 客户端主动断连，等待服务端缓冲区发完再优雅关闭" << std::endl;

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
            // 关键：不return终止读，下一轮继续do_read，持续清空TCP缓冲区
            do_read();
            return;
        }

        // 网络异常、连接断开
        if (ec)
        {
            std::cout << "[WS] 读取异常: " << ec.message() << std::endl;
            do_final_close();
            return;
        }

        // 业务消息处理
        std::string recv_msg = beast::buffers_to_string(read_buf_.data());
        std::cout << "[Recv] " << recv_msg << std::endl;

        // 消耗缓冲区并缩容，避免长连接内存膨胀
        read_buf_.consume(read_buf_.size());
        read_buf_.shrink_to_fit();

        // 继续常驻读循环
        do_read();
    }

    // 串行发送循环：异步递归天然串行，无需sending_标记
    void do_write_loop()
    {
        std::lock_guard<std::mutex> lock(queue_mtx_);
        if (send_queue_.empty())
        {
            // 队列发完，且处于关闭中，发起WS关闭握手
            if (state_.load(std::memory_order_acquire) == SessionState::CLOSING)
            {
                std::cout << "[WS] 缓冲区全部消息发送完毕，发起关闭握手" << std::endl;
                do_async_close();
            }
            return;
        }

        // 取出队首消息发送
        std::string msg = std::move(send_queue_.front());
        send_queue_.pop();

        auto self(this->shared_from_this());
        ws_.async_write(asio::buffer(msg), [self](beast::error_code ec, std::size_t)
        {
            if (ec)
            {
                std::cout << "[WS] 发送异常: " << ec.message() << std::endl;
                self->do_final_close();
                return;
            }
            // 递归继续发送下一条
            self->do_write_loop();
        });
    }

    // 发起WebSocket标准关闭帧
    void do_async_close()
    {
        auto self(this->shared_from_this());
        ws_.async_close(ws::close_code::normal, [self](beast::error_code ec)
        {
            if (ec)
            {
                std::cout << "[WS] 关闭帧发送异常: " << ec.message() << std::endl;
            }
            self->do_final_close();
        });
    }

    // 最终关闭：防重复关闭、手动close保证TCP四次挥手
    void do_final_close()
    {
        // CAS原子防重复关闭
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
        // 手动关闭底层socket，不依赖析构粗暴RST，保证标准四次挥手
        ws_.next_layer().close(ec);
        if (ec)
        {
            std::cout << "[Close] Socket关闭异常: " << ec.message() << std::endl;
        }
        else
        {
            std::cout << "[Close] 连接优雅关闭，TCP四次挥手完成" << std::endl;
        }
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
        // make_strand 为每个新连接分配独立strand
        acceptor_.async_accept(
            asio::make_strand(ioc_),
            beast::bind_front_handler(&WsListener::on_accept, this));
    }

    void on_accept(beast::error_code ec, tcp::socket socket)
    {
        if (!ec)
        {
            // 直接传入带strand的socket，会话自动继承串行
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
        acceptor_.async_accept(
            asio::make_strand(ioc_),
            beast::bind_front_handler(&WssListener::on_accept, this));
    }

    void on_accept(beast::error_code ec, tcp::socket socket)
    {
        if (!ec)
        {
            // 包装SSL流，继承原有strand
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

// 初始化SSL上下文（生产安全加固配置）
ssl::context create_ssl_context()
{
    ssl::context ctx(ssl::context::tlsv12_server);
    // 禁用老旧不安全协议
    ctx.set_options(ssl::context::default_workarounds
        | ssl::context::no_sslv2
        | ssl::context::no_sslv3
        | ssl::context::no_tlsv1
        | ssl::context::no_tlsv11
        | ssl::context::single_dh_use);

    // 加载证书和私钥
    ctx.use_certificate_chain_file("server.crt");
    ctx.use_private_key_file("server.key", ssl::context::pem);
    return ctx;
}

int main()
{
    try
    {
        // 20线程IO池，完全安全无竞态
        asio::io_context ioc{20};

        // 启动普通WS 8080端口
        WsListener wsServer(ioc, 8080);

        // 启动WSS 8443端口
        ssl::context ssl_ctx = create_ssl_context();
        WssListener wssServer(ioc, 8443, ssl_ctx);

        // 启动工作线程
        std::vector<std::thread> threads;
        for (size_t i = 0; i < 20; ++i)
        {
            threads.emplace_back([&ioc](){ ioc.run(); });
        }

        // 等待所有线程结束
        for (auto& t : threads)
        {
            t.join();
        }
    }
    catch (std::exception& e)
    {
        std::cerr << "[Main] 全局异常: " << e.what() << std::endl;
    }
    return 0;
}