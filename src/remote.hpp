#include <iostream>
#include <memory>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/un.h>
#include <sys/types.h>
#include <netdb.h>
#include <thread>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <unistd.h>
#include <condition_variable>
#include <vector>


#ifdef __cplusplus
extern "C"{
#endif
void close_socket(int fd)
{
    close(fd);
}

#ifdef __cplusplus
}
#endif

extern "C"
{
struct __attribute__((__packed__))remote_data
{
    int id;
    int msgcount;
    double longitude;
    double latitude;
    double heading;
    double speed;
};
}


namespace remote
{


    enum class Type {
            server,
            client
        };

    class _remote;

    typedef std::shared_ptr<_remote> SharedRemotePtr;

    class _remote:public std::enable_shared_from_this<_remote>
    {
        int fd; /* socket decscriptor */
        int domain;
        int protocol;

        std::condition_variable cv;
        std::mutex m;
        std::thread m_thread;
        int stop_;
        Type type;
        struct sockaddr_un my_addr, peer_addr;
        sa_family_t saFamily;
        size_t addrlen;
        uint16_t port;
        struct sockaddr _sockadr;
        struct remote_data *_rem_data;

        std::vector<struct remote_data *> dataList;



        public:
            SharedRemotePtr get()
            {
                return shared_from_this();
            }

            _remote(Type type=Type::server)
            {
                this->type = type;
                fd = -1;
                stop_ = 0;
                addrlen = INET_ADDRSTRLEN;
            }

            ~_remote()
            {
                close_socket(fd);
            }

            int create(std::string& peer, int port, int domain = AF_UNSPEC, int type = SOCK_DGRAM, int protocol=0)
            {
                struct addrinfo hints;
                struct addrinfo *res = nullptr;
                const char *node = nullptr;
                std::string service(std::to_string(port));


                hints.ai_family = domain;
                hints.ai_socktype = type;
                hints.ai_protocol = protocol;
                hints.ai_addr = nullptr;
                hints.ai_canonname = nullptr;
                hints.ai_next = nullptr;

                this->port = port;


                hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;

                if(this->type == Type::server)
                {
                    hints.ai_flags = AI_PASSIVE; /*fill my address for me */
                }

                if(!peer.empty())
                    node = peer.c_str();
                if(port > 0)
                    service = std::to_string(port);
                std::cout << "port numeber " << service << std::endl;
                int ret = getaddrinfo(node, service.c_str(), &hints,&res);
                if(ret != 0)
                {
                    perror("getaddrinfo failes");
                    std::cout << "getaddrinfo error " << gai_strerror(ret) << std::endl;
                    return ret;
                }
                struct addrinfo *_res = res;

                while (res != nullptr)
                {
                    /* lets just take the first one */
                    fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
                    if(fd == -1)
                    {
                        perror("socket failed");
                        res = res->ai_next;
                        continue;
                    }
                    if(this->type == Type::server)
                    {
                        if(bind(fd, res->ai_addr, res->ai_addrlen) == 0) break;
                    }else{
                            memcpy(&peer_addr, res->ai_addr, res->ai_addrlen);
                            break;
                    }

                    close(fd);
                    res = res->ai_next;
                }

                if(_res)
                    freeaddrinfo(_res);
                return 0;
           }
        void start()
        {
            std::cout << "start the the network thread" << std::endl;
            if(static_cast<int>(type) == static_cast<int>(Type::server))
            {
                m_thread = std::thread(&_remote::server, this);
            }else{
                m_thread = std::thread(&_remote::client, this);
            }
           m_thread.detach();
        }
        void stop()

        {
            stop_=1;
        }

        void data_send(const struct remote_data data)
        {
            {
                /* acquire the lock */
                std::lock_guard<std::mutex> lck(m);
                _rem_data = (remote_data *)malloc(sizeof(remote_data));
                if(_rem_data == nullptr)
                {
                    return ;
                }
                _rem_data->id = data.id;
                _rem_data->msgcount = data.msgcount;
                _rem_data->heading = data.heading;
                _rem_data->longitude = data.longitude;
                _rem_data->latitude = data.latitude;
                _rem_data->speed = data.speed;
                dataList.push_back(_rem_data);
                cv.notify_all();
            }
        }

        /* client handler */
        void client()
        {
            std::cout << "client thread handler" << std::endl;
            std::string msg("this is test messgae ");
            // int count = 0;
            // int data_socket=0;
            int ret = 0;
            bool connected = false;
            struct remote_data *remoteData;

            while(!stop_)
            {
                if(connected == false)
                {
                    ret = connect(fd, (struct sockaddr *)&peer_addr, sizeof(struct sockaddr_un));
                    if(ret == -1 && errno != EISCONN)
                    {
                        
                        std::cout << " error " << errno << " " << strerror(errno) << std::endl;
                        perror("_remote::remote::cleint::connect");
                        /* try after 5 seconds */
                        std::this_thread::sleep_for(std::chrono::seconds(5));
                        continue;
                    }
                    connected = true;
                }
                /* wait for data arrival */
                {
                    std::unique_lock<std::mutex> lck(m);
                    cv.wait(lck, [this](){return dataList.size() != 0;});
                    while(dataList.size() != 0)
                    {
                        remoteData = (remote_data *)dataList.front();
                        dataList.pop_back();
                        ret = sendto(fd, (void *)remoteData, sizeof(*remoteData),0,(struct sockaddr *)&peer_addr, sizeof(struct sockaddr_un));
                        if(ret == -1 || ret != sizeof(*remoteData))
                        {
                            perror("remote::_remote::client::write");
                            std::cout << "num bytes written " << ret << " written " << std::endl;
                            stop_= 1;
                        }
                        free(remoteData);
                    }
                    // lck.unlock();
                }
            }
            close_socket(fd);
        }

        void server()
        {
            std::cout << "server thread handler" << std::endl;
            std::string msg("this is test messgae ");
            // int count = 0;
            // int data_socket=0;
            // int ret = 0;
            struct sockaddr_un peer_addr;
            socklen_t peer_addr_len;
            std::thread _thread;

            while(!stop_)
            {
                int data_socket = accept(fd,(struct sockaddr *)&peer_addr,&peer_addr_len);
                if(data_socket == -1)
                {
                    perror("remote::_remote::accept");
                    stop_=1;
                    continue;
                }
                std::cout << "incoming connection from " << peer_addr.sun_path << std::endl;

                _thread = std::thread(&_remote::handle_connection, this, data_socket);
                _thread.detach();
            }
            close_socket(fd);
        }

        /* this is the thread that handles the incoming data */
        void handle_connection(int fd)
        {
            fd_set rd;
            // FD_CLR(fd, &rd);
            // FD_CLR(fd, &wr);
            FD_ZERO(&rd);
            // FD_ZERO(&wr);

            FD_SET(fd, &rd);
            // FD_SET(fd, &wr);
            int nfd = fd + 1;
            uint8_t buffer[256];

            std::cout << " handle_connection " << fd << std::endl;
            while(!stop_)
            {
                int ret = select(nfd,&rd, NULL, NULL, NULL);
                if(ret == -1)
                {
                    stop_=1;
                }
                /* fd is set set in rd descriptor*/
                if(FD_ISSET(fd, &rd))
                {
                    /* read the available bytes */
                    int data = read(fd, buffer, sizeof(buffer));
                    if(data == -1)
                    {
                        perror("remote::_remote::handle_connection");
                        stop_ = 1;
                    }else{
                        std::cout << " read " << buffer << std::endl;
                    }
                }
                /* reinitialize the read mask */
                FD_ZERO(&rd);
                FD_SET(fd, &rd);
            }
        }
        // /* the function to handle data on the given file descriptor */
        // void handler(int sfd)
        // {
        // }
    }; /* class network */
}; /* name space remote */
