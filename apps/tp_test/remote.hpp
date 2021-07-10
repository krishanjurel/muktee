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
    _Float64 longitude;
    _Float64 latitude;
    _Float64 heading;
    _Float64 speed;
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
        
        std::thread m_thread;
        int stop_;
        Type type;
        struct sockaddr_un my_addr, peer_addr;
        sa_family_t saFamily;
        size_t addrlen;
        uint16_t port;
        struct sockaddr _sockadr;
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

        // int create(std::string& addr,int domain = AF_LOCAL, int type = SOCK_SEQPACKET, int protocol=0)
        // {
        //     int ret = 0;
        //     int sockVal = 1;
        //     if(static_cast<int>(this->type)==static_cast<int>(Type::server))
        //     {
        //         unlink(addr.c_str());
        //     }

        //     fd = socket(domain, type, protocol);
        //     if(fd == -1)
        //     {
        //         perror("_remote::create");
        //         return fd;
        //     }

        //     if(setsockopt(fd, SOL_SOCKET,SO_REUSEADDR,&sockVal, sizeof(int)) == -1)
        //     {
        //         perror ("remote::_remote::setsockopt");
        //     }
        //     if(this->type == Type::client)
        //     {
        //         struct addrinfo _hints;
        //         _hints.ai_family = AF_UNSPEC;
        //         _hints.ai_socktype = type;
        //     }


        //     // if(domain == AF_LOCAL)
        //     {
        //         /* use the struct sockaddr_un to create a handle to a file */
        //         /* reset the structure */
        //         memset(&my_addr, 0, sizeof(my_addr));
        //         my_addr.sun_family = domain;
        //         strncpy(my_addr.sun_path, addr.c_str(), sizeof(my_addr.sun_path)-1);
        //     }
        //     // else if(domain == AF_UNSPEC){
        //     //     struct addrinfo hints;
        //     //     hints.ai_family=domain;
        //     //     hints.ai_socktype = 0; /* anytype*/
        //     //     hints.ai_protocol = 0;
        //     //     hints.ai_flags = AI_PASSIVE;

        //     //     getaddrinfo()

        //     // }
        //     if(static_cast<int>(this->type) == static_cast<int>(Type::server))
        //     {
        //         std::cout << "bind " << my_addr.sun_path << std::endl;
        //         ret = bind(fd, (struct sockaddr *)&my_addr, sizeof(my_addr));
        //         if(ret == -1)
        //         {
        //             perror("_remote::create::bind");
        //             close(fd);
        //             fd = -1;
        //             return fd;
        //         }
        //         ret =  listen(fd, 20);
        //         if(ret == -1)
        //         {
        //             perror("_remote::create::listen");
        //             close(fd);
        //             fd = -1;
        //             return fd;
        //         }
        //     }
        //     return fd;
        // }

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

        /* client handler */
        void client()
        {
            std::cout << "client thread handler" << std::endl;
            std::string msg("this is test messgae ");
            // int count = 0;
            // int data_socket=0;
            int ret = 0;
            bool connected = false;
            struct remote_data remoteData{0};

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
                // std::this_thread::sleep_for(std::chrono::milliseconds(500));
                // ret = write(fd, msg.c_str(),msg.size());
                remoteData.id = 12345;
                remoteData.heading = 1.0523;
                remoteData.speed = 2.52437;
                remoteData.longitude += 1.0867;
                remoteData.latitude += 2.0566;
                ret = sendto(fd, (void *)&remoteData, sizeof(remoteData),0,(struct sockaddr *)&peer_addr, sizeof(struct sockaddr_un));
                if(ret == -1 || ret != sizeof(remoteData))
                {
                    perror("remote::_remote::client::write");
                    std::cout << "num bytes written " << ret << " written " << std::endl;
                    stop_= 1;
                }
                // else{
                //     std::cout << "num bytes " << ret << " written " << std::endl;

                // }
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
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
