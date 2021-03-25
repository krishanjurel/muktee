#include <iostream>
#include <memory>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <netdb.h>
#include <thread>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <unistd.h>

#ifdef __cplusplus
extern "C"
{
#endif
void close_socket(int fd)
{
    close(fd);
}

#ifdef __cplusplus
}
#endif


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
            }

            ~_remote()
            {
                close_socket(fd);
            }

        int create(std::string& addr,int domain = AF_LOCAL, int type = SOCK_SEQPACKET, int protocol=0)
        {
            int ret = 0;
            int sockVal = 1;
            
            if(static_cast<int>(this->type)==static_cast<int>(Type::server))
            {
                unlink(addr.c_str());
            }

            fd = socket(domain, type, protocol);
            if(fd == -1)
            {
                perror("_remote::create");
                return fd;
            }

            if(setsockopt(fd, SOL_SOCKET,SO_REUSEADDR,&sockVal, sizeof(int)) == -1)
            {
                perror ("remote::_remote::setsockopt");
            }

            // if(domain == AF_LOCAL)
            {
                /* use the struct sockaddr_un to create a handle to a file */
                
                /* reset the structure */
                memset(&my_addr, 0, sizeof(my_addr));
                my_addr.sun_family = domain;
                strncpy(my_addr.sun_path, addr.c_str(), sizeof(my_addr.sun_path)-1);
            }
            // else if(domain == AF_UNSPEC){
            //     struct addrinfo hints;
            //     hints.ai_family=domain;
            //     hints.ai_socktype = 0; /* anytype*/
            //     hints.ai_protocol = 0;
            //     hints.ai_flags = AI_PASSIVE;

            //     getaddrinfo()

            // }
            if(static_cast<int>(this->type) == static_cast<int>(Type::server))
            {
                std::cout << "bind " << my_addr.sun_path << std::endl;
                ret = bind(fd, (struct sockaddr *)&my_addr, sizeof(my_addr));
                if(ret == -1)
                {
                    perror("_remote::create::bind");
                    close(fd);
                    fd = -1;
                    return fd;
                }
                ret =  listen(fd, 20);
                if(ret == -1)
                {
                    perror("_remote::create::listen");
                    close(fd);
                    fd = -1;
                    return fd;
                }
            }
            return fd;
        }

        void start()
        {
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
            int count = 0;
            int data_socket=0;
            int ret = 0;
            bool connected = false;

            while(!stop_)
            {
                if(connected == false)
                {
                    ret = connect(fd, (struct sockaddr *)&my_addr, sizeof(my_addr));
                    if(ret == -1 && errno != EISCONN)
                    {
                        
                        std::cout << " error " << errno << " " << strerror(errno) << std::endl;
                        perror("_remote::remote::cleint::connect");
                        /* try after 5 seconds */
                        std::this_thread::sleep_for(std::chrono::seconds(5));
                        continue;
                    }
                    connected == true;
                }

                std::this_thread::sleep_for(std::chrono::milliseconds(500));
                ret = write(fd, msg.c_str(),msg.size());
                if(ret == -1)
                {
                    perror("remote::_remote::client::write");
                    stop_= 1;
                }else{
                    std::cout << "msg " << msg.c_str() << " written " << std::endl;

                }
            }
            close_socket(fd);
        }

        void server()
        {
            std::cout << "server thread handler" << std::endl;
            std::string msg("this is test messgae ");
            int count = 0;
            int data_socket=0;
            int ret = 0;
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