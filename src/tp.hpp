#ifndef __TP_HPP__
#define __TP_HPP__

#include <iostream>
#include <vector>
#include <memory>
#include <map>
#include <mutex>
#include <thread>
#include <sys/time.h>
#include <map>
#include <condition_variable>
#if defined(USE_LIB_CONFIG)
 #include <libconfig.h++>
#endif

#include "dot2common.hpp"
#include "dot2cert.hpp"
#include "dot2data.hpp"

void print_data(const char* file, const uint8_t *buf, size_t len);

namespace ctp
{
    class TP //:public std::enable_shared_from_this<TP>
    {
        //private:
        using TP_PTR = std::shared_ptr<TP>;
        tp_cfg *cfg;
        std::map<int, psid_tp_client*> psid_clients;
        std::vector<client_msg*> q_in_msg;
        std::vector<client_msg*> q_out_msg;
        bool init_done;
        bool stop_;
       std::shared_ptr<Ieee1609Certs> certs;
        public:
            void enrol_mgr();
            void cert_mgr();
            void crl_mgr();
            void report_mgr();
        public:
            /* delete conpy constructor */
            TP(const TP&) = delete;
            /* delete copy assignment */
            const TP& operator=(const TP&)=delete;
            TP(); /* private constructor */
            ~TP();
            void cfg_mgr();
            int verify();
            /* asynchronous verfication routine */
            int verify(void *buf, size_t length);
            /* synchronous verification routine */
            int verify(void *buf, size_t length, uint8_t **out, size_t *outLength);
            int sign();
            /* let this be the blocking call */
            int sign(const int psid, const uint8_t *buf, size_t len,
                  uint8_t **signedData, size_t *signedDataLen);
            int encrypt();
            int decrypt();
            TP_PTR instance_get();
            // static TP_PTR init();
            TP_PTR  init();
            void start();
            void stop();
            void psid_list();
            void curves_list();
            /* register a  client with the given psid */
            void client_register(const int psid, std::shared_ptr<tp_client> obj);
            /* process clients */
            void process_clients();

            std::mutex q_in_mutex;
            std::mutex q_out_mutex;

            std::thread t_in_thread;
    };
}/* namespace ctp */

#endif //__TP_HPP__