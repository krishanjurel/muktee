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
#include "tp_util.hpp"
#include "dot2common.hpp"
#include "dot2cert.hpp"
#include "dot2data.hpp"

namespace ctp
{
    class TP;
    using PTR_TP = TP *;
    using SHARED_TP = std::shared_ptr<TP>;

    class TP //:public std::enable_shared_from_this<TP>
    {

        std::shared_ptr<tp_cfg> cfg;
        bool init_done;
        bool stop_;

        std::vector<client_msg*> q_in_msg;
        std::vector<client_msg*> q_out_msg;
        std::mutex q_in_mutex;
        std::mutex q_out_mutex;
        std::thread t_in_thread;

        std::map<int, psid_tp_client*> psid_clients;


        /* cert manager */
        SHARED_CERTMGR certMgr;
        SHARED_CERT cert;

        const int MODULE = MODULE_TP;


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
            /* delete move` constructor */
            TP(const TP&&) = delete;
            /* delete move assignment */
            const TP& operator=(const TP&&)=delete;

            TP(); /* private constructor */
            ~TP();
            void cfg_mgr();
            /* control blocks */
            SHARED_TP instance_get();
            // static TP_PTR init();
            // SHARED_TP  init();
            void start();
            void stop();

            /* register a  client with the given psid */
            void client_register(const int psid, std::shared_ptr<tp_client> obj);
            /* process clients */
            void process_clients();


            /* verification methods */
            int verify();
            /* asynchronous verfication routine */
            int verify(void *buf, size_t length);
            /* synchronous verification routine */
            int verify(void *buf, size_t length, uint8_t **out, size_t *outLength);

            /* sign methods */
            int sign();
            /* let this be the blocking call */
            int sign(const int psid, const uint8_t *buf, size_t len,
                  uint8_t **signedData, size_t *signedDataLen);

            /* encryption/decryption methods */
            int encrypt();
            int decrypt();

            /* get the list of supported psids for self-signed certs */
            const std::vector<int>& psid_list() const;
            void curves_list();

            /* to keep track of calling process */
            const int module_id_get() const {
                // char thrdId[16];
                // pthread_getname_np(pthread_self(), thrdId, 16);
                // return atoi(thrdId);
                return MODULE;
            }

            const void module_id_set(const int id)
            {
                char thrdId[16];
                snprintf(thrdId, sizeof(thrdId), "%d", id);
                pthread_setname_np(pthread_self(), thrdId);
            }
    };
}/* namespace ctp */

#endif //__TP_HPP__