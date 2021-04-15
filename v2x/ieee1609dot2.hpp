#ifndef __IEEE_1609DOT2_HPP__
#define __IEEE_1609DOT2_HPP__
#include <stdint.h>
#include <iostream>
#include <memory>
#include <vector>
#include <sstream>
#include "ieee1609dot2common.hpp"
#include "libconfig.h++"
#include "openssl/ec.h"
#include "openssl/ecdsa.h"
#include "openssl/obj_mac.h"
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <exception>
#include <mutex>
#include <condition_variable>
#include <thread>

/*  This encpasulation of data definition, declaration of 
    IEEE 1609.2-2016     specification 
*/

void print_data(const char* file, const uint8_t *buf, size_t len);

namespace ctp
{
    class Exception:public std::exception
    {
        std::string *msg;
        public:
            Exception(std::string _msg):msg(new std::string(_msg)){};
            const char* what() const noexcept
            {
                return msg->c_str();
            }

            ~Exception()
            {
                delete msg;
            }
    };

    /* used for allocation/deallocation */
    class mem_mgr
    {
        const size_t alloc_multiple = 512;
        /* allocated memory*/
        size_t allocated_;
        /* used memory */
        size_t used_;
        /* allocated address */
        void *addr_;
        public:
            mem_mgr():allocated_(0), used_(0), addr_(0){};
            void* buf_alloc(size_t s)
            {
                try
                {
                    addr_ = malloc(s);
                    allocated_ = s;
                    used_ = s;
                }catch (std::bad_alloc& e){
                    throw Exception(e.what());
                }
                return addr_;
            }
            /* only alloc if addr_ != addr or s >= allocated_ */
            void *buf_realloc(void *addr, size_t s)
            {
                int factor_ = 0;
                used_ = s;

                if (addr == addr_ && s < allocated_)
                {
                    return addr_;
                }
                factor_ = s/alloc_multiple;
                s = factor_*alloc_multiple;
                s += alloc_multiple;

                try
                {   
                    addr_ = realloc(addr, s);
                    allocated_ = s;
                }catch(std::bad_alloc& e)
                {
                    throw Exception(e.what());
                }
                return addr_;
            }
            void buf_free(void *addr)
            {
                if(addr_ == addr)
                    addr_ = nullptr;
                free (addr);
            }
    };



    
    class TP; /* forward declaration */
    using TP_PTR = std::shared_ptr<TP>;

    typedef enum
    {
        LOG_LVL_ERR,
        LOG_LVL_DBG,
        LOG_LVL_WARN, 
        LOG_LVL_INFO
    }LogLvl;

    static struct _Loglevel
    {
       const char* lvl;
    }LogLevel[] = {
        {" Err "},
        {" Dbg "},
        {" Warn "},
        {" info "}
    };

    class log_mgr
    {

        std::mutex mLock;
        std::condition_variable cv;
        std::vector<std::string> queues[2];
        int index = 0;
        // std::thread _thread;s

        /* thread */
        void operator()()
        {
            std::unique_lock<std::mutex> lk(mLock);
            cv.wait(lk, [](){return 0;});
        }

        log_mgr()
        {
            /* clear both queues */
            queues[0].clear();
            queues[1].clear();
            index = 0;
        }

        public:
            static void log(LogLvl lvl, int mod,const std::string &msg)
            {
                // std::lock_guard<std::mutex> lk(mLock);
                std::cout << LogLevel[(int)lvl].lvl << " : " << mod << " : " << msg << std::endl;
            }

            static void log(LogLvl lvl, std::string& mod,const std::string &msg)
            {
                std::cout << LogLevel[(int)lvl].lvl << " : " << mod << ":" << msg << std::endl;
            }


            static void init()
            {
                static log_mgr *logmgr = nullptr;
                if(logmgr == nullptr)
                {
                    logmgr = new log_mgr();
                    std::thread _thread = std::thread(&log_mgr::operator(), logmgr);
                    _thread.detach();
                }
            }
    };

#define LOG_ERR(msg, mod) ctp::log_mgr::log(ctp::LOG_LVL_ERR,mod,msg)
#define LOG_DBG(msg, mod) ctp::log_mgr::log(ctp::LOG_LVL_DBG,mod,msg)
#define LOG_INFO(msg, mod) ctp::log_mgr::log(ctp::LOG_LVL_INFO,mod,msg)
#define LOG_WARN(msg, mod) ctp::log_mgr::log(ctp::LOG_LVL_WARN,mod,msg)
#define log_info(msg, mod) LOG_INFO(msg, mod)
#define log_dbg(msg, mod) LOG_DBG(msg, mod)


    class TP:public std::enable_shared_from_this<TP>
    {
        //private:
        public:
            void enrol_mgr();
            void cert_mgr();
            void crl_mgr();
            void report_mgr();
            //SequenceOfCertificate certs;
            //Ieee1609Dot2Data data;
            //libconfig::Config config;
            std::vector<int> psids;
            TP(); /* private constructor */

            // Ieee1609Certs *pCerts;
            // Ieee1609Data *pData;

        public:
            void cfg_mgr();
            int verify();
            int sign();
            int encrypt();
            int decrypt();
            TP_PTR instance_get();
            static TP_PTR init();
            ~TP();
            void psid_list();
    };
} //namespace ctp


#endif /* __IEEE_1609DOT2_HPP__*/