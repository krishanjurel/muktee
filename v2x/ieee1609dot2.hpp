#ifndef __IEEE_1609DOT2_HPP__
#define __IEEE_1609DOT2_HPP__
#include <stdint.h>
#include <iostream>
#include <memory>
#include <vector>
#include "ieee1609dot2common.hpp"
#include "libconfig.h++"
#include "openssl/ec.h"
#include "openssl/ecdsa.h"
#include "openssl/obj_mac.h"
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <exception>

/*  This encpasulation of data definition, declaration of 
    IEEE 1609.2-2016     specification 
*/

void print_data(const char* file, const uint8_t *buf, size_t len);

namespace ctp
{
    class Exception:public std::exception
    {
        std::string msg;
        public:
            Exception(std::string _msg):msg(std::move(_msg)){};
            const char* what() const noexcept
            {
                return msg.c_str();
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

    class log_mgr
    {
        public:
        static void log(LogLvl lvl, int mod,const std::string &msg)
        {
            std::cout << lvl<< ":" << msg << std::endl;
        }

        static void log(LogLvl lvl, std::string& mod,const std::string &msg)
        {
            std::cout << lvl << ":" << mod << ":" << msg << std::endl;
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