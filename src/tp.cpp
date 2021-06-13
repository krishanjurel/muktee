#include "tp.hpp"
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>

namespace ctp
{


    /* TP message queue locks */
    // static std::mutex q_in_mutex;
    // static std::mutex q_out_mutex;


    #define DC_CERTS_IP     "certs.ip"
    #define DC_CERTS_PORT   "certs.port"
    #define DC_CRLS_IP      "crls.ip"
    #define DC_CRLS_PORT    "crls.port"
    #define DC_CTLS_IP      "ctls.ip"
    #define DC_CTLS_PORT    "ctls.port"

    #define DC_SETTINGS     "app.components.DC"
    #define RA_SETTINGS     "app.components.RA"
    #define DCM_SETTINGS    "app.components.DCM"
    #define CERT_SETTINGS   "app.components.CERTS"


    #define CERTS_CURVES    "curves"
    #define CERTS_PSIDS     "psids"

    /* read the configuration file */
    tp_cfg::tp_cfg(const char *filename)
    {
    #ifdef USE_LIB_CONFIG
        using itr = libconfig::Setting::iterator;
        std::stringstream log_(std::ios_base::out);
        libconfig::Config config;
        FILE *fp = fopen(filename, "r");
        curves.clear();
        psids.clear();
        if(fp != nullptr)
        {
            try
            {
                config.read(fp);
                /* get the setting handle to the Distribution center */
                libconfig::Setting& dcSetting = config.lookup(DC_SETTINGS);
                if(dcSetting.getLength() == 0)
                {
                    std::stringstream log_(std::ios_base::out);
                    log_ << " tp_cfg::tp_cfg::config.lookup(\"app.component.DC\") not specified " << std::endl;
                    LOG_ERR(log_.str(), MODULE);
                }else{
                    /* read the cert distribution remote parameters */
                    dcSetting.lookupValue(DC_CERTS_IP, dc.certs.ip);
                    dcSetting.lookupValue(DC_CERTS_PORT, dc.certs.port);
                    /* remoe crl distribution parameters */
                    dcSetting.lookupValue(DC_CRLS_IP, dc.crls.ip);
                    dcSetting.lookupValue(DC_CRLS_PORT, dc.crls.port);

                    /* remoe ctl distribution parameters */
                    dcSetting.lookupValue(DC_CTLS_IP, dc.ctls.ip);
                    dcSetting.lookupValue(DC_CTLS_PORT, dc.ctls.port);
                }
                /* get the curves settinsgs */
                libconfig::Setting& certSettings = config.lookup(CERT_SETTINGS);
                if(dcSetting.getLength() == 0)
                {
                    log_ << " tp_cfg::tp_cfg::config.lookup( " << CERT_SETTINGS << ")" <<  " not specified " << std::endl;
                    LOG_ERR(log_.str(), MODULE);
                }else{
                    /* get the curve setting objects */
                    libconfig::Setting& curvesSetting = certSettings.lookup(CERTS_CURVES);
                    if(curvesSetting.getLength() == 0)
                    {
                        log_ << " tp_cfg::tp_cfg::config.lookup( " << CERT_SETTINGS << CERTS_CURVES << ")" <<  " not specified " << std::endl;
                    }else{
                        itr itr_ = curvesSetting.begin();
                        while(itr_ != curvesSetting.end())
                        {
                            std::string str_ = *itr_;
                            log_ << " tp_cfg::tp_cfg::config.lookup( " << CERT_SETTINGS << CERTS_CURVES << ")" << str_ << std::endl;
                            log_info(log_.str(), MODULE);
                            log_.str("");
                            curves.push_back(str_);
                            itr_++;
                        }
                    }
                    libconfig::Setting& psidsSetting = certSettings.lookup(CERTS_PSIDS);
                    if(curvesSetting.getLength() == 0)
                    {
                        log_ << " tp_cfg::tp_cfg::config.lookup( " << CERT_SETTINGS << CERTS_PSIDS << ")" <<  " not specified " << std::endl;
                    }else{
                        itr itr_ = psidsSetting.begin();
                        while(itr_ != psidsSetting.end())
                        {
                            psids.push_back(*itr_);
                            itr_++;
                        }
                    }
                }
            }
            catch(const std::exception& e)
            {
                log_ << "tp_cfg::tp_cfg (" << filename << ")" << e.what() << std::endl;
                LOG_ERR(log_.str(), MODULE);
            }

            certcfg.path1 = "./bin/certs";
            certcfg.path2 = nullptr;
            fclose(fp);
        }else
        {
            log_ << " tp_cfg::tp_cfg::fopen(\"" << filename << "\")" << " failed " << std::endl;
            LOG_ERR(log_.str(), MODULE);
        }
    #endif
    }
} //namespace ctp


namespace ctp
{
    
    void TP::cert_mgr()
    {
        LOG_INFO("cert_mgr", 1);
    }

    void TP::cfg_mgr()
    {
        LOG_INFO("cfg_mgr", 1);
    }

    void TP::enrol_mgr()
    {
        LOG_INFO("enrol_mgr", 1);
    }

    void TP::crl_mgr()
    {
        LOG_INFO("crll_mgr", 1);
    }

    void TP::report_mgr()
    {
        LOG_INFO("log_mgr", 1);
    }

    int TP::sign()
    {
        log_info("sign", 1);
        return 0;
    }

    LogLvl log_mgr::logLvl = ctp::LOG_LVL_DBG;
    int ctp::CertMgr::_initDone = 0;
    SHARED_CERTMGR ctp::CertMgr::pCertMgr = nullptr;

    TP::TP()
    {
        init_done = false;
        cfg = nullptr;
        std::stringstream log_(std::ios_base::out);
        log_ << "TP::TP() enter " << std::endl;
        log_dbg(log_.str(), MODULE);
        log_.str("");
        // certMgr = ctp::CertMgr::init();
        certMgr = std::make_shared<CertMgr>();
        log_ << "TP::TP() exit " << certMgr.use_count() << std::endl;
        log_dbg(log_.str(), MODULE);
        log_.str("");
    }

    TP::~TP()
    {
        /* assign certs to nullptr, it will free it */
        std::cout << "TP::~TP()  enter " << std::endl;
        cert=nullptr;
        cfg = nullptr;
        certMgr= nullptr;
    }

    void TP::start()
    {
        std::stringstream log_ (std::ios_base::out);
        log_ << " TP::start() enter " << std::endl;
        log_dbg(log_.str(), MODULE);
        log_.str("");
        if(init_done == false)
        {
            init_done = true;
            try
            {
                /* call out the config manager */
                log_ << "TP::start() ";
                cfg = std::shared_ptr<tp_cfg>(new tp_cfg("./bin/config.file"),[this](const tp_cfg* p){ log_dbg(" TP::start() delete tp_cfg\n", MODULE); delete p;});
            }
            catch(const std::exception& e)
            {
                log_.str("");
                /* in case of exception, only create the the self signed certificate with BSM psid */
                log_ << " TP::start() " << e.what() << std::endl;
                LOG_ERR(log_.str(), MODULE);
                cfg = nullptr;
            }
            certMgr->start(cfg);
        }

        t_in_thread = std::thread(&TP::process_clients, this);
        stop_ = false;
        log_ << " TP::start() exit " << std::endl;
        log_dbg(log_.str(), MODULE);
    }

    /* every client must be calling this routine */
    SHARED_TP TP::instance_get()
    {
        return SHARED_TP(this);
    }

    // SHARED_TP TP::init()
    // {
    //     // static TP_PTR pObj = nullptr;
    //     // static TP obj; /* need this for private constructor */
    //     // if(pObj == nullptr)
    //     // {
    //     //     pObj = std::make_shared<TP>(obj);
    //     // }
    //     /* initialize the cert manager */
    //     certMgr = ctp::CertMgr::init();
    //     return std::make_shared<TP>();
    // }

    const std::vector<int>& TP::psid_list() const
    {
        std::stringstream log_(std::ios_base::out);
        log_ << " TP::psid_list() "; 
        std::vector<int>::iterator itr = cfg->psids.begin();
        while(itr != cfg->psids.end())
        {
            int n = *itr;
            log_ << std::hex << n << " ";
            itr++;
        }
        log_ << std::endl;
        log_dbg( log_.str(), MODULE);
        return cfg->psids;
    }


    void TP::curves_list()
    {
        std::stringstream log_(std::ios_base::out);
        log_ << " TP::curves_list() "; 
        std::vector<std::string>::iterator itr = cfg->curves.begin();
        while(itr != cfg->curves.end())
        {
            log_ << *itr << " ";
            itr++;
        }
        log_ << std::endl;
        log_dbg(log_.str(), MODULE);
    }

    /* sign the given buffer and psid */
    int TP::sign(const int psid, const uint8_t *buf, size_t len,
                uint8_t **signedData, size_t *signedDataLen)
    {
        int ret = 1;
        ctp::Ieee1609Data *pdata = new ctp::Ieee1609Data();
        std::stringstream log_(std::ios_base::out);
        log_ << "TP::sign enter (psid:data length) " << psid <<":"<< len << std::endl;
        log_info(log_.str(), MODULE);
        log_.str("");

        cert = certMgr->operator[](psid);
        if(cert == nullptr)
        {
            log_.str("");
            log_ << "TP::sign() psid" << psid << " is not supported " << std::endl;
            LOG_ERR(log_.str(), MODULE);
            throw Exception(log_.str());

        }

        try
        {
            // pdata = new ctp::Ieee1609Data();
            pdata->sign(psid, (uint8_t *)buf, len, signedData, signedDataLen,cert);
        }catch(Exception& e)
        {
            ret = 0;
            log_ << "TP::sign failed " << std::endl;
            LOG_ERR(log_.str(), MODULE);
            LOG_ERR(e.what(), MODULE);
        }
        log_ << "TP::sign exit " << ret << std::endl;
        log_info(log_.str(),MODULE);
        delete pdata;
        // std::cout << "delete certs shared object " << certs.use_count() << std::endl;
        // certs.reset();
        return ret;
    }

    int TP::verify()
    {
        log_info("verify", 1);
        return 0;
    }

    int TP::verify(void *buf, size_t len, uint8_t **out, size_t *outLength)
    {
        /* create a data object */
        std::stringstream log_(std::ios_base::out);
        log_ << "TP::verify(sync..) enter" << std::endl;
        log_info(log_.str(), MODULE);
        log_.str("");

        Ieee1609Data *ieee1609DataObj = new ctp::Ieee1609Data();
        try
        {
            unlink("in_secured_data.txt");
            print_data("in_secured_data.txt",(const uint8_t *)buf, len);
            /* decode the message */
            ieee1609DataObj->decode((const uint8_t *)buf, len);
            /* verify the given data */
            ieee1609DataObj->verify();
            /* if all good, get the psid of this data and call the associated callback function */
            HeaderInfo* hdrInfo = ieee1609DataObj->HeaderInfo_();
            // int psid = hdrInfo->psid;
            /*get the root data */
            Ieee1609Dot2Data *dot2data = ieee1609DataObj->Data_();
            ToBeSignedData *tbs = ieee1609DataObj->ToBeSignedData_();
            Ieee1609Dot2Data *data = nullptr;
            if(dot2data->content.type == Ieee1609Dot2ContentSignedData)
            {
                data = tbs->payload.data;
            }else{
                data=dot2data;
            }
            *outLength = data->content.content.unsecuredData.length;
            log_ << "header info psid " << hdrInfo->psid << std::endl;
            log_dbg(log_.str(), MODULE);
            log_.str("");
            *out = (uint8_t *)malloc(*outLength);
            memcpy(*out,data->content.content.unsecuredData.octets, *outLength);

            unlink("in_app_data.txt");
            print_data("in_app_data.txt",(const uint8_t *)*out, *outLength);
        }catch(Exception& e)
        {
            /* handle the exception and process the next message in queue */
            log_.str("");
            log_ << " TP::verify(synchronous) ";
            log_ << e.what() << std::endl;
            LOG_ERR(log_.str(), MODULE);
            delete ieee1609DataObj;
            throw;
        }
        delete ieee1609DataObj;
        log_ << "TP::verify(sync..) exit" << std::endl;
        log_info(log_.str(), MODULE);
        log_.str("");
        return 1;
    }

    int TP::verify(void *buf, size_t length)
    {
        int ret = 0;
        std::stringstream log_(std::ios_base::out);
        log_ << "TP::verify enter" << std::endl;
        log_info(log_.str(), MODULE);
        log_.str("");
        std::lock_guard<std::mutex> lock_(q_in_mutex);
        {
            // client_msg *msg_ = new client_msg(buf, length);
            {
                // q_in_msg.push_back(msg_);
                q_in_msg.emplace_back(new client_msg(buf, length));
            }
        }

        log_ << " TP::verify exit " << ret << std::endl;
        log_info(log_.str(), MODULE);
        return ret;
    }

    /* process the clients */
    void TP::process_clients()
    {
        std::stringstream log_(std::ios_base::out);
        log_ << " TP::process_clients() enter " << std::endl;
        log_dbg(log_.str(), MODULE);
        log_.str("");
        while(stop_ == false)
        {
            std::lock_guard<std::mutex> lock_(q_in_mutex);
            {
                std::vector<client_msg *>::iterator _itr = q_in_msg.begin();
                /*process all elements of vector */
                while(_itr != q_in_msg.end())
                {
                    /* get the client message */
                    client_msg *msg = *_itr;
                    Ieee1609Data *ieee1609DataObj = new ctp::Ieee1609Data();
                    try
                    {
                        unlink("process_clients_data.txt");
                        print_data("process_clients_data.txt",(const uint8_t *)msg->buf, msg->len);
                        /* decode the message */
                        ieee1609DataObj->decode((const uint8_t *)msg->buf, msg->len);
                        /* verify the given data */
                        ieee1609DataObj->verify();
                        /* if all good, get the psid of this data and call the associated callback function */
                        HeaderInfo* hdrInfo = ieee1609DataObj->HeaderInfo_();
                        int psid = hdrInfo->psid;
                        /*get the root data */
                        Ieee1609Dot2Data *dot2data = ieee1609DataObj->Data_();
                        ToBeSignedData *tbs = ieee1609DataObj->ToBeSignedData_();
                        Ieee1609Dot2Data *data = nullptr; 
                        if(dot2data->content.type == Ieee1609Dot2ContentSignedData)
                        {
                            data = tbs->payload.data;
                        }else{
                            data=dot2data;
                        }

                        std::cout << "header info psid " << hdrInfo->psid << std::endl;
                        /* since we only supports signed data */
                        /* get the client object associated with the given psid */
                        auto keyobj = psid_clients.find(psid);
                        if(keyobj != psid_clients.end())
                        {
                            std::cout << "registered client found " << std::endl;
                            std::vector<std::shared_ptr<tp_client>> clients = keyobj->second->clients;
                            /* go thru all the clients */
                            for(auto itr = clients.begin(); itr != clients.end(); itr++)
                            {
                                std::cout << "called the client " << std::endl;
                                std::shared_ptr<tp_client>_tpclient = *itr;
                                _tpclient->callback(data->content.content.unsecuredData.octets, data->content.content.unsecuredData.length);
                            }
                        }
                    }catch(Exception& e)
                    {
                        /* handle the exception and process the next message in queue */
                        log_ << " TP::process_clients() ";
                        log_ << e.what() << std::endl;
                        LOG_ERR(log_.str(), MODULE);
                        delete ieee1609DataObj;
                    }
                    /* move the iterator to the next client message */
                    _itr = q_in_msg.erase(_itr);
                }
            }
        } /* while(stop == false )*/
        log_ << " TP::process_clients() exit " << std::endl;
        log_dbg(log_.str(), MODULE);
        log_.str("");
    }

    void TP::stop()
    {
        stop_= true;
        t_in_thread.join();
        certMgr->stop();
        std::string log_("TP::stop() done\n");
        log_dbg(log_, MODULE);
    }
    void TP::client_register(const int psid, std::shared_ptr<tp_client> obj)
    {
        std::stringstream log_(std::ios_base::out);
        log_ << "TP::client_register enter " << std::endl;
        log_info(log_.str(), MODULE);
        log_.str("");

        /* psid tp client object */
        // psid_tp_client* client = nullptr;
        /* checks if there is a psid_tp_client object for this psid */
        auto search = psid_clients.find(psid);
        if (search == psid_clients.end())
        {
            log_ << "create a new client for psid  " << psid << std::endl;
            log_info(log_.str(),MODULE);
            log_.str("");
            psid_clients.emplace(std::make_pair(psid,new psid_tp_client(psid)));

        }
        // client = psid_clients[psid];
        log_ << "clients exists for psid  " << psid << "" << psid_clients[psid]->clients.size() << std::endl;
        log_info(log_.str(),MODULE);
        log_.str("");

        log_ << "TP::client_register enter1 " << std::endl;
        log_info(log_.str(), MODULE);
        log_.str("");

        /* create one more reference */
        // std::shared_ptr<tp_client> _obj(obj);
        // client->clients.push_back(_obj);
        psid_clients[psid]->clients.emplace_back(std::shared_ptr<tp_client>(obj));
        log_ << "TP::client_register exit " << std::endl;
        log_info(log_.str(), MODULE);
        log_.str("");

    }

    

    int TP::encrypt ()
    {
        log_info("encrypt", 1);
        return 0;
    }

     int TP::decrypt()
     {
         log_info("decrypt",1);
         return 0;
     }
} //namespace ctp