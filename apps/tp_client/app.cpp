/* this is the file that will do the key generataion, cert parsing, data signing and sign verification
*/

#include <signal.h> /* for signal */
#include "signal.h"
#include "tp.hpp"
#define MODULE 4 //test

static int stop_=0;


static void tp_client();

void signal_handler(int sig)
{
    std::cout << "signal " << sig <<  " had been caugth" << std::endl;
    //std::terminate();
    stop_=1;
    return;
}

void terminate_handler()
{
    std::cout << "terminate has been raised "<< std::endl;
    std::abort();
    
}


/* initialize the log lvl */
ctp::LogLvl ctp::log_mgr::logLvl = ctp::LOG_LVL_DBG;    


int main()
{
    
    struct sigaction sigAct;
    sigAct.sa_flags = SA_NOCLDSTOP | SA_NOCLDWAIT;
    sigAct.sa_restorer = nullptr;

    sigAct.sa_handler = signal_handler;
    sigemptyset(&sigAct.sa_mask);

    sigaddset(&sigAct.sa_mask, SIGKILL);
    sigaddset(&sigAct.sa_mask, SIGABRT);
    sigaddset(&sigAct.sa_mask, SIGTERM);
    sigaddset(&sigAct.sa_mask, SIGCHLD);
    //sigaddset(&sigAct.sa_mask, SIGSEGV);
    sigprocmask(SIG_UNBLOCK, &sigAct.sa_mask, nullptr);
    
    sigaction(SIGKILL, &sigAct, NULL);
    sigaction(SIGABRT, &sigAct, NULL);
    sigaction(SIGTERM, &sigAct, NULL);
    sigaction(SIGCHLD, &sigAct, NULL);
    //sigaction(SIGSEGV, &sigAct, NULL);

    std::set_terminate(terminate_handler);

    tp_client();

    while(!stop_)
    {
       std::this_thread::sleep_for(std::chrono::seconds(5));
       //std::abort();
       std::this_thread::sleep_for(std::chrono::seconds(5));
    }
    raise(SIGKILL);
    return 0;
}



class tp_test_client: public ctp::tp_client
{
    int psid; /* client for this psid */
    /* count the number of packets*/
    int packets;
    public:
        tp_test_client():psid(32),packets(0),ctp::tp_client(){};
        /* define the callback routine */
        void callback(void *data, size_t len)
        {
            std::stringstream log_(std::ios_base::out);
            packets ++;
            /* since the test data is a string , lets print it */
            std::string _data((const char*)data, len);
            log_ << packets << _data << std::endl;
            std::cout << log_.str();
        }
        const int psid_get() const
        {
            return psid;
        }
};


void tp_client()
{
    /* create and get trust pointer object */
    // ctp::TP_PTR tp = ctp::TP::init();
    ctp::TP_PTR tp = ctp::TP_PTR(new ctp::TP());
    /* create a new object tp_test_client */
    std::shared_ptr<tp_test_client> tpTestClient = std::shared_ptr<tp_test_client>(new tp_test_client(),[](const tp_test_client *obj){delete obj;});
    /* register the clients */
    try
    {
        /* start the trust pointer*/
        tp->start();
        tp->client_register(tpTestClient->psid_get(),tpTestClient);
        

        /*call the routine to sign the data */
        std::string tbsData("this is dummy test data!!!");
        std::string tbsData1("this is dummy test data1!!!");
        uint8_t *signedData = nullptr;
        size_t signedDataLen = 0;
        uint8_t *signedData1 = nullptr;
        size_t signedDataLen1 = 0;
        /* sign the data */
        tp->sign(tpTestClient->psid_get(),(const uint8_t *)tbsData.c_str(),tbsData.size(), &signedData, &signedDataLen);
        tp->sign(tpTestClient->psid_get(),(const uint8_t *)tbsData1.c_str(),tbsData1.size(), &signedData1, &signedDataLen1);
        /* use the one below for failure testing */
        // tp->sign(33,(const uint8_t *)tbsData1.c_str(),tbsData1.size(), &signedData1, &signedDataLen1);

        tp->verify(signedData, signedDataLen);
        tp->verify(signedData1, signedDataLen1);
        /* now the callaback must be called */
    }
    catch(const ctp::Exception& e)
    {
        std::cerr << e.what() << '\n';
    }
    tpTestClient.reset();
    tp.reset();
}
