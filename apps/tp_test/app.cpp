/* this is the file that will do the key generataion, cert parsing, data signing and sign verification
*/

#include <signal.h> /* for signal */
#include "openssl/ec.h"
#include "openssl/ecdsa.h"
#include "openssl/obj_mac.h"
#include <openssl/bn.h>
#include "signal.h"
#include <unistd.h>
#include <stdio.h>
#include <cstring>
#include <string>
#include <thread>
#include <chrono>
#include <fstream>
#include <memory>
#include <semaphore.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <vector>
#include <sstream>
#include <iostream>
#include <algorithm>
#include "tp.hpp"
#include "remote.hpp"
#define MODULE 4 //test

#define TEST(_x_) test ## _x_
void TEST(data_encoding)();
void TEST(data_decoding)();
void TEST(cert_encoding)();
void TEST(certs_encoding)();
void TEST(cert_decoding)();
void TEST(ipc_sockets)();
void TEST(logging)();
void TEST(hashing)();
void TEST(encoding)();
void TEST(config)();
void TEST(tp_test_client)();



static int stop_=0;

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

typedef union 
{
    struct {
        uint8_t upper:4;
        uint8_t lower:4;
    }nibbles;
    uint8_t data;
}FullByte;



#define sync_file   "/sync_file"
#define pubkey_file "./pubkey_file"
#define privkey_file "./privkey_file"

#define handle_error(msg) \
    do { perror(msg); exit(EXIT_FAILURE);}while(0)



/* initialize the log lvl */
// ctp::LogLvl ctp::log_mgr::logLvl = ctp::LOG_LVL_DBG;


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
    
#if 0
  /* create a memory map file  to contain the semaphore to be shared between two processes 
    */
    cosmoV2XKey->syncFd = shm_open(sync_file, O_RDWR | O_CREAT, S_IWUSR);
    if(cosmoV2XKey->syncFd == -1)
    {
        handle_error("shm_open");
    }

    if(ftruncate(cosmoV2XKey->syncFd, sizeof(sem_t)) ==  -1)
    {
        shm_unlink(sync_file);
        perror("ftruncate");
    }

    void *addr = mmap(nullptr, sizeof(sem_t), PROT_READ | PROT_WRITE, MAP_SHARED, cosmoV2XKey->syncFd, 0);
    if (addr == MAP_FAILED)
    {
        shm_unlink(sync_file);
        handle_error("mmap");
    }
    close(cosmoV2XKey->syncFd);

    /* point the semaphore the shared buffer */
    cosmoV2XKey->syncSem = (sem_t *)addr;
    /* this semaphore will be shared among the processes*/
    sem_init(cosmoV2XKey->syncSem,1,0);


    //privkey_to_octet(cosmoV2XKey);
    

    pid_t cpid = fork();
    int wstatus;
    if(cpid  == 0)
    {
        struct timespec ts1, ts2;
        /* clock get time */
        if(clock_gettime(CLOCK_REALTIME, &ts1) ==  -1)
        {
            handle_error("clock_gettime");
        }
        sem_wait(cosmoV2XKey->syncSem);

        if(clock_gettime(CLOCK_REALTIME, &ts2) ==  -1)
        {
            handle_error("clock_gettime 2");
        }
        std::cout << "the wait time secs " << ts2.tv_sec - ts1.tv_sec << "seconds " << std::endl;
        std::this_thread::sleep_for(std::chrono::seconds(5));
        return 0;
    }
    else {
        std::this_thread::sleep_for(std::chrono::seconds(5));
        sem_post(cosmoV2XKey->syncSem);
    }
    std::cout << "wait for the child to finish " << std::endl;

    waitpid(cpid, &wstatus, WUNTRACED | WCONTINUED);

    if(WIFEXITED(wstatus))
    {
        std::cout << "exited status " << WEXITSTATUS(wstatus) << std::endl;
    }else if(WIFSIGNALED(wstatus))
    {
        std::cout << "exited status " << WTERMSIG(wstatus) << std::endl;
    }else if(WIFCONTINUED(wstatus))
    {
        std::cout << "continued " << std::endl;
    }
    shm_unlink(sync_file);
    munmap(addr, sizeof(sem_t));
#endif

    // ctp::Ieee1609Cert *pcert = new ctp::Ieee1609Cert();
    // pcert->create();
    // uint8_t *encBuf = nullptr;
    // size_t encLen = 0;
    // encLen = pcert->encode(&encBuf);
    // // std::cout << "encoded buffer length " << encLen << std::endl;
    
    // pcert->print();

    // std::string tbsData("this is dummy test data!!!");
    // ctp::Ieee1609Data *pdata = new ctp::Ieee1609Data();
    // uint8_t *signedData = nullptr;
    // size_t signedDataLength = 0;
    // pdata->sign(32, (uint8_t *)tbsData.c_str(), tbsData.length(), &signedData, &signedDataLength, pcert);
    // print_data("data_payload.txt", signedData, signedDataLength);
    // std::cout << "number of bytes " << signedDataLength << std::endl;


    // /* test the decoding */
    // /* create a new data object */
    // ctp::Ieee1609Data *pData = new ctp::Ieee1609Data();
    // pData->decode(signedData, signedDataLength);
    // //pData->print_decoded("decode-data.txt");
    // pData->print_encoded("decoded-data.txt");


    //TEST(ipc_sockets)();
    // TEST(certs_encoding)();
    // TEST(data_encoding)();
    TEST(data_decoding)();
    // TEST(cert_decoding)();
    // TEST(logging)();
    // TEST(hashing)();
    // TEST(encoding)();

    // TEST(config)();
    TEST(tp_test_client)();

    // while(!stop_)
    // {
        std::this_thread::sleep_for(std::chrono::seconds(5));
        //std::abort();
        std::this_thread::sleep_for(std::chrono::seconds(5));
    // }
    // delete pcert;
    // delete pdata;
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


void TEST(tp_test_client)()
{
    /* create and get trust pointer object */
    // ctp::TP_PTR tp = ctp::TP::init();
    ctp::TP_PTR tp = ctp::TP_PTR(new ctp::TP());
    /* create a new object tp_test_client */
    std::shared_ptr<tp_test_client> tpTestClient = std::shared_ptr<tp_test_client>(new tp_test_client());
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
    
    
}

typedef void (*ptrTestFunction)();
ptrTestFunction test_data[]{
        TEST(data_encoding),
        TEST(data_decoding)
};


void TEST(config)()
{
    try
    {
        // ctp::TP_PTR tp = ctp::TP::init();
        ctp::TP_PTR tp = std::shared_ptr<ctp::TP>(new ctp::TP());
        tp->start();
        tp->psid_list();
        tp->curves_list();
    }
    catch(const std::exception& e)
    {
        std::cerr << e.what() << '\n';
    }
    
}

void TEST(hashing)()
{
    printf("Hashing \n");
    uint8_t *hash = nullptr;
    int ret = 0;
    /* get an empty string */
    std::string str("");
    ctp::Ieee1609Cert *pCert = new ctp::Ieee1609Cert();
    ret = pCert->Hash256((const uint8_t *)str.c_str(), str.length(), &hash);
    if(ret == 0)
    {
        LOG_ERR("TEST(hashing): has failed creating hash of empty string ",MODULE);
        delete pCert;
        raise(SIGKILL);
    }

    print_data(nullptr, hash, SHA256_DIGEST_LENGTH);
    free(hash);
    LOG_INFO("TEST(hashing): has passed ", MODULE);

    raise(SIGKILL);

}



void TEST(data_encoding)()
{
    printf("data_encoding\n");
    ctp::Ieee1609Certs *pcert = new ctp::Ieee1609Certs();
    // pcerts->create();
    uint8_t *encBuf = nullptr;
    size_t encLen = 0;
    encLen = pcert->encode(&encBuf);
    std::cout << "encoded buffer length " << encLen << std::endl;
    
    //pcert->print_encoded(std::string("encoded-cert.txt"));
    //pcert->print_decoded(std::string("decoded-cert.txt"));

    std::string tbsData("this is dummy test data!!!");
    ctp::Ieee1609Data *pdata = new ctp::Ieee1609Data();
    uint8_t *signedData = nullptr;
    size_t signedDataLength = 0;
    pdata->sign(32, (uint8_t *)tbsData.c_str(), tbsData.length(), &signedData, &signedDataLength, pcert);
    print_data("data_payload.txt", signedData, signedDataLength);
    std::cout << "number of bytes " << signedDataLength << std::endl;
    delete pcert;
    delete pdata;
    raise(SIGKILL);
    return;
}

void TEST(data_decoding)()
{
    std::stringstream log_(std::ios_base::out);
    std::string tbsData("this is dummy test data!!!");
    ctp::Ieee1609Data *pdata = nullptr;
    uint8_t *signedData = nullptr;
    size_t signedDataLength = 0;
    ctp::Ieee1609Certs *pcerts = nullptr;
    ctp::Ieee1609Data *pdata2 = nullptr;
    try
    {
    
        log_ << "data_decoding start " << std::endl;
        LOG_DBG(log_.str(), MODULE);
        log_.str("");
        pcerts = new ctp::Ieee1609Certs();
        pcerts->create();
        // uint8_t *encBuf = nullptr;
        // size_t encLen = 0;
        // encLen = pcerts->encode(&encBuf);
        // log_ << "encoded buffer length " << std::dec << encLen << std::endl;
        // LOG_DBG(log_.str(), MODULE);
        // log_.str("");
        // unlink("data_decoding_enc_cert.txt");
        // print_data("data_decoding_enc_cert.txt",encBuf, encLen);
        pdata = new ctp::Ieee1609Data();
        pdata->sign(32, (uint8_t *)tbsData.c_str(), tbsData.length(), &signedData, &signedDataLength, pcerts);
        unlink("data_decoding_enc_data.txt");
        print_data("data_decoding_enc_data.txt", signedData, signedDataLength);
        delete pdata;
        // std::cout << "number of bytes " << signedDataLength << std::endl;

        /* decoding section */


        pdata2 = new ctp::Ieee1609Data();
        pdata2->decode(signedData,signedDataLength);
        uint8_t *encBuf2 = nullptr;

        size_t encLen2 = pdata2->encode(&encBuf2);

        unlink("data_decoding_dec_data.txt");
        // print_data("data_decoding_dec_data.txt", encBuf2, encLen2);
        // print_data(nullptr, encBuf2, encLen2);

        if(signedDataLength != encLen2)
        {
            log_ << "the decoding has failed length(expected) " << encLen2 << "(" << signedDataLength << ")" << std::endl;
            LOG_ERR(log_.str(), MODULE);
            throw;
        }
        for(int i =0; i < encLen2; i++)
        {
            if(signedData[i] != encBuf2[i])
            {
                log_ << "the decoding failed at index " << i << std::endl;
                LOG_ERR(log_.str(), MODULE);
                throw;
            }
        }
        log_.str("");
        log_ << "data_decoding verification start " << std::endl;
        log_info(log_.str(), MODULE);
        log_.str("");
        /* do the verification */
        pdata2->verify();
    }catch(ctp::Exception& e)
    {
        log_ << "TEST(data_decoding)() is failed " << std::endl;
        LOG_ERR(log_.str(), MODULE);
        throw;
    }
    log_ << "TEST(data_decoding)() passed " << std::endl;
    LOG_DBG(log_.str(), MODULE);
    // delete pcerts;
    // delete pdata;
    delete pdata2;
    return;
}
void TEST(certs_encoding)()
{
    std::cout << "certs_encoding " << std::endl;
    // ctp::Ieee1609Certs *pcerts = new ctp::Ieee1609Certs();
    // pcerts->encode();
    // pcerts->print();
    // raise(SIGKILL);
    
}
void TEST(cert_encoding)()
{
    printf("cert_encoding\n");
    ctp::Ieee1609Cert *pcert = new ctp::Ieee1609Cert();
    pcert->create();
    uint8_t *encBuf = nullptr;
    size_t encLen = 0;
    encLen = pcert->encode(&encBuf);
    // std::cout << "encoded buffer length " << encLen << std::endl;
    unlink("encoded-cert.txt");
    pcert->print_encoded(std::string("encoded-cert.txt"));
    delete pcert;
    raise(SIGKILL);
    return;
}

void TEST(cert_decoding)()
{
    std::stringstream log_(std::ios_base::out);
    ctp::Ieee1609Cert *pcert2 = nullptr;
    ctp::Ieee1609Cert *pcert1 = nullptr;
    try
    {

        log_ << "cert_decoding: encoding cycle" << std::endl;
        LOG_DBG(log_.str(), MODULE);
        log_.str("");
        pcert1 = new ctp::Ieee1609Cert();
        pcert1->create();
        uint8_t *encBuf = nullptr;
        size_t encLen = 0;
        encLen = pcert1->encode(&encBuf);
        unlink("cert_decoding_encoded_cert.txt");
        print_data("cert_decoding_encoded_cert.txt",encBuf, encLen);
        log_ << "cert_decoding: decoding cycle" << std::endl;
        log_info(log_.str(), MODULE);
        log_.str("");

        /* create a certificate object */
        pcert2 = new ctp::Ieee1609Cert();
        pcert2->decode(encBuf, encLen);
        uint8_t *encBuf2 = nullptr;
        size_t encLen2 = 0;
        encLen2 = pcert2->encode(&encBuf2);
        unlink("cert_decoding_deccode_encoded_cert.txt");
        print_data("cert_decoding_deccode_encoded_cert.txt", encBuf2, encLen2);


        for (int i = 0; i < encLen2; i++)
        {
            if(encBuf[i] != encBuf2[i])
            {
                log_ << "cert_decoding mismatch at index " << i <<std::endl;
                LOG_ERR(log_.str(), MODULE);
            }
        }
    }catch(ctp::Exception& e)
    {
        LOG_ERR(e.what(), MODULE);
        throw;
        raise(SIGKILL);
    }
    log_ << "TEST(cert_decoding)() passed " << std::endl;
    LOG_DBG(log_.str(), MODULE);

    delete pcert1;
    delete pcert2;
    return;
}



void TEST(ipc_sockets)()
{
    int wstatus;
    remote::_remote *ptrServer = new remote::_remote(remote::Type::server);
    remote::_remote *ptrClient = new remote::_remote(remote::Type::client);
    std::string filename("/tmp/test.txt");
    ptrServer->create(filename, AF_LOCAL);
    ptrClient->create(filename, AF_LOCAL);

    /* create a new process */
    pid_t cpid = fork();

    if(cpid == 0)
    {
        /* start the server process */
        ptrServer->start();
        while(1)
        {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }else{
        ptrClient->start();
        while(1)
        {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }

    std::cout << "wait for the child to finish " << std::endl;

    waitpid(cpid, &wstatus, WUNTRACED | WCONTINUED);

    if(WIFEXITED(wstatus))
    {
        std::cout << "exited status " << WEXITSTATUS(wstatus) << std::endl;
    }else if(WIFSIGNALED(wstatus))
    {
        std::cout << "exited status " << WTERMSIG(wstatus) << std::endl;
    }else if(WIFCONTINUED(wstatus))
    {
        std::cout << "continued " << std::endl;
    }
}

void TEST(logging)()
{
    std::stringstream strStream(std::ios_base::out);
    strStream << "Hello world" << std::hex << 20 << std::endl;

    log_info(strStream.str(), MODULE);
    strStream.sync();
    strStream.clear();
    strStream.str("");
    strStream << "Hello world again" << std::hex << 20 << std::endl;

    log_info(strStream.str(), MODULE);
    return;
}


void TEST(encoding)()
{
    std::stringstream log_(std::ios_base::out);
    log_ << "TEST(encdoing) length\n";
    LOG_DBG(log_.str(), MODULE);
    log_.str("");
    std::vector<int> invalues={7,127,128,255,256, 32768, 65535, 65536};
    std::vector<int> expvalue={1,1, 1,    1,  2,   2,     2, 3};

    int enclen = 0;
    uint8_t *encbuf = nullptr;

    ctp::Ieee1609Encode *enc = new ctp::Ieee1609Encode();
    for(int i=0; i < invalues.size(); i++)
    {
        int encvalue = invalues.at(i);
        int retvalue = enc->Length(encvalue);
        if(retvalue != expvalue.at(i))
        {
            log_ << " TEST(encdoing) fails " << " input " << encvalue << " out/exp " << retvalue << "/";
            log_ << expvalue.at(i) << std::endl;
            LOG_ERR(log_.str(), MODULE);
            delete enc;
            raise(SIGKILL);
        }

        log_ << " TEST(encoding) the data for encoding  " << encvalue << std::endl;
        LOG_DBG(log_.str(), MODULE);
        log_.str("");
        enclen = enc->get(&encbuf);
        print_data(nullptr, encbuf, enclen);
        enc->clear();
    }

    log_ << " TEST(encdoing) passes " << std::endl;
    LOG_DBG(log_.str(), MODULE);   
    delete enc;
}