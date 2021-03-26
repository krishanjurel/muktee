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

#include "ieee1609dot2common.hpp"
#include "ieee1609dot2.hpp"
#include "ieee1609dot2cert.hpp"
#include "ieee1609dot2data.hpp"
#include "remote.hpp"



#define TEST(_x_) test ## _x_
void TEST(data_encoding)();
void TEST(data_decoding)();
void TEST(cert_encoding)();
void TEST(certs_encoding)();
void TEST(cert_decoding)();
void TEST(ipc_sockets)();



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


namespace ctp
{
    TP::TP()
    {
        psids.clear();
        libconfig::Config config;
        {
            FILE *fp = fopen("./config.file", "r");
            if(fp != nullptr)
            {
                try
                {
                    config.read(fp);
                    libconfig::Setting& setting = config.lookup("app.components.psid");
                    if(setting.getLength() == 0)
                    {
                        throw libconfig::SettingException("app.components.psid");
                    }
                    using itr = libconfig::Setting::iterator;
                    itr it=setting.begin();
                    while(it != setting.end())
                    {
                        psids.push_back(*it);
                        it++;
                    }
                }
                catch(const std::exception& e)
                {
                    std::cerr << e.what() << '\n';
                }
                fclose(fp);
            }
        }

        /* create instances of cert and data manager */
        // pCerts = new Ieee1609Certs();
        // pData = new Ieee1609Data();


    }

    TP::~TP()
    {
        // delete pCerts;
        // delete pData;
    }

    /* every client must be calling this routine */
    TP_PTR TP::instance_get()
    {
        return shared_from_this();
    }

    TP_PTR TP::init()
    {
        static TP_PTR pObj = nullptr;
        static TP obj; /* need this for private constructor */
        if(pObj == nullptr)
        {
            pObj = std::make_shared<TP>(obj);
        }
        return pObj;
    }

    void TP::psid_list()
    {
        std::for_each(psids.begin(), psids.end(), [](const int n){ std::cout << n << " ";});
    }
}


int main()
{
    
    struct sigaction sigAct;
    //  = {
    //     .sa_flags = SA_NOCLDSTOP | SA_NOCLDWAIT,
    //     .sa_restorer = nullptr,
    // };
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
    //TEST(certs_encoding)();
    //  TEST(data_encoding)();
    TEST(data_decoding)();

    while(!stop_)
    {
        std::this_thread::sleep_for(std::chrono::seconds(5));
        //std::abort();
        std::this_thread::sleep_for(std::chrono::seconds(5));
    }
    // delete pcert;
    // delete pdata;
    return 0;
}




typedef void (*ptrTestFunction)();
ptrTestFunction test_data[]{
        TEST(data_encoding),
        TEST(data_decoding)
};



void TEST(data_encoding)()
{
    printf("data_encoding\n");
    ctp::Ieee1609Cert *pcert = new ctp::Ieee1609Cert();
    pcert->create();
    uint8_t *encBuf = nullptr;
    size_t encLen = 0;
    encLen = pcert->encode(&encBuf);
    std::cout << "encoded buffer length " << encLen << std::endl;
    
    pcert->print_encoded(std::string("encoded-cert.txt"));
    pcert->print_decoded(std::string("decoded-cert.txt"));

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
    printf("data_decoding\n");
    ctp::Ieee1609Cert *pcert = new ctp::Ieee1609Cert();
    pcert->create();
    uint8_t *encBuf = nullptr;
    size_t encLen = 0;
    encLen = pcert->encode(&encBuf);
    std::cout << "encoded buffer length " << encLen << std::endl;
    
    pcert->print_encoded(std::string("encoded-cert.txt"));
    pcert->print_decoded(std::string("decoded-cert.txt"));

    ctp::Ieee1609Cert *pcert1 = new ctp::Ieee1609Cert();
    /* decode from the previously created certificate */
    pcert1->decode(encBuf, encLen);

    pcert1->print_decoded(std::string("decoded-cert1.txt"));





    // std::string tbsData("this is dummy test data!!!");
    // ctp::Ieee1609Data *pdata = new ctp::Ieee1609Data();
    // uint8_t *signedData = nullptr;
    // size_t signedDataLength = 0;
    // pdata->sign(32, (uint8_t *)tbsData.c_str(), tbsData.length(), &signedData, &signedDataLength, pcert);
    // print_data("data_payload.txt", signedData, signedDataLength);
    // std::cout << "number of bytes " << signedDataLength << std::endl;
    delete pcert;
    // delete pdata;
    raise(SIGKILL);


    return;
}
void TEST(certs_encoding)()
{
    std::cout << "certs_encoding " << std::endl;
    ctp::Ieee1609Certs *pcerts = new ctp::Ieee1609Certs();
    pcerts->encode();
    pcerts->print();
    raise(SIGKILL);
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
    pcert->print_encoded(std::string("cert.txt"));
    delete pcert;
    raise(SIGKILL);
    return;
}
void TEST(cert_decoding)()
{
    printf("cert_decoding\n");
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