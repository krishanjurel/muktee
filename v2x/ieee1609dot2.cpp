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


typedef struct 
{
    EC_KEY *key;  /* key object */
    EC_KEY *key1;
    const BIGNUM *privKey; /* private key */
    const EC_POINT *pubKey; /* public key */
    sem_t *syncSem;  /*! synchronizing semaphore */
    const char* syncSemFile; /*! file used for synchronization */
    int syncFd;     /*! file descriptor */
    int pubfd;      /*! public key file descriptor */
    int privFd;     /* privkey file descriptor */
}CosmoV2XKey;


static CosmoV2XKey cosmoV2XKey_g;


void signal_handler(int sig)
{
    std::cout << "signal " << sig <<  " had been caugth" << std::endl;
    //std::terminate();
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


/* read the key from the file, copy it into the buffer key, and length into len*/
void ec_key_oct_read(const char *path, uint8_t **key, size_t *len)
{
    std::ifstream ifs;
    ifs.open(path, std::ifstream::in | std::ifstream::binary);
    std::stringbuf strBuf;
    std::istringstream strStream("number of characters ");

    if(ifs.is_open() == true)
    {
        LOG_INFO("file open for reading ", 1);
        /* print all the */
        while(ifs.good() == true)
        {
            char c = ifs.get();
            if (c != ':')
                strBuf.sputc(c);
        }
    }
    std::string lenEnc(std::to_string(strBuf.str().size()));
    strBuf.sputn(strStream.str().c_str(), strStream.str().size());
    strBuf.sputn(lenEnc.c_str(), lenEnc.size());

    log_info(strBuf.str().c_str(), 1);
    ifs.close();
}



uint8_t *ec_key_key2buf(const EC_KEY *key, point_conversion_form_t form, size_t *length,  const char *tag) 
{

    std::ofstream ofs("ecc_key.txt", std::ofstream::out | std::ofstream::binary | std::ofstream::app);
    size_t i=0;
    size_t count = 0;
    uint8_t *keyBuf = nullptr;
    size_t keyBufSize = 0;
    //keyBufSize = EC_KEY_key2buf(key,form, &keyBuf, nullptr);
    if(keyBufSize ==  0)
    {
        std::cout << "Error: EC_KEY_key2buf " << std::endl;
        perror("EC_KEY_key2buf");
        *length = 0;
        return keyBuf;
    }
    *length = keyBufSize;

    std::cout << "out put buffer size " << keyBufSize << std::endl;
    uint8_t *tempPtr = keyBuf;
    size_t charSize = 0;
    
    ofs << "\r\n" << tag << "\r\n";
    /* convert every octect to ascii rep */
    for(i = 0; i < keyBufSize && count < keyBufSize * 2; i++)
    {
        int data;
        uint8_t _temp = *keyBuf;
        keyBuf++;
        charSize = snprintf((char *)&data, sizeof(int), "%c", _temp);

        // std::cout << "byte # " << std::dec << (i+1) << " " << " size " << std::dec << charSize << " " << std::hex << (data & 0xff) << std::endl;
        ofs << std::hex << data;
        ofs << ":";
    }
    ofs << "\r\n" << tag << "\r\n";
    ofs.close();
    return tempPtr;
}


// int ec_key_buf2key(EC_KEY *key, const uint8_t *buf, size_t length)
// {
//     uint8_t *keyBuf;
//     int ret = EC_KEY_oct2key(key, buf, length, NULL);
//     if(ret == 0)
//     {
//         std::cout << "Error: ec_key_buf2key " << std::endl;
//         //LOG_ERR("Error: ec_key_buf2key", 1);
//         return ret;
//     }
//     keyBuf = ec_key_key2buf(key, POINT_CONVERSION_UNCOMPRESSED, &length, "uncompressed-key");
//     free(keyBuf);
//     return ret;
// }



void ec_key_buf2key(EC_KEY *key, unsigned char *buf, size_t len)
{
    uint8_t *keyBuf;
    size_t length;
    std::cout << "size of the enc key buffer " << len << std::endl;
    int ret = 0;//EC_KEY_oct2key(key,buf,len, nullptr);
    if(ret == 0)
    {
        std::cout << "Error: ec_key_buf2key " << std::endl;
        perror("EC_KEY_oct2key");
        free(buf);
        return;
    }
    free (buf);
    buf = ec_key_key2buf(key, POINT_CONVERSION_UNCOMPRESSED, &length, "compressed derived");
    free(buf);
    return;
}



void privkey_to_octet(CosmoV2XKey *cosmoV2XKey)
{
    uint8_t *octBuf = nullptr;
    size_t octKeyLen = 0;
    FullByte fullByte;
    char decodedByte[4];
    

    //octKeyLen = EC_KEY_priv2oct(cosmoV2XKey->key, octBuf, octKeyLen);
    if(octKeyLen != 0)
    {
        std::cout << "private key length " << octKeyLen << std::endl;
        try 
        {
            octBuf = new uint8_t[octKeyLen];

            //octKeyLen = EC_KEY_priv2oct(cosmoV2XKey->key, octBuf, octKeyLen);
            if(octKeyLen == 0)
            {
                std::cout << "EC_KEY_priv2oct: failed" << std::endl;
            }else{

                std::cout << "private key " << std::endl;
                for (int i = 0; i < octKeyLen; i++)
                {
                     fullByte.data = *(octBuf+i);
                     std::cout << "byte #" << (i+1) << " " << (fullByte.nibbles.upper + '0') <<  fullByte.nibbles.lower + '0' << std::endl;
                    snprintf(decodedByte, sizeof(decodedByte), "%d", *(octBuf+i));
                    std::cout << " byte #" << (i+1) << " " << decodedByte << std::endl;
                    std::cout << " *******" << std::endl;
                }
            }
        }catch(std::bad_alloc &ex)
        {
            std::cout << "memory allocation failure " << ex.what() << std::endl;
        }

    }
}

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
    }

    TP::~TP()
    {

    }

    TP_PTR TP::instance_get()
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
    sigaddset(&sigAct.sa_mask, SIGSEGV);
    sigprocmask(SIG_UNBLOCK, &sigAct.sa_mask, nullptr);
    
    sigaction(SIGKILL, &sigAct, NULL);
    sigaction(SIGABRT, &sigAct, NULL);
    sigaction(SIGTERM, &sigAct, NULL);
    sigaction(SIGCHLD, &sigAct, NULL);
    sigaction(SIGSEGV, &sigAct, NULL);

    std::set_terminate(terminate_handler);
   #if 0
    CosmoV2XKey *cosmoV2XKey = &cosmoV2XKey_g;
    /* create an instance of the trusted platform */
    ctp::TP_PTR tpObj = ctp::TP::instance_get();

    /* create the key */
    /* associate a curve name with the key */
    cosmoV2XKey->key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (cosmoV2XKey->key == nullptr)
    {
        perror("<Main> Error associating key with a curve");
        std::terminate();
    }

    // cosmoV2XKey->key1 = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    // if (cosmoV2XKey->key1 == nullptr)
    // {
    //     perror("<Main> Error associating key with a curve");
    //     std::terminate();
    // }

    EC_KEY_set_conv_form(cosmoV2XKey->key, POINT_CONVERSION_UNCOMPRESSED);
    /* generate the private and associate public key */
    if (EC_KEY_generate_key(cosmoV2XKey->key) != 1)
    {
        perror("Error creating keys");
        EC_KEY_free(cosmoV2XKey->key);        
        std::abort();
    }

    // if (EC_KEY_generate_key(cosmoV2XKey->key1) != 1)
    // {
    //     perror("Error creating keys");
    //     EC_KEY_free(cosmoV2XKey->key);        
    //     std::abort();
    // }

    cosmoV2XKey->privKey = EC_KEY_get0_private_key(cosmoV2XKey->key);
    if(cosmoV2XKey->privKey == nullptr)
    {
        perror("Error creating the private key");
        EC_KEY_free(cosmoV2XKey->key);
        std::abort();
    }

    /* create the public key */

    cosmoV2XKey->pubKey = EC_KEY_get0_public_key(cosmoV2XKey->key);
    if(cosmoV2XKey->pubKey == nullptr)
    {
        perror("Error creating the private key");
        EC_KEY_free(cosmoV2XKey->key);
        std::abort();
    }

    {
        uint8_t *keyBuf;
        size_t keyLen = 0;
    
        keyBuf = ec_key_key2buf(cosmoV2XKey->key, POINT_CONVERSION_UNCOMPRESSED,&keyLen,"key-original");
        free(keyBuf);

        keyLen = 0;

        keyBuf = ec_key_key2buf(cosmoV2XKey->key, POINT_CONVERSION_COMPRESSED,&keyLen,"key-compressed");

        // if(keyBuf != nullptr)
        // {
        //     ec_key_buf2key(cosmoV2XKey->key1, keyBuf, keyLen);
        // }

        //ec_key_oct_read("ecc_key.txt");
        
        //EC_KEY_free(cosmoV2XKey->key1);
        /* recreate a new object, just to make sure we recover the key from a brand new object*/
        cosmoV2XKey->key1 = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);

        ec_key_buf2key(cosmoV2XKey->key1, keyBuf, keyLen);
        EC_KEY_free(cosmoV2XKey->key);
        EC_KEY_free(cosmoV2XKey->key1);

    }

    FILE *fp = fopen("ec_key_obj.txt", "w+");
    if (fp != nullptr)
    {
        EC_KEY_print_fp(fp, cosmoV2XKey->key, 0);
        ECParameters_print_fp(fp, cosmoV2XKey->key);
    }
    fclose(fp);
#endif    
    
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

    ctp::Ieee1609Cert *pcert = new ctp::Ieee1609Cert();
    uint8_t *encBuf = nullptr;
    size_t encLen = 0;
    pcert->create();
    // encLen = pcert->encode(&encBuf);
    // std::cout << "encoded buffer length " << encLen << std::endl;
    
    pcert->print();

    std::string tbsData("this is dummy test data!!!");
    ctp::Ieee1609Data *pdata = new ctp::Ieee1609Data();
    uint8_t *signedData = nullptr;
    size_t signedDataLength = 0;
    pdata->sign(32, (uint8_t *)tbsData.c_str(), tbsData.length(), &signedData, &signedDataLength, pcert);
    print_data("data_payload.txt", signedData, signedDataLength);
    std::cout << "number of bytes " << signedDataLength << std::endl;


    while(0)
    {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        std::abort();
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    delete pcert;
    delete pdata;
    return 0;
}