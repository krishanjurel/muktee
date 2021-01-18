/* this is the file that will do the key generataion, cert parsing, data signing and sign verification
*/
#include "ieee1609dot2.hpp"
#include <signal.h> /* for signal */
#include "openssl/ec.h"
#include "openssl/ecdsa.h"
#include "openssl/obj_mac.h"
#include "signal.h"
#include <unistd.h>
#include <stdio.h>
#include <cstring>
#include <string>
#include <thread>
#include <chrono>
#include <fstream>

typedef struct 
{
    EC_KEY *key;  /* key object */
    const BIGNUM *privKey; /* private key */
    const EC_POINT *pubKey; /* public key */
}CosmoV2XKey;


static CosmoV2XKey cosmoV2XKey_g;


void signal_handler(int sig)
{
    std::cout << "signal " << sig <<  " had been caugth" << std::endl;
    return;
}

void terminate_handler()
{
    std::cout << "terminate has been raised "<< std::endl;
    std::abort();
}


int main()
{
    CosmoV2XKey *cosmoV2XKey = &cosmoV2XKey_g;
 
    struct sigaction sigAct = {
        .sa_flags = SA_NOCLDSTOP | SA_NOCLDWAIT,
        .sa_restorer = nullptr,
    };
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
   
    /* create the key */
    /* associate a curve name with the key */
    cosmoV2XKey->key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (cosmoV2XKey->key == nullptr)
    {
        perror("<Main> Error associating key with a curve");
        std::terminate();
    }

    /* generate the private and associate public key */
    if (EC_KEY_generate_key(cosmoV2XKey->key) != 1)
    {
        perror("Error creating keys");
        EC_KEY_free(cosmoV2XKey->key);        
        std::abort();

    }
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

    std::ofstream ofs("ecc_key.txt", std::ofstream::out | std::ofstream::app);
    size_t i=0;
    size_t count = 0;
    uint8_t *keyBuf = nullptr;
    size_t keyBufSize = 0;
    keyBufSize = EC_KEY_key2buf(cosmoV2XKey->key,POINT_CONVERSION_UNCOMPRESSED, &keyBuf, nullptr);

    std::cout << "out put buffer size " << keyBufSize << std::endl;
    //std::cout << keyBuf << std::endl;
    uint8_t *encBuffer = new uint8_t[keyBufSize * 2+1];
    uint8_t *tempPtr = keyBuf;
    
    /* convert every octect to ascii rep */
    for(i = 0; i < keyBufSize && count < keyBufSize * 2; i++)
    {
        uint8_t _temp = *keyBuf;
        encBuffer[count++] =  (_temp & 0x0f)+'0';
        //std::cout << (_temp & 0x0f)+ '0' << " " ;
        encBuffer[count++] =  ((_temp >>4) & 0x0f) + '0';
        //std::cout << ((_temp >>4) & 0x0f) + '0' << std::endl ;
        keyBuf++;
    }
    
    free(tempPtr);
    encBuffer[count] = '\0';


    if(keyBufSize != 0)
    {
        ofs << "---BEGIN EC KEY----" << std::endl;
        ofs << encBuffer << std::endl;
        ofs << "---END EC KEY----" << std::endl;
    }
    ofs.close();

#if 0

    const char *cwd = "ec_params.txt";
    if (cwd != nullptr)
    {
        std::cout << "current director " << cwd << std::endl;
        FILE *fp = fopen(cwd, "w+");
        if(fp != nullptr)
        {
            ECParameters_print_fp(fp, cosmoV2XKey->key);
            fclose(fp);
        }
    }
#endif
    while(0)
    {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        std::abort();
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    EC_KEY_free(cosmoV2XKey->key);
    return 0;
}