#ifndef __IEEE_1609DOT2DATA_HPP__
#define __IEEE_1609DOT2DATA_HPP__

#include "ieee1609dot2common.hpp"
#include "ieee1609dot2cert.hpp"
#include "ieee1609dot2.hpp"
#include <string.h>

namespace ctp
{

    class Ieee1609Data:public mem_mgr
    {
        /* create an instance of encode object */
        std::shared_ptr<Ieee1609Encode> enc;
        std::shared_ptr<Ieee1609Decode> dec;
        /* FIXME, create an instance of decode object */
        //decode *decode;

        // HashAlgorithmType *hashId;
        ToBeSignedData *tbsData;
        SignerIdentifier *signer;
        Signature *signature;
        SignedData *signedData;
        const ECDSA_SIG* sig;
        TP_PTR tpPtr;
        Ieee1609Cert *certMgrPtr;
        /* signer for this data */
        Ieee1609Cert *cert;
        Ieee1609Certs *certs; /* the sequence of certificate */

        /* data member */
        Ieee1609Dot2Data *data;
        public:
            Ieee1609Data(){
                enc = std::shared_ptr<Ieee1609Encode>(new Ieee1609Encode(), [](Ieee1609Encode *ptr){delete ptr;});
                dec =  std::shared_ptr<Ieee1609Decode>(new Ieee1609Decode(), [](Ieee1609Decode *ptr){delete ptr;});
                tpPtr = TP::init();
                data = (Ieee1609Dot2Data *)buf_alloc(sizeof(Ieee1609Dot2Data));
                signedData = (SignedData *)&data->content.content.signedData;
                tbsData = (ToBeSignedData *)&signedData->toBeSignedData;
                signature = (Signature *)&signedData->signature;
                signer = (SignerIdentifier*)&signedData->signer;
                tbsData->payload.data=(Ieee1609Dot2Data *)buf_alloc(sizeof(Ieee1609Dot2Data));
                data->protocolVersion = 0x03;
                /* get the certificate manager */
                //certMgrPtr = tpPtr->cert_mgr();
                certs = new ctp::Ieee1609Certs();
            }

            ~Ieee1609Data()
            {
                enc.reset();
                dec.reset();
                free(data);
                free(tbsData->payload.data);
                // delete certs;
            }
            /* a method that can be called on recieving signed data */
            void process(const uint8_t *data,size_t len, ...)
            {
                /* this function handles the incoming data */
            }

            /* this routine, creates signed data payload
            1. create Ieee1609Dot2Data structure, with payload SignedData
            */
            void sign(int psid, const uint8_t *tbsData, size_t len,
                    uint8_t **signedData, size_t *signedDataLen);
            
            /* sign with a supplied certificate */
            void sign(int psid, const uint8_t *buf, size_t len,
                    uint8_t **signedData, size_t *signedDataLen,
                    Ieee1609Certs *cert);
            
            /* verify the received payload */    
            int verify()
            {
                int ret = 0;
                uint8_t *hash1; /* hash of the tbsData */
                uint8_t *hash2; /* hash of the certificate (not sequence of certificate, rather hash of the signer) */
                uint8_t *hashBuf = nullptr;
                size_t hash1Len, hash2Len;
                try
                {
                    Ieee1609Dot2Data *data_ = tbsData->payload.data;
#ifdef __VERBOSE__
                    std::cout << "Ieee1609Data::verify payload  " << std::endl;
                    print_data(nullptr, data_->content.content.unsecuredData.octets,
                                        data_->content.content.unsecuredData.length);
#endif                                        



                    /* create the hash of the received data */
                    ret = certs->Hash256(data_->content.content.unsecuredData.octets, 
                                    data_->content.content.unsecuredData.length, &hash1);
                    if(ret == 0)
                    {
                        std::string err_("Ieee1609Data::verify::certs->Hash256:payload");
                        LOG_ERR(err_, MODULE);
                        throw Exception(err_);
                    }

                    /* now get the signer's hash */
                    /* get the encoded buffer of the signer */
                    hash2Len = certs->encode_signer(&hashBuf);
#ifdef __VERBOSE__
                    std::cout << "Ieee1609Data::verify certs->encode_signer" << std::endl;
                    print_data(nullptr, hashBuf, hash2Len);
#endif                    

                    ret = certs->Hash256(hashBuf, hash2Len,&hash2);
                    if(ret == 0)
                    {
                        std::string err_("Ieee1609Data::verify::certs->Hash256:signer");
                        LOG_ERR(err_, MODULE);
                        throw Exception(err_);
                    }
                    free(hashBuf);
                    /* combine the hash of payload and signer, 32+32=64 */
                    hashBuf = (uint8_t*)buf_alloc(64);
                    memcpy((void*)hashBuf, hash1, SHA256_DIGEST_LENGTH);
                    memcpy((void*)&hashBuf[SHA256_DIGEST_LENGTH],hash2, SHA256_DIGEST_LENGTH);
                    /* free the buffers */
                    free(hash1);
                    free(hash2);
#ifdef __VERBOSE__
                    std::cout << "Ieee1609Data::sign certs->Hash256 final " << std::endl;
                    print_data(nullptr, hashBuf,  2*SHA256_DIGEST_LENGTH);
#endif                    

                    /* calculate the hash of payload and signer */
                    ret = certs->Hash256(hashBuf, 2*SHA256_DIGEST_LENGTH, &hash1);
                    if(ret == 0)
                    {
                        std::string err_("Ieee1609Data::verify::certs->Hash256:signer and payload");
                        LOG_ERR(err_, MODULE);
                        throw Exception(err_);
                    }
                    ret = certs->verify(hash1, SHA256_DIGEST_LENGTH, std::ref(*signature));
                    if(ret != 1)
                    {
                        std::string msg_("Ieee1609Data::verify::certs->verify failed");
                        LOG_ERR(msg_, MODULE);
                    }
                    return 1;

                }catch(ctp::Exception &e)
                {
                    free(hashBuf);
                    LOG_ERR(e.what(), MODULE);
                    throw;
                    return 0;
                }
            }

            /* encode the data*/
            void encode();
            void encode_content(bool cont = true);
            int encode_signeridentifier(bool cont = true);
            int encode_tbsdata(bool cont = true);
            int encode_signeddata(bool cont = true);
            int encode_signature(bool cont = true);
            int encode(uint8_t **buf);


            /* decode the data */
            int decode(const uint8_t * buf, size_t len);
            //int decode(std::shared_ptr<Ieee1609Decode> ptr); 
            int decode_content();
            int decode_signeridentifier();
            int decode_tbsdata();
            int decode_signeddata();
            int decode_signature();

            void print_encoded(const char *file);
            void print(const char* file="data.txt");
            void print_decoded(const char* file);
    };



}/* namespace ctp */

















#endif //__IEEE_1609DOT2DATA_HPP__
