#ifndef __DOT2DATA_HPP__
#define __DOT2DATA_HPP__

#include "dot2common.hpp"
#include "dot2cert.hpp"
#include "tp.hpp"
// #include "dot2encdec.hpp"
#include <string.h>

namespace ctp
{
    class TP; /* forward declaration */
    using TP_PTR = std::shared_ptr<TP>;

    class Ieee1609Data:public mem_mgr
    {
        /* create an instance of encode object */
        std::shared_ptr<Ieee1609Encode> enc;
        std::shared_ptr<Ieee1609Decode> dec;
        /* FIXME, create an instance of decode object */
        //decode *decode;

        // HashAlgorithmType *hashId;
        HeaderInfo *headerInfo;
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
                tpPtr = nullptr; //TP::init();
                data = (Ieee1609Dot2Data *)buf_alloc(sizeof(Ieee1609Dot2Data));
                signedData = (SignedData *)&data->content.content.signedData;
                tbsData = (ToBeSignedData *)&signedData->toBeSignedData;
                signature = (Signature *)&signedData->signature;
                signer = (SignerIdentifier*)&signedData->signer;
                tbsData->payload.data=(Ieee1609Dot2Data *)buf_alloc(sizeof(Ieee1609Dot2Data));
                headerInfo = (HeaderInfo*)&tbsData->headerInfo;
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
                size_t hash2Len;
                std::stringstream log_(std::ios_base::out);
                log_ << "Ieee1609Data::verify() enter " << std::endl;
                log_info(log_.str(), MODULE);
                log_.str("");
                try
                {
                    Ieee1609Dot2Data *data_ = tbsData->payload.data;
#ifdef __VERBOSE__
                    std::cout << "Ieee1609Data::verify payload  " << std::endl;
                    print_data(nullptr, data_->content.content.unsecuredData.octets,
                                        data_->content.content.unsecuredData.length);
#endif
                    /* check the signing capability of the signer */
                    /* consistency check of the certificate */
                    ret = certs->ConsistencyCheck(std::ref(*headerInfo));
                    if(ret == 0)
                    {
                        log_.str("");
                        log_ << "Ieee1609Data::verify::certs->ConsistencyCheck(const HeaderInfo& header) failed ";
                        log_ << std::endl;
                        LOG_ERR(log_.str(), MODULE);
                        throw Exception(log_.str());
                    }

                    /* create the hash of the received data */
                    ret = certs->Hash256(data_->content.content.unsecuredData.octets, 
                                    data_->content.content.unsecuredData.length, &hash1);
                    if(ret == 0)
                    {
                        log_ << "Ieee1609Data::verify::certs->Hash256:payload" << std::endl;
                        LOG_ERR(log_.str(), MODULE);
                        throw Exception(log_.str());
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
                        log_.str("");
                        log_ << "Ieee1609Data::verify::certs->Hash256:signer";
                        log_ << std::endl;
                        LOG_ERR(log_.str(), MODULE);
                        throw Exception(log_.str());
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
                        log_.str("");
                        log_ << "Ieee1609Data::verify::certs->Hash256:signer and payload";
                        log_ << std::endl;
                        LOG_ERR(log_.str(), MODULE);
                        throw Exception(log_.str());
                    }
                    ret = certs->verify(hash1, SHA256_DIGEST_LENGTH, std::ref(*signature));
                    if(ret != 1)
                    {
                        log_ << "Ieee1609Data::verify::certs->verify failed";
                        log_ << std::endl;
                        LOG_ERR(log_.str(), MODULE);
                        throw Exception(log_.str());
                    }
                }catch(ctp::Exception &e)
                {
                    free(hashBuf);
                    log_.str("");
                    log_ << "Ieee1609Data::verify " << e.what() << std::endl;
                    LOG_ERR(log_.str(), MODULE);
                    throw;
                }
                return ret;
            }

            /* exposed apis for clients to access information*/
            HeaderInfo* HeaderInfo_()
            {
                return headerInfo;
            }
            /* to be signed data */
            ToBeSignedData* ToBeSignedData_()
            {
                return tbsData;
            }
            /* get the root data structure */
            Ieee1609Dot2Data *Data_()
            {
                return data;
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
}//namespace ctp
#endif //__IEEE_1609DOT2DATA_HPP__
