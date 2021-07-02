#ifndef __DOT2DATA_HPP__
#define __DOT2DATA_HPP__

#include "dot2common.hpp"
#include "dot2cert.hpp"
#include "tp.hpp"
#include <string.h>

namespace ctp
{
    class Ieee1609Data;
    using SHARED_DATA = std::shared_ptr<Ieee1609Data>;
    using PTR_DATA = Ieee1609Data *;

    class Ieee1609Data:public mem_mgr
    {
        /* create an instance of encode object */
        SHARED_ENC enc;
        SHARED_DEC dec;

        // HashAlgorithmType *hashId;
        HeaderInfo *headerInfo;
        ToBeSignedData *tbsData;
        SignerIdentifier *signer;
        Signature *signature;
        SignedData *signedData;
        const ECDSA_SIG* sig;
        SHARED_CERT cert;
        /* signer for this data */
        // Ieee1609Cert *cert;
        SHARED_CERTS certs; /* the sequence of certificate */
        /* data member */
        Ieee1609Dot2Data *data;

        /* every module must have this */
        const int MODULE=MODULE_DATA;

        public:
            Ieee1609Data(){
                enc = SHARED_ENC(new Ieee1609Encode(), [](PTR_ENC ptr){delete ptr;});
                dec =  SHARED_DEC(new Ieee1609Decode(), [](PTR_DEC ptr){delete ptr;});
                data = (Ieee1609Dot2Data *)buf_alloc(sizeof(Ieee1609Dot2Data));
                signedData = (SignedData *)&data->content.content.signedData;
                tbsData = (ToBeSignedData *)&signedData->toBeSignedData;
                tbsData->payload.data = nullptr;
                signature = (Signature *)&signedData->signature;
                signer = (SignerIdentifier*)&signedData->signer;
                tbsData->payload.data=(Ieee1609Dot2Data *)buf_alloc(sizeof(Ieee1609Dot2Data));
                tbsData->payload.data->content.content.unsecuredData.octets = nullptr;
                headerInfo = (HeaderInfo*)&tbsData->headerInfo;
                data->protocolVersion = 0x03;
                /* get the certificate manager */
                certs = std::make_shared<Ieee1609Certs>();
                cert = std::make_shared<Ieee1609Cert>();
            }

            ~Ieee1609Data()
            {
                log_dbg("Ieee1609Data::~Ieee1609Data\n", MODULE);
                enc.reset();
                dec.reset();
                Ieee1609Dot2Data *data_ = tbsData->payload.data;
                if(data_)
                {
                    if(data_->content.content.unsecuredData.octets)
                    {
                        buf_free(data_->content.content.unsecuredData.octets);
                    }
                    buf_free(data_);
                }
                buf_free(data);
                if(certs.operator bool() == true)
                {
                    certs = nullptr;
                }
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
            int sign(int psid, const uint8_t *buf, size_t len,
                    uint8_t **signedData, size_t *signedDataLen,
                    SHARED_CERT cert);
            
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
                    /* FIXME, for now take the last certificate in the chain, as
                       last one is tha data signer,
                    */
                    std::vector<SHARED_CERT> _certs = certs->CertList();
                    cert = _certs[_certs.size()-1];
                    /* check the signing capability of the signer */
                    /* consistency check of the certificate */
                    ret = cert->ConsistencyCheck(std::ref(*headerInfo));
                    if(ret == 0)
                    {
                        log_.str("");
                        log_ << "Ieee1609Data::verify::certs->ConsistencyCheck(const HeaderInfo& header) failed ";
                        log_ << std::endl;
                        LOG_ERR(log_.str(), MODULE);
                        throw Exception(log_.str());
                    }

                    /* create the hash of the received data */
                    ret = cert->Hash256(data_->content.content.unsecuredData.octets, 
                                    data_->content.content.unsecuredData.length, &hash1);
                    if(ret == 0)
                    {
                        log_ << "Ieee1609Data::verify::certs->Hash256:payload" << std::endl;
                        LOG_ERR(log_.str(), MODULE);
                        throw Exception(log_.str());
                    }

                    /* now get the signer's hash */
                    /* get the encoded buffer of the signer */
                    hash2Len = cert->encode(&hashBuf);
#ifdef __VERBOSE__
                    std::cout << "Ieee1609Data::verify certs->encode_signer" << std::endl;
                    print_data(nullptr, hashBuf, hash2Len);
#endif                    

                    ret = cert->Hash256(hashBuf, hash2Len,&hash2);
                    if(ret == 0)
                    {
                        log_.str("");
                        log_ << "Ieee1609Data::verify::certs->Hash256:signer";
                        log_ << std::endl;
                        LOG_ERR(log_.str(), MODULE);
                        throw Exception(log_.str());
                    }
                    /* combine the hash of payload and signer, 32+32=64 */
                    hashBuf = (uint8_t*)buf_alloc(2*SHA256_DIGEST_LENGTH);
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
                    ret = cert->Hash256(hashBuf, 2*SHA256_DIGEST_LENGTH, &hash1);
                    if(ret == 0)
                    {
                        log_.str("");
                        log_ << "Ieee1609Data::verify::certs->Hash256:signer and payload";
                        log_ << std::endl;
                        LOG_ERR(log_.str(), MODULE);
                        buf_free(hashBuf);
                        throw Exception(log_.str());
                    }
                    ret = cert->verify(hash1, SHA256_DIGEST_LENGTH, std::ref(*signature));
                    if(ret != 1)
                    {
                        log_ << "Ieee1609Data::verify::certs->verify failed";
                        log_ << std::endl;
                        LOG_ERR(log_.str(), MODULE);
                        buf_free(hashBuf);
                        hashBuf = nullptr;
                        throw Exception(log_.str());
                    }
                }catch(ctp::Exception &e)
                {
                    if(hashBuf)
                        buf_free(hashBuf);
                    log_.str("");
                    log_ << "Ieee1609Data::verify exit" << e.what() << std::endl;
                    LOG_ERR(log_.str(), MODULE);
                    throw;
                }
                if(hashBuf)
                    buf_free(hashBuf);
                log_ << "Ieee1609Data::verify() exit " << std::endl;
                log_info(log_.str(), MODULE);
                log_.str("");
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
