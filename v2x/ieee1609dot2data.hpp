#ifndef __IEEE_1609DOT2DATA_HPP__
#define __IEEE_1609DOT2DATA_HPP__

#include "ieee1609dot2common.hpp"
#include "ieee1609dot2cert.hpp"
#include "ieee1609dot2.hpp"

namespace ctp
{

    class Ieee1609Data
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
                free(signature);
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
