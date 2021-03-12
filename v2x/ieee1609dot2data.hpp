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
        Ieee1609Encode *enc;
        /* FIXME, create an instance of decode object */
        //decode *decode;

        HashAlgorithmType *hashId;
        ToBeSignedData *tbsData;
        const SignerIdentifier *signer;
        const Signature *signature;
        TP_PTR tpPtr;
        Ieee1609Cert *certMgrPtr;
        /* signer for this data */
        Ieee1609Cert *cert; 

        /* data member */
        Ieee1609Dot2Data *data;
        Ieee1609Dot2Content *content;



        
        public:
            Ieee1609Data(){
                enc = new Ieee1609Encode();
                tpPtr = TP::instance_get();
                data = (Ieee1609Dot2Data *)buf_alloc(sizeof(Ieee1609Dot2Data));
                content = (Ieee1609Dot2Content *) buf_alloc(sizeof(Ieee1609Dot2Content));
                content->type = Ieee1609Dot2ContentSignedData;
                data->protocolVersion = 0x03;
                tbsData = nullptr;
                hashId = nullptr;
                cert = nullptr;
                

                /* get the certificate manager */
                //certMgrPtr = tpPtr->cert_mgr();
            }

            ~Ieee1609Data()
            {
                delete enc;
                free(data);
                free(content);
                free(tbsData);
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
            void sign(int psid, const uint8_t *tbsData, size_t len,
                    uint8_t **signedData, size_t *signedDataLen,
                    Ieee1609Cert *cert);

            /* encode the data*/
            void encode();
            void encode_content();
            int encode_signeridentifier();
            int encode_tbsdata();
            int encode_signeddata(bool cont = false);


            void print();
    };



}/* namespace ctp */

















#endif //__IEEE_1609DOT2DATA_HPP__
