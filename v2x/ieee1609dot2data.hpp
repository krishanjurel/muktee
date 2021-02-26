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

        public:
            Ieee1609Data(){
                enc = new Ieee1609Encode();
                tpPtr = TP::instance_get();
                /* get the certificate manager */
                //certMgrPtr = tpPtr->cert_mgr();
            }

            ~Ieee1609Data()
            {
                delete enc;
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

            /* encode the data*/
            void encode();
    };



}/* namespace ctp */

















#endif //__IEEE_1609DOT2DATA_HPP__
