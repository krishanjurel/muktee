#include "ieee1609dot2data.hpp"
#include <stdlib.h>
#include <string.h>


//#define MOUDLE "1609DATA"
#define MODULE 2

namespace ctp
{
    void Ieee1609Data::sign(int psid, const uint8_t *tbsData, size_t len,
                  uint8_t **signedData, size_t *signedDataLen)
    {

        /* create the ToBeSignedData (6.3.6) data structure */
        this->tbsData = (ToBeSignedData *) buf_realloc(this->tbsData, sizeof(ToBeSignedData));
        this->tbsData->headerInfo.psid = psid; /* just use the psid only for now */
        SignedDataPayload *payload = &this->tbsData->payload;
        payload->data = (Ieee1609Dot2Data *)buf_realloc(payload->data, sizeof(Ieee1609Dot2Data));
        /* unsecured data */
        payload->data->content.type = Ieee1609Dot2ContentUnsecuredData;
        payload->data->protocolVersion = 0x03;
        payload->data->content.UNSECUREDDATA.length = len;
        payload->data->content.UNSECUREDDATA.octets = (uint8_t *)buf_alloc(len);
        /* copy the data into unsecured buffer */
        for(int i = 0; i < len; i++)
        {
            payload->data->content.UNSECUREDDATA.octets[i] = tbsData[i];
        }

        /* the complete flow is something like this */
        // /* get the cert for this psid */
        cert = certMgrPtr->operator[](psid);
        if (cert != nullptr)
        {
            /* sign the data */
            sig = cert->SignData(tbsData, len, ecdsaNistP256Signature);
        }
        encode();
        *signedDataLen = enc->get(signedData);
    }


    void Ieee1609Data::sign(int psid, const uint8_t *tbsData, size_t len,
                  uint8_t **signedData, size_t *signedDataLen,
                  Ieee1609Cert *cert)
    {
        LOG_INFO("Ieee1609Data::sign", MODULE);

        /* create the ToBeSignedData (6.3.6) data structure */
        this->tbsData = (ToBeSignedData *) buf_realloc(this->tbsData, sizeof(ToBeSignedData));
        this->tbsData->headerInfo.psid = psid; /* just use the psid only for now */
        SignedDataPayload *payload = &this->tbsData->payload;
        payload->data = nullptr;
        payload->data = (Ieee1609Dot2Data *)buf_realloc(payload->data, sizeof(Ieee1609Dot2Data));
        /* unsecured data */
        payload->data->content.type = Ieee1609Dot2ContentUnsecuredData;
        payload->data->protocolVersion = 0x03;
        payload->data->content.UNSECUREDDATA.length = len;
        payload->data->content.UNSECUREDDATA.octets = (uint8_t *)buf_alloc(len);
        /* create a local copy of the certificate */
        this->cert = cert;
        /* copy the data into unsecured buffer */
        for(int i = 0; i < len; i++)
        {
            payload->data->content.UNSECUREDDATA.octets[i] = tbsData[i];
        }
        if (cert != nullptr)
        {
            /* sign the data */
            sig = cert->SignData(tbsData, len, ecdsaNistP256Signature);
        }
         encode();
         size_t templen = 0;
         uint8_t *tempbuf = nullptr;
         /* 
         FIXME, directly writing into signedDataLen and signedData results in segment fault,
         indicating an illegal memory access 
         */
        templen = enc->get(&tempbuf);
        if(templen)
        {
            //*signedDataLen = enc->get(signedData);
            *signedData = (uint8_t *)buf_alloc(templen);
            memcpy(*signedData, tempbuf, templen);
            *signedDataLen  = templen;
        }
        LOG_INFO("Ieee1609Data::sign", MODULE);
    }


    /* encode tobesigned data */
    int Ieee1609Data::encode_tbsdata()
    {
        enc->clear();
        return enc->ToBesignedData_(std::ref(*tbsData));
    }
    /* we are always signing with a  cert */
    int Ieee1609Data::encode_signeridentifier()
    {
        return enc->SignerIdentifier_(std::ref(*cert), SignerIdentifierTypeCert);
    }

    /*encode signed data */
    int Ieee1609Data::encode_signeddata(bool cont)
    {
        if (cont == false)
            enc->clear();
        enc->HashAlgo(HashAlgorithmTypeSha256);
        enc->ToBesignedData_(std::ref(*tbsData));
        /* encode the signer */
        encode_signeridentifier();
        //return enc->Signature_(signature);
        return 0;
    }


    void Ieee1609Data::encode_content()
    {
        /* encode signed data content type */
        enc->Ieee1609Dot2ContentType_(content->type);
        switch(content->type)
        {
            case Ieee1609Dot2ContentSignedData:
                encode_signeddata(true);
                break;
            default:
                LOG_ERR("content type not supported ", MODULE);
                break;
        }
    }

    void Ieee1609Data::encode()
    {
        /* clear everything */
        enc->clear();

        enc->OctectsFixed(&data->protocolVersion, 1);
        encode_content();
        // enc->HashAlgo(HashAlgorithmTypeSha256);
        // enc->ToBesignedData_(std::ref(*tbsData));
        // /* since signer is the certificate, we need to pass the object to the certificate */
        // enc->SignerIdentifier_(std::ref(*cert), SignerIdentifierTypeCert); 
        // enc->Signature_(signature);
    }
}//namespace ctp 
