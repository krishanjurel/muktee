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


    void Ieee1609Data::sign(int psid, const uint8_t *tbsData, size_t tbsDataLen,
                  uint8_t **signedData, size_t *signedDataLen,
                  Ieee1609Cert *cert)
    {
        int ret = 0;
        /* for signing, get the encoded certiificate */
        uint8_t *hashBuf = nullptr;
        size_t hashBufLen = 0;;
        uint8_t *hash = nullptr;
        uint8_t *tbsBuf = nullptr;
        size_t tbsLen = 0;

        LOG_INFO("Ieee1609Data::sign", MODULE);
        this->tbsData = nullptr;
        /* create the ToBeSignedData (6.3.6) data structure */
        this->tbsData = (ToBeSignedData *) buf_realloc(this->tbsData, sizeof(ToBeSignedData));
        this->tbsData->headerInfo.psid = psid; /* just use the psid only for now */
        SignedDataPayload *payload = &this->tbsData->payload;
        payload->data = nullptr;
        payload->data = (Ieee1609Dot2Data *)buf_realloc(payload->data, sizeof(Ieee1609Dot2Data));
        /* unsecured data */
        payload->data->content.type = Ieee1609Dot2ContentUnsecuredData;
        payload->data->protocolVersion = 0x03;
        payload->data->content.UNSECUREDDATA.length = tbsDataLen;
        payload->data->content.UNSECUREDDATA.octets = (uint8_t *)buf_alloc(tbsDataLen);
        /* create a local copy of the certificate */
        this->cert = cert;
        /* copy the data into unsecured buffer */
        for(int i = 0; i < tbsDataLen; i++)
        {
            payload->data->content.UNSECUREDDATA.octets[i] = tbsData[i];
        }
        if (cert != nullptr)
        {
            tbsLen = 0;

           /* get the hash the data */
            ret = cert->Hash256(tbsData, tbsDataLen, &hash);
            /* failure to calculate the hash */
            if(ret == 0)
            {
                LOG_ERR("Ieee1609Data::sign::cert->Hash256 tbsData::hash", MODULE);
                goto done;
            }

            tbsLen += SHA256_DIGEST_LENGTH;
            tbsBuf = nullptr;
            tbsBuf = (uint8_t *)buf_realloc(tbsBuf, tbsLen);
            memcpy(tbsBuf,hash,tbsLen);
            free(hash);
            hash = nullptr;

            /* get the encoded buffer of the signer */
            hashBufLen = cert->encode(&hashBuf);
            /* get the hash of the  certificate buffer */
            ret = cert->Hash256(hashBuf, hashBufLen, &hash);
            /* failure to calculate the hash */
            if(ret == 0)
            {
                LOG_ERR("Ieee1609Data::sign::cert->Hash256 cert::hash", MODULE);
                goto done;
            }

            tbsLen += SHA256_DIGEST_LENGTH;
            tbsBuf = (uint8_t *)buf_realloc(tbsBuf, tbsLen);
            /*hash(tbsData) || hash(signer)*/
            memcpy(&tbsBuf[SHA256_DIGEST_LENGTH], hash, SHA256_DIGEST_LENGTH);
            free(hash);
            hash = nullptr;
            /* calculate the hash of hash(tbsData) || hash(signer) */
            ret = cert->Hash256(tbsBuf, tbsLen, &hash);
            /* failure to calculate the hash */
            if(ret == 0)
            {
                LOG_ERR("Ieee1609Data::sign::cert->Hash256 cert::hash", MODULE);
                goto done;
            }
            /* sign the data */
            sig = cert->SignData(hash, SHA256_DIGEST_LENGTH,ecdsaNistP256Signature);
            if(signature == nullptr)
            signature = (Signature *)buf_alloc(sizeof(Signature));

            /* get the signature from sig */
            cert->SigToSignature(sig, std::ref(*signature));
        }
        encode();
        /* get the encoded buffer */
        *signedDataLen = enc->get(signedData);
        done:
            if(hash)
                free (hash);
            if(tbsBuf)
                free(tbsBuf);

        LOG_INFO("Ieee1609Data::sign Exit", MODULE);
    }


    /* encode tobesigned data */
    int Ieee1609Data::encode_tbsdata(bool cont)
    {
        if(cont == false)
            enc->clear();
        return enc->ToBesignedData_(std::ref(*tbsData));
    }
    /* we are always signing with a  cert */
    int Ieee1609Data::encode_signeridentifier(bool cont)
    {
        /* if only signer identifier need to be encoded */
        if (cont == false)
            enc->clear();
        return enc->SignerIdentifier_(std::ref(*cert), SignerIdentifierTypeCert);
    }

    int Ieee1609Data::encode_signature(bool cont)
    {
        if(cont == false)
            enc->clear();
        return enc->Signature_(std::ref(*signature));
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
        encode_signature();
        return 0;
    }


    void Ieee1609Data::encode_content(bool cont)
    {
        if(cont == false)
            enc->clear();
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
        enc->OctetsFixed(&data->protocolVersion, 1);
        encode_content();
        // enc->HashAlgo(HashAlgorithmTypeSha256);
        // enc->ToBesignedData_(std::ref(*tbsData));
        // /* since signer is the certificate, we need to pass the object to the certificate */
        // enc->SignerIdentifier_(std::ref(*cert), SignerIdentifierTypeCert); 
        // enc->Signature_(signature);
    }
}//namespace ctp 
