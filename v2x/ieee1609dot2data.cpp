#include "ieee1609dot2data.hpp"

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
        payload->data->content.unsecuredData.length = len;
        payload->data->content.unsecuredData.octets = (uint8_t *)buf_alloc(len);
        /* copy the data into unsecured buffer */
        for(int i = 0; i < len; i++)
        {
            payload->data->content.unsecuredData.octets[i] = tbsData[i];
        }

        /* the complete flow is something like this */
        // /* get the cert for this psid */
        cert = certMgrPtr->operator[](psid);
        if (cert != nullptr)
        {
            /* sign the data */
            signature = cert->signEx(tbsData, len);
        }
        encode();
        *signedDataLen = enc->get(signedData);
    }
    /* encode tobesigned data */
    int Ieee1609Data::encode_tbsdata()
    {
        enc->clear();
        return enc->ToBesignedData_(std::ref(*tbsData));
    }
    /*encode signed data */
    int Ieee1609Data::encode_signeddata()
    {
        enc->clear();
        enc->HashAlgo(HashAlgorithmTypeSha256);
        enc->ToBesignedData_(std::ref(*tbsData));
        cert->encode(nullptr);
        return enc->Signature_(signature);
    }

    void Ieee1609Data::encode()
    {
        /* clear everything */
        enc->clear();

        enc->OctectsFixed(&data->protocolVersion, 1);
        /* encode signed data content type */
        enc->Ieee1609Dot2ContentType_(Ieee1609Dot2ContentSignedData);
        enc->HashAlgo(HashAlgorithmTypeSha256);
        enc->ToBesignedData_(std::ref(*tbsData));
        /* since signer is the certificate, we need to pass the object to the certificate */
        enc->SignerIdentifier_(std::ref(*cert), SignerIdentifierTypeCert); 
        enc->Signature_(signature);
    }
}//namespace ctp 
