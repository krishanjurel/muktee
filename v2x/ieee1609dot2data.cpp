#include "ieee1609dot2data.hpp"

namespace ctp
{
    void Ieee1609Data::sign(int psid, const uint8_t *tbsData, size_t len,
                  uint8_t **signedData, size_t *signedDataLen)
    {
        /* the complete flow is something like this */
        // /* get the cert for this psid */
        const Ieee1609Cert *cert = certMgrPtr->operator[](psid);
        if (cert != nullptr)
        {
            /* sign the data */
            signature = certMgrPtr->signEx(tbsData, len);
        }
    }

    void Ieee1609Data::encode()
    {
        enc->HashAlgo(HashAlgorithmTypeSha256);
        enc->ToBesignedData_(std::ref(*tbsData));
        enc->SignerIdentifier_(std::ref(*signer));
        enc->Signature_(signature);
    }
}//namespace ctp 
