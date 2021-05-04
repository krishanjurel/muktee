#ifndef __DOT2ENCDEC_HPP__
#define __DOT2ENCDEC_HPP__
#include <iostream>
#include "dot2common.hpp"
#include "dot2cert.hpp"
#include "../tp.hpp"
#include <map>
#include <vector>
#include <iostream>
#include <fstream>
#include <sstream>
#include <memory>
#include <string>

#define MODULE 4


namespace ctp
{

    class Ieee1609Encode:public std::enable_shared_from_this<Ieee1609Encode>,public mem_mgr
    {
        using sharedPtr = std::shared_ptr<Ieee1609Encode>;
        uint8_t *encBuf; /*encoded buffer */
        size_t encLen;   /* encoded length */

        public:
            sharedPtr getPtr()
            {
                return shared_from_this();
            }
            Ieee1609Encode():encBuf(nullptr),encLen(0){};
            ~Ieee1609Encode()
            {
                std::cout << " Ieee1609Encode::Ieee1609Encode " << std::endl;
                delete encBuf;
                encBuf = nullptr;
                encLen = 0;
            }
            /* encode fixed length octets, i.e, no need for length encoding */
            int OctetsFixed(const uint8_t *octets, size_t len);
            /* encode psid */
            int psid_(int psid, int bytes = 1);
            /* encode octets */
            int Octets_(const uint8_t* octets, size_t len);
            /* encode certificate identifier */
            int CertId(const CertificateId& id);
            /* encode crl series */
            int CrlSeries(const uint16_t series);
            /* encode hashid3 */
            int HashId3(const uint8_t* hash, size_t len);
            /* encode the signature */
            int Sign(const Signature& signature);
            /* encode validity period */
            int VP(const ValidityPeriod& validityPeriod);
            /* encode verfication key indicator */
            int Vki(const VerificationKeyIndicator& vki);
            int SequenceOf(size_t quantity);
            int SequenceOfPsid_(const SequenceOfPsidSsp& psids);
            int IssuerIdentifier_(const IssuerIdentifier& issuer);
            int Length(size_t bytes);
            int Length(const uint8_t *values, size_t bytes);
            /* There are instances where only the number of bytes to store a number, i.e. sequence-of, and 
                There are instances where a certain length has to be encoded. the length encoding is done 
                by Length method.
            */
            size_t NumBytes(size_t number);


           /*encoding of signed data, 6.3.4 */
            int SignedDataPayload_(const Ieee1609Dot2Data& data);
            int HashAlgo(HashAlgorithmType type);
            int HeaderInfo_(const HeaderInfo& header);
            int ToBesignedData_(const ToBeSignedData& tbsData);
            int SignerIdentifier_(Ieee1609Cert& signer, SignerIdentifierType type);
            int SignerIdentifier_(Ieee1609Certs& signer, SignerIdentifierType type);
            int Signature_(const Signature& signature);
            int ContentType_(const Ieee1609Dot2ContentType type);
            // int SequenceOfCerts_(const SequenceOfCertificate& certs);
            /* int encoded buffer get */
            int get(uint8_t **buf);
            /* clear the encoded buuffer */
            int clear();
    };


    class Ieee1609Decode:public std::enable_shared_from_this<Ieee1609Decode>,public mem_mgr
    {
        uint8_t *buf; /*encoded buffer */
        size_t len;   /* encoded length */
        size_t offset; /* buffer offset */
        typedef std::shared_ptr<Ieee1609Decode> SharedPtr;
        public:

            SharedPtr GetPtr()
            {
                return shared_from_this();
            }

            Ieee1609Decode():buf(nullptr),len(0){};
            ~Ieee1609Decode()
            {
                std::cout << "Ieee1609Decode::~Ieee1609Decode" << std::endl;
                delete buf;
                len = 0;
            }
            /* decode fixed length octets, i.e, no need for length encoding */
            int OctetsFixed(uint8_t *octets, size_t len_)
            {
                std::stringbuf log_(std::ios_base::out);
                std::ostream os(&log_);
                os << " Ieee1609Decode::OctetsFixed enter " <<  len << " offset " << offset << std::endl;
                log_info(log_.str(), MODULE);
                log_.str("");
                if (len_+offset > this->len)
                {
                    os << " Ieee1609Decode::OctetsFixed not enough buffer " <<  len << " offset " << offset << std::endl;
                    LOG_ERR(log_.str(), MODULE);
                    throw Exception(log_.str());
                    return 0;
                }

                while(len_--)
                {
                    *octets++ = buf[offset++];
                }

                os << " Ieee1609Decode::OctetsFixed exit " <<  len << " offset " << offset << std::endl;
                log_info(log_.str(), MODULE);
                return offset;
            }
            /* decode psid */
            int psid_(int *psid, int bytes = 1)
            {
                return 0;
            }
            /* encode octets */
            int Octets_(uint8_t* octets, size_t len)
            {
                return OctetsFixed(octets, len);
            }

            /* encode the signature */
            int Sign(Signature& signature)
            {
                return 0;
            }
            /* encode validity period */
            
            int VP(ValidityPeriod& vp)
            {
                
                std::stringbuf log_(std::ios_base::out | std::ios_base::ate);
                std::ostream os(&log_);
                os << " Ieee1609Decode::VP enter " <<  len << " offset " << offset << std::endl;
                log_info(log_.str(), MODULE);
                log_.str("");

                /* read 4 bytes of uint32 in big endian format */
                uint8_t *buf_ = (uint8_t *)&vp.start;
                size_t len_ = 4;
                while(len_)
                {
                    len_ --;
                    buf_[len_] = buf[offset++];
                }
                os << " Ieee1609Decode::VP start " << vp.start << std::endl;
                log_info(log_.str(), MODULE);
                log_.str("");
                /* get the choice of duration */
                vp.duration.type = (DurationType)(buf[offset++] & ASN1_COER_CHOICE_MASK_CLR);
                os << " Ieee1609Decode::VP " << " duration type " << vp.duration.type << std::endl;
                log_info(log_.str(), MODULE);
                log_.str("");
                /* read remaining two bytes of the duration */
                vp.duration.duration = (buf[offset++] << 8);
                vp.duration.duration |= (buf[offset++]);
                os << " Ieee1609Decode::VP exit " <<  len << " offset " << offset << std::endl;
                log_info(log_.str(), MODULE);
                os.clear();

                return 0;
            }
            /* encode verfication key indicator,6.4.35  */
            /* FIXME, break it into sub modules */
            int Vki(VerificationKeyIndicator& vki)
            {
                std::stringstream log_(std::ios_base::out);
                log_ << " Ieee1609Decode::Vki enter " <<  len << " offset " << offset << std::endl;
                log_info(log_.str(), MODULE);
                log_.str("");

                /* read the choice, 6.4.35 */
                vki.type = (VerificationKeyIndicatorType)(buf[offset++] & ASN1_COER_CHOICE_MASK_CLR);
                switch(vki.type)
                {
                    case VerificationKeyIndicatorTypeKey:
                        /* decode public verfiification key, 6.4.36 */
                        vki.indicator.verificationKey.type = (PublicVerificationKeyType)(buf[offset++] & ASN1_COER_CHOICE_MASK_CLR);
                        switch(vki.indicator.verificationKey.type)
                        {
                            case PublicVerificationKeyTypEecdsaNistP256S:
                            {
                                /* decode the curve point 6.3.23*/
                                EccP256CurvPoint *point = &vki.indicator.verificationKey.key.ecdsaNistP256;
                                /* get the choice type */
                                point->type = (EccP256CurvPointType)(buf[offset++] & ASN1_COER_CHOICE_MASK_CLR);
                                char *_buff = point->point.octets.x;
                                size_t _len = 0;
                                switch(point->type)
                                {
                                    case EccP256CurvPointTypeXOnly:
                                    case EccP256CurvPointTypeCompressedy0:
                                    case EccP256CurvPointTypeCompressedy1:
                                        _len = 32;
                                        break;
                                    case EccP256CurvPointTypeUncompressed:
                                        _len = 64;
                                        break;
                                    case EccP256CurvPointTypeFill:
                                        _len = 0;
                                        break;
                                    default:
                                        log_ << "Ieee1609Decode::Vki:: point type not supported " << point->type << std::endl;
                                        LOG_ERR(log_.str(), MODULE);
                                        throw Exception(log_.str());

                                }
                                /* handle the available buffer size */
                                if(_len+offset > len)
                                {
                                    log_ << "Ieee1609Decode::Vki:: point type not enough length " << _len << "offset " << offset << "total " << len << std::endl;
                                    LOG_ERR(log_.str(), MODULE);
                                    throw Exception(log_.str());
                                }

                                while(_len--)
                                {
                                    *_buff++ = buf[offset++];
                                }
                            }
                            break;
                            default:
                                log_ << "Ieee1609Decode::Vki:: verfication public key type not supported " << vki.indicator.verificationKey.type << std::endl;
                                LOG_ERR(log_.str(), MODULE);
                                throw Exception(log_.str());
                        }
                    break;
                    default:
                        log_ << "Ieee1609Decode::Vki:: verfication key type not supported " << vki.type << std::endl;
                        LOG_ERR(log_.str(), MODULE);
                        throw Exception(log_.str());
                }

                log_ << " Ieee1609Decode::Vki exit " <<  len << " offset " << offset << std::endl;
                log_info(log_.str(), MODULE);
                return offset;
            }
            /* decode the sequence of quantity, it returns the number of iterations in quantity
             */
            int SequenceOf(uint8_t *quantity, size_t bufLen)
            {
                std::stringstream log_;
                log_ << "Ieee1609Decode::SequenceOf enter " <<  len << " offset " << offset << std::endl;
                log_info(log_.str(), MODULE);
                log_.str("");
                /* first get the length of iterations */
                size_t iterations;
                size_t bytes = Length((uint8_t *)&iterations, sizeof(size_t));
                if( bytes > bufLen)
                {
                    throw Exception("Ieee1609Decode::SequenceOf quantity buffer is not enough");
                }
                log_ << "Ieee1609Decode::SequenceOf length bytes " <<  bytes << std::endl;
                log_info(log_.str(), MODULE);
                log_.str("");
                /* copy the quantity bytes */
                while(bytes)
                {
                    quantity[--bytes] = buf[offset++];
                }
                log_ << "Ieee1609Decode::SequenceOf exit " <<  len << " offset " << offset << std::endl;
                log_info(log_.str(), MODULE);
                log_.str("");
                return offset;
            }
            int SequenceOfPsid_(SequenceOfPsidSsp& psids)
            {
                std::stringbuf log_(std::ios_base::out | std::ios_base::ate);
                std::ostream os(&log_);
                os << " Ieee1609Decode::SequenceOfPsid_ enter " <<  len << " offset " << offset << std::endl;
                log_info(log_.str(), MODULE);
                log_.str("");

                /* get the number of items in the sequence */
                psids.quantity= 0;
                SequenceOf((uint8_t *)&psids.quantity, sizeof(psids.quantity));
                os << " Ieee1609Decode::SequenceOfPsid_ psids.quantity " <<  psids.quantity << std::endl;
                log_info(log_.str(), MODULE);
                log_.str("");


                psids.psidSsp = (PsidSsp*)buf_alloc(psids.quantity * sizeof(PsidSsp));
                for(int i = 0; i < psids.quantity; i++)
                {
                    PsidSsp *ssp = psids.psidSsp + i;
                    uint8_t *buf_ = (uint8_t *)&ssp->psid;
                    /* get the optinal map of the first ssp */
                    ssp->optionalMask = buf[offset++];
                    /* get the variable length bytes */
                    int intBytes = buf[offset++];
                    os << "Ieee1609Decode::SequenceOfPsid_ optional mask / number of bytes " << std::to_string(ssp->optionalMask) << " " << intBytes << std::endl;
                    log_info(log_.str(), MODULE);
                    log_.str("");
                    for(int j = intBytes; j > 0; j--)
                    {
                        buf_[j-1] = buf[offset++];
                    }
                    /*FIXME, throw away the data, not using for the time being */
                    if (ssp->optionalMask)
                    {
                        /* get the length of the bytes, assuming it is less than 127 */
                        int len_ = (int)buf[offset++];
                        
                        /* just increment the offset by length */
                        offset += len_;
                    }
                }
                os << " Ieee1609Decode::SequenceOfPsid_ exit " <<  len << " offset " << offset << std::endl;
                log_info(log_.str(), MODULE);
                os.clear();
                return offset;
            }
            int IssuerIdentifier_(IssuerIdentifier& issuer)
            {
                std::stringbuf log_(std::ios_base::out | std::ios_base::ate);
                std::ostream os(&log_);
                os << "Ieee1609Decode::IssuerIdentifier_ enter " <<  len << " offset " << offset << std::endl;
                log_info(log_.str(), MODULE);
                log_.str("");

                /* get the choice */
                int c = (int)buf[offset];
                os << "Ieee1609Decode::IssuerIdentifier_ the value at offset " << offset << " is " << std::hex << std::to_string(c) << std::endl;
                log_info(log_.str(), MODULE);
                log_.str("");
                issuer.type = (IssuerIdentifierType)(buf[offset++] & ASN1_COER_CHOICE_MASK_CLR);
                switch(issuer.type)
                {
                    case IssuerIdentifierTypeHashId:
                    {
                        os << "Ieee1609Decode::IssuerIdentifier_ is hash " << std::endl;
                        log_info(log_.str(), MODULE);
                        log_.str("");
                        char *buf_ = issuer.issuer.hashId.x;
                        /* copy fixed size eight bytes */
                        for (int i = 0; i < 8; i++)
                        {
                            *buf_++ = buf[offset++];
                        }
                    }
                    break;
                    case IssuerIdentifierTypeSelf:
                        /* there is only one type of hash algo, so just skip it */
                        issuer.issuer.algo = (HashAlgorithmType)buf[offset++];
                        
                    break;
                    default:
                        os << "Ieee1609Decode::IssuerIdentifier_ unsuuported issuer type " << issuer.type;
                        LOG_ERR(log_.str(), MODULE);
                        throw Exception(log_.str());
                }
                os << " Ieee1609Decode::IssuerIdentifier_ exit " <<  len << " offset " << offset << std::endl;
                log_info(log_.str(), MODULE);
                os.clear();

                return 0;
            }
            /* only copies the integer encoded and returns number of bytes integer occupies */
            int Length(uint8_t *value, size_t bytes)
            {
                int numBytes = 0;
                uint8_t lengthEncoding=1;
                std::stringbuf log_(std::ios_base::out | std::ios_base::ate);
                std::ostream os(&log_);
                os << " Ieee1609Decode::Length enter " <<  len << " offset " << offset << std::endl;
                log_info(log_.str(), MODULE);
                log_.str("");
                /* read first byte of the integer encoding */
                lengthEncoding = buf[offset];
                if(buf[offset] & ASN1_LENGTH_ENCODING_MASK)
                {
                    /* number of bytes in the length */
                    lengthEncoding = (buf[offset++] & ~ASN1_LENGTH_ENCODING_MASK);
                }else{
                    /* only 1 bytes */
                    lengthEncoding = 1;
                }
                if(lengthEncoding > bytes)
                {
                    throw Exception("the supplied buffer not long enough");
                }
                numBytes = lengthEncoding;
                /* copy the bytes into the given buffer */
                while(lengthEncoding)
                {
                    lengthEncoding--;
                    value[lengthEncoding] = buf[offset++];
                }
                os << " Ieee1609Decode::Length exit " <<  len << " offset " << offset << std::endl;
                log_info(log_.str(), MODULE);
                os.clear();
                return numBytes;
            }

            int ContentType_(Ieee1609Dot2ContentType& type)
            {
                std::stringbuf log_(std::ios_base::out | std::ios_base::ate);
                std::ostream os(&log_);
                os << " Ieee1609Decode::ContentType_ enter " <<  len << " offset " << offset << std::endl;
                log_info(log_.str(), MODULE);
                os.clear();
                type =  (Ieee1609Dot2ContentType)(buf[offset++] & ASN1_COER_CHOICE_MASK_CLR);

                os << " Ieee1609Decode::ContentType_ exit " <<  len << " offset " << offset << std::endl;
                log_info(log_.str(), MODULE);
                os.clear();
                return offset;
            }
            

            /* encode certificate identifier */
            int CertId(CertificateId& id);
            // /* encode crl series */
            int CrlSeries(uint16_t& series);
            // /* encode hashid3 */
            int HashId3(uint8_t* hash, size_t len);
            /* encode the signature */
            int Signature_(Signature& signature);
            /* decode signdata payload */
            int SignedDataPayload_(Ieee1609Dot2Data& data);
            /* to be signed data */
            int ToBesignedData_(ToBeSignedData& tbsData);
            /* two versions of decoding 1609Dot2data */
            int SignedData(Ieee1609Dot2Data& data);
            int Ieee1609Dot2Data_(Ieee1609Dot2Data& data);
            int SignedDataPayload1(SignedDataPayload& payload);
            int HeaderInfo_(HeaderInfo& header);
            int SignerIdentifier_(SignerIdentifier& signer);
            // /* encode validity period */
            // int ValidityPeriod(const validityPeriod& validityPeriod);
            // /* encode verfication key indicator */
            // int Vki(const VerificationKeyIndicator& vki);

            /* initialize the decoding engine buffers with the incoming data */
            void set(const uint8_t *buf, size_t len);
            void clear()
            {
                delete buf;
                buf = nullptr;
                len  = 0;
            }
    };
} //namespace ctp 

#endif //__DOT2ENCDEC_HPP__