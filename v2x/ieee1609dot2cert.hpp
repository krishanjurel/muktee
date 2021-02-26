#ifndef __IEEE_1609DOT2CERT_HPP__
#define __IEEE_1609DOT2CERT_HPP__
#include <iostream>
#include "ieee1609dot2common.hpp"
#include "ieee1609dot2.hpp"
#include "openssl/ec.h"
#include "openssl/ecdsa.h"
#include "openssl/obj_mac.h"
#include <openssl/bn.h>
#include <map>
#include <vector>



namespace ctp
{

    class Ieee1609Encode
    {
        uint8_t *encBuf; /*encoded buffer */
        size_t encLen;   /* encoded length */
        size_t len_; /* another length to encode the individual components */
        public:
            Ieee1609Encode():encBuf(nullptr),encLen(0){};
            ~Ieee1609Encode()
            {
                free(encBuf);
                encLen = 0;
            }
            /* encoding of SignerIdentifier */
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




            /*encoding of signed data, 6.3.4 */
            int HashAlgo(HashAlgorithmType type);
            int ToBesignedData_(const ToBeSignedData& tbsData);
            int SignerIdentifier_(const SignerIdentifier& signer);
            int Signature_(const Signature *signature);

            /* int encoded buffer get */
            int get(uint8_t **buf);



    };


    class decode
    {
        uint8_t *buf; /*encoded buffer */
        size_t len;   /* encoded length */
        public:
            decode():buf(nullptr),len(0){};
            ~decode()
            {
                delete buf;
                len = 0;
            }
            /* encode certificate identifier */
            int CertId(const CertificateId& id);
            /* encode crl series */
            int CrlSeries(const uint16_t series);
            /* encode hashid3 */
            int HashId3(const uint8_t* hash, size_t len);
            /* encode the signature */
            int Signature(const Signature& signature);
            /* encode validity period */
            int ValidityPeriod(const validityPeriod& validityPeriod);
            /* encode verfication key indicator */
            int Vki(const VerificationKeyIndicator& vki);
    };



    /* cert class */
    class Ieee1609Cert
    {
        std::vector<CertificateBase *> certs;
        std::map<int, ctp::Ieee1609Cert*> certsPsidMap;
        std::map<std::string, ctp::Ieee1609Cert*> certsHashIdMap;

        /* encode/decode objects*/

        
        const EC_GROUP *ecGroup;
        EC_KEY *ecKey;
        uint8_t keyType;
        ECDSA_SIG *sig;
        CertificateBase *base;
        Issuer *issuer;
        ToBeSignedCertificate *tbs;
        VerificationKeyIndicator *vki;
        Signature *signature;
        SequenceOfCertificate *seqOfCert;
        int public_key_get(point_conversion_form_t conv = POINT_CONVERSION_UNCOMPRESSED);
        int private_key_get();
        int _sign(const uint8_t *buf, size_t len, SignatureType type);
        /* encode the certificate */
        uint8_t *encBuf, *encBuf1; 
        int encLen;


        int encode();
        int encode_certid();
        int encode_hashid3();
        int encode_crlseries();
        int encode_validityperiod();
        int encode_sequenceofpsid();
        /* encode verificattion key indicator */
        int encode_vki();
        /* encode the signature */
        int encode_sign();
        /* print to stdout or store in a file */
        int print();

        public:
            void create();

            //void encode();
            //void decode();

            explicit Ieee1609Cert();
            /* no copy constructure */
            Ieee1609Cert(const Ieee1609Cert&) = delete;
            /* no copy assignment */
            const Ieee1609Cert& operator=(const Ieee1609Cert&) = delete;
            /* no move constructor */
            Ieee1609Cert(const Ieee1609Cert&&) = delete;
            ~Ieee1609Cert(){delete encBuf;}
            /* returns the certificate for the given psid */
            const Ieee1609Cert* operator[](int psid);
            //int sign (SignatureType type = ecdsaNistP256Signature);
            int sign(const uint8_t *buf, size_t len, SignatureType type=ecdsaNistP256Signature);
            const Signature *signEx(const uint8_t *buf, size_t len, SignatureType type = ecdsaNistP256Signature);
    };

} /* namespace ctp */

#endif // __IEEE_1609DOT2CERT_HPP__