#include <iostream>
#include <vector>

namespace ctp
{
    /*! Trusted platform class */
    class TP
    {
        private:
            /*! constructor */
            /*! constructor is private to enable single instance of the Trusted Platform
            */
            TP();

            /*! certificate manager */
            /*! used to communicate with Registration authority for certificate provisioning, update certificate
            */
            void cert_mgr();
            /*! certificate revocation list manager */
            void crl_mgr();
            /*! report manager */
            /*! */

    };

} //namespace ctp



