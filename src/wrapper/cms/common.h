#include "../common/common.h"

#include <openssl/pem.h>
#include <openssl/cms.h>

#include "../pki/pki.h"

class CTWRAPPER_API CertificateId;
class CTWRAPPER_API Signer;
class CTWRAPPER_API SignerCollection;
class CTWRAPPER_API SignerAttributeCollection;
class CTWRAPPER_API SignedData;

#include "signer_attrs.h"
#include "signer.h"
#include "signers.h"
#include "signed_data.h"