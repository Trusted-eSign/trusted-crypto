declare module 'trusted-crypto' {
    import * as dataFormat from "data_format";
    import * as publicExponent from "public_exponent";
    import * as cryptoMethod from "crypto_method";
    import * as jwt from "jwt";
    import * as cert from "cert";
    import * as certs from "certs";
    import * as crl from "crl";
    import * as crls from "crls";
    import * as key from "key";
    import * as oid from "oid";
    import * as alg from "alg";
    import * as certRegInfo from "certRegInfo";
    import * as certReg from "certReg";
    import * as csr from "csr";
    import * as cipher from "cipher";
    import * as chain from "chain";
    import * as revocation from "revocation";
    import * as pkcs12 from "pkcs12";
    import * as signed_data from "signed_data";
    import * as signer from "signer";
    import * as signercollection from "signers";
    import * as store from "pkistore";
    import * as provider_system from "psystem";
    import * as provider_microsoft from "pmicrosoft";
    import * as provider_cryptopro from "pcryptopro";
    import * as cashjson from "cashjson";
    export let DataFormat: typeof dataFormat.DataFormat;
    export let PublicExponent: typeof publicExponent.PublicExponent;
    export let CryptoMethod: typeof cryptoMethod.CryptoMethod;
    export namespace utils {
        let Jwt: typeof jwt.Jwt;
    }
    export namespace pki {
        let Certificate: typeof cert.Certificate;
        let CertificateCollection: typeof certs.CertificateCollection;
        let Crl: typeof crl.Crl;
        let CrlCollection: typeof crls.CrlCollection;
        let Key: typeof key.Key;
        let Oid: typeof oid.Oid;
        let Algorithm: typeof alg.Algorithm;
        let CertificationRequestInfo: typeof certRegInfo.CertificationRequestInfo;
        let CertificationRequest: typeof certReg.CertificationRequest;
        let CSR: typeof csr.CSR;
        let Cipher: typeof cipher.Cipher;
        let Chain: typeof chain.Chain;
        let Revocation: typeof revocation.Revocation;
        let Pkcs12: typeof pkcs12.Pkcs12;
    }
    export namespace cms {
        let SignedData: typeof signed_data.SignedData;
        let SignedDataContentType: typeof signed_data.SignedDataContentType;
        let Signer: typeof signer.Signer;
        let SignerCollection: typeof signercollection.SignerCollection;
    }
    export namespace pkistore {
        let PkiStore: typeof store.PkiStore;
        let Provider_System: typeof provider_system.Provider_System;
        let ProviderMicrosoft: typeof provider_microsoft.ProviderMicrosoft;
        let ProviderCryptopro: typeof provider_cryptopro.ProviderCryptopro;
        let CashJson: typeof cashjson.CashJson;
    }
}

declare module 'data_format' {
    /**
      *
      * @export
      * @enum {number}
      */
    export enum DataFormat {
        DER = 0,
        PEM = 1,
    }
}

declare module 'public_exponent' {
    /**
      * Public exponent values
      *
      * @export
      * @enum {number}
      */
    export enum PublicExponent {
        RSA_3 = 0,
        RSA_F4 = 1,
    }
}

declare module 'crypto_method' {
    /**
      *
      * @export
      * @enum {number}
      */
    export enum CryptoMethod {
        SYMMETRIC = 0,
        ASSYMETRIC = 1,
    }
}

declare module 'jwt' {
    import * as native from "native";
    import * as object from "object";
    /**
        * JSON Web Token (JWT)
        * Uses only with CTGOSTCP
        *
        * @export
        * @class Jwt
        * @extends {object.BaseObject<native.JWT.Jwt>}
        */
    export class Jwt extends object.BaseObject<native.UTILS.Jwt> {
            /**
                * Verify jwt license file
                *
                * @static
                * @returns {boolean}
                *
                * @memberOf Jwt
                */
            static ckeckLicense(): boolean;
            /**
                * Creates an instance of Jwt.
                *
                *
                * @memberOf Jwt
                */
            constructor();
            /**
                * Verify jwt license file
                *
                * @returns {boolean}
                *
                * @memberOf Jwt
                */
            ckeckLicense(): boolean;
    }
}

declare module 'cert' {
    import * as native from "native";
    import * as object from "object";
    import { DataFormat } from "data_format";
    /**
        * Wrap X509
        *
        * @export
        * @class Certificate
        * @extends {object.BaseObject<native.PKI.Certificate>}
        */
    export class Certificate extends object.BaseObject<native.PKI.Certificate> {
            /**
                * Load certificate from file
                *
                * @static
                * @param {string} filename File location
                * @param {DataFormat} [format=DEFAULT_DATA_FORMAT] PEM | DER (default)
                * @returns {Certificate}
                *
                * @memberOf Certificate
                */
            static load(filename: string, format?: DataFormat): Certificate;
            /**
                * Load certificate from memory
                *
                * @static
                * @param {Buffer} buffer
                * @param {DataFormat} [format=DEFAULT_DATA_FORMAT] PEM | DER (default)
                * @returns {Certificate}
                *
                * @memberOf Certificate
                */
            static import(buffer: Buffer, format?: DataFormat): Certificate;
            /**
                * Creates an instance of Certificate.
                *
                *
                * @memberOf Certificate
                */
            constructor();
            /**
                * Creates an instance of Certificate.
                *
                * @param {native.PKI.Certificate} handle
                *
                * @memberOf Certificate
                */
            constructor(handle: native.PKI.Certificate);
            /**
                * Return version of certificate
                *
                * @readonly
                * @type {number}
                * @memberOf Certificate
                */
            readonly version: number;
            /**
                * Return serial number of certificate
                *
                * @readonly
                * @type {string}
                * @memberOf Certificate
                */
            readonly serialNumber: string;
            /**
                * Return type of certificate
                *
                * @readonly
                * @type {number}
                * @memberOf Certificate
                */
            readonly type: number;
            /**
                * Return KeyUsageFlags collection
                *
                * @readonly
                * @type {number}
                * @memberOf Certificate
                */
            readonly keyUsage: number;
            /**
                * Return CN from issuer name
                *
                * @readonly
                * @type {string}
                * @memberOf Certificate
                */
            readonly issuerFriendlyName: string;
            /**
                * Return issuer name
                *
                * @readonly
                * @type {string}
                * @memberOf Certificate
                */
            readonly issuerName: string;
            /**
                * Return CN from subject name
                *
                * @readonly
                * @type {string}
                * @memberOf Certificate
                */
            readonly subjectFriendlyName: string;
            /**
                * Return subject name
                *
                * @readonly
                * @type {string}
                * @memberOf Certificate
                */
            readonly subjectName: string;
            /**
                * Return Not Before date
                *
                * @readonly
                * @type {Date}
                * @memberOf Certificate
                */
            readonly notBefore: Date;
            /**
                * Return Not After date
                *
                * @readonly
                * @type {Date}
                * @memberOf Certificate
                */
            readonly notAfter: Date;
            /**
                * Return SHA-1 thumbprint
                *
                * @readonly
                * @type {string}
                * @memberOf Certificate
                */
            readonly thumbprint: string;
            /**
                * Return signature algorithm
                *
                * @readonly
                * @type {string}
                * @memberOf Certificate
                */
            readonly signatureAlgorithm: string;
            /**
                * Return signature digest algorithm
                *
                * @readonly
                * @type {string}
                * @memberOf Certificate
                */
            readonly signatureDigest: string;
            /**
                * Return organization name
                *
                * @readonly
                * @type {string}
                * @memberOf Certificate
                */
            readonly organizationName: string;
            /**
                * Compare certificates
                *
                * @param {Certificate} cert Certificate for compare
                * @returns {number}
                *
                * @memberOf Certificate
                */
            compare(cert: Certificate): number;
            /**
                * Compare certificates
                *
                * @param {Certificate} cert Certificate for compare
                * @returns {boolean}
                *
                * @memberOf Certificate
                */
            equals(cert: Certificate): boolean;
            /**
                * Return certificate hash
                *
                * @param {string} [algorithm="sha1"]
                * @returns {String}
                *
                * @memberOf Certificate
                */
            hash(algorithm?: string): String;
            /**
                * Return certificate duplicat
                *
                * @returns {Certificate}
                *
                * @memberOf Certificate
                */
            duplicate(): Certificate;
            /**
                * Load certificate from file location
                *
                * @param {string} filename File location
                * @param {DataFormat} [format=DEFAULT_DATA_FORMAT]
                *
                * @memberOf Certificate
                */
            load(filename: string, format?: DataFormat): void;
            /**
                * Load certificate from memory
                *
                * @param {Buffer} buffer
                * @param {DataFormat} [format=DEFAULT_DATA_FORMAT]
                *
                * @memberOf Certificate
                */
            import(buffer: Buffer, format?: DataFormat): void;
            /**
                * Save certificate to memory
                *
                * @param {DataFormat} [format=DEFAULT_DATA_FORMAT]
                * @returns {Buffer}
                *
                * @memberOf Certificate
                */
            export(format?: DataFormat): Buffer;
            /**
                * Write certificate to file
                *
                * @param {string} filename File location
                * @param {DataFormat} [format=DEFAULT_DATA_FORMAT] PEM | DER (default)
                *
                * @memberOf Certificate
                */
            save(filename: string, format?: DataFormat): void;
    }
}

declare module 'certs' {
    import * as native from "native";
    import * as object from "object";
    import * as Collection from "collection";
    import { Certificate } from "cert";
    /**
        * Collection of Certificate
        *
        * @export
        * @class CertificateCollection
        * @extends {object.BaseObject<native.PKI.CertificateCollection>}
        * @implements {Collection.ICollectionWrite}
        */
    export class CertificateCollection extends object.BaseObject<native.PKI.CertificateCollection> implements Collection.ICollectionWrite {
            /**
                * Creates an instance of CertificateCollection.
                *
                * @param {native.PKI.CertificateCollection} handle
                *
                * @memberOf CertificateCollection
                */
            constructor(handle: native.PKI.CertificateCollection);
            /**
                * Creates an instance of CertificateCollection.
                *
                *
                * @memberOf CertificateCollection
                */
            constructor();
            /**
                * Return element by index from collection
                *
                * @param {number} index
                * @returns {Certificate}
                *
                * @memberOf CertificateCollection
                */
            items(index: number): Certificate;
            /**
                * Return collection length
                *
                * @readonly
                * @type {number}
                * @memberOf CertificateCollection
                */
            readonly length: number;
            /**
                * Add new element to collection
                *
                * @param {Certificate} cert
                *
                * @memberOf CertificateCollection
                */
            push(cert: Certificate): void;
            /**
                * Remove last element from collection
                *
                *
                * @memberOf CertificateCollection
                */
            pop(): void;
            /**
                * Remove element by index from collection
                *
                * @param {number} index
                *
                * @memberOf CertificateCollection
                */
            removeAt(index: number): void;
    }
}

declare module 'crl' {
    import * as native from "native";
    import * as object from "object";
    import { DataFormat } from "data_format";
    import { Certificate } from "cert";
    /**
        * Wrap X509_CRL
        *
        * @export
        * @class Crl
        * @extends {object.BaseObject<native.PKI.CRL>}
        */
    export class Crl extends object.BaseObject<native.PKI.CRL> {
            /**
                * Load CRL from File location
                *
                * @static
                * @param {string} filename File location
                * @param {DataFormat} [format=DEFAULT_DATA_FORMAT] PEM | DER (default)
                * @returns {Crl}
                *
                * @memberOf Crl
                */
            static load(filename: string, format?: DataFormat): Crl;
            /**
                * Load CRL from memory
                *
                * @static
                * @param {Buffer} buffer
                * @param {DataFormat} [format=DEFAULT_DATA_FORMAT]
                * @returns {Crl}
                *
                * @memberOf Crl
                */
            static import(buffer: Buffer, format?: DataFormat): Crl;
            /**
                * Creates an instance of Crl.
                *
                *
                * @memberOf Crl
                */
            constructor();
            /**
                * Creates an instance of Crl.
                *
                * @param {native.PKI.CRL} handle
                *
                * @memberOf Crl
                */
            constructor(handle: native.PKI.CRL);
            /**
                * Return CRL in DER format
                *
                * @readonly
                * @type {Buffer}
                * @memberOf Crl
                */
            readonly encoded: Buffer;
            /**
                * Return signature
                *
                * @readonly
                * @type {Buffer}
                * @memberOf Crl
                */
            readonly signature: Buffer;
            /**
                * Return version of CRL
                *
                * @readonly
                * @type {number}
                * @memberOf Crl
                */
            readonly version: number;
            /**
                * Return issuer name
                *
                * @readonly
                * @type {string}
                * @memberOf Crl
                */
            readonly issuerName: string;
            /**
                * Return CN from issuer name
                *
                * @readonly
                * @type {string}
                * @memberOf Crl
                */
            readonly issuerFriendlyName: string;
            /**
                * Return last update date
                *
                * @readonly
                * @type {Date}
                * @memberOf Crl
                */
            readonly lastUpdate: Date;
            /**
                * Return next update date
                *
                * @readonly
                * @type {Date}
                * @memberOf Crl
                */
            readonly nextUpdate: Date;
            /**
                * Return SHA-1 thumbprint
                *
                * @readonly
                * @type {string}
                * @memberOf Crl
                */
            readonly thumbprint: string;
            /**
                * Return signature algorithm
                *
                * @readonly
                * @type {string}
                * @memberOf Crl
                */
            readonly sigAlgName: string;
            /**
                * Return signature short algorithm
                *
                * @readonly
                * @type {string}
                * @memberOf Crl
                */
            readonly sigAlgShortName: string;
            /**
                * Return signature algorithm OID
                *
                * @readonly
                * @type {string}
                * @memberOf Crl
                */
            readonly sigAlgOID: string;
            /**
                * Return revoked certificate
                *
                * @param {Certificate} cer
                * @returns {native.PKI.RevokedCertificate}
                *
                * @memberOf Crl
                */
            getRevokedCertificateCert(cer: Certificate): native.PKI.RevokedCertificate;
            /**
                * Return revoked certificates serial number
                *
                * @param {string} serial
                * @returns {native.PKI.RevokedCertificate}
                *
                * @memberOf Crl
                */
            getRevokedCertificateSerial(serial: string): native.PKI.RevokedCertificate;
            /**
                * Load CRL from file
                *
                * @param {string} filename File location
                * @param {DataFormat} [format=DEFAULT_DATA_FORMAT] PEM | DER (default)
                *
                * @memberOf Crl
                */
            load(filename: string, format?: DataFormat): void;
            /**
                * Load CRL from memory
                *
                * @param {Buffer} buffer
                * @param {DataFormat} [format=DEFAULT_DATA_FORMAT]
                *
                * @memberOf Crl
                */
            import(buffer: Buffer, format?: DataFormat): void;
            /**
                * Save CRL to memory
                *
                * @param {DataFormat} [format=DEFAULT_DATA_FORMAT]
                * @returns {Buffer}
                *
                * @memberOf Crl
                */
            export(format?: DataFormat): Buffer;
            /**
                * Write CRL to file
                *
                * @param {string} filename File location
                * @param {DataFormat} [dataFormat=DEFAULT_DATA_FORMAT]
                *
                * @memberOf Crl
                */
            save(filename: string, dataFormat?: DataFormat): void;
            /**
                * Compare CRLs
                *
                * @param {Crl} crl CRL for compare
                * @returns {number}
                *
                * @memberOf Crl
                */
            compare(crl: Crl): number;
            /**
                * Compare CRLs
                *
                * @param {Crl} crl CRL for compare
                * @returns {boolean}
                *
                * @memberOf Crl
                */
            equals(crl: Crl): boolean;
            /**
                * Return CRL hash
                *
                * @param {string} [algorithm="sha1"]
                * @returns {String}
                *
                * @memberOf Crl
                */
            hash(algorithm?: string): String;
            /**
                * Return CRL duplicat
                *
                * @returns {Crl}
                *
                * @memberOf Crl
                */
            duplicate(): Crl;
    }
}

declare module 'crls' {
    import * as native from "native";
    import * as object from "object";
    import * as Collection from "collection";
    import { Crl } from "crl";
    /**
        * Collection of Crl
        *
        * @export
        * @class CrlCollection
        * @extends {object.BaseObject<native.PKI.CrlCollection>}
        * @implements {Collection.ICollectionWrite}
        */
    export class CrlCollection extends object.BaseObject<native.PKI.CrlCollection> implements Collection.ICollectionWrite {
            /**
                * Creates an instance of CrlCollection.
                *
                * @param {native.PKI.CrlCollection} handle
                *
                * @memberOf CrlCollection
                */
            constructor(handle: native.PKI.CrlCollection);
            /**
                * Creates an instance of CrlCollection.
                *
                *
                * @memberOf CrlCollection
                */
            constructor();
            /**
                * Return element by index from collection
                *
                * @param {number} index
                * @returns {Crl}
                *
                * @memberOf CrlCollection
                */
            items(index: number): Crl;
            /**
                * Return collection length
                *
                * @readonly
                * @type {number}
                * @memberOf CrlCollection
                */
            readonly length: number;
            /**
                * Add new element to collection
                *
                * @param {Crl} crl
                *
                * @memberOf CrlCollection
                */
            push(crl: Crl): void;
            /**
                * Remove last element from collection
                *
                *
                * @memberOf CrlCollection
                */
            pop(): void;
            /**
                * Remove element by index from collection
                *
                * @param {number} index
                *
                * @memberOf CrlCollection
                */
            removeAt(index: number): void;
    }
}

declare module 'key' {
    import * as native from "native";
    import * as object from "object";
    import { DataFormat } from "data_format";
    import { PublicExponent } from "public_exponent";
    /**
        * Wrap EVP_PKEY
        *
        * @export
        * @class Key
        * @extends {object.BaseObject<native.PKI.Key>}
        */
    export class Key extends object.BaseObject<native.PKI.Key> {
            /**
                * Load private key from file
                *
                * @static
                * @param {string} filename File path
                * @param {DataFormat} format PEM | DER
                * @param {string} password
                * @returns {Key}
                *
                * @memberOf Key
                */
            static readPrivateKey(filename: string, format: DataFormat, password: string): Key;
            /**
                * Load public key from file
                *
                * @static
                * @param {string} filename File path
                * @param {DataFormat} format PEM | DER
                * @returns {Key}
                *
                * @memberOf Key
                */
            static readPublicKey(filename: string, format: DataFormat): Key;
            /**
                * Creates an instance of Key.
                *
                *
                * @memberOf Key
                */
            constructor();
            /**
                * Creates an instance of Key.
                *
                * @param {native.PKI.Key} handle
                *
                * @memberOf Key
                */
            constructor(handle: native.PKI.Key);
            /**
                * Generate key
                *
                * @param {DataFormat} format
                * @param {PublicExponent} pubExp
                * @param {number} keySize
                * @param {string} password
                * @returns {Key}
                *
                * @memberOf Key
                */
            generate(format: DataFormat, pubExp: PublicExponent, keySize: number, password: string): Key;
            /**
                * Load private key from file
                *
                * @param {string} filename File path
                * @param {DataFormat} format PEM | DER
                * @param {string} password
                * @returns {Key}
                *
                * @memberOf Key
                */
            readPrivateKey(filename: string, format: DataFormat, password: string): Key;
            /**
                * Write private key to file
                *
                * @param {string} filename File path
                * @param {DataFormat} format PEM | DER
                * @param {string} password Set for encrypt
                * @returns {*}
                *
                * @memberOf Key
                */
            writePrivateKey(filename: string, format: DataFormat, password: string): any;
            /**
                * Read public key from file
                *
                * @param {string} filename File path
                * @param {DataFormat} format PEM | DER
                * @returns {Key}
                *
                * @memberOf Key
                */
            readPublicKey(filename: string, format: DataFormat): Key;
            /**
                * Write public key to file
                *
                * @param {string} filename File path
                * @param {DataFormat} format PEM | DER
                * @returns {*}
                *
                * @memberOf Key
                */
            writePublicKey(filename: string, format: DataFormat): any;
            /**
                * Compare keys
                *
                * @param {Key} key Key for compare
                * @returns {number}
                *
                * @memberOf Key
                */
            compare(key: Key): number;
    }
}

declare module 'oid' {
    import * as native from "native";
    import * as object from "object";
    /**
        * Wrap ASN1_OBJECT
        *
        * @export
        * @class Oid
        * @extends {object.BaseObject<native.PKI.OID>}
        */
    export class Oid extends object.BaseObject<native.PKI.OID> {
            /**
                * Creates an instance of Oid.
                *
                * @param {native.PKI.OID} handle
                *
                * @memberOf Oid
                */
            constructor(handle: native.PKI.OID);
            /**
                * Creates an instance of Oid.
                *
                * @param {string} oid
                *
                * @memberOf Oid
                */
            constructor(oid: string);
            /**
                * Return text value for OID
                *
                * @readonly
                * @type {string}
                * @memberOf Oid
                */
            readonly value: string;
            /**
                * Return OID long name
                *
                * @readonly
                * @type {string}
                * @memberOf Oid
                */
            readonly longName: string;
            /**
                * Return OID short name
                *
                * @readonly
                * @type {string}
                * @memberOf Oid
                */
            readonly shortName: string;
    }
}

declare module 'alg' {
    import * as native from "native";
    import * as object from "object";
    import { Oid } from "oid";
    /**
        * Wrap X509_ALGOR
        *
        * @export
        * @class Algorithm
        * @extends {object.BaseObject<native.PKI.Algorithm>}
        */
    export class Algorithm extends object.BaseObject<native.PKI.Algorithm> {
            /**
                * Creates an instance of Algorithm.
                *
                *
                * @memberOf Algorithm
                */
            constructor();
            /**
                * Creates an instance of Algorithm.
                *
                * @param {native.PKI.Algorithm} handle
                *
                * @memberOf Algorithm
                */
            constructor(handle: native.PKI.Algorithm);
            /**
                * Creates an instance of Algorithm.
                *
                * @param {string} name
                *
                * @memberOf Algorithm
                */
            constructor(name: string);
            /**
                * Return algorithm name
                *
                * @readonly
                * @type {string}
                * @memberOf Algorithm
                */
            readonly name: string;
            /**
                * Return algorithm OID
                *
                * @readonly
                * @type {Oid}
                * @memberOf Algorithm
                */
            readonly typeId: Oid;
            /**
                * Return algorithm duplicat
                *
                * @returns {Algorithm}
                *
                * @memberOf Algorithm
                */
            duplicate(): Algorithm;
            /**
                * Return true if it digest algorithm
                *
                * @returns {boolean}
                *
                * @memberOf Algorithm
                */
            isDigest(): boolean;
    }
}

declare module 'certRegInfo' {
    import * as native from "native";
    import * as object from "object";
    import { Key } from "key";
    /**
        * Wrap X509_REQ_INFO
        *
        * @export
        * @class CertificationRequestInfo
        * @extends {object.BaseObject<native.PKI.CertificationRequestInfo>}
        */
    export class CertificationRequestInfo extends object.BaseObject<native.PKI.CertificationRequestInfo> {
            /**
                * Creates an instance of CertificationRequestInfo.
                *
                *
                * @memberOf CertificationRequestInfo
                */
            constructor();
            /**
                * Creates an instance of CertificationRequestInfo.
                *
                * @param {native.PKI.CertificationRequestInfo} handle
                *
                * @memberOf CertificationRequestInfo
                */
            constructor(handle: native.PKI.CertificationRequestInfo);
            /**
                * Set subject name
                *
                * @param {string} x509name Example "/C=US/O=Test/CN=example.com"
                *
                * @memberOf CertificationRequestInfo
                */
            subject: string;
            /**
                *  Set public key
                *
                *  @param {Key} pubkey Public key
                *
                * @memberOf CertificationRequestInfo
                */
            pubkey: Key;
            /**
                * Set version certificate
                *
                * @param {number} version
                *
                * @memberOf CertificationRequestInfo
                */
            version: number;
    }
}

declare module 'certReg' {
    import * as native from "native";
    import * as object from "object";
    import { Key } from "key";
    import { DataFormat } from "data_format";
    /**
        * Wrap X509_REQ
        *
        * @export
        * @class CertificationRequest
        * @extends {object.BaseObject<native.PKI.CertificationRequest>}
        */
    export class CertificationRequest extends object.BaseObject<native.PKI.CertificationRequest> {
            /**
                * Load request from file
                *
                * @static
                * @param {string} filename File location
                * @param {DataFormat} [format=DEFAULT_DATA_FORMAT] PEM | DER (default)
                * @returns {CertificationRequest}
                *
                * @memberOf CertificationRequest
                */
            static load(filename: string, format?: DataFormat): CertificationRequest;
            /**
                * Creates an instance of CertificationRequest.
                *
                *
                * @memberOf CertificationRequest
                */
            constructor();
            /**
                * Creates an instance of CertificationRequest.
                *
                * @param {native.PKI.CertificationRequest} handle
                *
                * @memberOf CertificationRequest
                */
            constructor(handle: native.PKI.CertificationRequest);
            /**
                * Load request from file
                *
                * @param {string} filename File location
                * @param {DataFormat} [format=DEFAULT_DATA_FORMAT] PEM | DER (default)
                *
                * @memberOf CertificationRequest
                */
            load(filename: string, format?: DataFormat): void;
            /**
                * Sign request
                *
                * @param {Key} key Private key
                *
                * @memberOf CertificationRequest
                */
            sign(key: Key): void;
            /**
                * Verify request
                *
                * @returns {boolean}
                *
                * @memberOf CertificationRequest
                */
            verify(): boolean;
            /**
                * Return request in PEM format
                *
                * @readonly
                * @type {Buffer}
                * @memberOf CertificationRequest
                */
            readonly PEMString: Buffer;
    }
}

declare module 'csr' {
    import * as native from "native";
    import * as object from "object";
    import { DataFormat } from "data_format";
    import { Key } from "key";
    /**
        * Final class for make certification request
        *
        * @export
        * @class CSR
        * @extends {object.BaseObject<native.PKI.CSR>}
        */
    export class CSR extends object.BaseObject<native.PKI.CSR> {
            /**
                * Creates an instance of CSR.
                *
                * @param {string} name
                * @param {Key} key
                * @param {string} digest
                *
                * @memberOf CSR
                */
            constructor(name: string, key: Key, digest: string);
            /**
                * Return encoded structure
                *
                * @readonly
                * @type {Buffer}
                * @memberOf CSR
                */
            readonly encoded: Buffer;
            /**
                * Write CSR to file
                *
                * @param {string} filename File path
                * @param {DataFormat} [dataFormat=DEFAULT_DATA_FORMAT]
                *
                * @memberOf CSR
                */
            save(filename: string, dataFormat?: DataFormat): void;
    }
}

declare module 'cipher' {
    import * as native from "native";
    import * as object from "object";
    import { DataFormat } from "data_format";
    import { CryptoMethod } from "crypto_method";
    import { Key } from "key";
    import { CertificateCollection } from "certs";
    import { Certificate } from "cert";
    import { CmsRecipientInfoCollection } from "recipientInfos";
    /**
        * Encrypt and decrypt operations
        *
        * @export
        * @class Cipher
        * @extends {object.BaseObject<native.PKI.Cipher>}
        */
    export class Cipher extends object.BaseObject<native.PKI.Cipher> {
            /**
                * Creates an instance of Cipher.
                *
                *
                * @memberOf Cipher
                */
            constructor();
            /**
                * Set crypto method
                *
                * @param method SYMMETRIC or ASSIMETRIC
                *
                * @memberOf Cipher
                */
            cryptoMethod: CryptoMethod;
            /**
                * Encrypt data
                *
                * @param {string} filenameSource This file will encrypted
                * @param {string} filenameEnc File path for save encrypted data
                * @param {DataFormat} [format]
                *
                * @memberOf Cipher
                */
            encrypt(filenameSource: string, filenameEnc: string, format?: DataFormat): void;
            /**
                * Decrypt data
                *
                * @param {string} filenameEnc This file will decrypt
                * @param {string} filenameDec File path for save decrypted data
                * @param {DataFormat} [format]
                *
                * @memberOf Cipher
                */
            decrypt(filenameEnc: string, filenameDec: string, format?: DataFormat): void;
            /**
                * Add recipients certificates
                *
                * @param {CertificateCollection} certs
                *
                * @memberOf Cipher
                */
            recipientsCerts: CertificateCollection;
            /**
                * Set private key
                *
                * @param {Key} key
                *
                * @memberOf Cipher
                */
            privKey: Key;
            /**
                * Set recipient certificate
                *
                * @param {Certificate} rcert
                *
                * @memberOf Cipher
                */
            recipientCert: Certificate;
            password: string;
            digest: string;
            readonly riv: Buffer;
            iv: string;
            readonly rkey: Buffer;
            key: string;
            readonly rsalt: Buffer;
            salt: string;
            readonly algorithm: String;
            readonly mode: String;
            readonly dgst: String;
            /**
                * Return recipient infos
                *
                * @param {string} filenameEnc File path
                * @param {DataFormat} format DataFormat.PEM | DataFormat.DER
                * @returns {CmsRecipientInfoCollection}
                *
                * @memberOf Cipher
                */
            getRecipientInfos(filenameEnc: string, format: DataFormat): CmsRecipientInfoCollection;
    }
}

declare module 'chain' {
    import * as native from "native";
    import * as object from "object";
    import { Certificate } from "cert";
    import { CertificateCollection } from "certs";
    import { CrlCollection } from "crls";
    /**
        * Chain of certificates
        *
        * @export
        * @class Chain
        * @extends {object.BaseObject<native.PKI.Chain>}
        */
    export class Chain extends object.BaseObject<native.PKI.Chain> {
            /**
                * Creates an instance of Chain.
                *
                *
                * @memberOf Chain
                */
            constructor();
            /**
                * Build chain
                *
                * @param {Certificate} cert Last certificate in chain
                * @param {CertificateCollection} certs All certificates where search issuer certificates
                * @returns {CertificateCollection}
                *
                * @memberOf Chain
                */
            buildChain(cert: Certificate, certs: CertificateCollection): CertificateCollection;
            /**
                * Verify chain (crl collection if need check revocation)
                *
                * @param {CertificateCollection} chain Certificates collection
                * @param {CrlCollection} crls Crl collection
                * @returns {boolean}
                *
                * @memberOf Chain
                */
            verifyChain(chain: CertificateCollection, crls: CrlCollection): boolean;
    }
}

declare module 'revocation' {
    import * as native from "native";
    import * as object from "object";
    import { Certificate } from "cert";
    import { Crl } from "crl";
    import { PkiStore } from "pkistore";
    /**
        * Revocatiom provaider
        *
        * @export
        * @class Revocation
        * @extends {object.BaseObject<native.PKI.Revocation>}
        */
    export class Revocation extends object.BaseObject<native.PKI.Revocation> {
            /**
                * Creates an instance of Revocation.
                *
                *
                * @memberOf Revocation
                */
            constructor();
            /**
                *  Search crl for certificate in local store
                *
                * @param {Certificate} cert
                * @param {PkiStore} store Local store
                * @returns {*}
                *
                * @memberOf Revocation
                */
            getCrlLocal(cert: Certificate, store: PkiStore): any;
            /**
                * Return array of distribution points for certificate
                *
                * @param {Certificate} cert
                * @returns {Array<string>}
                *
                * @memberOf Revocation
                */
            getCrlDistPoints(cert: Certificate): Array<string>;
            /**
                * Check validate CRL time
                *
                * @param {Crl} crl
                * @returns {boolean}
                *
                * @memberOf Revocation
                */
            checkCrlTime(crl: Crl): boolean;
            /**
                * Download CRl
                *
                * @param {Array<string>} distPoints Distribution points
                * @param {string} pathForSave File path
                * @param {Function} done callback
                *
                * @memberOf Revocation
                */
            downloadCRL(distPoints: Array<string>, pathForSave: string, done: Function): void;
    }
}

declare module 'pkcs12' {
    import * as native from "native";
    import * as object from "object";
    import { Certificate } from "cert";
    import { CertificateCollection } from "certs";
    import { Key } from "key";
    /**
        * PKCS#12 (PFX)
        *
        * @export
        * @class Pkcs12
        * @extends {object.BaseObject<native.PKI.Pkcs12>}
        */
    export class Pkcs12 extends object.BaseObject<native.PKI.Pkcs12> {
            /**
                * Load pkcs12 from file
                *
                * @static
                * @param {string} filename File location
                * @returns {Pkcs12}
                *
                * @memberOf Pkcs12
                */
            static load(filename: string): Pkcs12;
            /**
                * Creates an instance of Pkcs12.
                *
                *
                * @memberOf Pkcs12
                */
            constructor();
            /**
                * Creates an instance of Pkcs12.
                *
                * @param {native.PKI.Pkcs12} handle
                *
                * @memberOf Pkcs12
                */
            constructor(handle: native.PKI.Pkcs12);
            /**
                * Return certificate
                *
                * @param {string} password
                * @returns {Certificate}
                *
                * @memberOf Pkcs12
                */
            certificate(password: string): Certificate;
            /**
                * Return private key
                *
                * @param {string} password
                * @returns {Key}
                *
                * @memberOf Pkcs12
                */
            key(password: string): Key;
            /**
                * Return CA certificates (not client certificates)
                *
                * @param {string} password
                * @returns {CertificateCollection}
                *
                * @memberOf Pkcs12
                */
            ca(password: string): CertificateCollection;
            /**
                * Load pkcs12 from file
                *
                * @param {string} filename File location
                *
                * @memberOf Pkcs12
                */
            load(filename: string): void;
            /**
                * Write pkcs12 to file
                *
                * @param {string} filename File location
                *
                * @memberOf Pkcs12
                */
            save(filename: string): void;
            /**
                * Create PKCS12 structure
                *
                * @param {Certificate} cert
                * @param {Key} key Private key
                * @param {CertificateCollection} ca
                * @param {string} password
                * @param {string} name Friendly name
                * @returns {Pkcs12}
                *
                * @memberOf Pkcs12
                */
            create(cert: Certificate, key: Key, ca: CertificateCollection, password: string, name: string): Pkcs12;
    }
}

declare module 'signed_data' {
    import * as native from "native";
    import * as object from "object";
    import { DataFormat } from "data_format";
    import { Signer } from "signer";
    import { SignerCollection } from "signers";
    import { Certificate } from "cert";
    import { CertificateCollection } from "certs";
    import { Key } from "key";
    export enum SignedDataContentType {
            url = 0,
            buffer = 1,
    }
    export interface ISignedDataContent {
            type: SignedDataContentType;
            data: string | Buffer;
    }
    /**
        * Wrap CMS_ContentInfo
        *
        * @export
        * @class SignedData
        * @extends {object.BaseObject<native.CMS.SignedData>}
        */
    export class SignedData extends object.BaseObject<native.CMS.SignedData> {
            /**
                * Load signed data from file location
                *
                * @static
                * @param {string} filename File location
                * @param {DataFormat} [format=DEFAULT_DATA_FORMAT] PEM | DER (default)
                * @returns {SignedData}
                *
                * @memberOf SignedData
                */
            static load(filename: string, format?: DataFormat): SignedData;
            /**
                * Load signed data from memory
                *
                * @static
                * @param {Buffer} buffer
                * @param {DataFormat} [format=DEFAULT_DATA_FORMAT]
                * @returns {SignedData}
                *
                * @memberOf SignedData
                */
            static import(buffer: Buffer, format?: DataFormat): SignedData;
            /**
                * Creates an instance of SignedData.
                *
                *
                * @memberOf SignedData
                */
            constructor();
            /**
                * Set content v to signed data
                *
                *
                * @memberOf SignedData
                */
            content: ISignedDataContent;
            /**
                * Set sign policies
                *
                *
                * @memberOf SignedData
                */
            policies: Array<string>;
            /**
                * Return true if sign detached
                *
                * @returns {boolean}
                *
                * @memberOf SignedData
                */
            isDetached(): boolean;
            /**
                * Return certificate by index
                *
                * @param {number} index
                * @returns {Certificate}
                *
                * @memberOf SignedData
                */
            certificates(index: number): Certificate;
            /**
                * Return certificates collection
                *
                * @returns {CertificateCollection}
                *
                * @memberOf SignedData
                */
            certificates(): CertificateCollection;
            /**
                * Return signer by index
                *
                * @param {number} index
                * @returns {Signer}
                *
                * @memberOf SignedData
                */
            signers(index: number): Signer;
            /**
                * Return signers collection
                *
                * @returns {SignerCollection}
                *
                * @memberOf SignedData
                */
            signers(): SignerCollection;
            /**
                * Load sign from file location
                *
                * @param {string} filename File location
                * @param {DataFormat} [format=DEFAULT_DATA_FORMAT] PEM | DER (default)
                *
                * @memberOf SignedData
                */
            load(filename: string, format?: DataFormat): void;
            /**
                * Load sign from memory
                *
                * @param {Buffer} buffer
                * @param {DataFormat} [format=DEFAULT_DATA_FORMAT] PEM | DER (default)
                *
                * @memberOf SignedData
                */
            import(buffer: Buffer, format?: DataFormat): void;
            /**
                * Save sign to memory
                *
                * @param {DataFormat} [format=DEFAULT_DATA_FORMAT] PEM | DER (default)
                * @returns {Buffer}
                *
                * @memberOf SignedData
                */
            export(format?: DataFormat): Buffer;
            /**
                * Write sign to file
                *
                * @param {string} filename File location
                * @param {DataFormat} [format=DEFAULT_DATA_FORMAT] PEM | DER (default)
                *
                * @memberOf SignedData
                */
            save(filename: string, format?: DataFormat): void;
            /**
                * Create new signer
                *
                * @param {Certificate} cert Signer certificate
                * @param {Key} key Private key for signer certificate
                * @returns {Signer}
                *
                * @memberOf SignedData
                */
            createSigner(cert: Certificate, key: Key): Signer;
            /**
                * Verify signature
                *
                * @param {CertificateCollection} [certs] Certificate collection
                * @returns {boolean}
                *
                * @memberOf SignedData
                */
            verify(certs?: CertificateCollection): boolean;
            /**
                * Create sign
                *
                *
                * @memberOf SignedData
                */
            sign(): void;
    }
}

declare module 'signer' {
    import * as native from "native";
    import * as object from "object";
    import { Algorithm } from "alg";
    import { Attribute } from "attr";
    import { Certificate } from "cert";
    import { SignerAttributeCollection } from "signer_attrs";
    /**
        * Wrap CMS_SignerInfo
        *
        * @export
        * @class Signer
        * @extends {object.BaseObject<native.CMS.Signer>}
        */
    export class Signer extends object.BaseObject<native.CMS.Signer> {
            /**
                * Creates an instance of Signer.
                *
                * @param {native.CMS.Signer} handle
                *
                * @memberOf Signer
                */
            constructor(handle: native.CMS.Signer);
            /**
                * Set signer certificate
                * Error if cert no signer
                *
                * @param cert Certificate
                *
                * @memberOf Signer
                */
            certificate: Certificate;
            /**
                * Return digest algorithm
                *
                * @readonly
                * @type {Algorithm}
                * @memberOf Signer
                */
            readonly digestAlgorithm: Algorithm;
            /**
                * Return signed attributes collection
                *
                * @returns {SignerAttributeCollection}
                *
                * @memberOf Signer
                */
            signedAttributes(): SignerAttributeCollection;
            /**
                * Return attribute by index
                *
                * @param {number} index
                * @returns {Attribute}
                *
                * @memberOf Signer
                */
            signedAttributes(index: number): Attribute;
            /**
                * Return unsigned attributes collection
                *
                * @returns {SignerAttributeCollection}
                *
                * @memberOf Signer
                */
            unsignedAttributes(): SignerAttributeCollection;
            /**
                * Return unsigned attribute by index
                *
                * @param {number} index
                * @returns {Attribute}
                *
                * @memberOf Signer
                */
            unsignedAttributes(index: number): Attribute;
    }
}

declare module 'signers' {
    import * as native from "native";
    import * as object from "object";
    import * as Collection from "collection";
    import { Signer } from "signer";
    /**
        * Collection of Signer
        *
        * @export
        * @class SignerCollection
        * @extends {object.BaseObject<native.CMS.SignerCollection>}
        * @implements {Collection.ICollection}
        */
    export class SignerCollection extends object.BaseObject<native.CMS.SignerCollection> implements Collection.ICollection {
            /**
                * Creates an instance of SignerCollection.
                *
                * @param {native.CMS.SignerCollection} nativeHandle
                *
                * @memberOf SignerCollection
                */
            constructor(nativeHandle: native.CMS.SignerCollection);
            /**
                * Return element by index from collection
                *
                * @param {number} index
                * @returns {Signer}
                *
                * @memberOf SignerCollection
                */
            items(index: number): Signer;
            /**
                * Return collection length
                *
                * @readonly
                * @type {number}
                * @memberOf SignerCollection
                */
            readonly length: number;
    }
}

declare module 'pkistore' {
    import * as native from "native";
    import * as object from "object";
    import { Certificate } from "cert";
    import { Crl } from "crl";
    import { CertificationRequest } from "certReg";
    import { Key } from "key";
    import { CashJson } from "cashjson";
    /**
        * Filter for search objects
        *
        * @export
        * @class Filter
        * @extends {object.BaseObject<native.PKISTORE.Filter>}
        * @implements {native.PKISTORE.IFilter}
        */
    export class Filter extends object.BaseObject<native.PKISTORE.Filter> implements native.PKISTORE.IFilter {
            constructor();
            types: string;
            providers: string;
            categorys: string;
            hash: string;
            subjectName: string;
            subjectFriendlyName: string;
            issuerName: string;
            issuerFriendlyName: string;
            serial: string;
    }
    /**
        * Wrap pki objects (certificate, key, crl, csr)
        *
        * @export
        * @class PkiItem
        * @extends {object.BaseObject<native.PKISTORE.PkiItem>}
        * @implements {native.PKISTORE.IPkiItem}
        */
    export class PkiItem extends object.BaseObject<native.PKISTORE.PkiItem> implements native.PKISTORE.IPkiItem {
            /**
                * Creates an instance of PkiItem.
                *
                *
                * @memberOf PkiItem
                */
            constructor();
            format: string;
            type: string;
            provider: string;
            category: string;
            uri: string;
            hash: string;
            subjectName: string;
            subjectFriendlyName: string;
            issuerName: string;
            issuerFriendlyName: string;
            serial: string;
            notBefore: string;
            notAfter: string;
            lastUpdate: string;
            nextUpdate: string;
            key: string;
            keyEnc: boolean;
            organizationName: string;
            signatureAlgorithm: string;
    }
    export class PkiStore extends object.BaseObject<native.PKISTORE.PkiStore> {
            /**
                * Creates an instance of PkiStore.
                *
                * @param {native.PKISTORE.PkiStore} handle
                *
                * @memberOf PkiStore
                */
            constructor(handle: native.PKISTORE.PkiStore);
            /**
                * Creates an instance of PkiStore.
                *
                * @param {string} folder Path for create store
                *
                * @memberOf PkiStore
                */
            constructor(folder: string);
            /**
                * Return cash json
                *
                * @readonly
                * @type {CashJson}
                * @memberOf PkiStore
                */
            readonly cash: CashJson;
            /**
                * Add provider (system, microsoft | cryptopro)
                *
                * @param {native.PKISTORE.Provider} provider
                *
                * @memberOf PkiStore
                */
            addProvider(provider: native.PKISTORE.Provider): void;
            /**
                * Import certificste to local store
                *
                * @param {native.PKISTORE.Provider} provider SYSTEM, MICROSOFT, CRYPTOPRO
                * @param {string} category MY, OTHERS, TRUST, CRL
                * @param {Certificate} cert Certificate
                * @param {number} flags
                * @returns {string}
                *
                * @memberOf PkiStore
                */
            addCert(provider: native.PKISTORE.Provider, category: string, cert: Certificate, flags: number): string;
            /**
                * Import CRL to local store
                *
                * @param {native.PKISTORE.Provider} provider SYSTEM, MICROSOFT, CRYPTOPRO
                * @param {string} category MY, OTHERS, TRUST, CRL
                * @param {Crl} crl CRL
                * @param {number} flags
                * @returns {string}
                *
                * @memberOf PkiStore
                */
            addCrl(provider: native.PKISTORE.Provider, category: string, crl: Crl, flags: number): string;
            /**
                * Import key to local store
                *
                * @param {native.PKISTORE.Provider} provider SYSTEM, MICROSOFT, CRYPTOPRO
                * @param {Key} key
                * @param {string} password
                * @returns {string}
                *
                * @memberOf PkiStore
                */
            addKey(provider: native.PKISTORE.Provider, key: Key, password: string): string;
            /**
                * Import certificate request to local store
                *
                * @param {native.PKISTORE.Provider} provider SYSTEM, MICROSOFT, CRYPTOPRO
                * @param {string} category MY, OTHERS, TRUST, CRL
                * @param {CertificationRequest} csr
                * @returns {string}
                *
                * @memberOf PkiStore
                */
            addCsr(provider: native.PKISTORE.Provider, category: string, csr: CertificationRequest): string;
            /**
                * Find items in local store
                *
                * @param {native.PKISTORE.IFilter} [ifilter]
                * @returns {native.PKISTORE.IPkiItem[]}
                *
                * @memberOf PkiStore
                */
            find(ifilter?: native.PKISTORE.IFilter): native.PKISTORE.IPkiItem[];
            /**
                * Find key in local store
                *
                * @param {native.PKISTORE.IFilter} ifilter
                * @returns {native.PKISTORE.IPkiItem}
                *
                * @memberOf PkiStore
                */
            findKey(ifilter: native.PKISTORE.IFilter): native.PKISTORE.IPkiItem;
            /**
                * Return pki object (certificate, crl, request, key) by PkiItem
                *
                * @param {native.PKISTORE.IPkiItem} item
                * @returns {*}
                *
                * @memberOf PkiStore
                */
            getItem(item: native.PKISTORE.IPkiItem): any;
    }
}

declare module 'psystem' {
    import * as native from "native";
    import * as object from "object";
    /**
        * Native crypto provider (work in local folders)
        *
        * @export
        * @class Provider_System
        * @extends {object.BaseObject<native.PKISTORE.Provider_System>}
        */
    export class Provider_System extends object.BaseObject<native.PKISTORE.Provider_System> {
            /**
                * Creates an instance of Provider_System.
                *
                * @param {string} folder Path
                *
                * @memberOf Provider_System
                */
            constructor(folder: string);
            /**
                * Return PkiItem for pki object
                *
                * @param {string} path
                * @returns {native.PKISTORE.IPkiItem}
                *
                * @memberOf Provider_System
                */
            objectToPkiItem(path: string): native.PKISTORE.IPkiItem;
    }
}

declare module 'pmicrosoft' {
    import * as native from "native";
    import * as object from "object";
    import { Certificate } from "cert";
    import { Key } from "key";
    /**
        * Support Microsoft crypto provider (only windows platform)
        *
        * @export
        * @class ProviderMicrosoft
        * @extends {object.BaseObject<native.PKISTORE.ProviderMicrosoft>}
        */
    export class ProviderMicrosoft extends object.BaseObject<native.PKISTORE.ProviderMicrosoft> {
            /**
                * Creates an instance of ProviderMicrosoft.
                *
                *
                * @memberOf ProviderMicrosoft
                */
            constructor();
            /**
                * Return private key by certificate
                *
                * @param {Certificate} cert
                * @returns
                *
                * @memberOf ProviderMicrosoft
                */
            getKey(cert: Certificate): Key;
    }
}

declare module 'pcryptopro' {
    import * as native from "native";
    import * as object from "object";
    import { Certificate } from "cert";
    import { Key } from "key";
    /**
        * Support CryptoPro provider
        *
        * @export
        * @class ProviderCryptopro
        * @extends {object.BaseObject<native.PKISTORE.ProviderCryptopro>}
        */
    export class ProviderCryptopro extends object.BaseObject<native.PKISTORE.ProviderCryptopro> {
            constructor();
            /**
                * Return private key by certificate from CryptoPro store
                *
                * @param {Certificate} cert Certificate
                * @returns
                *
                * @memberOf ProviderCryptopro
                */
            getKey(cert: Certificate): Key;
    }
}

declare module 'cashjson' {
    import * as native from "native";
    import * as object from "object";
    /**
        * Work with json files
        *
        * @export
        * @class CashJson
        * @extends {object.BaseObject<native.PKISTORE.CashJson>}
        */
    export class CashJson extends object.BaseObject<native.PKISTORE.CashJson> {
            /**
                * Creates an instance of CashJson.
                *
                * @param {string} fileName File path
                *
                * @memberOf CashJson
                */
            constructor(fileName: string);
            /**
                * Return PkiItems from json
                *
                * @returns {native.PKISTORE.IPkiItem[]}
                *
                * @memberOf CashJson
                */
            export(): native.PKISTORE.IPkiItem[];
            /**
                * Import PkiItems to json
                *
                * @param {native.PKISTORE.IPkiItem[]} items
                *
                * @memberOf CashJson
                */
            import(items: native.PKISTORE.IPkiItem[]): void;
    }
}

declare module 'native' {
    import { DataFormat } from "data_format";
    import { PublicExponent } from "public_exponent";
    import { CryptoMethod } from "crypto_method";
    export namespace PKI {
            class Key {
                    generate(format: DataFormat, pubExp: PublicExponent, keySize: number): Key;
                    readPrivateKey(filename: string, format: DataFormat, password: string): any;
                    readPublicKey(filename: string, format: DataFormat): any;
                    writePrivateKey(filename: string, format: DataFormat, password: string): any;
                    writePublicKey(filename: string, format: DataFormat): any;
                    compare(key: Key): number;
                    duplicate(): Key;
            }
            class Algorithm {
                    constructor();
                    constructor(name: string);
                    getTypeId(): OID;
                    getName(): string;
                    duplicate(): Algorithm;
                    isDigest(): boolean;
            }
            class Attribute {
                    duplicate(): Attribute;
                    export(): Buffer;
                    values(): AttributeValueCollection;
                    getAsnType(): number;
                    setAsnType(type: number): void;
                    getTypeId(): OID;
                    setTypeId(oid: OID): void;
            }
            class AttributeValueCollection {
                    constructor(alg: Algorithm);
                    push(val: Buffer): void;
                    pop(): void;
                    removeAt(index: number): void;
                    items(index: number): Buffer;
                    length(): number;
            }
            class OID {
                    constructor();
                    constructor(value: string);
                    getLongName(): string;
                    getShortName(): string;
                    getValue(): string;
            }
            class Certificate {
                    getSubjectFriendlyName(): string;
                    getIssuerFriendlyName(): string;
                    getSubjectName(): string;
                    getIssuerName(): string;
                    getNotAfter(): string;
                    getNotBefore(): string;
                    getSerialNumber(): Buffer;
                    getThumbprint(): Buffer;
                    getVersion(): number;
                    getType(): number;
                    getKeyUsage(): number;
                    getSignatureAlgorithm(): string;
                    getSignatureDigest(): string;
                    getOrganizationName(): string;
                    load(filename: string, dataFormat: DataFormat): void;
                    import(raw: Buffer, dataFormat: DataFormat): void;
                    save(filename: string, dataFormat: DataFormat): void;
                    export(dataFormat: DataFormat): Buffer;
                    compare(cert: Certificate): number;
                    equals(cert: Certificate): boolean;
                    duplicate(): Certificate;
                    hash(digestName: string): Buffer;
            }
            class RevokedCertificate {
                    revocationDate(): string;
                    reason(): number;
            }
            class CertificateCollection {
                    items(index: number): Certificate;
                    length(): number;
                    push(cer: Certificate): void;
                    pop(): void;
                    removeAt(index: number): void;
            }
            class CRL {
                    getEncoded(): Buffer;
                    getSignature(): Buffer;
                    getVersion(): number;
                    getIssuerName(): string;
                    getIssuerFriendlyName(): string;
                    getLastUpdate(): string;
                    getNextUpdate(): string;
                    getCertificate(): Certificate;
                    getThumbprint(): Buffer;
                    getSigAlgName(): string;
                    getSigAlgShortName(): string;
                    getSigAlgOID(): string;
                    getRevokedCertificateCert(cer: Certificate): RevokedCertificate;
                    getRevokedCertificateSerial(serial: string): RevokedCertificate;
                    load(filename: string, dataFormat: DataFormat): void;
                    import(raw: Buffer, dataFormat: DataFormat): void;
                    save(filename: string, dataFormat: DataFormat): void;
                    export(dataFormat: DataFormat): Buffer;
                    compare(crl: CRL): number;
                    equals(crl: CRL): boolean;
                    hash(digestName: string): Buffer;
                    duplicate(): CRL;
            }
            class CrlCollection {
                    items(index: number): CRL;
                    length(): number;
                    push(crl: CRL): void;
                    pop(): void;
                    removeAt(index: number): void;
            }
            class CertificationRequestInfo {
                    setSubject(x509name: string): void;
                    setSubjectPublicKey(key: PKI.Key): void;
                    setVersion(version: number): void;
            }
            class CertificationRequest {
                    constructor();
                    constructor(csrinfo: PKI.CertificationRequestInfo);
                    load(filename: string, dataFormat: DataFormat): void;
                    sign(key: Key): void;
                    verify(): boolean;
                    getPEMString(): Buffer;
            }
            class CSR {
                    constructor(name: string, key: PKI.Key, digest: string);
                    save(filename: string, dataFormat: DataFormat): void;
                    getEncodedHEX(): Buffer;
            }
            class Cipher {
                    constructor();
                    setCryptoMethod(method: CryptoMethod): void;
                    encrypt(filenameSource: string, filenameEnc: string, format: DataFormat): void;
                    decrypt(filenameEnc: string, filenameDec: string, format: DataFormat): void;
                    addRecipientsCerts(certs: CertificateCollection): void;
                    setPrivKey(rkey: Key): void;
                    setRecipientCert(rcert: Certificate): void;
                    setPass(password: string): void;
                    setDigest(digest: string): void;
                    setIV(iv: string): void;
                    setKey(key: string): void;
                    setSalt(salt: string): void;
                    getSalt(): Buffer;
                    getIV(): Buffer;
                    getKey(): Buffer;
                    getAlgorithm(): string;
                    getMode(): string;
                    getDigestAlgorithm(): string;
                    getRecipientInfos(filenameEnc: string, format: DataFormat): CMS.CmsRecipientInfoCollection;
            }
            class Chain {
                    buildChain(cert: Certificate, certs: CertificateCollection): CertificateCollection;
                    verifyChain(chain: CertificateCollection, crls: CrlCollection): boolean;
            }
            class Revocation {
                    getCrlLocal(cert: Certificate, store: PKISTORE.PkiStore): any;
                    getCrlDistPoints(cert: Certificate): Array<string>;
                    checkCrlTime(crl: CRL): boolean;
                    downloadCRL(distPoints: Array<string>, path: string, done: Function): void;
            }
            class Pkcs12 {
                    getCertificate(password: string): Certificate;
                    getKey(password: string): Key;
                    getCACertificates(password: string): CertificateCollection;
                    load(filename: string): void;
                    save(filename: string): void;
                    create(cert: Certificate, key: Key, ca: CertificateCollection, password: string, name: string): Pkcs12;
            }
    }
    export namespace CMS {
            class SignedData {
                    constructor();
                    getContent(): Buffer;
                    setContent(v: Buffer): void;
                    getFlags(): number;
                    setFlags(v: number): void;
                    load(filename: string, dataFormat: DataFormat): void;
                    import(raw: Buffer, dataFormat: DataFormat): void;
                    save(filename: string, dataFormat: DataFormat): void;
                    export(dataFormat: DataFormat): Buffer;
                    getCertificates(): PKI.CertificateCollection;
                    getSigners(): SignerCollection;
                    isDetached(): boolean;
                    createSigner(cert: PKI.Certificate, key: PKI.Key): Signer;
                    addCertificate(cert: PKI.Certificate): void;
                    verify(certs?: PKI.CertificateCollection): boolean;
                    sign(): void;
            }
            class SignerCollection {
                    items(index: number): Signer;
                    length(): number;
            }
            class Signer {
                    setCertificate(cert: PKI.Certificate): void;
                    getCertificate(): PKI.Certificate;
                    getSignature(): Buffer;
                    getSignatureAlgorithm(): PKI.Algorithm;
                    getDigestAlgorithm(): PKI.Algorithm;
                    getSignedAttributes(): SignerAttributeCollection;
                    getUnsignedAttributes(): SignerAttributeCollection;
            }
            class SignerAttributeCollection {
                    length(): number;
                    push(attr: PKI.Attribute): void;
                    removeAt(index: number): void;
                    items(index: number): PKI.Attribute;
            }
            class CmsRecipientInfo {
                    getIssuerName(): string;
                    getSerialNumber(): Buffer;
                    ktriCertCmp(cert: PKI.Certificate): number;
            }
            class CmsRecipientInfoCollection {
                    length(): number;
                    push(ri: CmsRecipientInfo): void;
                    removeAt(index: number): void;
                    pop(): void;
                    items(index: number): CmsRecipientInfo;
            }
    }
    export namespace PKISTORE {
            interface IPkiItem extends IPkiCrl, IPkiCertificate, IPkiRequest, IPkiKey {
                    /**
                        * DER | PEM
                        */
                    format: string;
                    /**
                        * CRL | CERTIFICATE | KEY | REQUEST
                        */
                    type: string;
                    uri: string;
                    provider: string;
                    category: string;
                    hash: string;
            }
            interface IPkiKey {
                    encrypted?: boolean;
            }
            interface IPkiCrl {
                    issuerName?: string;
                    issuerFriendlyName?: string;
                    lastUpdate?: string;
                    nextUpdate?: string;
            }
            interface IPkiRequest {
                    subjectName?: string;
                    subjectFriendlyName?: string;
                    key?: string;
            }
            interface IPkiCertificate {
                    subjectName?: string;
                    subjectFriendlyName?: string;
                    issuerName?: string;
                    issuerFriendlyName?: string;
                    notAfter?: string;
                    notBefore?: string;
                    serial?: string;
                    key?: string;
                    organizationName?: string;
                    signatureAlgorithm?: string;
            }
            interface IFilter {
                    /**
                        * PkiItem
                        * CRL | CERTIFICATE | KEY | REQUEST
                        */
                    type?: string[];
                    /**
                        * Provider
                        * SYSTEM, MICROSOFT, CRYPTOPRO, TSL, PKCS11, TRUSTEDNET
                        */
                    provider?: string[];
                    /**
                        * MY, OTHERS, TRUST, CRL
                        */
                    category?: string[];
                    hash?: string;
                    subjectName?: string;
                    subjectFriendlyName?: string;
                    issuerName?: string;
                    issuerFriendlyName?: string;
                    isValid?: boolean;
                    serial?: string;
            }
            abstract class Provider {
                    type: string;
            }
            class Provider_System extends Provider {
                    constructor(folder: string);
                    objectToPkiItem(pathr: string): IPkiItem;
            }
            class ProviderMicrosoft extends Provider {
                    constructor();
                    getKey(cert: PKI.Certificate): PKI.Key;
            }
            class ProviderCryptopro extends Provider {
                    constructor();
                    getKey(cert: PKI.Certificate): PKI.Key;
            }
            class ProviderTSL extends Provider {
                    constructor(url: string);
            }
            class PkiStore {
                    constructor(json: string);
                    getCash(): CashJson;
                    /**
                        * Возвращает набор элементов по фильтру
                        * - если фильтр пустой, возвращает все элементы
                        */
                    find(filter?: Filter): IPkiItem[];
                    /**
                        * Возвращает ключ по фильтру
                        * - фильтр задается относительно элементов, которые могут быть связаны с ключом
                        */
                    findKey(filter: IFilter): IPkiItem;
                    /**
                        * Возвращает объект из структуры
                        */
                    getItem(item: PkiItem): any;
                    addProvider(provider: Provider): void;
                    addCert(provider: Provider, category: string, cert: PKI.Certificate, flags: number): string;
                    addCrl(provider: Provider, category: string, crl: PKI.CRL, flags: number): string;
                    addKey(provider: Provider, key: PKI.Key, password: string): string;
                    addCsr(provider: Provider, category: string, csr: PKI.CertificationRequest): string;
            }
            class CashJson {
                    filenName: string;
                    constructor(fileName: string);
                    save(fileName: string): any;
                    load(fileName: string): any;
                    export(): IPkiItem[];
                    import(items: IPkiItem[]): any;
                    import(item: PkiItem): any;
            }
            class Filter {
                    constructor();
                    setType(type: string): void;
                    setProvider(provider: string): void;
                    setCategory(category: string): void;
                    setHash(hash: string): void;
                    setSubjectName(subjectName: string): void;
                    setSubjectFriendlyName(subjectFriendlyName: string): void;
                    setIssuerName(issuerName: string): void;
                    setIssuerFriendlyName(issuerFriendlyName: string): void;
                    setIsValid(valid: boolean): void;
                    setSerial(serial: string): void;
            }
            class PkiItem {
                    constructor();
                    setFormat(type: string): void;
                    setType(type: string): void;
                    setProvider(provider: string): void;
                    setCategory(category: string): void;
                    setURI(category: string): void;
                    setHash(hash: string): void;
                    setSubjectName(subjectName: string): void;
                    setSubjectFriendlyName(subjectFriendlyName: string): void;
                    setIssuerName(issuerName: string): void;
                    setIssuerFriendlyName(issuerFriendlyName: string): void;
                    setSerial(serial: string): void;
                    setNotBefore(before: string): void;
                    setNotAfter(after: string): void;
                    setLastUpdate(lastUpdate: string): void;
                    setNextUpdate(nextUpdate: string): void;
                    setKey(key: string): void;
                    setKeyEncrypted(enc: boolean): void;
                    setOrganizationName(organizationName: string): void;
                    setSignatureAlgorithm(signatureAlgorithm: string): void;
            }
    }
    export namespace UTILS {
            class Jwt {
                    checkLicense(): boolean;
            }
    }
}

declare module 'object' {
    export interface IBaseObject {
        handle: any;
    }
    export class BaseObject<T> implements IBaseObject {
        static wrap<TIn, TOut extends IBaseObject>(obj: TIn): TOut;
        handle: T;
    }
}

declare module 'collection' {
    export interface ICollection {
            /**
                * Collection length
                *
                * @type {number}
                * @memberOf ICollection
                */
            length: number;
            /**
                * Return element by index from collection
                *
                * @param {number} index value of [0..n]
                * @returns {*}
                *
                * @memberOf ICollection
                */
            items(index: number): any;
    }
    export interface ICollectionWrite extends ICollection {
            /**
                * Add new element to collection
                *
                * @param {*} item
                *
                * @memberOf ICollectionWrite
                */
            push(item: any): void;
            /**
                * Remove last element from collection
                *
                *
                * @memberOf ICollectionWrite
                */
            pop(): void;
            /**
                * Remove element by index from collection
                *
                * @param {number} index
                *
                * @memberOf ICollectionWrite
                */
            removeAt(index: number): void;
    }
}

declare module 'recipientInfos' {
    import * as native from "native";
    import * as object from "object";
    import * as Collection from "collection";
    import { CmsRecipientInfo } from "recipientInfo";
    /**
        * Collection of CmsRecipientInfo
        *
        * @export
        * @class CmsRecipientInfoCollection
        * @extends {object.BaseObject<native.CMS.CmsRecipientInfoCollection>}
        * @implements {Collection.ICollectionWrite}
        */
    export class CmsRecipientInfoCollection extends object.BaseObject<native.CMS.CmsRecipientInfoCollection> implements Collection.ICollectionWrite {
            /**
                * Creates an instance of CmsRecipientInfoCollection.
                *
                *
                * @memberOf CmsRecipientInfoCollection
                */
            constructor();
            /**
                * Creates an instance of CmsRecipientInfoCollection.
                *
                * @param {native.CMS.CmsRecipientInfoCollection} handle
                *
                * @memberOf CmsRecipientInfoCollection
                */
            constructor(handle: native.CMS.CmsRecipientInfoCollection);
            /**
                * Return element by index from collection
                *
                * @param {number} index
                * @returns {CmsRecipientInfo}
                *
                * @memberOf CmsRecipientInfoCollection
                */
            items(index: number): CmsRecipientInfo;
            /**
                * Return collection length
                *
                * @readonly
                * @type {number}
                * @memberOf CmsRecipientInfoCollection
                */
            readonly length: number;
            /**
                * Add new element to collection
                *
                * @param {CmsRecipientInfo} ri
                *
                * @memberOf CmsRecipientInfoCollection
                */
            push(ri: CmsRecipientInfo): void;
            /**
                * Remove last element from collection
                *
                *
                * @memberOf CmsRecipientInfoCollection
                */
            pop(): void;
            /**
                * Remove element by index from collection
                *
                * @param {number} index
                *
                * @memberOf CmsRecipientInfoCollection
                */
            removeAt(index: number): void;
    }
}

declare module 'attr' {
    import * as native from "native";
    import * as object from "object";
    import { Oid } from "oid";
    import { AttributeValueCollection } from "attr_vals";
    /**
        * Wrap X509_ATTRIBUTE
        *
        * @export
        * @class Attribute
        * @extends {object.BaseObject<native.PKI.Attribute>}
        */
    export class Attribute extends object.BaseObject<native.PKI.Attribute> {
            /**
                * Creates an instance of Attribute.
                *
                * @param {native.PKI.Attribute} handle
                *
                * @memberOf Attribute
                */
            constructor(handle: native.PKI.Attribute);
            /**
                * Set ASN1 type
                *
                * @param {number} value ASN1 type
                *
                * @memberOf Attribute
                */
            asnType: number;
            /**
                * Set attribute OID
                *
                * @param {Oid} oid
                *
                * @memberOf Attribute
                */
            typeId: Oid;
            /**
                * Return attribute duplicat
                *
                * @returns {Attribute}
                *
                * @memberOf Attribute
                */
            dupicate(): Attribute;
            /**
                * Return attribute in DER
                *
                * @returns {*}
                *
                * @memberOf Attribute
                */
            export(): any;
            /**
                * Return attribute by index
                *
                * @param {number} index
                * @returns {Buffer}
                *
                * @memberOf Attribute
                */
            values(index: number): Buffer;
            /**
                * Return attributes collection
                *
                * @returns {AttributeValueCollection}
                *
                * @memberOf Attribute
                */
            values(): AttributeValueCollection;
    }
}

declare module 'signer_attrs' {
    import * as native from "native";
    import * as object from "object";
    import { ICollection } from "collection";
    import { Attribute } from "attr";
    /**
        * Collection of SignerAttribute
        *
        * @export
        * @class SignerAttributeCollection
        * @extends {object.BaseObject<native.CMS.SignerAttributeCollection>}
        * @implements {ICollection}
        */
    export class SignerAttributeCollection extends object.BaseObject<native.CMS.SignerAttributeCollection> implements ICollection {
            /**
                * Creates an instance of SignerAttributeCollection.
                *
                * @param {native.CMS.SignerAttributeCollection} nativeSigner
                *
                * @memberOf SignerAttributeCollection
                */
            constructor(nativeSigner: native.CMS.SignerAttributeCollection);
            /**
                * Return collection length
                *
                * @readonly
                * @type {number}
                * @memberOf SignerAttributeCollection
                */
            readonly length: number;
            /**
                * Add new element to collection
                *
                * @param {Attribute} attr
                *
                * @memberOf SignerAttributeCollection
                */
            push(attr: Attribute): void;
            /**
                * Remove element by index from collection
                *
                * @param {number} index
                *
                * @memberOf SignerAttributeCollection
                */
            removeAt(index: number): void;
            /**
                * Return element by index from collection
                *
                * @param {number} index
                * @returns {Attribute}
                *
                * @memberOf SignerAttributeCollection
                */
            items(index: number): Attribute;
    }
}

declare module 'recipientInfo' {
    import * as native from "native";
    import * as object from "object";
    import { Certificate } from "cert";
    /**
        * Wrap CMS_RecipientInfo
        *
        * @export
        * @class CmsRecipientInfo
        * @extends {object.BaseObject<native.CMS.CmsRecipientInfo>}
        */
    export class CmsRecipientInfo extends object.BaseObject<native.CMS.CmsRecipientInfo> {
            /**
                * Creates an instance of CmsRecipientInfo.
                *
                *
                * @memberOf CmsRecipientInfo
                */
            constructor();
            /**
                * Creates an instance of CmsRecipientInfo.
                *
                * @param {native.CMS.CmsRecipientInfo} handle
                *
                * @memberOf CmsRecipientInfo
                */
            constructor(handle: native.CMS.CmsRecipientInfo);
            /**
                *  Return full issuer name
                *
                * @readonly
                * @type {string}
                * @memberOf CmsRecipientInfo
                */
            readonly issuerName: string;
            /**
                * Return serial number
                *
                * @readonly
                * @type {string}
                * @memberOf CmsRecipientInfo
                */
            readonly serialNumber: string;
            /**
                * Compares the certificate cert against the CMS_RecipientInfo structure
                *
                * @param {Certificate} cert
                * @returns {number}
                *
                * @memberOf CmsRecipientInfo
                */
            ktriCertCmp(cert: Certificate): number;
    }
}

declare module 'attr_vals' {
    import * as native from "native";
    import * as object from "object";
    import * as Collection from "collection";
    /**
        * Collection of Attribute
        *
        * @export
        * @class AttributeValueCollection
        * @extends {object.BaseObject<native.PKI.AttributeValueCollection>}
        * @implements {Collection.ICollectionWrite}
        */
    export class AttributeValueCollection extends object.BaseObject<native.PKI.AttributeValueCollection> implements Collection.ICollectionWrite {
            /**
                * Creates an instance of AttributeValueCollection.
                *
                * @param {native.PKI.AttributeValueCollection} handle
                *
                * @memberOf AttributeValueCollection
                */
            constructor(handle: native.PKI.AttributeValueCollection);
            /**
                * Return collection length
                *
                * @readonly
                * @type {number}
                * @memberOf AttributeValueCollection
                */
            readonly length: number;
            /**
                * Add new element to collection
                *
                * @param {Buffer} val
                *
                * @memberOf AttributeValueCollection
                */
            push(val: Buffer): void;
            /**
                * Remove last element from collection
                *
                *
                * @memberOf AttributeValueCollection
                */
            pop(): void;
            /**
                * Remove element by index from collection
                *
                * @param {number} index
                *
                * @memberOf AttributeValueCollection
                */
            removeAt(index: number): void;
            /**
                * Return element by index from collection
                *
                * @param {number} index
                * @returns {Buffer}
                *
                * @memberOf AttributeValueCollection
                */
            items(index: number): Buffer;
    }
}
