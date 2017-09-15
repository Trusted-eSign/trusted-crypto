/// <reference types="node" />
declare namespace trusted {
    /**
     *
     * @export
     * @enum {number}
     */
    enum DataFormat {
        DER = 0,
        PEM = 1,
    }
}
declare namespace trusted {
    /**
     *
     * @export
     * @enum {number}
     */
    enum CryptoMethod {
        SYMMETRIC = 0,
        ASSYMETRIC = 1,
    }
}
declare namespace trusted {
    /**
     * Public exponent values
     *
     * @export
     * @enum {number}
     */
    enum PublicExponent {
        RSA_3 = 0,
        RSA_F4 = 1,
    }
}
declare namespace trusted {
    /**
     *
     * @export
     * @enum {number}
     */
    enum LoggerLevel {
        NULL = 0,
        ERROR = 1,
        WARNING = 2,
        INFO = 4,
        DEBUG = 8,
        TRACE = 16,
        OPENSSL = 32,
        ALL = 63,
    }
}
declare namespace native {
    namespace PKI {
        class Key {
            generate(format: trusted.DataFormat, pubExp: trusted.PublicExponent, keySize: number): Key;
            readPrivateKey(filename: string, format: trusted.DataFormat, password: string): any;
            readPublicKey(filename: string, format: trusted.DataFormat): any;
            writePrivateKey(filename: string, format: trusted.DataFormat, password: string): any;
            writePublicKey(filename: string, format: trusted.DataFormat): any;
            compare(key: Key): number;
            duplicate(): Key;
        }
        class Algorithm {
            constructor(name?: string);
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
            constructor(value?: string);
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
            getOCSPUrls(): string[];
            getCAIssuersUrls(): string[];
            isSelfSigned(): boolean;
            isCA(): boolean;
            load(filename: string, dataFormat: trusted.DataFormat): void;
            import(raw: Buffer, dataFormat: trusted.DataFormat): void;
            save(filename: string, dataFormat: trusted.DataFormat): void;
            export(dataFormat: trusted.DataFormat): Buffer;
            compare(cert: Certificate): number;
            equals(cert: Certificate): boolean;
            duplicate(): Certificate;
            hash(digestName: string): Buffer;
        }
        class Revoked {
            getSerialNumber(): string;
            getRevocationDate(): string;
            getReason(): string;
            duplicate(): Revoked;
        }
        class RevokedCollection {
            items(index: number): Revoked;
            length(): number;
            push(rv: Revoked): void;
            pop(): void;
            removeAt(index: number): void;
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
            getRevoked(): RevokedCollection;
            load(filename: string, dataFormat: trusted.DataFormat): void;
            import(raw: Buffer, dataFormat: trusted.DataFormat): void;
            save(filename: string, dataFormat: trusted.DataFormat): void;
            export(dataFormat: trusted.DataFormat): Buffer;
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
            constructor(csrinfo?: PKI.CertificationRequestInfo);
            load(filename: string, dataFormat: trusted.DataFormat): void;
            sign(key: Key): void;
            verify(): boolean;
            getPEMString(): Buffer;
        }
        class CSR {
            constructor(name: string, key: PKI.Key, digest: string);
            save(filename: string, dataFormat: trusted.DataFormat): void;
            getEncodedHEX(): Buffer;
        }
        class Cipher {
            constructor();
            setCryptoMethod(method: trusted.CryptoMethod): void;
            encrypt(filenameSource: string, filenameEnc: string, format: trusted.DataFormat): void;
            decrypt(filenameEnc: string, filenameDec: string, format: trusted.DataFormat): void;
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
            getRecipientInfos(filenameEnc: string, format: trusted.DataFormat): CMS.CmsRecipientInfoCollection;
        }
        class Chain {
            buildChain(cert: Certificate, certs: CertificateCollection): CertificateCollection;
            verifyChain(chain: CertificateCollection, crls: CrlCollection): boolean;
        }
        class Revocation {
            getCrlLocal(cert: Certificate, store: PKISTORE.PkiStore): any;
            getCrlDistPoints(cert: Certificate): string[];
            checkCrlTime(crl: CRL): boolean;
            downloadCRL(distPoints: string[], path: string, done: (err: Error, crl: PKI.CRL) => void): void;
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
    namespace CMS {
        class SignedData {
            constructor();
            getContent(): Buffer;
            setContent(v: Buffer): void;
            getFlags(): number;
            setFlags(v: number): void;
            load(filename: string, dataFormat: trusted.DataFormat): void;
            import(raw: Buffer, dataFormat: trusted.DataFormat): void;
            save(filename: string, dataFormat: trusted.DataFormat): void;
            export(dataFormat: trusted.DataFormat): Buffer;
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
            getSignerId(): SignerId;
            getSignedAttributes(): SignerAttributeCollection;
            getUnsignedAttributes(): SignerAttributeCollection;
            verify(): boolean;
            verifyContent(v: Buffer): boolean;
        }
        class SignerId {
            getSerialNumber(): string;
            getIssuerName(): string;
            getKeyId(): string;
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
    namespace PKISTORE {
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
            hasPrivateKey(cert: PKI.Certificate): boolean;
        }
        class ProviderCryptopro extends Provider {
            constructor();
            getKey(cert: PKI.Certificate): PKI.Key;
            hasPrivateKey(cert: PKI.Certificate): boolean;
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
            findKey(filter: Filter): IPkiItem;
            /**
             * Возвращает объект из структуры
             */
            getItem(item: PkiItem): any;
            getCerts(): PKI.CertificateCollection;
            addProvider(provider: Provider): void;
            addCert(provider: Provider, category: string, cert: PKI.Certificate): string;
            addCrl(provider: Provider, category: string, crl: PKI.CRL): string;
            addKey(provider: Provider, key: PKI.Key, password: string): string;
            addCsr(provider: Provider, category: string, csr: PKI.CertificationRequest): string;
        }
        class CashJson {
            filenName: string;
            constructor(fileName: string);
            save(fileName: string): any;
            load(fileName: string): any;
            export(): IPkiItem[];
            import(items: IPkiItem[] | PkiItem): any;
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
    namespace UTILS {
        class Jwt {
            checkLicense(data?: string): number;
        }
        class Cerber {
            sign(modulePath: string, cert: PKI.Certificate, key: PKI.Key): void;
            verify(modulePath: string, cacerts?: PKI.CertificateCollection): object;
        }
        class Logger {
            start(filename: string, level: trusted.LoggerLevel): void;
            stop(): void;
            clear(): void;
        }
    }
    namespace COMMON {
        class OpenSSL {
            run(): void;
            stop(): void;
            printErrors(): string;
        }
    }
}
declare namespace trusted {
    interface IBaseObject {
        handle: any;
    }
    class BaseObject<T> implements IBaseObject {
        static wrap<TIn, TOut extends IBaseObject>(obj: TIn): TOut;
        handle: T;
    }
}
declare namespace trusted.core {
    interface ICollection {
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
    interface ICollectionWrite extends ICollection {
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
declare namespace trusted.common {
    /**
     * OpenSSL helper class
     *
     * @export
     * @class OpenSSL
     * @extends {BaseObject<native.COMMON.OpenSSL>}
     */
    class OpenSSL extends BaseObject<native.COMMON.OpenSSL> {
        /**
         * Load engines and add algorithms
         *
         * @static
         * @returns {void}
         *
         * @memberOf OpenSSL
         */
        static run(): void;
        /**
         * Cleanup openssl objects and free errors
         *
         * @static
         * @returns {void}
         *
         * @memberOf OpenSSL
         */
        static stop(): void;
        /**
         * Print OpenSSL error stack
         *
         * @static
         * @returns {string}
         *
         * @memberOf OpenSSL
         */
        static printErrors(): string;
        /**
         * Creates an instance of OpenSSL.
         *
         *
         * @memberOf OpenSSL
         */
        constructor();
    }
}
declare namespace trusted.utils {
    /**
     * Download file
     *
     * @param {string} url Url to remote file
     * @param {string} path Path for save in local system
     * @param {Function} done callback function
     */
    function download(url: string, path: string, done: (err: Error, url?: string, path?: string) => void): void;
}
declare namespace trusted.utils {
    /**
     * JSON Web Token (JWT)
     * Uses only with CTGOSTCP
     *
     * @export
     * @class Jwt
     * @extends {BaseObject<native.JWT.Jwt>}
     */
    class Jwt extends BaseObject<native.UTILS.Jwt> {
        /**
         * Verify jwt license file
         * Return 0 if license correct
         *
         * @static
         * @returns {number}
         *
         * @memberOf Jwt
         */
        static checkLicense(data?: string): number;
        /**
         * Creates an instance of Jwt.
         *
         *
         * @memberOf Jwt
         */
        constructor();
        /**
         * Verify jwt license file
         * Return 0 if license correct
         *
         * @returns {number}
         *
         * @memberOf Jwt
         */
        checkLicense(data?: string): number;
    }
}
declare namespace trusted.utils {
    /**
     * Wrap logger class
     *
     * @export
     * @class Logger
     * @extends {BaseObject<native.UTILS.Logger>}
     */
    class Logger extends BaseObject<native.UTILS.Logger> {
        /**
         * Start write log to a file
         *
         * @static
         * @param {string} filename
         * @param {LoggerLevel} [level=DEFAULT_LOGGER_LEVEL]
         * @returns {Logger}
         *
         * @memberOf Logger
         */
        static start(filename: string, level?: LoggerLevel): Logger;
        /**
         * Creates an instance of Logger.
         *
         * @memberOf Logger
         */
        constructor();
        /**
         * Start write log to a file
         *
         * @param {string} filename
         * @param {LoggerLevel} [level=DEFAULT_LOGGER_LEVEL]
         * @returns {void}
         *
         * @memberOf Logger
         */
        start(filename: string, level?: LoggerLevel): void;
        /**
         * Stop write log file
         *
         * @returns {void}
         *
         * @memberOf Logger
         */
        stop(): void;
        /**
         * Clean exsisting log file
         *
         * @returns {void}
         *
         * @memberOf Logger
         */
        clear(): void;
    }
}
declare const path: any;
declare const crypto2: any;
declare const fs2: any;
declare const os: any;
declare const OS_TYPE: any;
declare const DEFAULT_IGNORE: string[];
declare const DEFAULT_OUT_FILENAME = "cerber.lock";
interface IVerifyStatus {
    difModules: string[];
    signature: boolean;
}
declare namespace trusted.utils {
    /**
     * App for sign and verify node packages
     *
     * @export
     * @class Cerber
     * @extends {BaseObject<native.UTILS.Cerber>}
     */
    class Cerber extends BaseObject<native.UTILS.Cerber> {
        /**
         * Sign package
         *
         * @static
         * @param {string} modulePath Directory path
         * @param {pki.Certificate} cert Signer certificate
         * @param {pki.Key} key Signer private key
         *
         * @memberOf Cerber
         */
        static sign(modulePath: string, cert: pki.Certificate, key: pki.Key): void;
        /**
         * Verify package
         *
         * @static
         * @param {string} modulePath Directory path
         * @param {pki.CertificateCollection} [cacerts] CA certificates
         * @param {string[]} [policies]
         * @returns {IVerifyStatus}
         *
         * @memberOf Cerber
         */
        static verify(modulePath: string, cacerts?: pki.CertificateCollection, policies?: string[]): IVerifyStatus;
        /**
         * Return signer certificate info:
         * issuername, organization, subjectname, thumbprint
         *
         * @static
         * @param {string} modulePath
         * @returns {string[]}
         *
         * @memberOf Cerber
         */
        static getSignersInfo(modulePath: string): string[];
        /**
         * Creates an instance of Cerber.
         *
         *
         * @memberOf Cerber
         */
        constructor();
        /**
         * Sign package
         *
         * @param {string} modulePath Directory path
         * @param {pki.Certificate} cert Signer certificate
         * @param {pki.Key} key Signer private key
         *
         * @memberOf Cerber
         */
        sign(modulePath: string, cert: pki.Certificate, key: pki.Key): void;
        /**
         * Verify package
         *
         * @param {string} modulePath Directory path
         * @param {pki.CertificateCollection} [cacerts] CA certificates
         * @param {string[]} [policies]
         * @returns {IVerifyStatus}
         *
         * @memberOf Cerber
         */
        verify(modulePath: string, cacerts?: pki.CertificateCollection, policies?: string[]): IVerifyStatus;
        /**
         * Return signer certificate info:
         * issuername, organization, subjectname, thumbprint
         *
         * @param {string} modulePath
         * @returns {string[]}
         *
         * @memberOf Cerber
         */
        getSignersInfo(modulePath: string): string[];
        /**
         * Get filenames and sha1 hashes
         *
         * @private
         * @param {string} dir Directory path
         * @param {string} [relative] Subdirectory
         * @returns {string[]} module_name#sha1_hash
         *
         * @memberOf Cerber
         */
        private rehash(dir, relative?);
    }
}
declare namespace trusted.pki {
    /**
     * Key usage flags
     *
     * @export
     * @enum {number}
     */
    enum KeyUsageFlags {
        DigitalSignature = 128,
        NonRepudiation = 64,
        KeyEncipherment = 32,
        DataEncipherment = 16,
        KeyAgreement = 8,
        KeyCertSign = 4,
        CrlSign = 2,
        EncipherOnly = 1,
        DecipherOnly = 32768,
    }
}
declare namespace trusted.pki {
    /**
     * Wrap EVP_PKEY
     *
     * @export
     * @class Key
     * @extends {BaseObject<native.PKI.Key>}
     */
    class Key extends BaseObject<native.PKI.Key> {
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
         * @param {native.PKI.Key} [param]
         *
         * @memberOf Key
         */
        constructor(param?: native.PKI.Key);
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
declare namespace trusted.pki {
    /**
     * Wrap ASN1_OBJECT
     *
     * @export
     * @class Oid
     * @extends {BaseObject<native.PKI.OID>}
     */
    class Oid extends BaseObject<native.PKI.OID> {
        /**
         * Creates an instance of Oid.
         * @param {(native.PKI.OID | string)} param
         *
         * @memberOf Oid
         */
        constructor(param: native.PKI.OID | string);
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
declare namespace trusted.pki {
    /**
     * Wrap X509_ALGOR
     *
     * @export
     * @class Algorithm
     * @extends {BaseObject<native.PKI.Algorithm>}
     */
    class Algorithm extends BaseObject<native.PKI.Algorithm> {
        /**
         * Creates an instance of Algorithm.
         * @param {(native.PKI.Algorithm | string)} [param]
         *
         * @memberOf Algorithm
         */
        constructor(param?: native.PKI.Algorithm | string);
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
declare namespace trusted.pki {
    /**
     * Wrap X509_ATTRIBUTE
     *
     * @export
     * @class Attribute
     * @extends {BaseObject<native.PKI.Attribute>}
     */
    class Attribute extends BaseObject<native.PKI.Attribute> {
        /**
         * Creates an instance of Attribute.
         * @param {native.PKI.Attribute} [param]
         *
         * @memberOf Attribute
         */
        constructor(param?: native.PKI.Attribute);
        /**
         * Return ASN1 type of attribute
         *
         * @type {number}
         * @memberOf Attribute
         */
        /**
         * Set ASN1 type
         *
         * @param {number} value ASN1 type
         *
         * @memberOf Attribute
         */
        asnType: number;
        /**
         * Return attribute OID
         *
         * @type {Oid}
         * @memberOf Attribute
         */
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
        duplicate(): Attribute;
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
declare namespace trusted.pki {
    /**
     * Collection of Attribute
     *
     * @export
     * @class AttributeValueCollection
     * @extends {BaseObject<native.PKI.AttributeValueCollection>}
     * @implements {core.ICollectionWrite}
     */
    class AttributeValueCollection extends BaseObject<native.PKI.AttributeValueCollection> implements core.ICollectionWrite {
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
declare namespace trusted.pki {
    /**
     * Wrap X509
     *
     * @export
     * @class Certificate
     * @extends {BaseObject<native.PKI.Certificate>}
     */
    class Certificate extends BaseObject<native.PKI.Certificate> {
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
         * Download certificate
         *
         * @static
         * @param {string[]} urls
         * @param {string} pathForSave File path
         * @param {Function} done callback
         *
         * @memberOf Certificate
         */
        static download(urls: string[], pathForSave: string, done: (err: Error, certificate: Certificate) => void): void;
        /**
         * Creates an instance of Certificate.
         * @param {native.PKI.Certificate} [param]
         *
         * @memberOf Certificate
         */
        constructor(param?: native.PKI.Certificate);
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
         * Return array of OCSP urls
         *
         * @readonly
         * @type {string[]}
         * @memberof Certificate
         */
        readonly OCSPUrls: string[];
        /**
         * Return array of CA issuers urls
         *
         * @readonly
         * @type {string[]}
         * @memberof Certificate
         */
        readonly CAIssuersUrls: string[];
        /**
         * Return true is a certificate is self signed
         *
         * @readonly
         * @type {boolean}
         * @memberOf Certificate
         */
        readonly isSelfSigned: boolean;
        /**
         * Return true if it CA certificate (can be used to sign other certificates)
         *
         * @readonly
         * @type {boolean}
         * @memberOf Certificate
         */
        readonly isCA: boolean;
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
        hash(algorithm?: string): string;
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
declare namespace trusted.pki {
    /**
     * Collection of Certificate
     *
     * @export
     * @class CertificateCollection
     * @extends {BaseObject<native.PKI.CertificateCollection>}
     * @implements {core.ICollectionWrite}
     */
    class CertificateCollection extends BaseObject<native.PKI.CertificateCollection> implements core.ICollectionWrite {
        /**
         * Creates an instance of CertificateCollection.
         * @param {native.PKI.CertificateCollection} [param]
         *
         * @memberOf CertificateCollection
         */
        constructor(param?: native.PKI.CertificateCollection);
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
declare namespace trusted.pki {
    /**
     * Wrap X509_REQ
     *
     * @export
     * @class CertificationRequest
     * @extends {BaseObject<native.PKI.CertificationRequest>}
     */
    class CertificationRequest extends BaseObject<native.PKI.CertificationRequest> {
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
         * @param {native.PKI.CertificationRequest} [param]
         *
         * @memberOf CertificationRequest
         */
        constructor(param?: native.PKI.CertificationRequest);
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
declare namespace trusted.pki {
    /**
     * Wrap X509_REQ_INFO
     *
     * @export
     * @class CertificationRequestInfo
     * @extends {BaseObject<native.PKI.CertificationRequestInfo>}
     */
    class CertificationRequestInfo extends BaseObject<native.PKI.CertificationRequestInfo> {
        /**
         * Creates an instance of CertificationRequestInfo.
         * @param {native.PKI.CertificationRequestInfo} [param]
         *
         * @memberOf CertificationRequestInfo
         */
        constructor(param?: native.PKI.CertificationRequestInfo);
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
declare namespace trusted.pki {
    /**
     * Revocatiom provaider
     *
     * @export
     * @class Revocation
     * @extends {BaseObject<native.PKI.Revocation>}
     */
    class Revocation extends BaseObject<native.PKI.Revocation> {
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
        getCrlLocal(cert: Certificate, store: pkistore.PkiStore): any;
        /**
         * Return array of distribution points for certificate
         *
         * @param {Certificate} cert
         * @returns {Array<string>}
         *
         * @memberOf Revocation
         */
        getCrlDistPoints(cert: Certificate): string[];
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
        downloadCRL(distPoints: string[], pathForSave: string, done: (err: Error, crl: Crl) => void): void;
    }
}
declare namespace trusted.pki {
    /**
     * Wrap X509_CRL
     *
     * @export
     * @class Crl
     * @extends {BaseObject<native.PKI.CRL>}
     */
    class Crl extends BaseObject<native.PKI.CRL> {
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
         * @param {native.PKI.CRL} [param]
         *
         * @memberOf Crl
         */
        constructor(param?: native.PKI.CRL);
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
         * Return revoced collection
         *
         * @readonly
         * @type {native.PKI.RevokedCollection}
         * @memberOf Crl
         */
        readonly revoked: RevokedCollection;
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
        hash(algorithm?: string): string;
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
declare namespace trusted.pki {
    /**
     * Wrap X509_REVOKED
     *
     * @export
     * @class Revoked
     * @extends {BaseObject<native.PKI.Revoked>}
     */
    class Revoked extends BaseObject<native.PKI.Revoked> {
        /**
         * Creates an instance of Revoked.
         * @param {native.PKI.Revoked} [param]
         *
         * @memberOf Revoked
         */
        constructor(param?: native.PKI.Revoked);
        /**
         * Return serial nuber
         *
         * @readonly
         * @type {string}
         * @memberOf Revoked
         */
        readonly serialNumber: string;
        /**
         * Return revocation date
         *
         * @readonly
         * @type {string}
         * @memberOf Revoked
         */
        readonly revocationDate: string;
        /**
         * Return reason
         *
         * @readonly
         * @type {number}
         * @memberOf Revoked
         */
        readonly reason: string;
        /**
         * Return Revoked duplicat
         *
         * @returns {Revoked}
         *
         * @memberOf Revoked
         */
        duplicate(): Revoked;
    }
}
declare namespace trusted.pki {
    /**
     * Collection of Revoked
     *
     * @export
     * @class RevokedCollection
     * @extends {BaseObject<native.PKI.RevokedCollection>}
     * @implements {core.ICollectionWrite}
     */
    class RevokedCollection extends BaseObject<native.PKI.RevokedCollection> implements core.ICollectionWrite {
        /**
         * Creates an instance of RevokedCollection.
         * @param {native.PKI.RevokedCollection} [param]
         *
         * @memberOf RevokedCollection
         */
        constructor(param?: native.PKI.RevokedCollection);
        /**
         * Return element by index from collection
         *
         * @param {number} index
         * @returns {Revoked}
         *
         * @memberOf RevokedCollection
         */
        items(index: number): Revoked;
        /**
         * Return collection length
         *
         * @readonly
         * @type {number}
         * @memberOf RevokedCollection
         */
        readonly length: number;
        /**
         * Add new element to collection
         *
         * @param {Revoked} revoked
         *
         * @memberOf RevokedCollection
         */
        push(rv: Revoked): void;
        /**
         * Remove last element from collection
         *
         *
         * @memberOf RevokedCollection
         */
        pop(): void;
        /**
         * Remove element by index from collection
         *
         * @param {number} index
         *
         * @memberOf RevokedCollection
         */
        removeAt(index: number): void;
    }
}
declare namespace trusted.pki {
    /**
     * Collection of Crl
     *
     * @export
     * @class CrlCollection
     * @extends {BaseObject<native.PKI.CrlCollection>}
     * @implements {core.ICollectionWrite}
     */
    class CrlCollection extends BaseObject<native.PKI.CrlCollection> implements core.ICollectionWrite {
        /**
         * Creates an instance of CrlCollection.
         * @param {native.PKI.CrlCollection} [param]
         *
         * @memberOf CrlCollection
         */
        constructor(param?: native.PKI.CrlCollection);
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
declare namespace trusted.pki {
    /**
     * Final class for make certification request
     *
     * @export
     * @class CSR
     * @extends {BaseObject<native.PKI.CSR>}
     */
    class CSR extends BaseObject<native.PKI.CSR> {
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
declare namespace trusted.pki {
    /**
     * Chain of certificates
     *
     * @export
     * @class Chain
     * @extends {BaseObject<native.PKI.Chain>}
     */
    class Chain extends BaseObject<native.PKI.Chain> {
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
declare namespace trusted.pki {
    /**
     * Encrypt and decrypt operations
     *
     * @export
     * @class Cipher
     * @extends {BaseObject<native.PKI.Cipher>}
     */
    class Cipher extends BaseObject<native.PKI.Cipher> {
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
        readonly algorithm: string;
        readonly mode: string;
        readonly dgst: string;
        /**
         * Return recipient infos
         *
         * @param {string} filenameEnc File path
         * @param {DataFormat} format DataFormat.PEM | DataFormat.DER
         * @returns {CmsRecipientInfoCollection}
         *
         * @memberOf Cipher
         */
        getRecipientInfos(filenameEnc: string, format: DataFormat): cms.CmsRecipientInfoCollection;
    }
}
declare namespace trusted.pki {
    /**
     * PKCS#12 (PFX)
     *
     * @export
     * @class Pkcs12
     * @extends {BaseObject<native.PKI.Pkcs12>}
     */
    class Pkcs12 extends BaseObject<native.PKI.Pkcs12> {
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
         * @param {native.PKI.Pkcs12} [param]
         *
         * @memberOf Pkcs12
         */
        constructor(param?: native.PKI.Pkcs12);
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
declare namespace trusted.cms {
    /**
     * Wrap CMS_RecipientInfo
     *
     * @export
     * @class CmsRecipientInfo
     * @extends {BaseObject<native.CMS.CmsRecipientInfo>}
     */
    class CmsRecipientInfo extends BaseObject<native.CMS.CmsRecipientInfo> {
        /**
         * Creates an instance of CmsRecipientInfo.
         * @param {native.CMS.CmsRecipientInfo} [param]
         *
         * @memberOf CmsRecipientInfo
         */
        constructor(param?: native.CMS.CmsRecipientInfo);
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
        ktriCertCmp(cert: pki.Certificate): number;
    }
}
declare namespace trusted.cms {
    /**
     * Collection of CmsRecipientInfo
     *
     * @export
     * @class CmsRecipientInfoCollection
     * @extends {BaseObject<native.CMS.CmsRecipientInfoCollection>}
     * @implements {core.ICollectionWrite}
     */
    class CmsRecipientInfoCollection extends BaseObject<native.CMS.CmsRecipientInfoCollection> implements core.ICollectionWrite {
        /**
         * Creates an instance of CmsRecipientInfoCollection.
         * @param {native.CMS.CmsRecipientInfoCollection} [param]
         *
         * @memberOf CmsRecipientInfoCollection
         */
        constructor(param?: native.CMS.CmsRecipientInfoCollection);
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
declare namespace trusted.cms {
    /**
     * Wrap signer identifier information (keyidentifier, issuer name and serial number)
     *
     * @export
     * @class SignerId
     * @extends {BaseObject<native.CMS.SignerId>}
     */
    class SignerId extends BaseObject<native.CMS.SignerId> {
        /**
         * Creates an instance of SignerId.
         * @param {native.CMS.SignerId} [param]
         *
         * @memberOf SignerId
         */
        constructor(param?: native.CMS.SignerId);
        /**
         * Return full issuer name
         *
         * @readonly
         * @type {string}
         * @memberOf SignerId
         */
        readonly issuerName: string;
        /**
         * Return serial number
         *
         * @readonly
         * @type {string}
         * @memberOf SignerId
         */
        readonly serialNumber: string;
        /**
         * Return keyidentifier
         *
         * @readonly
         * @type {string}
         * @memberOf SignerId
         */
        readonly keyId: string;
    }
}
declare namespace trusted.cms {
    /**
     * Wrap CMS_SignerInfo
     *
     * @export
     * @class Signer
     * @extends {BaseObject<native.CMS.Signer>}
     */
    class Signer extends BaseObject<native.CMS.Signer> {
        /**
         * Creates an instance of Signer.
         *
         * @param {native.CMS.Signer} handle
         *
         * @memberOf Signer
         */
        constructor(handle: native.CMS.Signer);
        /**
         * Return signer certificate
         *
         * @type {Certificate}
         * @memberOf Signer
         */
        /**
         * Set signer certificate
         * Error if cert no signer
         *
         * @param cert Certificate
         *
         * @memberOf Signer
         */
        certificate: pki.Certificate;
        /**
         * Return digest algorithm
         *
         * @readonly
         * @type {Algorithm}
         * @memberOf Signer
         */
        readonly digestAlgorithm: Algorithm;
        /**
         * Return signer identifier information
         *
         * @readonly
         * @type {SignerId}
         * @memberOf Signer
         */
        readonly signerId: SignerId;
        /**
         * Verify signer content
         *
         * @param {ISignedDataContent} v
         * @returns {boolean}
         *
         * @memberOf Signer
         */
        verifyContent(v: ISignedDataContent): boolean;
        /**
         * Verify sign attributes
         *
         * @returns {boolean}
         *
         * @memberOf Signer
         */
        verify(): boolean;
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
        signedAttributes(index: number): pki.Attribute;
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
        unsignedAttributes(index: number): pki.Attribute;
    }
}
declare namespace trusted.cms {
    /**
     * Collection of SignerAttribute
     *
     * @export
     * @class SignerAttributeCollection
     * @extends {BaseObject<native.CMS.SignerAttributeCollection>}
     * @implements {ICollection}
     */
    class SignerAttributeCollection extends BaseObject<native.CMS.SignerAttributeCollection> implements core.ICollection {
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
        push(attr: pki.Attribute): void;
        /**
         * Remove element by index from collection
         *
         * @param {number} index
         *
         * @memberOf SignerAttributeCollection
         */
        removeAt(index: number): void;
        /**
         *
         * @param {number} index
         * @returns {Attribute}
         *
         * @memberOf SignerAttributeCollection
         */
        /**
         * Return element by index from collection
         *
         * @param {number} index
         * @returns
         *
         * @memberOf SignerAttributeCollection
         */
        items(index: number): pki.Attribute;
    }
}
declare namespace trusted.cms {
    /**
     * Collection of Signer
     *
     * @export
     * @class SignerCollection
     * @extends {BaseObject<native.CMS.SignerCollection>}
     * @implements {Collection.ICollection}
     */
    class SignerCollection extends BaseObject<native.CMS.SignerCollection> implements core.ICollection {
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
declare namespace trusted.cms {
    enum SignedDataContentType {
        url = 0,
        buffer = 1,
    }
    interface ISignedDataContent {
        type: SignedDataContentType;
        data: string | Buffer;
    }
    /**
     * Wrap CMS_ContentInfo
     *
     * @export
     * @class SignedData
     * @extends {BaseObject<native.CMS.SignedData>}
     */
    class SignedData extends BaseObject<native.CMS.SignedData> {
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
        private prContent;
        /**
         * Creates an instance of SignedData.
         *
         *
         * @memberOf SignedData
         */
        constructor();
        /**
         * Return content of signed data
         *
         * @type {ISignedDataContent}
         * @memberOf SignedData
         */
        /**
         * Set content v to signed data
         *
         *
         * @memberOf SignedData
         */
        content: ISignedDataContent;
        /**
         * Return sign policys
         *
         * @type {Array<string>}
         * @memberOf SignedData
         */
        /**
         * Set sign policies
         *
         *
         * @memberOf SignedData
         */
        policies: string[];
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
        certificates(index: number): pki.Certificate;
        /**
         * Return certificates collection
         *
         * @returns {CertificateCollection}
         *
         * @memberOf SignedData
         */
        certificates(): pki.CertificateCollection;
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
        createSigner(cert: pki.Certificate, key: pki.Key): Signer;
        /**
         * Verify signature
         *
         * @param {CertificateCollection} [certs] Certificate collection
         * @returns {boolean}
         *
         * @memberOf SignedData
         */
        verify(certs?: pki.CertificateCollection): boolean;
        /**
         * Create sign
         *
         *
         * @memberOf SignedData
         */
        sign(): void;
    }
}
declare namespace trusted.pkistore {
    /**
     * Work with json files
     *
     * @export
     * @class CashJson
     * @extends {BaseObject<native.PKISTORE.CashJson>}
     */
    class CashJson extends BaseObject<native.PKISTORE.CashJson> {
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
declare namespace trusted.pkistore {
    /**
     * Support CryptoPro provider
     *
     * @export
     * @class ProviderCryptopro
     * @extends {BaseObject<native.PKISTORE.ProviderCryptopro>}
     */
    class ProviderCryptopro extends BaseObject<native.PKISTORE.ProviderCryptopro> {
        constructor();
        /**
         * Return private key by certificate from CryptoPro store
         *
         * @param {Certificate} cert Certificate
         * @returns
         *
         * @memberOf ProviderCryptopro
         */
        getKey(cert: pki.Certificate): pki.Key;
        /**
         * Ensure that the certificate's private key is available
         *
         * @param {Certificate} cert
         * @returns {boolean}
         *
         * @memberOf ProviderCryptopro
         */
        hasPrivateKey(cert: pki.Certificate): boolean;
    }
}
declare namespace trusted.pkistore {
    /**
     * Support Microsoft crypto provider (only windows platform)
     *
     * @export
     * @class ProviderMicrosoft
     * @extends {BaseObject<native.PKISTORE.ProviderMicrosoft>}
     */
    class ProviderMicrosoft extends BaseObject<native.PKISTORE.ProviderMicrosoft> {
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
        getKey(cert: pki.Certificate): pki.Key;
        /**
         * Ensure that the certificate's private key is available
         *
         * @param {Certificate} cert
         * @returns {boolean}
         *
         * @memberOf ProviderMicrosoft
         */
        hasPrivateKey(cert: pki.Certificate): boolean;
    }
}
declare namespace trusted.pkistore {
    /**
     * Native crypto provider (work in local folders)
     *
     * @export
     * @class Provider_System
     * @extends {BaseObject<native.PKISTORE.Provider_System>}
     */
    class Provider_System extends BaseObject<native.PKISTORE.Provider_System> {
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
declare namespace trusted.pkistore {
    /**
     * Filter for search objects
     *
     * @export
     * @class Filter
     * @extends {BaseObject<native.PKISTORE.Filter>}
     * @implements {native.PKISTORE.IFilter}
     */
    class Filter extends BaseObject<native.PKISTORE.Filter> implements native.PKISTORE.IFilter {
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
     * @extends {BaseObject<native.PKISTORE.PkiItem>}
     * @implements {native.PKISTORE.IPkiItem}
     */
    class PkiItem extends BaseObject<native.PKISTORE.PkiItem> implements native.PKISTORE.IPkiItem {
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
    class PkiStore extends BaseObject<native.PKISTORE.PkiStore> {
        private cashJson;
        /**
         * Creates an instance of PkiStore.
         * @param {(native.PKISTORE.PkiStore | string)} param
         *
         * @memberOf PkiStore
         */
        constructor(param: native.PKISTORE.PkiStore | string);
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
         * @returns {string}
         *
         * @memberOf PkiStore
         */
        addCert(provider: native.PKISTORE.Provider, category: string, cert: pki.Certificate): string;
        /**
         * Import CRL to local store
         *
         * @param {native.PKISTORE.Provider} provider SYSTEM, MICROSOFT, CRYPTOPRO
         * @param {string} category MY, OTHERS, TRUST, CRL
         * @param {Crl} crl CRL
         * @returns {string}
         *
         * @memberOf PkiStore
         */
        addCrl(provider: native.PKISTORE.Provider, category: string, crl: pki.Crl): string;
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
        addKey(provider: native.PKISTORE.Provider, key: pki.Key, password: string): string;
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
        addCsr(provider: native.PKISTORE.Provider, category: string, csr: pki.CertificationRequest): string;
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
        readonly certs: pki.CertificateCollection;
    }
}
declare module "trusted-crypto" {
    export = trusted;
}
