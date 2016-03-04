let native = require("../build/Release/trusted.node");

import {DataFormat} from "./data_format";
import {PublicExponent} from "./public_exponent";
import {CryptoMethod} from "./crypto_method";

export namespace PKI {
    export declare class Key {
        keypairGenerate(filename: string, format: DataFormat, pubExp: PublicExponent, keySize: number, password: string);
        keypairGenerateMemory(format: DataFormat, pubExp: PublicExponent, keySize: number, password: string);
        keypairGenerateBIO(format: DataFormat, pubExp: PublicExponent, keySize: number, password: string);
        privkeyLoad(filename: string, format: DataFormat, password: string);
        privkeyLoadMemory(filename: string, format: DataFormat, password: string);
        pubkeyLoad(filename: string, format: DataFormat);
        pubkeyLoadMemory();
        privkeySave(filename: string, format: DataFormat, password: string);
        privkeySaveBIO();
        privkeySaveMemory();
        pubkeySave(filename: string, format: DataFormat);
        pubkeySaveBIO();
        pubkeySaveMemory();
    }

    export declare class Algorithm {
        constructor();
        constructor(name: string);
        getTypeId(): OID;
        getName(): string;
        duplicate(): Algorithm;
        isDigest(): boolean;
    }

    export declare class Attribute {
        duplicate(): Attribute;
        export(): Buffer;
        values(): AttributeValueCollection;
        getAsnType(): number;
        setAsnType(type: number): void;
        getTypeId(): OID;
        setTypeId(oid: OID): void;
    }

    export declare class AttributeValueCollection {
        constructor(alg: Algorithm);
        push(val: Buffer): void;
        pop(): void;
        removeAt(index: number): void;
        items(index: number): Buffer;
        length(): number;
    }

    export declare class OID {
        constructor();
        constructor(value: string);
        getLongName(): string;
        getShortName(): string;
        getValue(): string;
    }

    export declare class Certificate {
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

        load(filename: string, dataFormat: DataFormat): void;
        import(raw: Buffer, dataFormat: DataFormat): void;
        save(filename: string, dataFormat: DataFormat): void;
        export(dataFormat: DataFormat): Buffer;
        compare(cert: Certificate): number;
        equals(cert: Certificate): boolean;
        duplicate(): Certificate;
        hash(digestName: string): Buffer;

    }

    export declare class RevokedCertificate {
        revocationDate(): string;
        reason(): number;
    }

    export declare class CertificateCollection {
        items(index: number): Certificate;
        length(): number;
        push(cer: Certificate): void;
        pop(): void;
        removeAt(index: number): void;
    }

    export declare class CRL {
        load(filename: string, dataFormat: DataFormat): void;
        import(raw: Buffer, dataFormat: DataFormat): void;
        save(filename: string, dataFormat: DataFormat): void;
        export(dataFormat: DataFormat): Buffer;
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
        equals(crl: CRL): boolean;
        hash(digestName: string): Buffer;
        duplicate(): CRL;
    }

    export declare class CertStore {
        addCertStore(pvdType: string, pvdURI: string): void;
        removeCertStore(pvdType: string): void;
        createCache(cacheURI: string): void;
        addCacheSection(cacheURI: string, pvdType: string): void;
        getCertStore(): string;
        getPrvTypePresent(pvdType: string): boolean;
    }

    export declare class ProviderSystem {
        constructor(filename: string);
        fillingCache(cacheURI: string, pvdURI: string): void;
        readJson(filename: string): string;
        testRead(filename: string): string;
    }

    export declare class CertificationRequestInfo {
       setSubject(x509name: string): void;
       setSubjectPublicKey(key: PKI.Key): void;
       setVersion(version: number): void;
    }

    export declare class CertificationRequest {
       constructor(csrinfo: PKI.CertificationRequestInfo);
       sign(key: Key): void;
       verify(): boolean;
       getPEMString(): Buffer;
    }

    export declare class CSR {
        constructor(name: string, key: PKI.Key, digest: string);
        save(filename: string, dataFormat: DataFormat): void;
        getEncodedHEX(): Buffer;
    }

    export declare class Cipher {
        constructor(cipherName: string);
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
    }

    export declare class Chain {
        buildChain(cert: Certificate, certs: CertificateCollection): CertificateCollection;
        verifyChain(chain: CertificateCollection, prvSys: ProviderSystem): boolean;
    }
    
    export interface IPkiItem extends IPkiCrl, IPkiCertificate, IPkiRequest, IPkiKey {
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

export interface IPkiKey{
    encrypted?: boolean;
}

export interface IPkiCrl{
    issuerName?: string;
    issuerFriendlyName?: string;
    lastUpdate?: string;
    nextUpdate?: string;
}

export interface IPkiRequest{
    subjectName?: string;
    subjectFriendlyName?: string;
    key?: string; // thumbprint ket SHA1
}

export interface IPkiCertificate{
    subjectName?: string;
    subjectFriendlyName?: string;
    issuerName?: string;
    issuerFriendlyName?: string;
    notAfter?: string;
    notBefore?: string;
    serial?: string;
    key?: string; // thumbprint ket SHA1
}

export interface IFilter {
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

export declare abstract class Provider {
    type: string;

    /**
     * Возвращает полный список хранимых элементов
     */
    items: IPkiItem[];
}

export declare class Provider_System extends Provider {
    constructor(folder: string);
}

export declare class ProviderMicrosoft extends Provider {
    constructor();
}

export declare class ProviderTSL extends Provider {
    constructor(url: string);
}

export declare class PkiStore {
    constructor(json: string);

    getCash(): CashJson;

    items: IPkiItem[];
    /**
     * Возвращает набор элементов по фильтру
     * - если фильтр пустой, возвращает все элементы
     */
    find(filter?: Filter): IPkiItem[];
    /**
     * ?
     */
    find(item: IPkiItem, filter: IFilter): IPkiItem[];
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
    /**
     * Коллекция провайдеров
     */
    providers: Provider[];
}

export declare class CashJson {
    constructor(fileName: string);
    filenName: string;
    save(fileName: string);
    load(fileName: string);
    export(): IPkiItem[];
    import(items: IPkiItem[]);
    import(item: PkiItem);
}

export declare class Filter {
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

export declare class PkiItem {
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
}
}

export namespace CMS {
    export declare class SignedData {
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
        createSigner(cert: PKI.Certificate, key: PKI.Key, digestNAme: string): Signer;
        addCertificate(cert: PKI.Certificate): void;
        verify(certs: PKI.CertificateCollection): boolean;
        sign(): void;
    }

    export declare class SignerCollection {
        items(index: number): Signer;
        length(): number;
    }

    export declare class Signer {
        setCertificate(cert: PKI.Certificate): void;
        getCertificate(): PKI.Certificate;
        getSignature(): Buffer;
        getSignatureAlgorithm(): PKI.Algorithm;
        getDigestAlgorithm(): PKI.Algorithm;
        getSignedAttributes(): SignerAttributeCollection;
        getUnsignedAttributes(): SignerAttributeCollection;
    }

    export declare class SignerAttributeCollection {
        length(): number;
        push(attr: PKI.Attribute): void;
        removeAt(index: number): void;
        items(index: number): PKI.Attribute;
    }

}

module.exports.PKI = native.PKI;
module.exports.CMS = native.CMS;