/* tslint:disable:no-namespace */
/* tslint:disable:no-var-requires */
let native = require("../build/Release/trusted.node");

import {DataFormat} from "./data_format";
import {PublicExponent} from "./public_exponent";
import {CryptoMethod} from "./crypto_method";

export namespace PKI {
    export declare class Key {
        public generate(format: DataFormat, pubExp: PublicExponent, keySize: number): Key;
        public readPrivateKey(filename: string, format: DataFormat, password: string);
        public readPublicKey(filename: string, format: DataFormat);
        public writePrivateKey(filename: string, format: DataFormat, password: string);
        public writePublicKey(filename: string, format: DataFormat);

        public compare(key: Key): number;
        public duplicate(): Key;
    }

    export declare class Algorithm {
        constructor();
        constructor(name: string);
        public getTypeId(): OID;
        public getName(): string;
        public duplicate(): Algorithm;
        public isDigest(): boolean;
    }

    export declare class Attribute {
        public duplicate(): Attribute;
        public export(): Buffer;
        public values(): AttributeValueCollection;
        public getAsnType(): number;
        public setAsnType(type: number): void;
        public getTypeId(): OID;
        public setTypeId(oid: OID): void;
    }

    export declare class AttributeValueCollection {
        constructor(alg: Algorithm);
        public push(val: Buffer): void;
        public pop(): void;
        public removeAt(index: number): void;
        public items(index: number): Buffer;
        public length(): number;
    }

    export declare class OID {
        constructor();
        constructor(value: string);
        public getLongName(): string;
        public getShortName(): string;
        public getValue(): string;
    }

    export declare class Certificate {
        public getSubjectFriendlyName(): string;
        public getIssuerFriendlyName(): string;
        public getSubjectName(): string;
        public getIssuerName(): string;
        public getNotAfter(): string;
        public getNotBefore(): string;
        public getSerialNumber(): Buffer;
        public getThumbprint(): Buffer;
        public getVersion(): number;
        public getType(): number;
        public getKeyUsage(): number;
        public getSignatureAlgorithm(): string;
        public getOrganizationName(): string;

        public load(filename: string, dataFormat: DataFormat): void;
        public import(raw: Buffer, dataFormat: DataFormat): void;
        public save(filename: string, dataFormat: DataFormat): void;
        public export(dataFormat: DataFormat): Buffer;
        public compare(cert: Certificate): number;
        public equals(cert: Certificate): boolean;
        public duplicate(): Certificate;
        public hash(digestName: string): Buffer;
    }

    export declare class RevokedCertificate {
        public revocationDate(): string;
        public reason(): number;
    }

    export declare class CertificateCollection {
        public items(index: number): Certificate;
        public length(): number;
        public push(cer: Certificate): void;
        public pop(): void;
        public removeAt(index: number): void;
    }

    export declare class CRL {
        public getEncoded(): Buffer;
        public getSignature(): Buffer;
        public getVersion(): number;
        public getIssuerName(): string;
        public getIssuerFriendlyName(): string;
        public getLastUpdate(): string;
        public getNextUpdate(): string;
        public getCertificate(): Certificate;
        public getThumbprint(): Buffer;
        public getSigAlgName(): string;
        public getSigAlgShortName(): string;
        public getSigAlgOID(): string;
        public getRevokedCertificateCert(cer: Certificate): RevokedCertificate;
        public getRevokedCertificateSerial(serial: string): RevokedCertificate;

        public load(filename: string, dataFormat: DataFormat): void;
        public import(raw: Buffer, dataFormat: DataFormat): void;
        public save(filename: string, dataFormat: DataFormat): void;
        public export(dataFormat: DataFormat): Buffer;
        public compare(crl: CRL): number;
        public equals(crl: CRL): boolean;
        public hash(digestName: string): Buffer;
        public duplicate(): CRL;
    }

    export declare class CrlCollection {
        public  items(index: number): CRL;
        public length(): number;
        public push(crl: CRL): void;
        public pop(): void;
        public removeAt(index: number): void;
    }

    export declare class CertificationRequestInfo {
       public setSubject(x509name: string): void;
       public setSubjectPublicKey(key: PKI.Key): void;
       public setVersion(version: number): void;
    }

    export declare class CertificationRequest {
       constructor();
       constructor(csrinfo: PKI.CertificationRequestInfo);
       public load(filename: string, dataFormat: DataFormat): void;
       public sign(key: Key): void;
       public verify(): boolean;
       public getPEMString(): Buffer;
    }

    export declare class CSR {
        constructor(name: string, key: PKI.Key, digest: string);
        public save(filename: string, dataFormat: DataFormat): void;
        public getEncodedHEX(): Buffer;
    }

    export declare class Cipher {
        constructor(cipherName: string);
        public setCryptoMethod(method: CryptoMethod): void;
        public encrypt(filenameSource: string, filenameEnc: string, format: DataFormat): void;
        public decrypt(filenameEnc: string, filenameDec: string, format: DataFormat): void;
        public addRecipientsCerts(certs: CertificateCollection): void;
        public setPrivKey(rkey: Key): void;
        public setRecipientCert(rcert: Certificate): void;
        public setPass(password: string): void;
        public setDigest(digest: string): void;
        public setIV(iv: string): void;
        public setKey(key: string): void;
        public setSalt(salt: string): void;
        public getSalt(): Buffer;
        public getIV(): Buffer;
        public getKey(): Buffer;
        public getAlgorithm(): string;
        public getMode(): string;
        public getDigestAlgorithm(): string;
    }

    export declare class Chain {
        public buildChain(cert: Certificate, certs: CertificateCollection): CertificateCollection;
        public verifyChain(chain: CertificateCollection, crls: CrlCollection): boolean;
    }

    export declare class Revocation {
        public getCrlLocal(cert: Certificate, store: PKISTORE.PkiStore): any;
        public getCrlDistPoints(cert: Certificate): Array<string>;
        public checkCrlTime(crl: CRL): boolean;
        public downloadCRL(distPoints: Array<string>, path: string, done: Function): void;
    }

    export declare class Pkcs12 {
        public getCertificate(password: string): Certificate;
        public getKey(password: string): Key;
        public getCACertificates(password: string): CertificateCollection;

        public load(filename: string): void;
        public save(filename: string): void;
        public create(cert: Certificate, key: Key, ca: CertificateCollection, password: string, name: string): Pkcs12;
    }
}

export namespace CMS {
    export declare class SignedData {
        constructor();
        public getContent(): Buffer;
        public setContent(v: Buffer): void;
        public getFlags(): number;
        public setFlags(v: number): void;
        public load(filename: string, dataFormat: DataFormat): void;
        public import(raw: Buffer, dataFormat: DataFormat): void;
        public save(filename: string, dataFormat: DataFormat): void;
        public export(dataFormat: DataFormat): Buffer;
        public getCertificates(): PKI.CertificateCollection;
        public getSigners(): SignerCollection;
        public isDetached(): boolean;
        public createSigner(cert: PKI.Certificate, key: PKI.Key, digestNAme: string): Signer;
        public  addCertificate(cert: PKI.Certificate): void;
        public verify(certs: PKI.CertificateCollection): boolean;
        public sign(): void;
    }

    export declare class SignerCollection {
        public items(index: number): Signer;
        public length(): number;
    }

    export declare class Signer {
        public setCertificate(cert: PKI.Certificate): void;
        public getCertificate(): PKI.Certificate;
        public getSignature(): Buffer;
        public getSignatureAlgorithm(): PKI.Algorithm;
        public getDigestAlgorithm(): PKI.Algorithm;
        public getSignedAttributes(): SignerAttributeCollection;
        public getUnsignedAttributes(): SignerAttributeCollection;
    }

    export declare class SignerAttributeCollection {
        public length(): number;
        public push(attr: PKI.Attribute): void;
        public removeAt(index: number): void;
        public items(index: number): PKI.Attribute;
    }

}

export namespace PKISTORE {
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

    export interface IPkiKey {
        encrypted?: boolean;
    }

    export interface IPkiCrl {
        issuerName?: string;
        issuerFriendlyName?: string;
        lastUpdate?: string;
        nextUpdate?: string;
    }

    export interface IPkiRequest {
        subjectName?: string;
        subjectFriendlyName?: string;
        key?: string; // thumbprint ket SHA1
    }

    export interface IPkiCertificate {
        subjectName?: string;
        subjectFriendlyName?: string;
        issuerName?: string;
        issuerFriendlyName?: string;
        notAfter?: string;
        notBefore?: string;
        serial?: string;
        key?: string; // thumbprint ket SHA1
        organizationName?: string;
        signatureAlgorithm?: string;
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
        public type: string;
    }

    /* tslint:disable-next-line:class-name */
    export declare class Provider_System extends Provider {
        constructor(folder: string);
        public  objectToPkiItem(pathr: string): IPkiItem;
    }

    export declare class ProviderMicrosoft extends Provider {
        constructor();
        public getKey(cert: PKI.Certificate): PKI.Key;
    }

    export declare class ProviderCryptopro extends Provider {
        constructor();
        public getKey(cert: PKI.Certificate): PKI.Key;
    }

    export declare class ProviderTSL extends Provider {
        constructor(url: string);
    }

    export declare class PkiStore {
        constructor(json: string);

        public getCash(): CashJson;

        /**
         * Возвращает набор элементов по фильтру
         * - если фильтр пустой, возвращает все элементы
         */
        public find(filter?: Filter): IPkiItem[];

        /**
         * Возвращает ключ по фильтру
         * - фильтр задается относительно элементов, которые могут быть связаны с ключом
         */
        public findKey(filter: IFilter): IPkiItem;

        /**
         * Возвращает объект из структуры
         */
        public getItem(item: PkiItem): any;

        public addProvider(provider: Provider): void;

        public addCert(provider: Provider, category: string, cert: PKI.Certificate, flags: number): string;
        public addCrl(provider: Provider, category: string, crl: PKI.CRL, flags: number): string;
        public addKey(provider: Provider, key: PKI.Key, password: string): string;
        public addCsr(provider: Provider, category: string, csr: PKI.CertificationRequest): string;
    }

    export declare class CashJson {
        public filenName: string;
        constructor(fileName: string);
        public save(fileName: string);
        public load(fileName: string);
        public export(): IPkiItem[];
        public import(items: IPkiItem[]);
        public import(item: PkiItem);
    }

    export declare class Filter {
        constructor();
        public setType(type: string): void;
        public setProvider(provider: string): void;
        public setCategory(category: string): void;
        public setHash(hash: string): void;
        public setSubjectName(subjectName: string): void;
        public setSubjectFriendlyName(subjectFriendlyName: string): void;
        public setIssuerName(issuerName: string): void;
        public setIssuerFriendlyName(issuerFriendlyName: string): void;
        public setIsValid(valid: boolean): void;
        public setSerial(serial: string): void;
    }

    export declare class PkiItem {
        constructor();
        public setFormat(type: string): void;
        public setType(type: string): void;
        public setProvider(provider: string): void;
        public setCategory(category: string): void;
        public setURI(category: string): void;
        public setHash(hash: string): void;
        public setSubjectName(subjectName: string): void;
        public setSubjectFriendlyName(subjectFriendlyName: string): void;
        public setIssuerName(issuerName: string): void;
        public setIssuerFriendlyName(issuerFriendlyName: string): void;
        public setSerial(serial: string): void;
        public setNotBefore(before: string): void;
        public setNotAfter(after: string): void;
        public setLastUpdate(lastUpdate: string): void;
        public setNextUpdate(nextUpdate: string): void;
        public setKey(key: string): void;
        public setKeyEncrypted(enc: boolean): void;
        public setOrganizationName(organizationName: string): void;
        public setSignatureAlgorithm(signatureAlgorithm: string): void;
    }
}

module.exports.PKI = native.PKI;
module.exports.CMS = native.CMS;
module.exports.PKISTORE = native.PKISTORE;
