/// <reference types="node" />
/* tslint:disable:no-namespace */
/* tslint:disable:no-var-requires */
/* tslint:disable:max-classes-per-file */

declare namespace native {
    namespace PKI {
        class Key {
            public generate(format: trusted.DataFormat, pubExp: trusted.PublicExponent, keySize: number): Key;
            public readPrivateKey(filename: string, format: trusted.DataFormat, password: string);
            public readPublicKey(filename: string, format: trusted.DataFormat);
            public writePrivateKey(filename: string, format: trusted.DataFormat, password: string);
            public writePublicKey(filename: string, format: trusted.DataFormat);

            public compare(key: Key): number;
            public duplicate(): Key;
        }

        class Algorithm {
            constructor(name?: string);
            public getTypeId(): OID;
            public getName(): string;
            public duplicate(): Algorithm;
            public isDigest(): boolean;
        }

        class Attribute {
            public duplicate(): Attribute;
            public export(): Buffer;
            public values(): AttributeValueCollection;
            public getAsnType(): number;
            public setAsnType(type: number): void;
            public getTypeId(): OID;
            public setTypeId(oid: OID): void;
        }

        class AttributeValueCollection {
            constructor(alg: Algorithm);
            public push(val: Buffer): void;
            public pop(): void;
            public removeAt(index: number): void;
            public items(index: number): Buffer;
            public length(): number;
        }

        class OID {
            constructor(value?: string);
            public getLongName(): string;
            public getShortName(): string;
            public getValue(): string;
        }

        class Extension {
            constructor(oid?: OID, value?: string);
            public getTypeId(): OID;
            public setTypeId(oid: OID): void;
            public getCritical(): boolean;
            public setCritical(critical: boolean): void;
        }

        class ExtensionCollection {
            public items(index: number): Extension;
            public length(): number;
            public push(ext: Extension): void;
            public pop(): void;
            public removeAt(index: number): void;
        }

        class Certificate {
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
            public getSignatureDigestAlgorithm(): string;
            public getPublicKeyAlgorithm(): string;
            public getOrganizationName(): string;
            public getOCSPUrls(): string[];
            public getCAIssuersUrls(): string[];
            public isSelfSigned(): boolean;
            public isCA(): boolean;

            public load(filename: string, dataFormat?: trusted.DataFormat): void;
            public import(raw: Buffer, dataFormat: trusted.DataFormat): void;
            public save(filename: string, dataFormat: trusted.DataFormat): void;
            public export(dataFormat: trusted.DataFormat): Buffer;
            public compare(cert: Certificate): number;
            public equals(cert: Certificate): boolean;
            public duplicate(): Certificate;
            public hash(digestName: string): Buffer;
        }

        class Revoked {
            public getSerialNumber(): string;
            public getRevocationDate(): string;
            public getReason(): string;

            public duplicate(): Revoked;
        }

        class RevokedCollection {
            public items(index: number): Revoked;
            public length(): number;
            public push(rv: Revoked): void;
            public pop(): void;
            public removeAt(index: number): void;
        }

        class CertificateCollection {
            public items(index: number): Certificate;
            public length(): number;
            public push(cer: Certificate): void;
            public pop(): void;
            public removeAt(index: number): void;
        }

        class CRL {
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
            public getRevoked(): RevokedCollection;

            public load(filename: string, dataFormat: trusted.DataFormat): void;
            public import(raw: Buffer, dataFormat: trusted.DataFormat): void;
            public save(filename: string, dataFormat: trusted.DataFormat): void;
            public export(dataFormat: trusted.DataFormat): Buffer;
            public compare(crl: CRL): number;
            public equals(crl: CRL): boolean;
            public hash(digestName: string): Buffer;
            public duplicate(): CRL;
        }

        class CrlCollection {
            public items(index: number): CRL;
            public length(): number;
            public push(crl: CRL): void;
            public pop(): void;
            public removeAt(index: number): void;
        }

        class CertificationRequestInfo {
            public getSubject(): string;
            public setSubject(x509name: string): void;
            public getPublicKey(): Key;
            public setPublicKey(key: Key): void;
            public getVersion(): number;
            public setVersion(version: number): void;
        }

        class CertificationRequest {
            constructor(csrinfo?: PKI.CertificationRequestInfo);
            public load(filename: string, dataFormat?: trusted.DataFormat): void;
            public save(filename: string, dataFormat?: trusted.DataFormat): void;
            public getSubject(): string;
            public setSubject(x509name: string): void;
            public getPublicKey(): Key;
            public setPublicKey(key: Key): void;
            public getVersion(): number;
            public setVersion(version: number): void;
            public sign(key: Key, digest: string): void;
            public verify(): boolean;
            public getPEMString(): Buffer;
            public toCertificate(days: number, key: Key): Certificate;
        }

        class CSR {
            constructor(name: string, key: PKI.Key, digest: string);
            public save(filename: string, dataFormat: trusted.DataFormat): void;
            public getEncodedHEX(): Buffer;
        }

        class Cipher {
            constructor();
            public setCryptoMethod(method: trusted.CryptoMethod): void;
            public encrypt(filenameSource: string, filenameEnc: string, format: trusted.DataFormat): void;
            public decrypt(filenameEnc: string, filenameDec: string, format?: trusted.DataFormat): void;
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
            public getRecipientInfos(filenameEnc: string, format: trusted.DataFormat): CMS.CmsRecipientInfoCollection;
        }

        class Chain {
            public buildChain(cert: Certificate, certs: CertificateCollection): CertificateCollection;
            public verifyChain(chain: CertificateCollection, crls: CrlCollection): boolean;
        }

        class Revocation {
            public getCrlLocal(cert: Certificate, store: PKISTORE.PkiStore): any;
            public getCrlDistPoints(cert: Certificate): string[];
            public checkCrlTime(crl: CRL): boolean;
            public downloadCRL(distPoints: string[], path: string, done: (err: Error, crl: PKI.CRL) => void): void;
        }

        class Pkcs12 {
            public getCertificate(password: string): Certificate;
            public getKey(password: string): Key;
            public getCACertificates(password: string): CertificateCollection;

            public load(filename: string): void;
            public save(filename: string): void;
            public create(cert: Certificate, key: Key, ca: CertificateCollection,
                          password: string, name: string): Pkcs12;
        }
    }

    export namespace CMS {
        class SignedData {
            constructor();
            public getContent(): Buffer;
            public setContent(v: Buffer): void;
            public freeContent(): void;
            public getFlags(): number;
            public setFlags(v: number): void;
            public load(filename: string, dataFormat?: trusted.DataFormat): void;
            public import(raw: Buffer, dataFormat: trusted.DataFormat): void;
            public save(filename: string, dataFormat: trusted.DataFormat): void;
            public export(dataFormat: trusted.DataFormat): Buffer;
            public getCertificates(): PKI.CertificateCollection;
            public getSigners(): SignerCollection;
            public isDetached(): boolean;
            public createSigner(cert: PKI.Certificate, key: PKI.Key): Signer;
            public addCertificate(cert: PKI.Certificate): void;
            public verify(certs?: PKI.CertificateCollection): boolean;
            public sign(): void;
        }

        class SignerCollection {
            public items(index: number): Signer;
            public length(): number;
        }

        class Signer {
            public setCertificate(cert: PKI.Certificate): void;
            public getCertificate(): PKI.Certificate;
            public getSignature(): Buffer;
            public getSignatureAlgorithm(): PKI.Algorithm;
            public getDigestAlgorithm(): PKI.Algorithm;
            public getSignerId(): SignerId;
            public getSignedAttributes(): SignerAttributeCollection;
            public getUnsignedAttributes(): SignerAttributeCollection;
            public getSigningTime(): string;
            public verify(): boolean;
            public verifyContent(v: Buffer): boolean;
        }

        class SignerId {
            public getSerialNumber(): string;
            public getIssuerName(): string;
            public getKeyId(): string;
        }

        class SignerAttributeCollection {
            public length(): number;
            public push(attr: PKI.Attribute): void;
            public removeAt(index: number): void;
            public items(index: number): PKI.Attribute;
        }

        class CmsRecipientInfo {
            public getIssuerName(): string;
            public getSerialNumber(): Buffer;
            public ktriCertCmp(cert: PKI.Certificate): number;
        }

        class CmsRecipientInfoCollection {
            public length(): number;
            public push(ri: CmsRecipientInfo): void;
            public removeAt(index: number): void;
            public pop(): void;
            public items(index: number): CmsRecipientInfo;
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
            signatureDigestAlgorithm?: string;
            publicKeyAlgorithm?: string;
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

        abstract class Provider {
            public type: string;
        }

        /* tslint:disable-next-line:class-name */
        class Provider_System extends Provider {
            constructor(folder: string);
            public objectToPkiItem(pathr: string): IPkiItem;
        }

        class ProviderMicrosoft extends Provider {
            constructor();
            public getKey(cert: PKI.Certificate): PKI.Key;
            public hasPrivateKey(cert: PKI.Certificate): boolean;
        }

        class ProviderCryptopro extends Provider {
            constructor();
            public getKey(cert: PKI.Certificate): PKI.Key;
            public hasPrivateKey(cert: PKI.Certificate): boolean;
        }

        class ProviderTSL extends Provider {
            constructor(url: string);
        }

        class PkiStore {
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
            public findKey(filter: Filter): IPkiItem;

            /**
             * Возвращает объект из структуры
             */
            public getItem(item: PkiItem): any;

            public getCerts(): PKI.CertificateCollection;

            public addProvider(provider: Provider): void;

            public addCert(provider: Provider, category: string, cert: PKI.Certificate): string;
            public addCrl(provider: Provider, category: string, crl: PKI.CRL): string;
            public addKey(provider: Provider, key: PKI.Key, password: string): string;
            public addCsr(provider: Provider, category: string, csr: PKI.CertificationRequest): string;

            public deleteCert(provider: Provider, category: string, cert: PKI.Certificate): void;
        }

        class CashJson {
            public filenName: string;
            constructor(fileName: string);
            public save(fileName: string);
            public load(fileName: string);
            public export(): IPkiItem[];
            public import(items: IPkiItem[] | PkiItem);
        }

        class Filter {
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

        class PkiItem {
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
            public setSignatureAlgorithm(signatureAlgorithm: string): void;
            public setSignatureDigestAlgorithm(signatureDigestAlgorithm: string): void;
            public setPublicKeyAlgorithm(publicKeyAlgorithm: string): void;
        }
    }

    namespace UTILS {
        export interface IContainerName {
            container: string;
            unique: string;
            fqcnA: string;
            fqcnW: string;
        }

        class Jwt {
            public checkLicense(data?: string): number;
        }

        class Cerber {
            public sign(modulePath: string, cert: PKI.Certificate, key: PKI.Key): void;
            public verify(modulePath: string, cacerts?: PKI.CertificateCollection): object;
        }

        class Logger {
            public start(filename: string, level: trusted.LoggerLevel): void;
            public stop(): void;
            public clear(): void;
        }

        class Csp {
            public isGost2001CSPAvailable(): boolean;
            public isGost2012_256CSPAvailable(): boolean;
            public isGost2012_512CSPAvailable(): boolean;
            public checkCPCSPLicense(): boolean;
            public getCPCSPLicense(): string;
            public getCPCSPVersion(): string;
            public getCPCSPVersionPKZI(): string;
            public getCPCSPVersionSKZI(): string;
            public getCPCSPSecurityLvl(): string;
            public enumProviders(): object[];
            public enumContainers(type?: number, provName?: string): IContainerName[];
            public getCertifiacteFromContainer(contName: string, provType: number, provName?: string): PKI.Certificate;
            public getContainerNameByCertificate(cert: PKI.Certificate, category: string): string;
            public installCertifiacteFromContainer(contName: string, provType: number, provName?: string): void;
            public deleteContainer(contName: string, provType: number, provName?: string): void;
            public buildChain(cert: PKI.Certificate): PKI.CertificateCollection;
            public verifyCertificateChain(cert: PKI.Certificate): boolean;
            public isHaveExportablePrivateKey(cert: PKI.Certificate): boolean;
            public certToPkcs12(cert: PKI.Certificate, exportPrivateKey: boolean, password?: string): PKI.Pkcs12;
        }
    }

    namespace COMMON {
        class OpenSSL {
            public run(): void;
            public stop(): void;
            public printErrors(): string;
        }
    }
}
