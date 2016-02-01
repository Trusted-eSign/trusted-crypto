let native = require("../build/Release/trusted.node");

import {DataFormat} from "./data_format";
import {PublicExponent} from "./public_exponent";

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
    }
        
    export declare class CSR {
        constructor(name: string, key: PKI.Key, digest: string);
        save(filename: string, dataFormat: DataFormat): void;
        getEncoded(): Buffer;
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