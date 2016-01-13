import {native} from "../native";
import {BaseObject} from "../object";
import {DataFormat} from "../data_format";

const DEFAULT_DATA_FORMAT = DataFormat.DER;

export class Certificate extends BaseObject {

    constructor() {
        super();

        this.handle = new native.PKI.Certificate();
    }

    get version(): number {
        return this.handle.getVersion();
    }

    get serialNumber(): string {
        return this.handle.getSerialNumber().toString("hex");
    }

    get type(): number {
        return this.handle.getType();
    }

    get keyUsage(): number {
        return this.handle.getKeyUsage();
    }

    get issuerFriendlyName(): string {
        return this.handle.getIssuerFriendlyName();
    }

    get issuerName(): string {
        return this.handle.getIssuerName();
    }

    get subjectFriendlyName(): string {
        return this.handle.getSubjectFriendlyName();
    }

    get subjectName(): string {
        return this.handle.getSubjectName();
    }

    get notBefore(): Date {
        return new Date(this.handle.getNotBefore());
    }

    get notAfter(): Date {
        return new Date(this.handle.getNotAfter());
    }

    get thumbprint(): string {
        return this.handle.getThumbprint().toString("hex");
    }

    compare(cert: Certificate): number {
        let cmp = this.handle.compare(cert.handle);
        if (cmp < 0)
            return -1;
        if (cmp > 0)
            return 1;
        return 0;
    }

    equals(cert: Certificate): boolean {
        return this.handle.equals(cert.handle);
    }

    hash(algorithm: string = "sha1"):String {
        return this.handle.hash(algorithm).toString("hex");
    }
    
    duplicate(): Certificate{
        let cert = new Certificate();
        cert.handle = this.handle.duplicate();
        return cert;
    }

    load(filename: string, format: DataFormat = DEFAULT_DATA_FORMAT) {
        this.handle.load(filename);
    }

    static load(filename: string, format: DataFormat = DEFAULT_DATA_FORMAT): Certificate {
        let cert = new Certificate();
        cert.handle.load(filename, format);
        return cert;
    }

    import(buffer: Buffer, format: DataFormat = DEFAULT_DATA_FORMAT) {
        this.handle.import(buffer, format);
    }

    static import(buffer: Buffer, format: DataFormat = DEFAULT_DATA_FORMAT): Certificate {
        let cert = new Certificate();
        cert.handle.import(buffer, format);
        return cert;
    }

    export(format: DataFormat = DEFAULT_DATA_FORMAT) {
        return this.handle.export(format);
    }

    save(filename: string, format: DataFormat = DEFAULT_DATA_FORMAT) {
        this.handle.save(filename, format);
    }

}