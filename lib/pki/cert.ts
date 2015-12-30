import {native} from '../native'
import {BaseObject} from "../object"

export class Certificate extends BaseObject {

	constructor() {
		super();

		this.handle = new native.PKI.Certificate();
	}

	get version(): number {
		return this.handle.getVersion();
	}
    
	get serialNumber(): number {
		return this.handle.getSerialNumber();
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

	get notBefore() {
		return new Date(this.handle.getNotBefore());
	}

	get notAfter() {
		return new Date(this.handle.getNotAfter());
	}
    
    get thumbprint(){
        return this.handle.getThumbprint();
    }

	compare(cert: Certificate) {
		return this.handle.compare(cert.handle);
	}

	load(filename: string) {
		this.handle.load(filename);
	}
    
    static load(filename: string): Certificate {
        let cert = new Certificate();
		cert.handle.load(filename);
        return cert;
	}

	import(buffer: Buffer) {
		this.handle.import(buffer);
	}
    
    static import(buffer: Buffer): Certificate {
        let cert = new Certificate();
		cert.handle.import(buffer);
        return cert;
	}

	export() {
		return this.handle.export();
	}

	save(filename: string) {
		this.handle.save(filename);
	}

}