import {native} from '../native'
import {BaseObject} from "../object"

export class Crl extends BaseObject{
	
	constructor(){
		super();	
		
		this.handle = new native.PKI.CRL();
	}
	
	get version(): number{
		return this.handle.getVersion();
	}
	
	get issuerName(): string{
		return this.handle.getIssuerName();
	}
	
	get lastUpdate(){
		return new Date(this.handle.getLastUpdate());
	}
	
	get nextUpdate(){
		return new Date(this.handle.getNextUpdate());
	}
	
	load(filename: string){
		this.handle.load(filename);
	}
    
    static load(filename: string): Crl {
        let crl = new Crl();
		crl.handle.load(filename);
        return crl;
	}
	
	import(buffer: Buffer){
		this.handle.import(buffer);
	}
    
    static import(buffer: Buffer): Crl {
        let crl = new Crl();
		crl.handle.import(buffer);
        return crl;
	}
	
	export(){
		return this.handle.export();
	}
	
	save(filename: string){
		this.handle.save(filename);
	}
	
}