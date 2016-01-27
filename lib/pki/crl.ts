import * as native from "../native";
import * as object from "../object";
import {DataFormat} from "../data_format";

const DEFAULT_DATA_FORMAT = DataFormat.DER;

export class Crl extends object.BaseObject<native.PKI.CRL>{
	
	constructor();
	constructor(handle: native.PKI.CRL);
	constructor(param?){
		super();	
		if (param instanceof native.PKI.CRL){
            this.handle = param;            
        }
        else{
		  this.handle = new native.PKI.CRL();
        }
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
    
    get thumbprint(): string {
        return this.handle.getThumbprint().toString("hex");
    }
	
	load(filename: string, dataFormat: DataFormat = DEFAULT_DATA_FORMAT){
		this.handle.load(filename, dataFormat);
	}
    
    static load(filename: string, dataFormat: DataFormat = DEFAULT_DATA_FORMAT): Crl {
        let crl = new Crl();
		crl.load(filename, dataFormat);
        return crl;
	}
	
	import(buffer: Buffer, dataFormat: DataFormat = DEFAULT_DATA_FORMAT){
		this.handle.import(buffer, dataFormat);
	}
    
    static import(buffer: Buffer, dataFormat: DataFormat = DEFAULT_DATA_FORMAT): Crl {
        let crl = new Crl();
		crl.import(buffer, dataFormat);
        return crl;
	}
	
	export(dataFormat: DataFormat = DEFAULT_DATA_FORMAT){
		return this.handle.export(dataFormat);
	}
	
	save(filename: string, dataFormat: DataFormat = DEFAULT_DATA_FORMAT){
		this.handle.save(filename, dataFormat);
	}
         
    equals(crl: Crl): boolean {
        return this.handle.equals(crl.handle);
    }
    
     hash(algorithm: string = "sha1"): String {
        return this.handle.hash(algorithm).toString("hex");
    }
    
     duplicate(): Crl {
        let crl = new Crl(this.handle.duplicate());
        return crl;
    }
	
}