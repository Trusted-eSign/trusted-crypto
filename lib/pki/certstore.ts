import * as native from "../native";
import * as object from "../object";

export class CertStore extends object.BaseObject<native.PKI.CertStore>{
	
	constructor();
	constructor(handle: native.PKI.CertStore);
	constructor(param?){
		super();
        
        if (param instanceof native.PKI.CertStore){
            this.handle = param;
        }	
		this.handle = new native.PKI.CertStore();
	}
       
    addCertStore(pvdType: string, pvdURI: string){
        return this.handle.addCertStore(pvdType, pvdURI);
    }
    
   removeCertStore(pvdType: string){
        return this.handle.removeCertStore(pvdType);
    }
    
    createCache(cacheURI: string) {
		return this.handle.createCache(cacheURI);
	}
    
    addCacheSection(cacheURI: string, pvdType: string) {
		return this.handle.addCacheSection(cacheURI, pvdType);
	}
    
    get listCertStore(): string {
        return this.handle.getCertStore();
    }
    
    getPrvTypePresent(pvdType: string): boolean {
        return this.handle.getPrvTypePresent(pvdType);
    }
}