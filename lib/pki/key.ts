import {native} from '../native'
import {BaseObject} from "../object"
import {DataFormat} from "../data_format";

const DEFAULT_DATA_FORMAT = DataFormat.PEM;

export class Key extends BaseObject{
	
	constructor(){
		super();	
		
		this.handle = new native.PKI.Key();
	}
    
    keypairGenerate(filename: string, format: DataFormat, keySize: Int32Array, password: string) {
		return this.handle.keypairGenerate(filename, format, keySize, password);
	}
    
    keypairGenerateMemory(format: DataFormat, keySize: Int32Array, password: string) {
		return this.handle.keypairGenerateMemory(format, keySize, password);
	}
    
    keypairGenerateBIO(format: DataFormat, keySize: Int32Array, password: string) {
		return this.handle.keypairGenerateBIO(format, keySize, password);
	}
    
    static privkeyLoad(filename: string, format: DataFormat, password: string) {
        var key = new Key();
		key.privkeyLoad.apply(key, arguments);
        return key;
	}
    
    privkeyLoad(filename: string, format: DataFormat, password: string) {
		return this.handle.privkeyLoad(filename, format, password);
	}
    
    privkeySave(filename: string, format: DataFormat, password: string) {
		return this.handle.privkeySave(filename, format, password);
	}
    
    pubkeyLoad(filename: string, format: DataFormat) {
		return this.handle.pubkeyLoad(filename, format);
	}
    
    pubkeySave(filename: string, format: DataFormat) {
		return this.handle.pubkeySave(filename, format);
	}
}