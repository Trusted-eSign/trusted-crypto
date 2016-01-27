import * as native from "../native";
import * as object from "../object";
import {DataFormat} from "../data_format";
import {PublicExponent} from "../public_exponent";

const DEFAULT_DATA_FORMAT = DataFormat.PEM;

export class Key extends object.BaseObject<native.PKI.Key>{

    constructor();
    constructor(handle: native.PKI.Key);
    constructor(param?) {
        super();
        if (param instanceof native.PKI.Key) {
            this.handle = param;
        }
        else
            this.handle = new native.PKI.Key();
    }

    keypairGenerate(filename: string, format: DataFormat, pubExp: PublicExponent, keySize: number, password: string) {
        return this.handle.keypairGenerate(filename, format, pubExp, keySize, password);
    }

    keypairGenerateMemory(format: DataFormat, pubExp: PublicExponent, keySize: number, password: string) {
        return this.handle.keypairGenerateMemory(format, pubExp, keySize, password);
    }

    keypairGenerateBIO(format: DataFormat, pubExp: PublicExponent, keySize: number, password: string) {
        return this.handle.keypairGenerateBIO(format, pubExp, keySize, password);
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