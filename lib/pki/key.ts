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

    generate(format: DataFormat, pubExp: PublicExponent, keySize: number, password: string) {
        return Key.wrap<native.PKI.Key, Key>(this.handle.generate(format, pubExp, keySize));
    }

    static readPrivateKey(filename: string, format: DataFormat, password: string) {
        let key = new Key();
        key.readPrivateKey.apply(key, arguments);
        return Key.wrap<native.PKI.Key, Key>(key.handle);
    }

    readPrivateKey(filename: string, format: DataFormat, password: string) {
        return Key.wrap<native.PKI.Key, Key>(this.handle.readPrivateKey(filename, format, password));
    }

    writePrivateKey(filename: string, format: DataFormat, password: string) {
        return this.handle.writePrivateKey(filename, format, password);
    }

    readPublicKey(filename: string, format: DataFormat) {
        return Key.wrap<native.PKI.Key, Key>(this.handle.readPublicKey(filename, format));
    }

    writePublicKey(filename: string, format: DataFormat) {
        return this.handle.writePublicKey(filename, format);
    }

    compare(key: Key): number {
        let cmp = this.handle.compare(key.handle);
        if (cmp < 0)
            return -1;
        if (cmp > 0)
            return 1;
        return 0;
    }
}