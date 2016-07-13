import * as native from "../native";
import * as object from "../object";
import {DataFormat} from "../data_format";
import {PublicExponent} from "../public_exponent";

export class Key extends object.BaseObject<native.PKI.Key> {
    public static readPrivateKey(filename: string, format: DataFormat, password: string): Key {
        let key: Key = new Key();
        key.readPrivateKey.apply(key, arguments);
        return Key.wrap<native.PKI.Key, Key>(key.handle);
    }

    constructor();
    constructor(handle: native.PKI.Key);
    constructor(param?: any) {
        super();
        if (param instanceof native.PKI.Key) {
            this.handle = param;
        } else {
            this.handle = new native.PKI.Key();
        }
    }

    public generate(format: DataFormat, pubExp: PublicExponent, keySize: number, password: string): Key {
        return Key.wrap<native.PKI.Key, Key>(this.handle.generate(format, pubExp, keySize));
    }

    public readPrivateKey(filename: string, format: DataFormat, password: string): Key {
        return Key.wrap<native.PKI.Key, Key>(this.handle.readPrivateKey(filename, format, password));
    }

    public writePrivateKey(filename: string, format: DataFormat, password: string): any {
        return this.handle.writePrivateKey(filename, format, password);
    }

    public readPublicKey(filename: string, format: DataFormat): Key {
        return Key.wrap<native.PKI.Key, Key>(this.handle.readPublicKey(filename, format));
    }

    public writePublicKey(filename: string, format: DataFormat): any {
        return this.handle.writePublicKey(filename, format);
    }

    public compare(key: Key): number {
        let cmp: number = this.handle.compare(key.handle);
        if (cmp < 0) {
            return -1;
        }
        if (cmp > 0) {
            return 1;
        }

        return 0;
    }
}
