import * as native from "../native";
import * as object from "../object";
import {ICollection} from "../core/collection";
import {Attribute} from "../pki/attr";

/**
 * Collection of SignerAttribute
 *
 * @export
 * @class SignerAttributeCollection
 * @extends {object.BaseObject<native.CMS.SignerAttributeCollection>}
 * @implements {ICollection}
 */
export class SignerAttributeCollection extends object.BaseObject<native.CMS.SignerAttributeCollection>
 implements ICollection {
    /**
     * Creates an instance of SignerAttributeCollection.
     *
     * @param {native.CMS.SignerAttributeCollection} nativeSigner
     *
     * @memberOf SignerAttributeCollection
     */
    constructor(nativeSigner: native.CMS.SignerAttributeCollection) {
        super();

        this.handle = nativeSigner;
    }

    /**
     * Return collection length
     *
     * @readonly
     * @type {number}
     * @memberOf SignerAttributeCollection
     */
    get length(): number {
        return this.handle.length();
    }

    /**
     * Add new element to collection
     *
     * @param {Attribute} attr
     *
     * @memberOf SignerAttributeCollection
     */
    public push(attr: Attribute): void {
        this.handle.push(attr.handle);
    }

    /**
     * Remove element by index from collection
     *
     * @param {number} index
     *
     * @memberOf SignerAttributeCollection
     */
    public removeAt(index: number): void {
        this.handle.removeAt(index);
    }

    /**
     * Return element by index from collection
     *
     * @param {number} index
     * @returns {Attribute}
     *
     * @memberOf SignerAttributeCollection
     */
    public items(index: number): Attribute {
        return new Attribute(this.handle.items(index));
    }
}
