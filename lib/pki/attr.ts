/// <reference path="../native.ts" />
/// <reference path="../object.ts" />

namespace trusted.pki {

    /**
     * Wrap X509_ATTRIBUTE
     *
     * @export
     * @class Attribute
     * @extends {BaseObject<native.PKI.Attribute>}
     */
    export class Attribute extends BaseObject<native.PKI.Attribute> {

        /**
         * Creates an instance of Attribute.
         * @param {native.PKI.Attribute} [param]
         *
         * @memberOf Attribute
         */
        constructor(param?: native.PKI.Attribute) {
            super();
            if (param instanceof native.PKI.Attribute) {
                this.handle = param;
            } else {
                this.handle = new native.PKI.Attribute();
            }
        }

        /**
         * Return ASN1 type of attribute
         *
         * @type {number}
         * @memberOf Attribute
         */
        get asnType(): number {
            return this.handle.getAsnType();
        }

        /**
         * Set ASN1 type
         *
         * @param {number} value ASN1 type
         *
         * @memberOf Attribute
         */
        set asnType(value: number) {
            this.handle.setAsnType(value);
        }

        /**
         * Return attribute OID
         *
         * @type {Oid}
         * @memberOf Attribute
         */
        get typeId(): Oid {
            return new Oid(this.handle.getTypeId());
        }

        /**
         * Set attribute OID
         *
         * @param {Oid} oid
         *
         * @memberOf Attribute
         */
        set typeId(oid: Oid) {
            this.handle.setTypeId(oid.handle);
        }

        /**
         * Return attribute duplicat
         *
         * @returns {Attribute}
         *
         * @memberOf Attribute
         */
        public duplicate(): Attribute {
            const nattr: any = this.handle.duplicate();
            const attr: Attribute = Attribute.wrap<native.PKI.Attribute, Attribute>(nattr);

            return attr;
        }

        /**
         * Return attribute in DER
         *
         * @returns {*}
         *
         * @memberOf Attribute
         */
        public export(): any {
            return this.handle.export();
        }

        /**
         * Return attribute by index
         *
         * @param {number} index
         * @returns {Buffer}
         *
         * @memberOf Attribute
         */
        public values(index: number): Buffer;

        /**
         * Return attributes collection
         *
         * @returns {AttributeValueCollection}
         *
         * @memberOf Attribute
         */
        public values(): AttributeValueCollection;

        /**
         * Return attributes collection or attribute by index (if request)
         *
         * @param {number} [index]
         * @returns {*}
         *
         * @memberOf Attribute
         */
        public values(index?: number): any {
            const vals: any = this.handle.values();
            const attrVals: AttributeValueCollection =
                AttributeValueCollection.wrap<native.PKI.AttributeValueCollection, AttributeValueCollection>(vals);

            if (index === undefined) {
                return attrVals;
            } else {
                return attrVals.items(index);
            }
        }
    }
}
