/// <reference path="../native.ts" />
/// <reference path="../object.ts" />

namespace trusted.pki {
    /**
     * Wrap X509_EXTENSION
     *
     * @export
     * @class Extension
     * @extends {BaseObject<native.PKI.Extension>}
     */
    export class Extension extends BaseObject<native.PKI.Extension> {
        /**
         * Creates an instance of Extension.
         * @param {native.PKI.OID} [oid]
         * @param {string} [value]
         * @memberof Extension
         */
        constructor(oid?: pki.Oid, value?: string) {
            super();
            if (oid && oid instanceof pki.Oid && value) {
                this.handle = new native.PKI.Extension(oid.handle, value);
            } else if (arguments[0] instanceof native.PKI.Extension) {
                this.handle = arguments[0];
            } else {
                this.handle = new native.PKI.Extension();
            }
        }

        /**
         * Return extension oid
         *
         * @readonly
         * @type {Oid}
         * @memberof Extension
         */
        get typeId(): Oid {
            return new Oid(this.handle.getTypeId());
        }

        /**
         * Set extension oid
         *
         * @memberof Extension
         */
        set typeId(oid: Oid) {
            this.handle.setTypeId(oid.handle);
        }

        /**
         * Get critical
         *
         * @type {boolean}
         * @memberof Extension
         */
        get critical(): boolean {
            return this.handle.getCritical();
        }

        /**
         * Set critical
         *
         * @memberof Extension
         */
        set critical(critical: boolean) {
            this.handle.setCritical(critical);
        }
    }
}
