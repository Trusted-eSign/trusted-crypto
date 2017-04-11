/// <reference path="../native.ts" />
/// <reference path="../object.ts" />

namespace trusted.pki {
    /**
     * Collection of Certificate
     *
     * @export
     * @class CertificateCollection
     * @extends {BaseObject<native.PKI.CertificateCollection>}
     * @implements {core.ICollectionWrite}
     */
    export class CertificateCollection extends BaseObject<native.PKI.CertificateCollection>
        implements core.ICollectionWrite {

        /**
         * Creates an instance of CertificateCollection.
         * @param {native.PKI.CertificateCollection} [param]
         *
         * @memberOf CertificateCollection
         */
        constructor(param?: native.PKI.CertificateCollection) {
            super();
            if (param instanceof native.PKI.CertificateCollection) {
                this.handle = param;
            } else {
                this.handle = new native.PKI.CertificateCollection();
            }
        }

        /**
         * Return element by index from collection
         *
         * @param {number} index
         * @returns {Certificate}
         *
         * @memberOf CertificateCollection
         */
        public items(index: number): Certificate {
            return Certificate.wrap<native.PKI.Certificate, Certificate>(this.handle.items(index));
        }

        /**
         * Return collection length
         *
         * @readonly
         * @type {number}
         * @memberOf CertificateCollection
         */
        get length(): number {
            return this.handle.length();
        }

        /**
         * Add new element to collection
         *
         * @param {Certificate} cert
         *
         * @memberOf CertificateCollection
         */
        public push(cert: Certificate): void {
            this.handle.push(cert.handle);
        }

        /**
         * Remove last element from collection
         *
         *
         * @memberOf CertificateCollection
         */
        public pop(): void {
            this.handle.pop();
        }

        /**
         * Remove element by index from collection
         *
         * @param {number} index
         *
         * @memberOf CertificateCollection
         */
        public removeAt(index: number): void {
            this.handle.removeAt(index);
        }
    }
}
