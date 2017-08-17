/// <reference path="../native.ts" />
/// <reference path="../object.ts" />
/* tslint:disable:max-classes-per-file */

namespace trusted.pkistore {
    /**
     * Filter for search objects
     *
     * @export
     * @class Filter
     * @extends {BaseObject<native.PKISTORE.Filter>}
     * @implements {native.PKISTORE.IFilter}
     */
    export class Filter extends BaseObject<native.PKISTORE.Filter> implements native.PKISTORE.IFilter {
        constructor() {
            super();
            this.handle = new native.PKISTORE.Filter();
        }

        set types(type: string) {
            this.handle.setType(type);
        }

        set providers(provider: string) {
            this.handle.setProvider(provider);
        }

        set categorys(category: string) {
            this.handle.setCategory(category);
        }

        set hash(hash: string) {
            this.handle.setHash(hash);
        }

        set subjectName(subjectName: string) {
            this.handle.setSubjectName(subjectName);
        }

        set subjectFriendlyName(subjectFriendlyName: string) {
            this.handle.setSubjectFriendlyName(subjectFriendlyName);
        }

        set issuerName(issuerName: string) {
            this.handle.setIssuerName(issuerName);
        }

        set issuerFriendlyName(issuerFriendlyName: string) {
            this.handle.setIssuerFriendlyName(issuerFriendlyName);
        }

        set serial(serial: string) {
            this.handle.setSerial(serial);
        }
    }

    /**
     * Wrap pki objects (certificate, key, crl, csr)
     *
     * @export
     * @class PkiItem
     * @extends {BaseObject<native.PKISTORE.PkiItem>}
     * @implements {native.PKISTORE.IPkiItem}
     */
    export class PkiItem extends BaseObject<native.PKISTORE.PkiItem> implements native.PKISTORE.IPkiItem {
        /**
         * Creates an instance of PkiItem.
         *
         *
         * @memberOf PkiItem
         */
        constructor() {
            super();
            this.handle = new native.PKISTORE.PkiItem();
        }

        set format(format: string) {
            this.handle.setFormat(format);
        }

        set type(type: string) {
            this.handle.setType(type);
        }

        set provider(provider: string) {
            this.handle.setProvider(provider);
        }

        set category(category: string) {
            this.handle.setCategory(category);
        }

        set uri(uri: string) {
            this.handle.setURI(uri);
        }

        set hash(hash: string) {
            this.handle.setHash(hash);
        }

        set subjectName(subjectName: string) {
            this.handle.setSubjectName(subjectName);
        }

        set subjectFriendlyName(subjectFriendlyName: string) {
            this.handle.setSubjectFriendlyName(subjectFriendlyName);
        }

        set issuerName(issuerName: string) {
            this.handle.setIssuerName(issuerName);
        }

        set issuerFriendlyName(issuerFriendlyName: string) {
            this.handle.setIssuerFriendlyName(issuerFriendlyName);
        }

        set serial(serial: string) {
            this.handle.setSerial(serial);
        }

        set notBefore(before: string) {
            this.handle.setNotBefore(before);
        }

        set notAfter(after: string) {
            this.handle.setNotAfter(after);
        }

        set lastUpdate(lastUpdate: string) {
            this.handle.setLastUpdate(lastUpdate);
        }

        set nextUpdate(nextUpdate: string) {
            this.handle.setNextUpdate(nextUpdate);
        }

        set key(key: string) {
            this.handle.setKey(key);
        }

        set keyEnc(enc: boolean) {
            this.handle.setKeyEncrypted(enc);
        }

        set organizationName(organizationName: string) {
            this.handle.setOrganizationName(organizationName);
        }

        set signatureAlgorithm(signatureAlgorithm: string) {
            this.handle.setSignatureAlgorithm(signatureAlgorithm);
        }
    }

    export class PkiStore extends BaseObject<native.PKISTORE.PkiStore> {
        private cashJson: CashJson;

        /**
         * Creates an instance of PkiStore.
         * @param {(native.PKISTORE.PkiStore | string)} param
         *
         * @memberOf PkiStore
         */
        constructor(param: native.PKISTORE.PkiStore | string) {
            super();
            if (typeof (param) === "string") {
                this.handle = new native.PKISTORE.PkiStore(param);
                this.cashJson = new CashJson(param);
            } else if (param instanceof native.PKISTORE.PkiStore) {
                this.handle = param;
            } else {
                throw new TypeError("PkiStore::constructor: Wrong input param");
            }
        }

        /**
         * Return cash json
         *
         * @readonly
         * @type {CashJson}
         * @memberOf PkiStore
         */
        get cash(): CashJson {
            return this.cashJson;
        }

        /**
         * Add provider (system, microsoft | cryptopro)
         *
         * @param {native.PKISTORE.Provider} provider
         *
         * @memberOf PkiStore
         */
        public addProvider(provider: native.PKISTORE.Provider): void {
            this.handle.addProvider(provider);
        }

        /**
         * Import certificste to local store
         *
         * @param {native.PKISTORE.Provider} provider SYSTEM, MICROSOFT, CRYPTOPRO
         * @param {string} category MY, OTHERS, TRUST, CRL
         * @param {Certificate} cert Certificate
         * @param {number} flags
         * @returns {string}
         *
         * @memberOf PkiStore
         */
        public addCert(provider: native.PKISTORE.Provider, category: string,
                       cert: pki.Certificate, flags: number): string {
            return this.handle.addCert(provider, category, cert.handle, flags);
        }

        /**
         * Import CRL to local store
         *
         * @param {native.PKISTORE.Provider} provider SYSTEM, MICROSOFT, CRYPTOPRO
         * @param {string} category MY, OTHERS, TRUST, CRL
         * @param {Crl} crl CRL
         * @param {number} flags
         * @returns {string}
         *
         * @memberOf PkiStore
         */
        public addCrl(provider: native.PKISTORE.Provider, category: string, crl: pki.Crl, flags: number): string {
            return this.handle.addCrl(provider, category, crl.handle, flags);
        }

        /**
         * Import key to local store
         *
         * @param {native.PKISTORE.Provider} provider SYSTEM, MICROSOFT, CRYPTOPRO
         * @param {Key} key
         * @param {string} password
         * @returns {string}
         *
         * @memberOf PkiStore
         */
        public addKey(provider: native.PKISTORE.Provider, key: pki.Key, password: string): string {
            return this.handle.addKey(provider, key.handle, password);
        }

        /**
         * Import certificate request to local store
         *
         * @param {native.PKISTORE.Provider} provider SYSTEM, MICROSOFT, CRYPTOPRO
         * @param {string} category MY, OTHERS, TRUST, CRL
         * @param {CertificationRequest} csr
         * @returns {string}
         *
         * @memberOf PkiStore
         */
        public addCsr(provider: native.PKISTORE.Provider, category: string, csr: pki.CertificationRequest): string {
            return this.handle.addCsr(provider, category, csr.handle);
        }

        /**
         * Find items in local store
         *
         * @param {native.PKISTORE.IFilter} [ifilter]
         * @returns {native.PKISTORE.IPkiItem[]}
         *
         * @memberOf PkiStore
         */
        public find(ifilter?: native.PKISTORE.IFilter): native.PKISTORE.IPkiItem[] {
            const filter: Filter = new Filter();

            if (!ifilter) {
                return this.handle.find(filter.handle);
            }

            if (ifilter.type) {
                for (const type of ifilter.type) {
                    filter.types = type;
                }
            }

            if (ifilter.provider) {
                for (const provider of ifilter.provider) {
                    filter.providers = provider;
                }
            }

            if (ifilter.category) {
                for (const category of ifilter.category) {
                    filter.categorys = category;
                }
            }

            if (ifilter.hash) {
                filter.hash = ifilter.hash;
            }

            if (ifilter.subjectName) {
                filter.subjectName = ifilter.subjectName;
            }

            if (ifilter.subjectFriendlyName) {
                filter.subjectFriendlyName = ifilter.subjectFriendlyName;
            }

            if (ifilter.issuerName) {
                filter.issuerName = ifilter.issuerName;
            }

            if (ifilter.issuerFriendlyName) {
                filter.issuerFriendlyName = ifilter.issuerFriendlyName;
            }

            if (ifilter.serial) {
                filter.serial = ifilter.serial;
            }

            return this.handle.find(filter.handle);
        }

        /**
         * Find key in local store
         *
         * @param {native.PKISTORE.IFilter} ifilter
         * @returns {native.PKISTORE.IPkiItem}
         *
         * @memberOf PkiStore
         */
        public findKey(ifilter: native.PKISTORE.IFilter): native.PKISTORE.IPkiItem {
            const filter: Filter = new Filter();

            if (ifilter.type) {
                for (const type of ifilter.type) {
                    filter.types = type;
                }
            }

            if (ifilter.provider) {
                for (const provider of ifilter.provider) {
                    filter.providers = provider;
                }
            }

            if (ifilter.category) {
                for (const category of ifilter.category) {
                    filter.categorys = category;
                }
            }

            if (ifilter.hash) {
                filter.hash = ifilter.hash;
            }

            if (ifilter.subjectName) {
                filter.subjectName = ifilter.subjectName;
            }

            if (ifilter.subjectFriendlyName) {
                filter.subjectFriendlyName = ifilter.subjectFriendlyName;
            }

            if (ifilter.issuerName) {
                filter.issuerName = ifilter.issuerName;
            }

            if (ifilter.issuerFriendlyName) {
                filter.issuerFriendlyName = ifilter.issuerFriendlyName;
            }

            if (ifilter.serial) {
                filter.serial = ifilter.serial;
            }

            return this.handle.findKey(filter.handle);
        }

        /**
         * Return pki object (certificate, crl, request, key) by PkiItem
         *
         * @param {native.PKISTORE.IPkiItem} item
         * @returns {*}
         *
         * @memberOf PkiStore
         */
        public getItem(item: native.PKISTORE.IPkiItem): any {
            const pkiItem: PkiItem = new PkiItem();

            pkiItem.format = item.format;
            pkiItem.type = item.type;
            pkiItem.category = item.category;
            pkiItem.provider = item.provider;
            pkiItem.uri = item.uri;
            pkiItem.hash = item.hash;
            if (item.subjectName) {
                pkiItem.subjectName = item.subjectName;
            }
            if (item.subjectFriendlyName) {
                pkiItem.subjectFriendlyName = item.subjectFriendlyName;
            }
            if (item.issuerName) {
                pkiItem.issuerName = item.issuerName;
            }
            if (item.issuerFriendlyName) {
                pkiItem.issuerFriendlyName = item.issuerFriendlyName;
            }
            if (item.serial) {
                pkiItem.serial = item.serial;
            }
            if (item.notBefore) {
                pkiItem.notBefore = item.notBefore;
            }
            if (item.notAfter) {
                pkiItem.notAfter = item.notAfter;
            }
            if (item.lastUpdate) {
                pkiItem.lastUpdate = item.lastUpdate;
            }
            if (item.nextUpdate) {
                pkiItem.nextUpdate = item.nextUpdate;
            }
            if (item.key) {
                pkiItem.key = item.key;
            }
            if (item.encrypted) {
                pkiItem.keyEnc = item.encrypted;
            }
            if (item.organizationName) {
                pkiItem.organizationName = item.organizationName;
            }
            if (item.signatureAlgorithm) {
                pkiItem.signatureAlgorithm = item.signatureAlgorithm;
            }

            if (item.type === "CERTIFICATE") {
                return pki.Certificate.wrap<native.PKI.Certificate, pki.Certificate>
                    (this.handle.getItem(pkiItem.handle));
            }

            if (item.type === "CRL") {
                return pki.Crl.wrap<native.PKI.CRL, pki.Crl>(this.handle.getItem(pkiItem.handle));
            }

            if (item.type === "REQUEST") {
                return pki.CertificationRequest.wrap<native.PKI.CertificationRequest,
                    pki.CertificationRequest>(this.handle.getItem(pkiItem.handle));
            }

            if (item.type === "KEY") {
                return pki.Key.wrap<native.PKI.Key, pki.Key>(this.handle.getItem(pkiItem.handle));
            }
        }

        public get certs(): pki.CertificateCollection {
            return new pki.CertificateCollection(this.handle.getCerts());
        }
    }
}
