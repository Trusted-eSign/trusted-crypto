/// <reference path="../native.ts" />
/// <reference path="../object.ts" />

namespace trusted.utils {
    /**
     * cryptographic service provider (CSP) helper
     * Uses on WIN32 or with CPROCSP
     *
     * @export
     * @class Csp
     * @extends {BaseObject<native.UTILS.Csp>}
     */
    export class Csp extends BaseObject<native.UTILS.Csp> {
        /**
         * Check available provaider for GOST 2001
         *
         * @static
         * @returns {boolean}
         * @memberof Csp
         */
        public static isGost2001CSPAvailable(): boolean {
            const csp = new native.UTILS.Csp();
            return csp.isGost2001CSPAvailable();
        }

        /**
         * Check available provaider for GOST 2012-256
         *
         * @static
         * @returns {boolean}
         * @memberof Csp
         */
        public static isGost2012_256CSPAvailable(): boolean {
            const csp = new native.UTILS.Csp();
            return csp.isGost2012_256CSPAvailable();
        }

        /**
         * Check available provaider for GOST 2012-512
         *
         * @static
         * @returns {boolean}
         * @memberof Csp
         */
        public static isGost2012_512CSPAvailable(): boolean {
            const csp = new native.UTILS.Csp();
            return csp.isGost2012_512CSPAvailable();
        }

        /**
         * Verify license for CryptoPro CSP
         * Throw exception if provaider not available
         *
         * @static
         * @returns {boolean}
         * @memberof Csp
         */
        public static checkCPCSPLicense(): boolean {
            const csp = new native.UTILS.Csp();
            return csp.checkCPCSPLicense();
        }

        /**
         * Return instaled correct license for CryptoPro CSP
         * Throw exception if provaider not available
         *
         * @static
         * @returns {boolean}
         * @memberof Csp
         */
        public static getCPCSPLicense(): string {
            const csp = new native.UTILS.Csp();
            return csp.getCPCSPLicense();
        }

        /**
         * Return instaled correct version for CryptoPro CSP
         * Throw exception if provaider not available
         *
         * @static
         * @returns {boolean}
         * @memberof Csp
         */
        public static getCPCSPVersion(): string {
            const csp = new native.UTILS.Csp();
            return csp.getCPCSPVersion();
        }

        public static getCPCSPVersionPKZI(): string {
            const csp = new native.UTILS.Csp();
            return csp.getCPCSPVersionPKZI();
        }

        public static getCPCSPVersionSKZI(): string {
            const csp = new native.UTILS.Csp();
            return csp.getCPCSPVersionSKZI();
        }

        public static getCPCSPSecurityLvl(): string {
            const csp = new native.UTILS.Csp();
            return csp.getCPCSPSecurityLvl();
        }

        /**
         * Enumerate available CSP
         *
         * @static
         * @returns {object[]} {type: nuber, name: string}
         * @memberof Csp
         */
        public static enumProviders(): object[] {
            const csp = new native.UTILS.Csp();
            return csp.enumProviders();
        }

        /**
         * Enumerate conainers
         *
         * @static
         * @param {number} [type]
         * @returns {string[]} Fully Qualified Container Name
         * @memberof Csp
         */
        public static enumContainers(type: null, provName = ""): native.UTILS.IContainerName[] {
            const csp = new native.UTILS.Csp();
            return csp.enumContainers(type, provName);
        }

        /**
         * Get certificate by container and provider props
         *
         * @static
         * @param {string} contName
         * @param {number} provType
         * @param {string} [provName=""]
         * @returns {pki.Certificate}
         * @memberof Csp
         */
        public static getCertifiacteFromContainer(contName: string, provType: number, provName = ""): pki.Certificate {
            const cert: pki.Certificate = new pki.Certificate();
            const csp = new native.UTILS.Csp();
            cert.handle = csp.getCertifiacteFromContainer(contName, provType, provName);
            return cert;
        }

        public static installCertifiacteFromContainer(contName: string, provType: number, provName = ""): void {
            const csp = new native.UTILS.Csp();
            csp.installCertifiacteFromContainer(contName, provType, provName);
            return;
        }

        public static installCertifiacteToContainer(cert: pki.Certificate, contName: string,
                                                    provType: number, provName = ""): void {
            const csp = new native.UTILS.Csp();
            csp.installCertifiacteToContainer(cert.handle, contName, provType, provName);
            return;
        }

        public static deleteContainer(contName: string, provType: number, provName = ""): void {
            const csp = new native.UTILS.Csp();
            csp.deleteContainer(contName, provType, provName);
            return;
        }

        /**
         * Get container name by certificate
         *
         * @static
         * @param {pki.Certificate} cert
         * @param {string} [category="MY"]
         * @returns {string}
         * @memberof Csp
         */
        public static getContainerNameByCertificate(cert: pki.Certificate, category: string = "MY"): string {
            const csp = new native.UTILS.Csp();
            return csp.getContainerNameByCertificate(cert.handle, category);
        }

        public static buildChain(cert: pki.Certificate): pki.CertificateCollection {
            const csp = new native.UTILS.Csp();

            const certscol: pki.CertificateCollection =
                new pki.CertificateCollection(csp.buildChain(cert.handle));

            return certscol;
        }

        public static verifyCertificateChain(cert: pki.Certificate): boolean {
            const csp = new native.UTILS.Csp();
            return csp.verifyCertificateChain(cert.handle);
        }

        /**
         * Find certificate in MY store and check that private key exportable
         *
         * @static
         * @param {pki.Certificate} cert
         * @returns {boolean}
         * @memberof Csp
         */
        public static isHaveExportablePrivateKey(cert: pki.Certificate): boolean {
            const csp = new native.UTILS.Csp();
            return csp.isHaveExportablePrivateKey(cert.handle);
        }

        /**
         * Create Pkcs by cert
         * NOTE:  only for certificates with exportable key. Check it by isHaveExportablePrivateKey
         *
         * @static
         * @param {pki.Certificate} cert
         * @param {boolean} exportPrivateKey
         * @param {string} [password]
         * @returns {pki.Pkcs12}
         * @memberof Csp
         */
        public static certToPkcs12(cert: pki.Certificate, exportPrivateKey: boolean, password?: string): pki.Pkcs12 {
            const csp = new native.UTILS.Csp();

            return pki.Pkcs12.wrap<native.PKI.Pkcs12, pki.Pkcs12>
                (csp.certToPkcs12(cert.handle, exportPrivateKey, password));
        }

        /**
         * Import PFX to store
         *
         * @static
         * @param {pki.Pkcs12} p12
         * @param {string} [password]
         * @returns {void}
         * @memberof Csp
         */
        public static importPkcs12(p12: pki.Pkcs12, password?: string): void {
            const csp = new native.UTILS.Csp();

            csp.importPkcs12(p12.handle, password);
            return;
        }

        /**
         * Creates an instance of Csp.
         *
         *
         * @memberOf Csp
         */
        constructor() {
            super();
            this.handle = new native.UTILS.Csp();
        }
    }
}
