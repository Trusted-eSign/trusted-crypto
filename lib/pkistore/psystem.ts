namespace trusted.pkistore {

    /* tslint:disable:class-name */
    /**
     * Native crypto provider (work in local folders)
     *
     * @export
     * @class Provider_System
     * @extends {BaseObject<native.PKISTORE.Provider_System>}
     */
    export class Provider_System extends BaseObject<native.PKISTORE.Provider_System> {
        /**
         * Creates an instance of Provider_System.
         *
         * @param {string} folder Path
         *
         * @memberOf Provider_System
         */
        constructor(folder: string) {
            super();
            this.handle = new native.PKISTORE.Provider_System(folder);
        }

        /**
         * Return PkiItem for pki object
         *
         * @param {string} path
         * @returns {native.PKISTORE.IPkiItem}
         *
         * @memberOf Provider_System
         */
        public objectToPkiItem(path: string): native.PKISTORE.IPkiItem {
            return this.handle.objectToPkiItem(path);
        }
    }

}