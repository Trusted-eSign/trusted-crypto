/// <reference path="../native.ts" />
/// <reference path="../object.ts" />

namespace trusted.pkcs11 {
    export class Slot extends BaseObject<native.PKCS11.Slot> {
        constructor() {
            super();
            this.handle = new native.PKCS11.Slot();
        };

        public findToken(): string {
            return this.handle.findToken();
        }
    }
}
