import * as native from "../native";
import * as object from "../object";
import * as fs  from "fs";
import * as request  from "request";
import * as async  from "async";

import {Certificate} from "./cert";
import {Crl} from "./crl";
import {PkiStore} from "../pkistore/pkistore";

/**
 * Download file
 *
 * @param {string} url Url to remote file
 * @param {string} path Path for save in local system
 * @param {Function} done callback function
 */
function download(url: string, path: string, done: Function): void {
    "use strict";

    let sendReq: any = request.get(url);

    sendReq.on("response", function (response) {
        switch (response.statusCode) {
            case 200:
                let stream = fs.createWriteStream(path);

                response.on("data", function (chunk) {
                    stream.write(chunk);
                }).on("end", function () {
                    stream.on("close", function () {
                        done(null, url, path);
                    });
                    stream.end();
                });

                break;
            default:
                done(new Error("Server responded with status code" + response.statusCode));
        }
    });

    sendReq.on("error", function (err) {
        fs.unlink(path);
        done(err.message);
    });
}

/**
 * Revocatiom provaider
 *
 * @export
 * @class Revocation
 * @extends {object.BaseObject<native.PKI.Revocation>}
 */
export class Revocation extends object.BaseObject<native.PKI.Revocation> {
    /**
     * Creates an instance of Revocation.
     *
     *
     * @memberOf Revocation
     */
    constructor() {
        super();
        this.handle = new native.PKI.Revocation();
    }

    /**
     *  Search crl for certificate in local store
     *
     * @param {Certificate} cert
     * @param {PkiStore} store Local store
     * @returns {*}
     *
     * @memberOf Revocation
     */
    public getCrlLocal(cert: Certificate, store: PkiStore): any {
        let res = this.handle.getCrlLocal(cert.handle, store.handle);
        if (res) {
            return Crl.wrap<native.PKI.CRL, Crl>(res);
        }
        return res;
    }

    /**
     * Return array of distribution points for certificate
     *
     * @param {Certificate} cert
     * @returns {Array<string>}
     *
     * @memberOf Revocation
     */
    public getCrlDistPoints(cert: Certificate): Array<string> {
        return this.handle.getCrlDistPoints(cert.handle);
    }

    /**
     * Check validate CRL time
     *
     * @param {Crl} crl
     * @returns {boolean}
     *
     * @memberOf Revocation
     */
    public checkCrlTime(crl: Crl): boolean {
        return this.handle.checkCrlTime(crl.handle);
    }

    /**
     * Download CRl
     *
     * @param {Array<string>} distPoints Distribution points
     * @param {string} pathForSave File path
     * @param {Function} done callback
     *
     * @memberOf Revocation
     */
    public downloadCRL(distPoints: Array<string>, pathForSave: string, done: Function): void {
        let crl = new Crl();
        let returnPath;

        try {
            async.forEachOf(distPoints, function (value, key, callback) {
                download(value, pathForSave + key, function (err, url, goodPath) {
                    if (err) {
                        return callback(err);
                    } else {
                        returnPath = goodPath;
                        callback();
                    }
                });
            }, function (err) {
                if (err) {
                    done(err.message, null);
                } else {
                    crl.load(returnPath);
                    done(null, crl);
                }
            });
        } catch (e) {
            done(e, null);
        }
    }
}
