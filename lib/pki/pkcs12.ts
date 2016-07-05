import * as native from "../native";
import * as object from "../object";
import {Certificate} from "../pki/cert";
import {CertificateCollection} from "../pki/certs";
import {Key} from "../pki/key";

export class Pkcs12 extends object.BaseObject<native.PKI.Pkcs12> {
    /**
     * чтение сертификата из файла
     * @param filename Путь к файлу
     */
    public static load(filename: string): Pkcs12 {
        let p12: Pkcs12 = new Pkcs12();
        p12.handle.load(filename);
        return p12;
    }

    constructor();
    constructor(handle: native.PKI.Pkcs12);
    constructor(param?: any) {
        super();
        if (param instanceof native.PKI.Pkcs12) {
            this.handle = param;
        } else {
            this.handle = new native.PKI.Pkcs12();
        }
    }

    /**
     * возвращает  сертификат
     */
    public certificate(password: string): Certificate {
        return  Certificate.wrap<native.PKI.Certificate, Certificate>(this.handle.getCertificate(password));
    }

    /**
     * возвращает приватный ключ
     */
    public key(password: string): Key {
        return Key.wrap<native.PKI.Key, Key>(this.handle.getKey(password));
    }

    /**
     * возвращает цепочку сертификатов
     */
    public ca(password: string): CertificateCollection {
       let caCerts: CertificateCollection = new CertificateCollection(this.handle.getCACertificates(password));
       return caCerts;
    }

    /**
     * чтение pkcs12 из файла
     * @param filename Путь к файлу
     */
    public load(filename: string): void {
        this.handle.load(filename);
    }

    /**
     * сохранение pkcs12 в файл
     * @param filename Путь к файлу
     */
    public save(filename: string): void {
        this.handle.save(filename);
    }

    /**
     * Create PKCS12 structure
     * @param  {Certificate} cert
     * @param  {Key} key
     * @param  {CertificateCollection} ca
     * @param  {string} password
     * @param  {string} name
     * @returns Pkcs12
     */
    public create(cert: Certificate, key: Key, ca: CertificateCollection, password: string, name: string): Pkcs12 {
       let p12: Pkcs12 = new Pkcs12();
       p12.handle = this.handle.create(cert.handle, key.handle, ca ? ca.handle : undefined, password, name);
       return p12;
    }
}
