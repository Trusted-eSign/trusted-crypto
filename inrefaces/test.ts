import * as store from "./store";
import * as assert from "assert";
import {Certificate} from "../lib/pki/cert";
import {Key} from "../lib/pki/key";

describe("PkiStore", () => {

    it("Инициализация", () => {

        let pkiStore = new store.PkiStore();

        pkiStore.providers.push(new store.ProviderSystem("/path/to/folder"));
        pkiStore.providers.push(new store.ProviderMicrosoft());
        pkiStore.providers.push(new store.ProviderTSL("http://www.tsl.com/file"));
        assert.equal(pkiStore.providers.length, 3);

        assert.equal(pkiStore.providers[0].type, "system");
        assert.equal(pkiStore.providers[1].type, "microsoft");
        assert.equal(pkiStore.providers[2].type, "tsl");

    });

    it("Получение ключа для сертификата", () => {

        let pkiStore = new store.PkiStore();

        pkiStore.providers.push(new store.ProviderSystem("/path/to/folder"));
        assert.equal(pkiStore.providers.length, 1);

        // Поиск сертификатов
        let certs = pkiStore.find({
            type: ["CERTIFICATE"],
            category: ["MY"]
        });

        let certWithKey: Certificate;
        for (let i in certs) {
            let item = certs[i];
            if (item.keyId) {
                certWithKey = pkiStore.getItem(item);
            }
            assert.equal(item.type, "CERTIFICATE");
            if (item.type === "CERTIFICATE") {
                let cert: Certificate = pkiStore.getItem(item);
                assert.equal(cert instanceof Certificate, true);
                assert.equal(cert.subjectName.length > 0, true);
            }
        }
        assert.equal(!!certWithKey, true, "Отсутствует сертификат с привязкой к ключу");

        let key = pkiStore.findKey({
            type: ["CERTIFICATE"],
            provider: ["SYSTEM"],
            category: ["MY"],
            hash: certWithKey.thumbprint
        });
        assert.equal(!!key, true, "Отсутствует ключ для сертификата");

        let _key: Key = pkiStore.getItem(key)
        assert.equal(!!_key, true, "Проблема при чтении ключа");

    });

});