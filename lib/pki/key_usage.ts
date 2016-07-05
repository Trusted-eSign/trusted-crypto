/**
 * Предназначение (применимость) ключа
 */
export enum KeyUsageFlags {
    DigitalSignature = 0x0080,
    NonRepudiation = 0x0040,
    KeyEncipherment = 0x0020,
    DataEncipherment = 0x0010,
    KeyAgreement = 0x0008,
    KeyCertSign = 0x0004,
    CrlSign = 0x0002,
    EncipherOnly = 0x0001,
    DecipherOnly = 0x8000
}
