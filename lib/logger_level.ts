namespace trusted {

    /**
     *
     * @export
     * @enum {number}
     */
    export enum LoggerLevel {
        NULL = 0,
        ERROR = 1,
        WARNING = 2,
        INFO = 4,
        DEBUG = 8,
        TRACE = 16,
        OPENSSL = 32,
        ALL = ERROR | WARNING | INFO | DEBUG | TRACE | OPENSSL
    }
}
