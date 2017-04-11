/// <reference path="../native.ts" />
/// <reference path="../object.ts" />

namespace trusted.utils {
    const DEFAULT_LOGGER_LEVEL: LoggerLevel = LoggerLevel.ALL;

    /**
     * Wrap logger class
     *
     * @export
     * @class Logger
     * @extends {BaseObject<native.UTILS.Logger>}
     */
    export class Logger extends BaseObject<native.UTILS.Logger> {
        /**
         * Start write log to a file
         *
         * @static
         * @param {string} filename
         * @param {LoggerLevel} [level=DEFAULT_LOGGER_LEVEL]
         * @returns {Logger}
         *
         * @memberOf Logger
         */
        public static start(filename: string, level: LoggerLevel = DEFAULT_LOGGER_LEVEL): Logger {
            const logger = new Logger();
            logger.handle.start(filename, level);
            return logger;
        }

        /**
         * Creates an instance of Logger.
         *
         * @memberOf Logger
         */
        constructor() {
            super();
            this.handle = new native.UTILS.Logger();
        }

        /**
         * Start write log to a file
         *
         * @param {string} filename
         * @param {LoggerLevel} [level=DEFAULT_LOGGER_LEVEL]
         * @returns {void}
         *
         * @memberOf Logger
         */
        public start(filename: string, level: LoggerLevel = DEFAULT_LOGGER_LEVEL): void {
             return this.handle.start(filename, level);
        }

        /**
         * Stop write log file
         *
         * @returns {void}
         *
         * @memberOf Logger
         */
        public stop(): void {
            return this.handle.stop();
        }

        /**
         * Clean exsisting log file
         *
         * @returns {void}
         *
         * @memberOf Logger
         */
        public clear(): void {
            return this.handle.clear();
        }
    }
}
