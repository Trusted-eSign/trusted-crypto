"use strict";

var assert = require("assert");
var trusted = require("../index.js");
var fs = require("fs");

var DEFAULT_OUT_PATH = "test/out";

/**
* Check file exists
* @param  {string} filePath Path to file
* @returns {boolean} file exists?
*/
function checkFile(filePath) {
    try {
        return fs.statSync(filePath).isFile();
    } catch (err) {
        return false;
    }
}

before(function() {
    if (checkFile(DEFAULT_OUT_PATH + "/logger.txt")) {
        fs.unlinkSync(DEFAULT_OUT_PATH + "/logger.txt");
    }
});

describe("LOGGER", function() {
    var logger;

    it("start_static", function() {
        logger = trusted.utils.Logger.start(DEFAULT_OUT_PATH + "/logger.txt", trusted.LoggerLevel.ALL);

        assert.equal(fs.existsSync(DEFAULT_OUT_PATH + "/logger.txt"), true, "Log file not exists");
    });

    it("stop", function() {
        logger.stop();

        assert.equal(fs.statSync(DEFAULT_OUT_PATH + "/logger.txt").size > 0, true, "Empty log file");
    });

    it("clear", function() {
        logger.clear();

        assert.equal(fs.statSync(DEFAULT_OUT_PATH + "/logger.txt").size === 0, true, "Error clean log file");
    });

    it("start_new", function() {
        logger = new trusted.utils.Logger();
        logger.start(DEFAULT_OUT_PATH + "/logger.txt", trusted.LoggerLevel.ALL);

        assert.equal(fs.statSync(DEFAULT_OUT_PATH + "/logger.txt").size === 0, true, "Empty log file");
    });
});

