"use strict";

var assert = require("assert");
var fs = require("fs");
var trusted = require("../index.js");

describe("CSP", function() {
    it("csp", function () {
        var licence = trusted.utils.Csp.getCPCSPLicense();
        console.log(licence);
        var csp = trusted.utils.Csp.getCPCSPVersion();
        console.log("csp - " + csp);
    });
});
