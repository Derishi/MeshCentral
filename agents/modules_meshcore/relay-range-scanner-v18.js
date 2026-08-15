"use strict";

var scanner;
try { scanner = require('relay-range-scanner-v17'); } catch (ex) { scanner = require('./relay-range-scanner-v17'); }

module.exports.parseRange = scanner.parseRange;

module.exports.scan = function (range, timeout, callback, options) {
    if (options == null) options = {};
    const setScanTimeout = options.setTimeout || setTimeout;
    const scannerOptions = Object.assign({}, options, {
        setTimeout: function (timeoutCallback, delay) {
            return setScanTimeout(timeoutCallback, Math.max(delay, 120000));
        }
    });
    return scanner.scan(range, timeout, callback, scannerOptions);
};