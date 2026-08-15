"use strict";

const MAX_SCAN_ADDRESSES = 1024;
const TCP_SCAN_CONCURRENCY = 32;
const PROGRESS_REPORT_INTERVAL = 8;
const activeChildren = [];

function parseIpv4Address(address) {
    if (typeof address != 'string') return null;
    const parts = address.split('.');
    if (parts.length != 4) return null;
    var value = 0;
    for (var i = 0; i < parts.length; i++) {
        if (!/^(0|[1-9][0-9]{0,2})$/.test(parts[i])) return null;
        const octet = parseInt(parts[i], 10);
        if (octet > 255) return null;
        value = (value * 256) + octet;
    }
    return value;
}

function addressFromNumber(value) {
    return Math.floor(value / 16777216) + '.' + Math.floor((value % 16777216) / 65536) + '.' + Math.floor((value % 65536) / 256) + '.' + (value % 256);
}

function parseRange(range) {
    if ((typeof range != 'string') || (range.length == 0) || (range.length > 64)) return null;
    var min = null, max = null;
    const rangeParts = range.split('-');
    if (rangeParts.length == 2) {
        min = parseIpv4Address(rangeParts[0]);
        max = parseIpv4Address(rangeParts[1]);
    } else {
        const cidrParts = range.split('/');
        if (cidrParts.length == 2) {
            const address = parseIpv4Address(cidrParts[0]);
            if (!/^(1[7-9]|2[0-9]|3[0-2])$/.test(cidrParts[1])) return null;
            const size = Math.pow(2, 32 - parseInt(cidrParts[1], 10));
            min = Math.floor(address / size) * size;
            max = min + size - 1;
        } else if (rangeParts.length == 1) {
            min = max = parseIpv4Address(range);
        }
    }
    if ((min == null) || (max == null) || (min > max) || ((max - min + 1) > MAX_SCAN_ADDRESSES)) return null;
    return { min: min, max: max };
}

module.exports.parseRange = parseRange;

module.exports.scan = function (range, timeout, callback, options) {
    const parsedRange = parseRange(range);
    if (parsedRange == null) return false;
    if (options == null) options = {};
    if ((options.platform || process.platform) != 'linux') { callback({}, 'Relay TCP scanning requires Linux.'); return true; }
    const childProcess = options.childProcess || require('child_process');
    const setScanTimeout = options.setTimeout || setTimeout;
    const results = {};
    const addresses = [];
    const reportedAddresses = {};
    var completed = false;
    var child = null;
    var output = '';
    var progressBuffer = '';
    var completedCount = 0;
    var reportedCount = 0;

    for (var address = parsedRange.min; address <= parsedRange.max; address++) { addresses.push(addressFromNumber(address)); }
    const total = addresses.length;
    const scanTimeout = Math.max(timeout, (Math.ceil(total / TCP_SCAN_CONCURRENCY) * 7000) + 10000);
    const script = "for ip in " + addresses.join(' ') + "; do echo \"$ip\"; done | xargs -r -n1 -P" + TCP_SCAN_CONCURRENCY + " bash -c 'if curl -k -sS --connect-timeout 3 --max-time 3 -o /dev/null https://$1:16993 2>/dev/null; then echo \"$1,1\"; elif curl -sS --connect-timeout 3 --max-time 3 -o /dev/null http://$1:16992 2>/dev/null; then echo \"$1,0\"; fi; echo \"P,$1\"' _";

    function reportProgress() {
        if ((typeof options.onProgress == 'function') && ((completedCount == total) || ((completedCount - reportedCount) >= PROGRESS_REPORT_INTERVAL))) {
            reportedCount = completedCount;
            try { options.onProgress(completedCount, total); } catch (ex) { }
        }
    }

    function processProgress(data) {
        progressBuffer += data.toString();
        const lines = progressBuffer.split(/\r?\n/);
        progressBuffer = lines.pop();
        for (var i = 0; i < lines.length; i++) {
            if (lines[i].startsWith('P,') == false) continue;
            const value = parseIpv4Address(lines[i].substring(2));
            if ((value == null) || (value < parsedRange.min) || (value > parsedRange.max) || (reportedAddresses[value] != null)) continue;
            reportedAddresses[value] = true;
            completedCount++;
            reportProgress();
        }
    }

    function complete(error) {
        if (completed) return;
        completed = true;
        const childIndex = activeChildren.indexOf(child);
        if (childIndex >= 0) activeChildren.splice(childIndex, 1);
        if ((options.mesh != null) && (options.mesh.amtRangeScanChild === child)) delete options.mesh.amtRangeScanChild;
        callback(results, error);
    }

    try {
        if (typeof options.onProgress == 'function') options.onProgress(0, total);
        child = childProcess.execFile('/bin/sh', ['sh']);
        activeChildren.push(child);
        if (options.mesh != null) options.mesh.amtRangeScanChild = child;
        child.stdout.on('data', function (data) { output += data.toString(); processProgress(data); });
        child.stderr.on('data', function () { });
        child.on('exit', function () {
            const lines = output.trim().split(/\r?\n/);
            for (var i = 0; i < lines.length; i++) {
                const parts = lines[i].split(',');
                if ((parts.length != 2) || (parseIpv4Address(parts[0]) == null) || ((parts[1] != '0') && (parts[1] != '1'))) continue;
                results[parts[0]] = { ver: 'Unknown', tls: parseInt(parts[1], 10), state: 2, hostname: parts[0], hosttype: 'addr' };
            }
            complete();
        });
        setScanTimeout(function () { try { child.kill(); } catch (ex) { } complete('The relay TCP scan timed out.'); }, scanTimeout);
        child.stdin.write(script + '\nexit\n');
    } catch (ex) {
        complete('The relay agent could not initialize the TCP scanner.');
    }
    return true;
};