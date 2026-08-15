"use strict";

const MAX_SCAN_ADDRESSES = 1024;
const SCAN_BATCH_SIZE = 10;
const SCAN_BATCH_INTERVAL = 10;
const TCP_SCAN_CONCURRENCY = 16;
const TCP_SCAN_TIMEOUT = 1000;

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

function ipv4NumberToString(value) {
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

function parseResponse(data, address, results) {
    if ((data == null) || (data.length < 22)) return;
    if (((data[12] == 0) || (data[13] != 0) || (data[14] != 1) || (data[15] != 0x57)) && (data[21] & 32)) {
        const state = data[19] & 0x03;
        if (state > 2) return;
        const port = (data[16] * 256) + data[17];
        results[address] = { ver: (data[18] >> 4) + '.' + (data[18] & 0x0F), tls: ((port == 16993) || ((data[19] & 0x04) != 0)) ? 1 : 0, state: state, hostname: address, hosttype: 'addr' };
    }
}

module.exports.parseRange = parseRange;

module.exports.scan = function (range, timeout, callback, options) {
    const parsedRange = parseRange(range);
    if (parsedRange == null) return false;
    if (options == null) options = {};
    const dgram = options.dgram || require('dgram');
    const setScanTimeout = options.setTimeout || setTimeout;
    const setScanInterval = options.setInterval || setInterval;
    const clearScanInterval = options.clearInterval || clearInterval;
    const socket = dgram.createSocket({ type: 'udp4' });
    const results = {};
    const packet = Buffer.from('06000006000011BE80000000', 'hex');
    var completed = false;
    var nextAddress = parsedRange.min;
    var sendTimer = null;
    var tcpFallbackStarted = false;

    function complete(error) {
        if (completed) return;
        completed = true;
        if (sendTimer != null) { clearScanInterval(sendTimer); sendTimer = null; }
        try { socket.close(); } catch (ex) { }
        callback(results, error);
    }

    function startTcpFallback() {
        tcpFallbackStarted = true;
        if (sendTimer != null) { clearScanInterval(sendTimer); sendTimer = null; }
        try { socket.close(); } catch (ex) { }
        var net;
        try { net = options.net || require('net'); } catch (ex) { complete('The relay agent could not load the TCP scanner.'); return; }
        var tcpNextAddress = parsedRange.min;
        var activeConnections = 0;

        function completeTcpProbe() {
            activeConnections--;
            pumpTcpProbes();
        }

        function probeTcpPort(address, port, onComplete) {
            var done = false;
            function completePort(open) { if (done) return; done = true; onComplete(open); }
            try {
                const client = net.createConnection({ host: address, port: port }, function () {
                    if ((results[address] == null) || (port == 16993)) { results[address] = { ver: 'Unknown', tls: (port == 16993) ? 1 : 0, state: 2, hostname: address, hosttype: 'addr' }; }
                    try { client.destroy(); } catch (ex) { }
                    completePort(true);
                });
                client.setTimeout(TCP_SCAN_TIMEOUT, function () { try { client.destroy(); } catch (ex) { } completePort(false); });
                client.once('error', function () { completePort(false); });
                client.once('close', function () { completePort(false); });
            } catch (ex) { completePort(false); }
        }

        function probeTcpAddress(address) {
            var completedAddress = false;
            function completeAddress() {
                if (completedAddress) return;
                completedAddress = true;
                completeTcpProbe();
            }
            setScanTimeout(completeAddress, (TCP_SCAN_TIMEOUT * 2) + 100);
            probeTcpPort(address, 16993, function (tlsOpen) {
                if (completedAddress) return;
                if (tlsOpen) { completeAddress(); } else {
                    probeTcpPort(address, 16992, completeAddress);
                }
            });
        }

        function pumpTcpProbes() {
            while ((activeConnections < TCP_SCAN_CONCURRENCY) && (tcpNextAddress <= parsedRange.max)) {
                activeConnections++;
                probeTcpAddress(ipv4NumberToString(tcpNextAddress));
                tcpNextAddress++;
            }
            if ((activeConnections == 0) && (tcpNextAddress > parsedRange.max)) { complete(); }
        }

        pumpTcpProbes();
    }

    function completeRmcpScan() {
        if (completed) return;
        if ((Object.keys(results).length == 0) && (tcpFallbackStarted == false)) { startTcpFallback(); } else { complete(); }
    }

    function sendPendingPackets() {
        var sent = 0;
        while ((sent++ < SCAN_BATCH_SIZE) && (nextAddress <= parsedRange.max)) {
            try { socket.send(packet, 623, ipv4NumberToString(nextAddress)); } catch (ex) { }
            nextAddress++;
        }
        if ((nextAddress > parsedRange.max) && (sendTimer != null)) { clearScanInterval(sendTimer); sendTimer = null; }
    }

    socket.on('error', function (error) { if (tcpFallbackStarted == false) { complete('The relay UDP socket failed: ' + ((error && error.message) ? error.message : 'unknown error')); } });
    socket.on('message', function (data, rinfo) { parseResponse(data, rinfo.address, results); });
    setScanTimeout(completeRmcpScan, timeout);
    socket.on('listening', function () {
        sendPendingPackets();
        if (nextAddress <= parsedRange.max) { sendTimer = setScanInterval(sendPendingPackets, SCAN_BATCH_INTERVAL); }
    });
    try { socket.bind({ address: '0.0.0.0', port: 0 }); } catch (ex) { complete('The relay UDP socket could not bind: ' + ((ex && ex.message) ? ex.message : 'unknown error')); }
    return true;
};