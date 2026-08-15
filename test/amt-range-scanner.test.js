const test = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const scanner = require('../agents/modules_meshcore/relay-range-scanner-v3');
const tcpOnlyScanner = require('../agents/modules_meshcore/relay-range-scanner-v19');

class FakeSocket extends EventEmitter {
    constructor() {
        super();
        this.sent = [];
        this.closed = false;
    }

    bind(options) {
        this.bindOptions = options;
        this.emit('listening');
    }

    send(packet, port, address) {
        this.sent.push({ packet: packet, port: port, address: address });
    }

    close() {
        this.closed = true;
    }
}

test('accepts only bounded IPv4 scan ranges', function () {
    assert.deepEqual(scanner.parseRange('192.0.2.10'), { min: 3221225994, max: 3221225994 });
    assert.deepEqual(scanner.parseRange('192.0.2.10-192.0.2.11'), { min: 3221225994, max: 3221225995 });
    assert.deepEqual(scanner.parseRange('192.0.2.0/24'), { min: 3221225984, max: 3221226239 });
    assert.equal(scanner.parseRange('192.0.2.0/16'), null);
    assert.equal(scanner.parseRange('192.0.2.2-192.0.2.1'), null);
    assert.equal(scanner.parseRange('example.com'), null);
});

test('sends RMCP probes and returns normalized AMT discovery results', function () {
    const socket = new FakeSocket();
    var completeScan;
    var results;
    var socketOptions;
    const started = scanner.scan('192.0.2.10-192.0.2.11', 3000, function (scanResults) { results = scanResults; }, {
        dgram: { createSocket: function (options) { socketOptions = options; return socket; } },
        setTimeout: function (callback) { completeScan = callback; }
    });

    assert.equal(started, true);
    assert.deepEqual(socketOptions, { type: 'udp4' });
    assert.deepEqual(socket.bindOptions, { address: '0.0.0.0', port: 0 });
    assert.deepEqual(socket.sent.map(function (entry) { return [entry.port, entry.address]; }), [[623, '192.0.2.10'], [623, '192.0.2.11']]);

    const reply = Buffer.alloc(22);
    reply[16] = 66;
    reply[17] = 97; // 16993
    reply[18] = 0xA4;
    reply[19] = 2;
    reply[21] = 32;
    socket.emit('message', reply, { address: '192.0.2.11' });
    completeScan();

    assert.equal(socket.closed, true);
    assert.deepEqual(results, { '192.0.2.11': { ver: '10.4', tls: 1, state: 2, hostname: '192.0.2.11', hosttype: 'addr' } });
});

test('completes with no results when the UDP socket errors', function () {
    const socket = new FakeSocket();
    var results;
    var error;
    const started = scanner.scan('192.0.2.10', 3000, function (scanResults, scanError) { results = scanResults; error = scanError; }, {
        dgram: { createSocket: function () { return socket; } },
        setTimeout: function () { }
    });

    assert.equal(started, true);
    socket.emit('error', new Error('bind failed'));
    assert.equal(socket.closed, true);
    assert.deepEqual(results, {});
    assert.equal(error, 'The relay UDP socket failed: bind failed');
});

test('reports a UDP bind failure', function () {
    const socket = new FakeSocket();
    socket.bind = function () { throw new Error('permission denied'); };
    var results;
    var error;
    const started = scanner.scan('192.0.2.10', 3000, function (scanResults, scanError) { results = scanResults; error = scanError; }, {
        dgram: { createSocket: function () { return socket; } },
        setTimeout: function () { }
    });

    assert.equal(started, true);
    assert.equal(socket.closed, true);
    assert.deepEqual(results, {});
    assert.equal(error, 'The relay UDP socket could not bind: permission denied');
});

test('falls back to AMT TCP ports when RMCP returns no devices', function () {
    const socket = new FakeSocket();
    var completeScan;
    var results;
    const clients = [];
    const net = {
        createConnection: function (options, onConnect) {
            const client = new EventEmitter();
            client.options = options;
            client.onConnect = onConnect;
            client.setTimeout = function () { };
            client.destroy = function () { };
            clients.push(client);
            return client;
        }
    };
    scanner.scan('192.0.2.10', 3000, function (scanResults) { results = scanResults; }, {
        dgram: { createSocket: function () { return socket; } },
        net: net,
        setTimeout: function (callback) { completeScan = callback; }
    });

    completeScan();
    const tlsClient = clients.find(function (client) { return client.options.port == 16993; });
    tlsClient.onConnect();
    tlsClient.emit('close');

    assert.deepEqual(results, { '192.0.2.10': { ver: 'Unknown', tls: 1, state: 2, hostname: '192.0.2.10', hosttype: 'addr' } });
    assert.equal(clients.filter(function (client) { return client.options.port == 16992; }).length, 0);
});

test('returns normalized TLS devices from the bounded relay TCP worker', function () {
    const child = new EventEmitter();
    const mesh = {};
    child.stdout = new EventEmitter();
    child.stderr = new EventEmitter();
    Object.preventExtensions(child.stdout);
    child.stdin = { script: '', write: function (data) { this.script += data; } };
    var results;
    var scheduledTimeout;
    const progress = [];
    const started = tcpOnlyScanner.scan('192.0.2.10-192.0.2.11', 10000, function (scanResults) { results = scanResults; }, {
        platform: 'linux',
        childProcess: { execFile: function (path, args) { assert.equal(path, '/bin/sh'); assert.deepEqual(args, ['sh']); return child; } },
        mesh: mesh,
        onProgress: function (completed, total, found) { progress.push([completed, total, found]); },
        setTimeout: function (callback, delay) { scheduledTimeout = delay; }
    });

    assert.equal(started, true);
    assert.equal(mesh.amtRangeScanChild, child);
    assert.match(child.stdin.script, /for ip in 192\.0\.2\.10 192\.0\.2\.11/);
    assert.match(child.stdin.script, /-P32/);
    assert.match(child.stdin.script, /if curl -k -sS --connect-timeout 3 --max-time 3/);
    assert.doesNotMatch(child.stdin.script, /\/dev\/tcp/);
    child.stdout.emit('data', Buffer.from('192.0.2.10,1\nP,192.0.2.10\nP,192.0.2.11\n'));
    child.emit('exit', 0);
    assert.deepEqual(results, { '192.0.2.10': { ver: 'Unknown', tls: 1, state: 2, hostname: '192.0.2.10', hosttype: 'addr' } });
    assert.deepEqual(progress, [[0, 2, 0], [0, 2, 1], [2, 2, 1]]);
    assert.equal(scheduledTimeout, 120000);
    assert.equal(mesh.amtRangeScanChild, undefined);
});