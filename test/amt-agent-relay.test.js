const test = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const { CreateAmtAgentRelay } = require('../amt/amt-agent-relay');

class FakeWebSocket extends EventEmitter {
    constructor(url, options) {
        super();
        this.url = url;
        this.options = options;
        this.sent = [];
        this.closed = false;
    }

    send(data, callback) {
        this.sent.push(data);
        if (callback) callback();
    }

    close() {
        this.closed = true;
    }
}

function createParent() {
    return {
        parent: {
            args: { port: 443, tlsoffload: false },
            loginCookieEncryptionKey: 'test-key',
            encodeCookie: function (content) { return Buffer.from(JSON.stringify(content)).toString('base64'); }
        }
    };
}

function createChannel(port) {
    var socket;
    const channel = CreateAmtAgentRelay(createParent(), { id: '', dns: null }, 'node//relay', '192.0.2.10', port, {
        WebSocket: function (url, options) { socket = new FakeWebSocket(url, options); return socket; }
    });
    return { channel: channel, getSocket: function () { return socket; } };
}

test('rejects non-AMT ports', function () {
    assert.throws(function () { createChannel(3389); }, /Invalid AMT relay target/);
});

test('buffers writes until the MeshAgent tunnel connects', function () {
    const relay = createChannel(16993);
    var connected = 0;
    relay.channel.onStateChange = function (connection, state) { if (state == 2) connected++; };
    relay.channel.start();
    assert.equal(relay.channel.write(Buffer.from('before-connect')), true);
    assert.equal(relay.getSocket().sent.length, 0);
    relay.getSocket().emit('message', 'c');
    assert.equal(connected, 1);
    assert.deepEqual(relay.getSocket().sent, [Buffer.from('before-connect')]);
});

test('forwards binary data and closes after an invalid handshake', function () {
    const relay = createChannel(16994);
    const received = [];
    relay.channel.onData = function (connection, data) { received.push(data); };
    relay.channel.start();
    relay.getSocket().emit('message', 'c');
    relay.getSocket().emit('message', Buffer.from([0, 1, 2]));
    assert.deepEqual(received, [Buffer.from([0, 1, 2])]);

    const rejectedRelay = createChannel(16994);
    var disconnected = 0;
    rejectedRelay.channel.onStateChange = function (connection, state) { if (state == 0) disconnected++; };
    rejectedRelay.channel.start();
    rejectedRelay.getSocket().emit('message', 'refused');
    assert.equal(rejectedRelay.channel.closed, true);
    assert.equal(disconnected, 1);
});
