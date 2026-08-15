/*jslint node: true */
/*jshint node: true */
/*jshint strict:false */
/*jshint esversion: 6 */
"use strict";

const AMT_PORTS = [16992, 16993, 16994, 16995];

// Creates a binary channel to an AMT target through a MeshAgent TCP tunnel.
module.exports.CreateAmtAgentRelay = function (parent, domain, relayNodeId, targetHost, targetPort, options) {
    if ((typeof relayNodeId != 'string') || (typeof targetHost != 'string') || (AMT_PORTS.indexOf(targetPort) == -1)) { throw new Error('Invalid AMT relay target'); }
    if (options == null) { options = {}; }

    const WebSocket = (options.WebSocket != null) ? options.WebSocket : require('ws');
    const obj = { onData: null, onStateChange: null, onSendOk: null, state: 0, closed: false, pendingWrites: [] };
    const maxPendingWrites = 16;
    var webSocket = null;

    function setState(state, force) {
        if ((obj.state == state) && (force !== true)) return;
        obj.state = state;
        if (obj.onStateChange != null) { obj.onStateChange(null, state); }
    }

    function close() {
        if (obj.closed) return;
        obj.closed = true;
        obj.pendingWrites = [];
        setState(0, true);
        if (webSocket != null) {
            try { webSocket.close(); } catch (ex) { }
            webSocket = null;
        }
    }

    function send(data) {
        if ((webSocket == null) || (obj.closed)) return false;
        try {
            webSocket.send(data, function () { if (obj.onSendOk != null) { obj.onSendOk(null); } });
            return true;
        } catch (ex) {
            close();
            return false;
        }
    }

    obj.start = function () {
        if ((webSocket != null) || obj.closed) return;
        const cookie = parent.parent.encodeCookie({ nouser: 1, domainid: domain.id, nodeid: relayNodeId, tcpaddr: targetHost, tcpport: targetPort }, parent.parent.loginCookieEncryptionKey);
        const protocol = parent.parent.args.tlsoffload ? 'ws' : 'wss';
        const domainPath = ((domain.dns == null) && (domain.id != '')) ? (domain.id + '/') : '';
        const url = protocol + '://localhost:' + parent.parent.args.port + '/' + domainPath + 'meshrelay.ashx?noping=1&hd=1&auth=' + cookie;
        webSocket = new WebSocket(url, { rejectUnauthorized: false });
        webSocket.on('message', function (data) {
            if (obj.closed) return;
            if (obj.state != 2) {
                if ((data == 'c') || (data == 'cr')) {
                    setState(2);
                    const pendingWrites = obj.pendingWrites;
                    obj.pendingWrites = [];
                    for (var i = 0; i < pendingWrites.length; i++) { send(pendingWrites[i]); }
                } else {
                    close();
                }
            } else if (obj.onData != null) {
                obj.onData(null, data);
            }
        });
        webSocket.on('close', close);
        webSocket.on('error', close);
    };

    obj.write = function (data) {
        if (obj.closed) return false;
        if (obj.state == 2) return send(data);
        if (obj.pendingWrites.length >= maxPendingWrites) return false;
        obj.pendingWrites.push(data);
        return true;
    };

    obj.close = close;
    return obj;
};
