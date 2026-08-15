var addedModules = [];
try { addModule("amt-apfclient", "/*\r\nCopyright 2018-2021 Intel Corporation\r\n\r\nLicensed under the Apache License, Version 2.0 (the \"License\");\r\nyou may not use this file except in compliance with the License.\r\nYou may obtain a copy of the License at\r\n\r\n    http://www.apache.org/licenses/LICENSE-2.0\r\n\r\nUnless required by applicable law or agreed to in writing, software\r\ndistributed under the License is distributed on an \"AS IS\" BASIS,\r\nWITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.\r\nSee the License for the specific language governing permissions and\r\nlimitations under the License.\r\n*/\r\n\r\n/**\r\n* @description APF/CIRA Client for Duktape\r\n* @author Joko Sastriawan & Ylian Saint-Hilaire\r\n* @copyright Intel Corporation 2020-2021\r\n* @license Apache-2.0\r\n* @version v0.0.2\r\n*/\r\n\r\nfunction CreateAPFClient(parent, args) {\r\n    if ((args.clientuuid == null) || (args.clientuuid.length != 36)) return null; // Require a UUID if this exact length\r\n\r\n    var obj = {};\r\n    obj.parent = parent;\r\n    obj.args = args;\r\n    obj.http = require(\'http\');\r\n    obj.net = require(\'net\');\r\n    obj.forwardClient = null;\r\n    obj.downlinks = {};\r\n    obj.pfwd_idx = 0;\r\n    obj.timer = null; // Keep alive timer\r\n\r\n    // obj.onChannelClosed\r\n    // obj.onJsonControl\r\n\r\n    // Function copied from common.js\r\n    function ReadInt(v, p) { return (v.charCodeAt(p) * 0x1000000) + (v.charCodeAt(p + 1) << 16) + (v.charCodeAt(p + 2) << 8) + v.charCodeAt(p + 3); }; // We use \"*0x1000000\" instead of \"<<24\" because the shift converts the number to signed int32.\r\n    function IntToStr(v) { return String.fromCharCode((v >> 24) & 0xFF, (v >> 16) & 0xFF, (v >> 8) & 0xFF, v & 0xFF); };\r\n    function hex2rstr(d) { var r = \'\', m = (\'\' + d).match(/../g), t; while (t = m.shift()) { r += String.fromCharCode(\'0x\' + t); } return r; };\r\n    function char2hex(i) { return (i + 0x100).toString(16).substr(-2).toUpperCase(); }; // Convert decimal to hex\r\n    function rstr2hex(input) { var r = \'\', i; for (i = 0; i < input.length; i++) { r += char2hex(input.charCodeAt(i)); } return r; }; // Convert a raw string to a hex string\r\n    function d2h(d) { return (d / 256 + 1 / 512).toString(16).substring(2, 4); }\r\n    function buf2hex(input) { var r = \'\', i; for (i = 0; i < input.length; i++) { r += d2h(input[i]); } return r; };\r\n    function Debug(str) {\r\n        //require(\'MeshAgent\').SendCommand({ action: \'msg\', type: \'console\', value: str });\r\n        if (obj.parent.debug) { console.log(str); }\r\n    }\r\n    function guidToStr(g) { return g.substring(6, 8) + g.substring(4, 6) + g.substring(2, 4) + g.substring(0, 2) + \"-\" + g.substring(10, 12) + g.substring(8, 10) + \"-\" + g.substring(14, 16) + g.substring(12, 14) + \"-\" + g.substring(16, 20) + \"-\" + g.substring(20); }\r\n    function strToGuid(s) { s = s.replace(/-/g, \'\'); var ret = s.substring(6, 8) + s.substring(4, 6) + s.substring(2, 4) + s.substring(0, 2) + s.substring(10, 12) + s.substring(8, 10) + s.substring(14, 16) + s.substring(12, 14) + s.substring(16, 20) + s.substring(20); return ret; }\r\n    function binzerostring(len) { var res = \'\'; for (var l = 0; l < len; l++) { res += String.fromCharCode(0 & 0xFF); } return res; }\r\n\r\n    // CIRA state\r\n    var CIRASTATE = {\r\n        INITIAL: 0,\r\n        PROTOCOL_VERSION_SENT: 1,\r\n        AUTH_SERVICE_REQUEST_SENT: 2,\r\n        AUTH_REQUEST_SENT: 3,\r\n        PFWD_SERVICE_REQUEST_SENT: 4,\r\n        GLOBAL_REQUEST_SENT: 5,\r\n        FAILED: -1\r\n    }\r\n    obj.cirastate = CIRASTATE.INITIAL;\r\n\r\n    // REDIR state\r\n    var REDIR_TYPE = {\r\n        REDIR_UNKNOWN: 0,\r\n        REDIR_SOL: 1,\r\n        REDIR_KVM: 2,\r\n        REDIR_IDER: 3\r\n    }\r\n\r\n    // redirection start command\r\n    obj.RedirectStartSol = String.fromCharCode(0x10, 0x00, 0x00, 0x00, 0x53, 0x4F, 0x4C, 0x20);\r\n    obj.RedirectStartKvm = String.fromCharCode(0x10, 0x01, 0x00, 0x00, 0x4b, 0x56, 0x4d, 0x52);\r\n    obj.RedirectStartIder = String.fromCharCode(0x10, 0x00, 0x00, 0x00, 0x49, 0x44, 0x45, 0x52);\r\n\r\n    // Intel AMT forwarded port list for non-TLS mode\r\n    //var pfwd_ports = [16992, 623, 16994, 5900];\r\n    var pfwd_ports = [ 16992, 16993 ];\r\n\r\n    // protocol definitions\r\n    var APFProtocol = {\r\n        UNKNOWN: 0,\r\n        DISCONNECT: 1,\r\n        SERVICE_REQUEST: 5,\r\n        SERVICE_ACCEPT: 6,\r\n        USERAUTH_REQUEST: 50,\r\n        USERAUTH_FAILURE: 51,\r\n        USERAUTH_SUCCESS: 52,\r\n        GLOBAL_REQUEST: 80,\r\n        REQUEST_SUCCESS: 81,\r\n        REQUEST_FAILURE: 82,\r\n        CHANNEL_OPEN: 90,\r\n        CHANNEL_OPEN_CONFIRMATION: 91,\r\n        CHANNEL_OPEN_FAILURE: 92,\r\n        CHANNEL_WINDOW_ADJUST: 93,\r\n        CHANNEL_DATA: 94,\r\n        CHANNEL_CLOSE: 97,\r\n        PROTOCOLVERSION: 192,\r\n        KEEPALIVE_REQUEST: 208,\r\n        KEEPALIVE_REPLY: 209,\r\n        KEEPALIVE_OPTIONS_REQUEST: 210,\r\n        KEEPALIVE_OPTIONS_REPLY: 211,\r\n        JSON_CONTROL: 250 // This is a Mesh specific command that sends JSON to and from the MPS server.\r\n    }\r\n\r\n    var APFDisconnectCode = {\r\n        HOST_NOT_ALLOWED_TO_CONNECT: 1,\r\n        PROTOCOL_ERROR: 2,\r\n        KEY_EXCHANGE_FAILED: 3,\r\n        RESERVED: 4,\r\n        MAC_ERROR: 5,\r\n        COMPRESSION_ERROR: 6,\r\n        SERVICE_NOT_AVAILABLE: 7,\r\n        PROTOCOL_VERSION_NOT_SUPPORTED: 8,\r\n        HOST_KEY_NOT_VERIFIABLE: 9,\r\n        CONNECTION_LOST: 10,\r\n        BY_APPLICATION: 11,\r\n        TOO_MANY_CONNECTIONS: 12,\r\n        AUTH_CANCELLED_BY_USER: 13,\r\n        NO_MORE_AUTH_METHODS_AVAILABLE: 14,\r\n        INVALID_CREDENTIALS: 15,\r\n        CONNECTION_TIMED_OUT: 16,\r\n        BY_POLICY: 17,\r\n        TEMPORARILY_UNAVAILABLE: 18\r\n    }\r\n\r\n    var APFChannelOpenFailCodes = {\r\n        ADMINISTRATIVELY_PROHIBITED: 1,\r\n        CONNECT_FAILED: 2,\r\n        UNKNOWN_CHANNEL_TYPE: 3,\r\n        RESOURCE_SHORTAGE: 4,\r\n    }\r\n\r\n    var APFChannelOpenFailureReasonCode = {\r\n        AdministrativelyProhibited: 1,\r\n        ConnectFailed: 2,\r\n        UnknownChannelType: 3,\r\n        ResourceShortage: 4,\r\n    }\r\n\r\n    obj.onSecureConnect = function onSecureConnect(resp, ws, head) {\r\n        Debug(\"APF Secure WebSocket connected.\");\r\n        //console.log(JSON.stringify(resp));                \r\n        obj.forwardClient.tag = { accumulator: [] };\r\n        obj.forwardClient.ws = ws;\r\n        obj.forwardClient.ws.on(\'end\', function () {\r\n            Debug(\"APF: Connection is closing.\");\r\n            if (obj.timer != null) { clearInterval(obj.timer); obj.timer = null; }\r\n            if (obj.onChannelClosed) { obj.onChannelClosed(obj); }\r\n        });\r\n\r\n        obj.forwardClient.ws.on(\'data\', function (data) {\r\n            obj.forwardClient.tag.accumulator += hex2rstr(buf2hex(data));\r\n            try {\r\n                var len = 0;\r\n                do {\r\n                    len = ProcessData(obj.forwardClient);\r\n                    if (len > 0) { obj.forwardClient.tag.accumulator = obj.forwardClient.tag.accumulator.slice(len); }\r\n                    if (obj.cirastate == CIRASTATE.FAILED) {\r\n                        Debug(\"APF: in a failed state, destroying socket.\");\r\n                        obj.forwardClient.ws.end();\r\n                    }\r\n                } while (len > 0);\r\n            } catch (ex) { Debug(ex); }\r\n        });\r\n\r\n        obj.forwardClient.ws.on(\'error\', function (e) {\r\n            Debug(\"APF: Connection error, ending connecting.\");\r\n            if (obj.timer != null) { clearInterval(obj.timer); obj.timer = null; }\r\n        });\r\n\r\n        obj.state = CIRASTATE.INITIAL;\r\n        if ((typeof obj.args.conntype == \'number\') && (obj.args.conntype != 0)) {\r\n            SendJsonControl(obj.forwardClient.ws, { action: \'connType\', value: obj.args.conntype });\r\n            if (obj.args.meiState != null) { SendJsonControl(obj.forwardClient.ws, { action: \'meiState\', value: obj.args.meiState }); }\r\n        }\r\n        SendProtocolVersion(obj.forwardClient.ws, obj.args.clientuuid);\r\n        SendServiceRequest(obj.forwardClient.ws, \'auth@amt.intel.com\');\r\n    }\r\n\r\n    obj.updateMeiState = function (state) { SendJsonControl(obj.forwardClient.ws, { action: \'meiState\', value: state }); }\r\n    obj.sendMeiDeactivationState = function (state) { SendJsonControl(obj.forwardClient.ws, { action: \'deactivate\', value: state }); }\r\n    obj.sendStartTlsHostConfigResponse = function (state) { SendJsonControl(obj.forwardClient.ws, { action: \'startTlsHostConfig\', value: state }); }\r\n    obj.sendStopConfigurationResponse = function (state) { SendJsonControl(obj.forwardClient.ws, { action: \'stopConfiguration\', value: state }); }\r\n\r\n    function SendJsonControl(socket, o) {\r\n        var data = JSON.stringify(o)\r\n        socket.write(String.fromCharCode(APFProtocol.JSON_CONTROL) + IntToStr(data.length) + data);\r\n        Debug(\"APF: Send JSON control: \" + data);\r\n    }\r\n\r\n    function SendProtocolVersion(socket, uuid) {\r\n        var data = String.fromCharCode(APFProtocol.PROTOCOLVERSION) + IntToStr(1) + IntToStr(0) + IntToStr(0) + hex2rstr(strToGuid(uuid)) + binzerostring(64);\r\n        socket.write(data);\r\n        Debug(\"APF: Send protocol version 1 0 \" + uuid);\r\n        obj.cirastate = CIRASTATE.PROTOCOL_VERSION_SENT;\r\n    }\r\n\r\n    function SendServiceRequest(socket, service) {\r\n        var data = String.fromCharCode(APFProtocol.SERVICE_REQUEST) + IntToStr(service.length) + service;\r\n        socket.write(data);\r\n        Debug(\"APF: Send service request \" + service);\r\n        if (service == \'auth@amt.intel.com\') {\r\n            obj.cirastate = CIRASTATE.AUTH_SERVICE_REQUEST_SENT;\r\n        } else if (service == \'pfwd@amt.intel.com\') {\r\n            obj.cirastate = CIRASTATE.PFWD_SERVICE_REQUEST_SENT;\r\n        }\r\n    }\r\n\r\n    function SendUserAuthRequest(socket, user, pass) {\r\n        var service = \"pfwd@amt.intel.com\";\r\n        var data = String.fromCharCode(APFProtocol.USERAUTH_REQUEST) + IntToStr(user.length) + user + IntToStr(service.length) + service;\r\n        //password auth\r\n        data += IntToStr(8) + \'password\';\r\n        data += binzerostring(1) + IntToStr(pass.length) + pass;\r\n        socket.write(data);\r\n        Debug(\"APF: Send username password authentication to MPS\");\r\n        obj.cirastate = CIRASTATE.AUTH_REQUEST_SENT;\r\n    }\r\n\r\n    function SendGlobalRequestPfwd(socket, amthostname, amtport) {\r\n        var tcpipfwd = \'tcpip-forward\';\r\n        var data = String.fromCharCode(APFProtocol.GLOBAL_REQUEST) + IntToStr(tcpipfwd.length) + tcpipfwd + binzerostring(1, 1);\r\n        data += IntToStr(amthostname.length) + amthostname + IntToStr(amtport);\r\n        socket.write(data);\r\n        Debug(\"APF: Send tcpip-forward \" + amthostname + \":\" + amtport);\r\n        obj.cirastate = CIRASTATE.GLOBAL_REQUEST_SENT;\r\n    }\r\n\r\n    function SendKeepAliveRequest(socket) {\r\n        socket.write(String.fromCharCode(APFProtocol.KEEPALIVE_REQUEST) + IntToStr(255));\r\n        Debug(\"APF: Send keepalive request\");\r\n    }\r\n\r\n    function SendKeepAliveReply(socket, cookie) {\r\n        socket.write(String.fromCharCode(APFProtocol.KEEPALIVE_REPLY) + IntToStr(cookie));\r\n        Debug(\"APF: Send keepalive reply\");\r\n    }\r\n\r\n    function ProcessData(socket) {\r\n        var cmd = socket.tag.accumulator.charCodeAt(0);\r\n        var len = socket.tag.accumulator.length;\r\n        var data = socket.tag.accumulator;\r\n        if (len == 0) { return 0; }\r\n\r\n        // Respond to MPS according to obj.cirastate\r\n        switch (cmd) {\r\n            case APFProtocol.SERVICE_ACCEPT: {\r\n                var slen = ReadInt(data, 1), service = data.substring(5, 6 + slen);\r\n                Debug(\"APF: Service request to \" + service + \" accepted.\");\r\n                if (service == \'auth@amt.intel.com\') {\r\n                    if (obj.cirastate >= CIRASTATE.AUTH_SERVICE_REQUEST_SENT) {\r\n                        SendUserAuthRequest(socket.ws, obj.args.mpsuser, obj.args.mpspass);\r\n                    }\r\n                } else if (service == \'pfwd@amt.intel.com\') {\r\n                    if (obj.cirastate >= CIRASTATE.PFWD_SERVICE_REQUEST_SENT) {\r\n                        SendGlobalRequestPfwd(socket.ws, obj.args.clientname, pfwd_ports[obj.pfwd_idx++]);\r\n                    }\r\n                }\r\n                return 5 + slen;\r\n            }\r\n            case APFProtocol.REQUEST_SUCCESS: {\r\n                if (len >= 5) {\r\n                    var port = ReadInt(data, 1);\r\n                    Debug(\"APF: Request to port forward \" + port + \" successful.\");\r\n                    // iterate to pending port forward request\r\n                    if (obj.pfwd_idx < pfwd_ports.length) {\r\n                        SendGlobalRequestPfwd(socket.ws, obj.args.clientname, pfwd_ports[obj.pfwd_idx++]);\r\n                    } else {\r\n                        // no more port forward, now setup timer to send keep alive\r\n                        Debug(\"APF: Start keep alive for every \" + obj.args.mpskeepalive + \" ms.\");\r\n                        obj.timer = setInterval(function () {\r\n                            SendKeepAliveRequest(obj.forwardClient.ws);\r\n                        }, obj.args.mpskeepalive);//\r\n                    }\r\n                    return 5;\r\n                }\r\n                Debug(\"APF: Request successful.\");\r\n                return 1;\r\n            }\r\n            case APFProtocol.USERAUTH_SUCCESS: {\r\n                Debug(\"APF: User Authentication successful\");\r\n                // Send Pfwd service request\r\n                SendServiceRequest(socket.ws, \'pfwd@amt.intel.com\');\r\n                return 1;\r\n            }\r\n            case APFProtocol.USERAUTH_FAILURE: {\r\n                Debug(\"APF: User Authentication failed\");\r\n                obj.cirastate = CIRASTATE.FAILED;\r\n                return 14;\r\n            }\r\n            case APFProtocol.KEEPALIVE_REQUEST: {\r\n                Debug(\"APF: Keep Alive Request with cookie: \" + ReadInt(data, 1));\r\n                SendKeepAliveReply(socket.ws, ReadInt(data, 1));\r\n                return 5;\r\n            }\r\n            case APFProtocol.KEEPALIVE_REPLY: {\r\n                Debug(\"APF: Keep Alive Reply with cookie: \" + ReadInt(data, 1));\r\n                return 5;\r\n            }\r\n            // Channel management\r\n            case APFProtocol.CHANNEL_OPEN: {\r\n                // Parse CHANNEL OPEN request\r\n                var p_res = parseChannelOpen(data);\r\n                Debug(\"APF: CHANNEL_OPEN request: \" + JSON.stringify(p_res));\r\n                // Check if target port is in pfwd_ports\r\n                if (pfwd_ports.indexOf(p_res.target_port) >= 0) {\r\n                    // Connect socket to that port\r\n                    var chan = obj.net.createConnection({ host: obj.args.clientaddress, port: p_res.target_port }, function () {\r\n                        //require(\'MeshAgent\').SendCommand({ action: \'msg\', type: \'console\', value: \"CHANNEL_OPEN-open\" });\r\n                        // obj.downlinks[p_res.sender_chan].setEncoding(\'binary\');//assume everything is binary, not interpreting\r\n                        SendChannelOpenConfirm(socket.ws, p_res);\r\n                    });\r\n\r\n                    // Setup flow control\r\n                    chan.maxInWindow = p_res.window_size; // Oddly, we are using the same window size as the other side.\r\n                    chan.curInWindow = 0;\r\n\r\n                    chan.on(\'data\', function (ddata) {\r\n                        // Relay data to fordwardclient\r\n                        // TODO: Implement flow control\r\n                        SendChannelData(socket.ws, p_res.sender_chan, ddata);\r\n                    });\r\n\r\n                    chan.on(\'error\', function (e) {\r\n                        //Debug(\"Downlink connection error: \" + e);\r\n                        SendChannelOpenFailure(socket.ws, p_res);\r\n                    });\r\n\r\n                    chan.on(\'end\', function () {\r\n                        var chan = obj.downlinks[p_res.sender_chan];\r\n                        if (chan != null) {\r\n                            Debug(\"Socket ends.\");\r\n                            try { SendChannelClose(socket.ws, p_res.sender_chan); } catch (ex) { }\r\n                            delete obj.downlinks[p_res.sender_chan];\r\n                        }\r\n                    });\r\n\r\n                    obj.downlinks[p_res.sender_chan] = chan;\r\n                } else {\r\n                    // Not a supported port, fail the connection\r\n                    SendChannelOpenFailure(socket.ws, p_res);\r\n                }\r\n                return p_res.len;\r\n            }\r\n            case APFProtocol.CHANNEL_OPEN_CONFIRMATION: {\r\n                Debug(\"APF: CHANNEL_OPEN_CONFIRMATION\");\r\n                return 17;\r\n            }\r\n            case APFProtocol.CHANNEL_CLOSE: {\r\n                var rcpt_chan = ReadInt(data, 1);\r\n                Debug(\"APF: CHANNEL_CLOSE: \" + rcpt_chan);\r\n                try { obj.downlinks[rcpt_chan].end(); } catch (ex) { }\r\n                return 5;\r\n            }\r\n            case APFProtocol.CHANNEL_DATA: {\r\n                Debug(\"APF: CHANNEL_DATA: \" + JSON.stringify(rstr2hex(data)));\r\n                var rcpt_chan = ReadInt(data, 1);\r\n                var chan_data_len = ReadInt(data, 5);\r\n                var chan_data = data.substring(9, 9 + chan_data_len);\r\n                var chan = obj.downlinks[rcpt_chan];\r\n                if (chan != null) {\r\n                    chan.curInWindow += chan_data_len;\r\n                    try {\r\n                        chan.write(Buffer.from(chan_data, \'binary\'), function () {\r\n                            Debug(\"Write completed.\");\r\n                            // If the incoming window is over half used, send an adjust.\r\n                            if (this.curInWindow > (this.maxInWindow / 2)) { SendChannelWindowAdjust(socket.ws, rcpt_chan, this.curInWindow); this.curInWindow = 0; }\r\n                        });\r\n                    } catch (ex) { Debug(\"Cannot forward data to downlink socket.\"); }\r\n                }\r\n                return 9 + chan_data_len;\r\n            }\r\n            case APFProtocol.CHANNEL_WINDOW_ADJUST: {\r\n                Debug(\"APF: CHANNEL_WINDOW_ADJUST\");\r\n                return 9;\r\n            }\r\n            case APFProtocol.JSON_CONTROL: {\r\n                Debug(\"APF: JSON_CONTROL\");\r\n                var len = ReadInt(data, 1);\r\n                if (obj.onJsonControl) { var o = null; try { o = JSON.parse(data.substring(5, 5 + len)); } catch (ex) { } if (o != null) { obj.onJsonControl(o); } }\r\n                return 5 + len;\r\n            }\r\n            default: {\r\n                Debug(\"CMD: \" + cmd + \" is not implemented.\");\r\n                obj.cirastate = CIRASTATE.FAILED;\r\n                return 0;\r\n            }\r\n        }\r\n    }\r\n\r\n    function parseChannelOpen(data) {\r\n        var result = { cmd: APFProtocol.CHANNEL_OPEN };\r\n        var chan_type_slen = ReadInt(data, 1);\r\n        result.chan_type = data.substring(5, 5 + chan_type_slen);\r\n        result.sender_chan = ReadInt(data, 5 + chan_type_slen);\r\n        result.window_size = ReadInt(data, 9 + chan_type_slen);\r\n        var c_len = ReadInt(data, 17 + chan_type_slen);\r\n        result.target_address = data.substring(21 + chan_type_slen, 21 + chan_type_slen + c_len);\r\n        result.target_port = ReadInt(data, 21 + chan_type_slen + c_len);\r\n        var o_len = ReadInt(data, 25 + chan_type_slen + c_len);\r\n        result.origin_address = data.substring(29 + chan_type_slen + c_len, 29 + chan_type_slen + c_len + o_len);\r\n        result.origin_port = ReadInt(data, 29 + chan_type_slen + c_len + o_len);\r\n        result.len = 33 + chan_type_slen + c_len + o_len;\r\n        return result;\r\n    }\r\n\r\n    function SendChannelOpenFailure(socket, chan_data) {\r\n        socket.write(String.fromCharCode(APFProtocol.CHANNEL_OPEN_FAILURE) + IntToStr(chan_data.sender_chan) + IntToStr(2) + IntToStr(0) + IntToStr(0));\r\n        Debug(\"APF: Send ChannelOpenFailure\");\r\n    }\r\n\r\n    function SendChannelOpenConfirm(socket, chan_data) {\r\n        socket.write(String.fromCharCode(APFProtocol.CHANNEL_OPEN_CONFIRMATION) + IntToStr(chan_data.sender_chan) + IntToStr(chan_data.sender_chan) + IntToStr(chan_data.window_size) + IntToStr(0xFFFFFFFF));\r\n        Debug(\"APF: Send ChannelOpenConfirmation\");\r\n    }\r\n\r\n    function SendChannelWindowAdjust(socket, chan, size) {\r\n        socket.write(String.fromCharCode(APFProtocol.CHANNEL_WINDOW_ADJUST) + IntToStr(chan) + IntToStr(size));\r\n        Debug(\"APF: Send ChannelWindowAdjust, channel: \" + chan + \", size: \" + size);\r\n    }\r\n\r\n    function SendChannelData(socket, chan, data) {\r\n        socket.write(Buffer.concat([Buffer.from(String.fromCharCode(APFProtocol.CHANNEL_DATA) + IntToStr(chan) + IntToStr(data.length), \'binary\'), data]));\r\n        Debug(\"APF: Send ChannelData: \" + data.toString(\'hex\'));\r\n    }\r\n\r\n    function SendChannelClose(socket, chan) {\r\n        socket.write(String.fromCharCode(APFProtocol.CHANNEL_CLOSE) + IntToStr(chan));\r\n        Debug(\"APF: Send ChannelClose \");\r\n    }\r\n\r\n    obj.connect = function () {\r\n        if (obj.forwardClient != null) {\r\n            try { obj.forwardClient.ws.end(); } catch (ex) { Debug(ex); }\r\n            //obj.forwardClient = null;\r\n        }\r\n        obj.cirastate = CIRASTATE.INITIAL;\r\n        obj.pfwd_idx = 0;\r\n\r\n        //obj.forwardClient = new obj.ws(obj.args.mpsurl, obj.tlsoptions);\r\n        //obj.forwardClient.on(\"open\", obj.onSecureConnect);\r\n\r\n        var wsoptions = obj.http.parseUri(obj.args.mpsurl);\r\n        wsoptions.rejectUnauthorized = 0;\r\n        obj.forwardClient = obj.http.request(wsoptions);\r\n        obj.forwardClient.upgrade = obj.onSecureConnect;\r\n        obj.forwardClient.end(); // end request, trigger completion of HTTP request\r\n    }\r\n\r\n    obj.disconnect = function () { try { obj.forwardClient.ws.end(); } catch (ex) { Debug(ex); } }\r\n\r\n    return obj;\r\n}\r\n\r\nmodule.exports = CreateAPFClient; "); addedModules.push("amt-apfclient"); } catch (ex) { }
try { addModule("amt-lme", "/*\r\nCopyright 2018-2021 Intel Corporation\r\n\r\nLicensed under the Apache License, Version 2.0 (the \"License\");\r\nyou may not use this file except in compliance with the License.\r\nYou may obtain a copy of the License at\r\n\r\n    http://www.apache.org/licenses/LICENSE-2.0\r\n\r\nUnless required by applicable law or agreed to in writing, software\r\ndistributed under the License is distributed on an \"AS IS\" BASIS,\r\nWITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.\r\nSee the License for the specific language governing permissions and\r\nlimitations under the License.\r\n*/\r\n\r\nvar MemoryStream = require(\'MemoryStream\');\r\nvar lme_id = 0;             // Our next channel identifier\r\nvar lme_port_offset = 0;    // Debug: Set this to \"-100\" to bind to 16892 & 16893 and IN_ADDRANY. This is for LMS debugging.\r\nvar lme_bindany = false;    // If true, bind to all network interfaces, not just loopback.\r\nvar xmlParser = null;\r\ntry { xmlParser = require(\'amt-xml\'); } catch (ex) { }\r\n\r\n// Documented in: https://software.intel.com/sites/manageability/AMT_Implementation_and_Reference_Guide/HTMLDocuments/MPSDocuments/Intel%20AMT%20Port%20Forwarding%20Protocol%20Reference%20Manual.pdf\r\nvar APF_DISCONNECT = 1;\r\nvar APF_SERVICE_REQUEST = 5;\r\nvar APF_SERVICE_ACCEPT = 6;\r\nvar APF_USERAUTH_REQUEST = 50;\r\nvar APF_USERAUTH_FAILURE = 51;\r\nvar APF_USERAUTH_SUCCESS = 52;\r\nvar APF_GLOBAL_REQUEST = 80;\r\nvar APF_REQUEST_SUCCESS = 81;\r\nvar APF_REQUEST_FAILURE = 82;\r\nvar APF_CHANNEL_OPEN = 90;\r\nvar APF_CHANNEL_OPEN_CONFIRMATION = 91;\r\nvar APF_CHANNEL_OPEN_FAILURE = 92;\r\nvar APF_CHANNEL_WINDOW_ADJUST = 93;\r\nvar APF_CHANNEL_DATA = 94;\r\nvar APF_CHANNEL_CLOSE = 97;\r\nvar APF_PROTOCOLVERSION = 192;\r\n\r\n\r\nfunction lme_object() {\r\n    this.ourId = ++lme_id;\r\n    this.amtId = -1;\r\n    this.LME_CHANNEL_STATUS = \'LME_CS_FREE\';\r\n    this.txWindow = 0;\r\n    this.rxWindow = 0;\r\n    this.localPort = 0;\r\n    this.errorCount = 0;\r\n}\r\n\r\nfunction stream_bufferedWrite() {\r\n    var emitterUtils = require(\'events\').inherits(this);\r\n    this.buffer = [];\r\n    this._readCheckImmediate = undefined;\r\n    this._ObjectID = \"bufferedWriteStream\";\r\n    // Writable Events\r\n    emitterUtils.createEvent(\'close\');\r\n    emitterUtils.createEvent(\'drain\');\r\n    emitterUtils.createEvent(\'error\');\r\n    emitterUtils.createEvent(\'finish\');\r\n    emitterUtils.createEvent(\'pipe\');\r\n    emitterUtils.createEvent(\'unpipe\');\r\n    \r\n    // Readable Events\r\n    emitterUtils.createEvent(\'readable\');\r\n    this.isEmpty = function () {\r\n        return (this.buffer.length == 0);\r\n    };\r\n    this.isWaiting = function () {\r\n        return (this._readCheckImmediate == undefined);\r\n    };\r\n    this.write = function (chunk) {\r\n        for (var args in arguments) { if (typeof (arguments[args]) == \'function\') { this.once(\'drain\', arguments[args]); break; } }\r\n        var tmp = Buffer.alloc(chunk.length);\r\n        chunk.copy(tmp);\r\n        this.buffer.push({ offset: 0, data: tmp });\r\n        this.emit(\'readable\');\r\n        return (this.buffer.length == 0 ? true : false);\r\n    };\r\n    this.read = function () {\r\n        var size = arguments.length == 0 ? undefined : arguments[0];\r\n        var bytesRead = 0;\r\n        var list = [];\r\n        while ((size == undefined || bytesRead < size) && this.buffer.length > 0) {\r\n            var len = this.buffer[0].data.length - this.buffer[0].offset;\r\n            var offset = this.buffer[0].offset;\r\n            \r\n            if (len > (size - bytesRead)) {\r\n                // Only reading a subset\r\n                list.push(this.buffer[0].data.slice(offset, offset + size - bytesRead));\r\n                this.buffer[0].offset += (size - bytesRead);\r\n                bytesRead += (size - bytesRead);\r\n            } else {\r\n                // Reading the entire thing\r\n                list.push(this.buffer[0].data.slice(offset));\r\n                bytesRead += len;\r\n                this.buffer.shift();\r\n            }\r\n        }\r\n        this._readCheckImmediate = setImmediate(function (buffered) {\r\n            buffered._readCheckImmediate = undefined;\r\n            if (buffered.buffer.length == 0) {\r\n                buffered.emit(\'drain\'); // Drained\r\n            } else {\r\n                buffered.emit(\'readable\'); // Not drained\r\n            }\r\n        }, this);\r\n        return (Buffer.concat(list));\r\n    };\r\n}\r\n\r\n\r\nfunction lme_heci(options) {\r\n    var emitterUtils = require(\'events\').inherits(this);\r\n    emitterUtils.createEvent(\'error\');\r\n    emitterUtils.createEvent(\'connect\');\r\n    emitterUtils.createEvent(\'notify\');\r\n    emitterUtils.createEvent(\'bind\');\r\n    \r\n    this.on(\'newListener\', function (name, func)\r\n    {\r\n        if (name == \'connect\' && this._LME._connected == true) { func.call(this); }\r\n        if (name == \'error\' && this._LME._error !=null) { func.call(this, this._LME._error); }\r\n    });\r\n    if (options != null) {\r\n        if (options.debug == true) { lme_port_offset = -100; } // LMS debug mode\r\n        if (options.bindany == true) { lme_bindany = true; } // Bind to all ports\r\n    }\r\n\r\n    var heci = require(\'heci\');\r\n    this.INITIAL_RXWINDOW_SIZE = 4096;\r\n    \r\n    this._ObjectID = \"lme\";\r\n    this._LME = heci.create();\r\n    this._LME._connected = false;\r\n    this._LME._error = null;\r\n    this._LME.descriptorMetadata = \"amt-lme\";\r\n    this._LME._binded = {};\r\n    this._LME.LMS = this;\r\n    this._LME.on(\'error\', function (e) { this._error = e; this.LMS.emit(\'error\', e); });\r\n    this._LME.on(\'connect\', function ()\r\n    {\r\n        this._connected = true;\r\n        this._emitConnected = false;\r\n        this.on(\'data\', function (chunk) {\r\n            // this = HECI\r\n            var cmd = chunk.readUInt8(0);\r\n            //console.log(\'LME Command \' + cmd + \', \' + chunk.length + \' byte(s).\');\r\n            \r\n            switch (cmd) {\r\n                default:\r\n                    console.log(\'Unhandled LME Command \' + cmd + \', \' + chunk.length + \' byte(s).\');\r\n                    break;\r\n                case APF_SERVICE_REQUEST:\r\n                    var nameLen = chunk.readUInt32BE(1);\r\n                    var name = chunk.slice(5, nameLen + 5);\r\n                    //console.log(\"Service Request for: \" + name);\r\n                    if (name == \'pfwd@amt.intel.com\' || name == \'auth@amt.intel.com\') {\r\n                        var outBuffer = Buffer.alloc(5 + nameLen);\r\n                        outBuffer.writeUInt8(6, 0);\r\n                        outBuffer.writeUInt32BE(nameLen, 1);\r\n                        outBuffer.write(name.toString(), 5);\r\n                        this.write(outBuffer);\r\n                        //console.log(\'Answering APF_SERVICE_REQUEST\');\r\n                    } else {\r\n                        //console.log(\'UNKNOWN APF_SERVICE_REQUEST\');\r\n                    }\r\n                    break;\r\n                case APF_GLOBAL_REQUEST:\r\n                    var nameLen = chunk.readUInt32BE(1);\r\n                    var name = chunk.slice(5, nameLen + 5).toString();\r\n\r\n                    switch (name) {\r\n                        case \'tcpip-forward\':\r\n                            var len = chunk.readUInt32BE(nameLen + 6);\r\n                            var port = chunk.readUInt32BE(nameLen + 10 + len);\r\n                            //console.log(\"[\" + chunk.length + \"/\" + len + \"] APF_GLOBAL_REQUEST for: \" + name + \" on port \" + port);\r\n                            if (this[name] == undefined) { this[name] = {}; }\r\n                            if (this[name][port] != null) { // Close the existing binding\r\n                                for (var i in this.sockets) {\r\n                                    var channel = this.sockets[i];\r\n                                    if (channel.localPort == port) { this.sockets[i].end(); delete this.sockets[i]; } // Close this socket\r\n                                }\r\n                            }\r\n                            if (this[name][port] == null)\r\n                            {\r\n                                try\r\n                                {\r\n                                    // Bind a new server socket if not already present\r\n                                    this[name][port] = require(\'net\').createServer();\r\n                                    this[name][port].descriptorMetadata = \'amt-lme (port: \' + port + \')\';\r\n                                    this[name][port].HECI = this;\r\n                                    if (lme_port_offset == 0) {\r\n                                        if (lme_bindany) {\r\n                                            this[name][port].listen({ port: port }); // Bind all mode\r\n                                        } else {\r\n                                            this[name][port].listen({ port: port, host: \'127.0.0.1\' }); // Normal mode\r\n                                        }\r\n                                    } else {\r\n                                        this[name][port].listen({ port: (port + lme_port_offset) }); // Debug mode\r\n                                    }\r\n                                    this[name][port].on(\'connection\', function (socket) {\r\n                                        //console.log(\'New [\' + socket.remoteFamily + \'] TCP Connection on: \' + socket.remoteAddress + \' :\' + socket.localPort);\r\n                                        this.HECI.LMS.bindDuplexStream(socket, socket.remoteFamily, socket.localPort - lme_port_offset);\r\n                                    });\r\n                                    this._binded[port] = true;\r\n                                    if (!this._emitConnected)\r\n                                    {\r\n                                        this._emitConnected = true;\r\n                                        this.LMS.emit(\'error\', \'APF/BIND error\');\r\n                                    }\r\n                                    this.LMS.emit(\'bind\', this._binded);\r\n                                } catch (ex)\r\n                                {\r\n                                    console.info1(ex, \'Port \' + port);\r\n                                    if(!this._emitConnected)\r\n                                    {\r\n                                        this._emitConnected = true;\r\n                                        this.LMS.emit(\'error\', \'APF/BIND error\');\r\n                                    }\r\n                                }\r\n                            }\r\n                            var outBuffer = Buffer.alloc(5);\r\n                            outBuffer.writeUInt8(81, 0);\r\n                            outBuffer.writeUInt32BE(port, 1);\r\n                            this.write(outBuffer);\r\n                            break;\r\n                        case \'cancel-tcpip-forward\':\r\n                            var outBuffer = Buffer.alloc(1);\r\n                            outBuffer.writeUInt8(APF_REQUEST_SUCCESS, 0);\r\n                            this.write(outBuffer);\r\n                            break;\r\n                        case \'udp-send-to@amt.intel.com\':\r\n                            var outBuffer = Buffer.alloc(1);\r\n                            outBuffer.writeUInt8(APF_REQUEST_FAILURE, 0);\r\n                            this.write(outBuffer);\r\n                            break;\r\n                        default:\r\n                            //console.log(\"Unknown APF_GLOBAL_REQUEST for: \" + name);\r\n                            break;\r\n                    }\r\n                    break;\r\n                case APF_CHANNEL_OPEN_CONFIRMATION:\r\n                    var rChannel = chunk.readUInt32BE(1);\r\n                    var sChannel = chunk.readUInt32BE(5);\r\n                    var wSize = chunk.readUInt32BE(9);\r\n                    //console.log(\'rChannel/\' + rChannel + \', sChannel/\' + sChannel + \', wSize/\' + wSize);\r\n                    if (this.sockets[rChannel] != undefined) {\r\n                        this.sockets[rChannel].lme.amtId = sChannel;\r\n                        this.sockets[rChannel].lme.rxWindow = wSize;\r\n                        this.sockets[rChannel].lme.txWindow = wSize;\r\n                        this.sockets[rChannel].lme.LME_CHANNEL_STATUS = \'LME_CS_CONNECTED\';\r\n                        //console.log(\'LME_CS_CONNECTED\');\r\n                        this.sockets[rChannel].bufferedStream = new stream_bufferedWrite();\r\n                        this.sockets[rChannel].bufferedStream.socket = this.sockets[rChannel];\r\n                        this.sockets[rChannel].bufferedStream.on(\'readable\', function () {\r\n                            if (this.socket.lme.txWindow > 0) {\r\n                                var buffer = this.read(this.socket.lme.txWindow);\r\n                                var packet = Buffer.alloc(9 + buffer.length);\r\n                                packet.writeUInt8(APF_CHANNEL_DATA, 0);\r\n                                packet.writeUInt32BE(this.socket.lme.amtId, 1);\r\n                                packet.writeUInt32BE(buffer.length, 5);\r\n                                buffer.copy(packet, 9);\r\n                                this.socket.lme.txWindow -= buffer.length;\r\n                                this.socket.HECI.write(packet);\r\n                            }\r\n                        });\r\n                        this.sockets[rChannel].bufferedStream.on(\'drain\', function () {\r\n                            this.socket.resume();\r\n                        });\r\n                        this.sockets[rChannel].on(\'data\', function (chunk) {\r\n                            if (!this.bufferedStream.write(chunk)) { this.pause(); }\r\n                        });\r\n                        this.sockets[rChannel].on(\'end\', function () {\r\n                            var outBuffer = Buffer.alloc(5);\r\n                            outBuffer.writeUInt8(APF_CHANNEL_CLOSE, 0);\r\n                            outBuffer.writeUInt32BE(this.lme.amtId, 1);\r\n                            this.HECI.write(outBuffer);\r\n                        });\r\n                        this.sockets[rChannel].resume();\r\n                    }\r\n                    \r\n                    break;\r\n                case APF_PROTOCOLVERSION:\r\n                    var major = chunk.readUInt32BE(1);\r\n                    var minor = chunk.readUInt32BE(5);\r\n                    var reason = chunk.readUInt32BE(9);\r\n                    var outBuffer = Buffer.alloc(93);\r\n                    outBuffer.writeUInt8(192, 0);\r\n                    outBuffer.writeUInt32BE(1, 1);\r\n                    outBuffer.writeUInt32BE(0, 5);\r\n                    outBuffer.writeUInt32BE(reason, 9);\r\n                    //console.log(\'Answering PROTOCOL_VERSION\');\r\n                    this.write(outBuffer);\r\n                    break;\r\n                case APF_CHANNEL_WINDOW_ADJUST:\r\n                    var rChannelId = chunk.readUInt32BE(1);\r\n                    var bytesToAdd = chunk.readUInt32BE(5);\r\n                    if (this.sockets[rChannelId] != undefined) {\r\n                        this.sockets[rChannelId].lme.txWindow += bytesToAdd;\r\n                        if (!this.sockets[rChannelId].bufferedStream.isEmpty() && this.sockets[rChannelId].bufferedStream.isWaiting()) {\r\n                            this.sockets[rChannelId].bufferedStream.emit(\'readable\');\r\n                        }\r\n                    } else {\r\n                        console.log(\'Unknown Recipient ID/\' + rChannelId + \' for APF_CHANNEL_WINDOW_ADJUST\');\r\n                    }\r\n                    break;\r\n                case APF_CHANNEL_DATA:\r\n                    var rChannelId = chunk.readUInt32BE(1);\r\n                    var dataLen = chunk.readUInt32BE(5);\r\n                    var data = chunk.slice(9, 9 + dataLen);\r\n                    if ((this.sockets != null) && (this.sockets[rChannelId] != undefined)) {\r\n                        this.sockets[rChannelId].pendingBytes.push(data.length);\r\n                        this.sockets[rChannelId].write(data, function () {\r\n                            var written = this.pendingBytes.shift();\r\n                            //console.log(\'adjust\', this.lme.amtId, written);\r\n                            var outBuffer = Buffer.alloc(9);\r\n                            outBuffer.writeUInt8(APF_CHANNEL_WINDOW_ADJUST, 0);\r\n                            outBuffer.writeUInt32BE(this.lme.amtId, 1);\r\n                            outBuffer.writeUInt32BE(written, 5);\r\n                            this.HECI.write(outBuffer);\r\n                        });\r\n                    } else if ((this.insockets != null) && (this.insockets[rChannelId] != undefined)) {\r\n                        var channel = this.insockets[rChannelId];\r\n                        if (channel.data == null) { channel.data = data.toString(); } else { channel.data += data.toString(); }\r\n                        channel.rxWindow += dataLen;\r\n                        //console.log(\'IN DATA\', channel.rxWindow, channel.data.length, dataLen, channel.amtId, data.toString());\r\n                        var httpData = parseHttp(channel.data);\r\n                        if ((httpData != null) || (channel.data.length >= 8000)) {\r\n                            // Parse the WSMAN\r\n                            var notify = null;\r\n                            if (xmlParser != null) { try { notify = xmlParser.ParseWsman(httpData); } catch (e) { } }\r\n\r\n                            // Event the http data\r\n                            if (notify != null) { this.LMS.emit(\'notify\', notify, channel.options, _lmsNotifyToCode(notify)); }\r\n\r\n                            // Send channel close\r\n                            var buffer = Buffer.alloc(5);\r\n                            buffer.writeUInt8(APF_CHANNEL_CLOSE, 0);\r\n                            buffer.writeUInt32BE(amtId, 1);\r\n                            this.write(buffer);\r\n                        } else {\r\n                            if (channel.rxWindow > 6000) {\r\n                                // Send window adjust\r\n                                var buffer = Buffer.alloc(9);\r\n                                buffer.writeUInt8(APF_CHANNEL_WINDOW_ADJUST, 0);\r\n                                buffer.writeUInt32BE(channel.amtId, 1);\r\n                                buffer.writeUInt32BE(channel.rxWindow, 5);\r\n                                this.write(buffer);\r\n                                channel.rxWindow = 0;\r\n                            }\r\n                        }\r\n                    } else {\r\n                        console.log(\'Unknown Recipient ID/\' + rChannelId + \' for APF_CHANNEL_DATA\');\r\n                    }\r\n                    break;\r\n                case APF_CHANNEL_OPEN_FAILURE:\r\n                    var rChannelId = chunk.readUInt32BE(1);\r\n                    var reasonCode = chunk.readUInt32BE(5);\r\n                    if ((this.sockets != null) && (this.sockets[rChannelId] != undefined)) {\r\n                        this.sockets[rChannelId].end();\r\n                        delete this.sockets[rChannelId];\r\n                    } else if ((this.insockets != null) && (this.insockets[rChannelId] != undefined)) {\r\n                        delete this.insockets[rChannelId];\r\n                    } else {\r\n                        console.log(\'Unknown Recipient ID/\' + rChannelId + \' for APF_CHANNEL_OPEN_FAILURE\');\r\n                    }\r\n                    break;\r\n                case APF_CHANNEL_CLOSE:\r\n                    var rChannelId = chunk.readUInt32BE(1);\r\n                    if ((this.sockets != null) && (this.sockets[rChannelId] != undefined)) {\r\n                        this.sockets[rChannelId].end();\r\n                        var amtId = this.sockets[rChannelId].lme.amtId;\r\n                        var buffer = Buffer.alloc(5);\r\n                        delete this.sockets[rChannelId];\r\n                        \r\n                        buffer.writeUInt8(APF_CHANNEL_CLOSE, 0); // ????????????????????????????\r\n                        buffer.writeUInt32BE(amtId, 1);\r\n                        this.write(buffer);\r\n                    } else if ((this.insockets != null) && (this.insockets[rChannelId] != undefined)) {\r\n                        delete this.insockets[rChannelId];\r\n                        // Should I send a close back????\r\n                    } else {\r\n                        console.log(\'Unknown Recipient ID/\' + rChannelId + \' for APF_CHANNEL_CLOSE\');\r\n                    }\r\n                    break;\r\n                case APF_CHANNEL_OPEN:\r\n                    var nameLen = chunk.readUInt32BE(1);\r\n                    var name = chunk.slice(5, nameLen + 5).toString();\r\n                    var channelSender = chunk.readUInt32BE(nameLen + 5);\r\n                    var initialWindowSize = chunk.readUInt32BE(nameLen + 9);\r\n                    var hostToConnectLen = chunk.readUInt32BE(nameLen + 17);\r\n                    var hostToConnect = chunk.slice(nameLen + 21, nameLen + 21 + hostToConnectLen).toString();\r\n                    var portToConnect = chunk.readUInt32BE(nameLen + 21 + hostToConnectLen);\r\n                    var originatorIpLen = chunk.readUInt32BE(nameLen + 25 + hostToConnectLen);\r\n                    var originatorIp = chunk.slice(nameLen + 29 + hostToConnectLen, nameLen + 29 + hostToConnectLen + originatorIpLen).toString();\r\n                    var originatorPort = chunk.readUInt32BE(nameLen + 29 + hostToConnectLen + originatorIpLen);\r\n                    //console.log(\'APF_CHANNEL_OPEN\', name, channelSender, initialWindowSize, \'From: \' + originatorIp + \':\' + originatorPort, \'To: \' + hostToConnect + \':\' + portToConnect);\r\n\r\n                    if (this.insockets == null) { this.insockets = {}; }\r\n                    var ourId = ++lme_id;\r\n                    var insocket = new lme_object();\r\n                    insocket.ourId = ourId;\r\n                    insocket.amtId = channelSender;\r\n                    insocket.txWindow = initialWindowSize;\r\n                    insocket.rxWindow = 0;\r\n                    insocket.options = { target: hostToConnect, targetPort: portToConnect, source: originatorIp, sourcePort: originatorPort };\r\n                    this.insockets[ourId] = insocket;\r\n\r\n                    var buffer = Buffer.alloc(17);\r\n                    buffer.writeUInt8(APF_CHANNEL_OPEN_CONFIRMATION, 0);\r\n                    buffer.writeUInt32BE(channelSender, 1);     // Intel AMT sender channel\r\n                    buffer.writeUInt32BE(ourId, 5);             // Our receiver channel id\r\n                    buffer.writeUInt32BE(4000, 9);              // Initial Window Size\r\n                    buffer.writeUInt32BE(0xFFFFFFFF, 13);       // Reserved\r\n                    this.write(buffer);\r\n\r\n                    /*\r\n                    var buffer = Buffer.alloc(17);\r\n                    buffer.writeUInt8(APF_CHANNEL_OPEN_FAILURE, 0);\r\n                    buffer.writeUInt32BE(channelSender, 1);     // Intel AMT sender channel\r\n                    buffer.writeUInt32BE(2, 5);                 // Reason code\r\n                    buffer.writeUInt32BE(0, 9);                 // Reserved\r\n                    buffer.writeUInt32BE(0, 13);                // Reserved\r\n                    this.write(buffer);\r\n                    console.log(\'Sent APF_CHANNEL_OPEN_FAILURE\', channelSender);\r\n                    */\r\n\r\n                    break;\r\n            }\r\n        });\r\n        //\r\n        // Due to a change in behavior with AMT/11 (and possibly earlier), we are not going to emit \'connect\' here, until\r\n        // we can verify that the first APF/Channel can be bound. Older AMT, like AMT/7 only allowed a single LME connection, so we\r\n        // used to emit connect here. However, newer AMT\'s will allow more than 1 LME connection, which will result in APF/Bind failure\r\n        //\r\n        //this.LMS.emit(\'connect\');\r\n        this.resume();\r\n\r\n    });\r\n    \r\n    this.bindDuplexStream = function (duplexStream, remoteFamily, localPort) {\r\n        var socket = duplexStream;\r\n        //console.log(\'New [\' + remoteFamily + \'] Virtual Connection/\' + socket.localPort);\r\n        socket.pendingBytes = [];\r\n        socket.HECI = this._LME;\r\n        socket.LMS = this;\r\n        socket.lme = new lme_object();\r\n        socket.lme.Socket = socket;\r\n        socket.localPort = localPort;\r\n        var buffer = new MemoryStream();\r\n        buffer.writeUInt8(0x5A);\r\n        buffer.writeUInt32BE(15);\r\n        buffer.write(\'forwarded-tcpip\');\r\n        buffer.writeUInt32BE(socket.lme.ourId);\r\n        buffer.writeUInt32BE(this.INITIAL_RXWINDOW_SIZE);\r\n        buffer.writeUInt32BE(0xFFFFFFFF);\r\n        for (var i = 0; i < 2; ++i) {\r\n            if (remoteFamily == \'IPv6\') {\r\n                buffer.writeUInt32BE(3);\r\n                buffer.write(\'::1\');\r\n            } else {\r\n                buffer.writeUInt32BE(9);\r\n                buffer.write(\'127.0.0.1\');\r\n            }\r\n            buffer.writeUInt32BE(localPort);\r\n        }\r\n        this._LME.write(buffer.buffer);\r\n        if (this._LME.sockets == undefined) { this._LME.sockets = {}; }\r\n        this._LME.sockets[socket.lme.ourId] = socket;\r\n        socket.pause();\r\n    };\r\n    \r\n    this._LME.connect(heci.GUIDS.LME, { noPipeline: 0 });\r\n}\r\n\r\nfunction parseHttp(httpData) {\r\n    var i = httpData.indexOf(\'\\r\\n\\r\\n\');\r\n    if ((i == -1) || (httpData.length < (i + 2))) { return null; }\r\n    var headers = require(\'http-headers\')(httpData.substring(0, i), true);\r\n    var contentLength = parseInt(headers[\'content-length\']);\r\n    if (httpData.length >= contentLength + i + 4) { return httpData.substring(i + 4, i + 4 + contentLength); }\r\n    return null;\r\n}\r\n\r\nfunction _lmsNotifyToCode(notify) {\r\n    if ((notify == null) || (notify.Body == null) || (notify.Body.MessageID == null)) return null;\r\n    var msgid = notify.Body.MessageID;\r\n    try { msgid += \'-\' + notify.Body.MessageArguments[0]; } catch (e) { }\r\n    return msgid;\r\n}\r\n\r\nmodule.exports = lme_heci;\r\n"); addedModules.push("amt-lme"); } catch (ex) { }
try { addModule("amt-manage", "/*\r\nCopyright 2018-2021 Intel Corporation\r\n\r\nLicensed under the Apache License, Version 2.0 (the \"License\");\r\nyou may not use this file except in compliance with the License.\r\nYou may obtain a copy of the License at\r\n\r\n    http://www.apache.org/licenses/LICENSE-2.0\r\n\r\nUnless required by applicable law or agreed to in writing, software\r\ndistributed under the License is distributed on an \"AS IS\" BASIS,\r\nWITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.\r\nSee the License for the specific language governing permissions and\r\nlimitations under the License.\r\n*/\r\n\r\n/**\r\n* @fileoverview Intel(r) AMT Management\r\n* @author Ylian Saint-Hilaire\r\n* @version v0.1.0\r\n*/\r\n\r\n/**\r\n * Construct a AmtStackCreateService object, this ia the main Intel AMT communication stack.\r\n * @constructor\r\n */\r\nfunction AmtManager(agent, db, isdebug) {\r\n    var sendConsole = function (msg) { agent.SendCommand({ \'action\': \'msg\', \'type\': \'console\', \'value\': msg }); }\r\n    var debug = function (msg) { if (isdebug) { sendConsole(\'amt-manager: \' + msg + \'<br />\'); } }\r\n    var amtMei = null, amtMeiState = 0;\r\n    var amtLms = null, amtLmsState = 0;\r\n    var amtGetVersionResult = null;\r\n    var obj = this;\r\n    var mestate;\r\n    var trustedHashes = null;;\r\n\r\n    require(\'events\').EventEmitter.call(obj, true)\r\n        .createEvent(\'stateChange_LMS\')\r\n        .createEvent(\'portBinding_LMS\');\r\n    obj._lmsstate = 0;\r\n    obj._mapping = [];\r\n\r\n    obj.on(\'newListener\', function (name, callback) {\r\n        if (name == \'portBinding_LMS\') { callback.call(this, this._mapping); }\r\n    });\r\n\r\n    Object.defineProperty(obj, \'lmsstate\',\r\n        {\r\n            get: function () { return (this._lmsstate); },\r\n            set: function (value) { if (this._lmsstate != value) { this._lmsstate = value; this.emit(\'stateChange_LMS\', value); } }\r\n        });\r\n\r\n    obj.state = 0;\r\n    obj.onStateChange = null;\r\n    obj.setDebug = function (x) { isdebug = x; }\r\n\r\n    // Try to load up the MEI module\r\n    var rebindToMeiRetrys = 0;\r\n    obj.reset = function () {\r\n        ++rebindToMeiRetrys;\r\n        obj.amtMei = null, amtMei = null, amtMeiState = 0, amtLms = null, amtLmsState = 0, obj.state = 0, obj.lmsstate = 0;\r\n        //debug(\'Binding to MEI\');\r\n        try {\r\n            var amtMeiLib = require(\'amt-mei\');\r\n            obj.amtMei = amtMei = new amtMeiLib();\r\n            amtMei.on(\'error\', function (e) { debug(\'MEI error\'); amtMei = null; amtMeiState = -1; obj.state = -1; if (obj.onStateChange != null) { obj.onStateChange(amtMeiState); } });\r\n            amtMei.getVersion(function (result) {\r\n                if (result == null) {\r\n                    obj.state = amtMeiState = -1;\r\n                    if (obj.onStateChange != null) { obj.onStateChange(amtMeiState); }\r\n                    if (rebindToMeiRetrys < 10) { setTimeout(obj.reset, 10000); }\r\n                } else {\r\n                    amtGetVersionResult = result;\r\n                    obj.state = amtMeiState = 2;\r\n                    rebindToMeiRetrys = 0;\r\n                    if (obj.onStateChange != null) { obj.onStateChange(amtMeiState); }\r\n                    //debug(\'MEI binded\');\r\n                    obj.lmsreset();\r\n                }\r\n            });\r\n        } catch (ex) { debug(\"MEI exception: \" + ex); amtMei = null; amtMeiState = -1; obj.state = -1; }\r\n    }\r\n\r\n    // Get Intel MEI State in a flexible way\r\n    // Flags: 1 = Versions, 2 = OsAdmin, 4 = Hashes, 8 = Network\r\n    var getMeiStateCache = {}; // Some MEI calls will only be made once and cached here.\r\n    obj.getMeiState = function(flags, func) {\r\n        if ((amtMei == null) || (amtMeiState < 2)) { if (func != null) { func(null); } return; }\r\n        try {\r\n            var amtMeiTmpState = { \'core-ver\': 1, OsHostname: require(\'os\').hostname(), Flags: 0 }; // Flags: 1=EHBC, 2=CCM, 4=ACM\r\n            if (getMeiStateCache.MeiVersion != null) { amtMeiTmpState.MeiVersion = getMeiStateCache.MeiVersion; } else { amtMei.getProtocolVersion(function (result) { if (result != null) { getMeiStateCache.MeiVersion = amtMeiTmpState.MeiVersion = result; } }); }\r\n            if ((flags & 1) != 0) {\r\n                if (getMeiStateCache.Versions != null) {\r\n                    amtMeiTmpState.Versions = getMeiStateCache.Versions;\r\n                } else {\r\n                    amtMei.getVersion(function (result) { if (result) { getMeiStateCache.Versions = amtMeiTmpState.Versions = {}; for (var version in result.Versions) { amtMeiTmpState.Versions[result.Versions[version].Description] = result.Versions[version].Version; } } });\r\n                }\r\n            }\r\n            amtMei.getProvisioningMode(function (result) { if (result) { amtMeiTmpState.ProvisioningMode = result.mode; } });\r\n            amtMei.getProvisioningState(function (result) { if (result) { amtMeiTmpState.ProvisioningState = result.state; if (result.state != 2) { amtMei.stopConfiguration(function () { }); } } }); // 0: \"Not Activated (Pre)\", 1: \"Not Activated (In)\", 2: \"Activated\". Make sure to stop remote configuration if needed.\r\n            amtMei.getEHBCState(function (result) { if ((result != null) && (result.EHBC == true)) { amtMeiTmpState.Flags += 1; } });\r\n            amtMei.getControlMode(function (result) { if (result != null) { if (result.controlMode == 1) { amtMeiTmpState.Flags += 2; } if (result.controlMode == 2) { amtMeiTmpState.Flags += 4; } } }); // Flag 2 = CCM, 4 = ACM\r\n            //amtMei.getMACAddresses(function (result) { if (result) { amtMeiTmpState.mac = result; } });\r\n            if ((flags & 8) != 0) {\r\n                amtMei.getLanInterfaceSettings(0, function (result) {\r\n                    if (result) {\r\n                        amtMeiTmpState.net0 = result;\r\n                        var fqdn = null, interfaces = require(\'os\').networkInterfaces(); // Look for the DNS suffix for the Intel AMT Ethernet interface\r\n                        for (var i in interfaces) { for (var j in interfaces[i]) { if ((interfaces[i][j].mac == result.mac) && (interfaces[i][j].fqdn != null) && (interfaces[i][j].fqdn != \'\')) { amtMeiTmpState.OsDnsSuffix = interfaces[i][j].fqdn; } } }\r\n                    }\r\n                });\r\n                amtMei.getLanInterfaceSettings(1, function (result) { if (result) { amtMeiTmpState.net1 = result; } });\r\n            }\r\n            if (getMeiStateCache.UUID != null) { amtMeiTmpState.UUID = getMeiStateCache.UUID; } else { amtMei.getUuid(function (result) { if ((result != null) && (result.uuid != null)) { getMeiStateCache.UUID = amtMeiTmpState.UUID = result.uuid; } }); }\r\n            if ((flags & 2) != 0) { amtMei.getLocalSystemAccount(function (x) { if ((x != null) && x.user && x.pass) { amtMeiTmpState.OsAdmin = { user: x.user, pass: x.pass }; } }); }\r\n            amtMei.getDnsSuffix(function (result) { if (result != null) { amtMeiTmpState.DnsSuffix = result; } if ((flags & 4) == 0) { if (func != null) { func(amtMeiTmpState); } } });\r\n            if ((flags & 4) != 0) {\r\n                amtMei.getHashHandles(function (handles) {\r\n                    if ((handles != null) && (handles.length > 0)) { amtMeiTmpState.Hashes = []; } else { func(amtMeiTmpState); }\r\n                    var exitOnCount = handles.length;\r\n                    for (var i = 0; i < handles.length; ++i) { this.getCertHashEntry(handles[i], function (hashresult) { amtMeiTmpState.Hashes.push(hashresult); if (--exitOnCount == 0) { if (func != null) { func(amtMeiTmpState); } } }); }\r\n                });\r\n            }\r\n        } catch (e) { if (func != null) { func(null); } return; }\r\n    }\r\n\r\n    // Called on MicroLMS Intel AMT user notification\r\n    var handleAmtNotification = function (notifyMsg) {\r\n        if ((notifyMsg == null) || (notifyMsg.Body == null) || (notifyMsg.Body.MessageID == null) || (notifyMsg.Body.MessageArguments == null)) return null;\r\n        var amtMessage = notifyMsg.Body.MessageID, amtMessageArg = notifyMsg.Body.MessageArguments[0], notify = null;\r\n\r\n        switch (amtMessage) {\r\n            case \'iAMT0050\': { if (amtMessageArg == \'48\') { notify = \"Intel&reg; AMT Serial-over-LAN connected\"; } else if (amtMessageArg == \'49\') { notify = \"Intel&reg; AMT Serial-over-LAN disconnected\"; } break; } // SOL\r\n            case \'iAMT0052\': { if (amtMessageArg == \'1\') { notify = \"Intel&reg; AMT KVM connected\"; } else if (amtMessageArg == \'2\') { notify = \"Intel&reg; AMT KVM disconnected\"; } break; } // KVM\r\n            default: { break; }\r\n        }\r\n\r\n        // Sent to the entire group, no sessionid or userid specified.\r\n        if (notify != null) { agent.SendCommand({ \'action\': \'msg\', \'type\': \'notify\', \'value\': notify, \'tag\': \'general\', \'amtMessage\': amtMessage }); }\r\n    }\r\n\r\n    // Launch LMS\r\n    obj.lmsreset = function () {\r\n        //debug(\'Binding to LMS\');\r\n        obj.lmsstate = 0;\r\n        try {\r\n            var lme_heci = require(\'amt-lme\');\r\n            obj.lmsstate = amtLmsState = 1;\r\n            amtLms = new lme_heci();\r\n            amtLms.on(\'error\', function (e) { amtLmsState = 0; obj.lmsstate = 0; amtLms = null; debug(\"LMS error: \" + e); });\r\n            amtLms.on(\'connect\', function () { amtLmsState = 2; obj.lmsstate = 2; debug(\"LMS connected\"); });\r\n            amtLms.on(\'bind\', function (map) { obj._mapping = map; obj.emit(\'portBinding_LMS\', map); });\r\n            amtLms.on(\'notify\', function (data, options, code) { handleAmtNotification(data); });\r\n        } catch (ex) {\r\n            require(\'MeshAgent\').SendCommand({ action: \'msg\', type: \'console\', value: \"ex: \" + ex });\r\n            amtLmsState = -1; obj.lmsstate = -1; amtLms = null;\r\n        }\r\n    }\r\n\r\n    // Start host based ACM activation with TLS\r\n    obj.startConfigurationHBased = function startConfigurationHBased(certHash, hostVpn, dnsSuffixList, func) {\r\n        if ((amtMei == null) || (amtMeiState < 2)) { if (func != null) { func({ status: -100 }); } return; }\r\n        amtMei.startConfigurationHBased(certHash, hostVpn, dnsSuffixList, func);\r\n    }\r\n\r\n}\r\n\r\nmodule.exports = AmtManager;\r\n"); addedModules.push("amt-manage"); } catch (ex) { }
try { addModule("amt-mei", "/*\r\nCopyright 2018-2021 Intel Corporation\r\n\r\nLicensed under the Apache License, Version 2.0 (the \"License\");\r\nyou may not use this file except in compliance with the License.\r\nYou may obtain a copy of the License at\r\n\r\n    http://www.apache.org/licenses/LICENSE-2.0\r\n\r\nUnless required by applicable law or agreed to in writing, software\r\ndistributed under the License is distributed on an \"AS IS\" BASIS,\r\nWITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.\r\nSee the License for the specific language governing permissions and\r\nlimitations under the License.\r\n*/\r\n\r\nvar Q = require(\'queue\');\r\nvar g_internal = null;\r\n\r\nfunction retry_pthi_later()\r\n{\r\n    if (++g_internal.errorCount < 20)\r\n    {\r\n        g_internal.timeout = setTimeout(function (p)\r\n        {\r\n            p.connect(require(\'heci\').GUIDS.AMT, { noPipeline: 1 });\r\n        }, 250, this);\r\n    }\r\n    else\r\n    {\r\n        this.Parent.emit(\'error\', \'PTHI Connection could not be established\'); \r\n    }\r\n}\r\n\r\nfunction amt_heci()\r\n{\r\n    var emitterUtils = require(\'events\').inherits(this);\r\n    emitterUtils.createEvent(\'error\');\r\n\r\n    var heci = require(\'heci\');\r\n    var sendConsole = function (msg) { try { require(\'MeshAgent\').SendCommand({ \"action\": \"msg\", \"type\": \"console\", \"value\": msg }); } catch (ex) { } }\r\n\r\n    this._ObjectID = \"pthi\";\r\n    var that = this;\r\n    if (g_internal == null)\r\n    {\r\n        g_internal = { _rq: new Q(), _amt: null, errorCount: 0 };\r\n        g_internal._setupPTHI = function _g_setupPTHI()\r\n        {\r\n            console.info1(\'setupPTHI()\');\r\n            this._amt = heci.create();\r\n            this._amt.descriptorMetadata = \"amt-pthi\";\r\n            this._amt.BiosVersionLen = 65;\r\n            this._amt.UnicodeStringLen = 20;\r\n            this._amt.Parent = that;\r\n\r\n            this._amt.on(\'error\', function _amtOnError(e)\r\n            {\r\n                console.info1(\'PTHIError: \' + e);\r\n                if (g_internal._rq.isEmpty())\r\n                {\r\n                    console.info1(\' Queue is empty\');\r\n                    this.Parent.emit(\'error\', e); // No pending requests, so propagate the error up\r\n                }\r\n                else\r\n                {\r\n                    console.info1(\' Queue is NOT empty\');\r\n\r\n                    // Try again\r\n                    retry_pthi_later.call(this);\r\n                }\r\n            });\r\n            this._amt.on(\'connect\', function _amtOnConnect()\r\n            {\r\n                g_internal.errorCount = 0;\r\n                this.on(\'data\', function _amtOnData(chunk)\r\n                {\r\n                    //console.log(\"Received: \" + chunk.length + \" bytes\");\r\n                    var header = this.Parent.getCommand(chunk);\r\n                    console.info1(\"CMD = \" + header.Command + \" (Status: \" + header.Status + \") Response = \" + header.IsResponse);\r\n\r\n                    var user = g_internal._rq.deQueue();\r\n                    var params = user.optional;\r\n                    var callback = user.func;\r\n\r\n                    params.unshift(header);\r\n                    callback.apply(this.Parent, params);\r\n\r\n                    if (g_internal._rq.isEmpty())\r\n                    {\r\n                        console.info1(\'No more requests, disconnecting\');\r\n\r\n                        // No More Requests, we can close PTHI\r\n                        g_internal._amt.disconnect();\r\n                        g_internal._amt = null;\r\n                    }\r\n                    else\r\n                    {\r\n                        // Send the next request\r\n                        console.info1(\'Sending Next Request\');\r\n                        this.write(g_internal._rq.peekQueue().send);\r\n                    }\r\n                });\r\n\r\n                // Start sending requests\r\n                this.write(g_internal._rq.peekQueue().send);\r\n            });\r\n\r\n\r\n\r\n        };\r\n    }\r\n\r\n    \r\n    function trim(x) { var y = x.indexOf(\'\\0\'); if (y >= 0) { return x.substring(0, y); } else { return x; } }\r\n    this.getCommand = function getCommand(chunk) {\r\n        var command = chunk.length == 0 ? (g_internal._rq.peekQueue().cmd | 0x800000) : chunk.readUInt32LE(4);\r\n        var ret = { IsResponse: (command & 0x800000) == 0x800000 ? true : false, Command: (command & 0x7FFFFF), Status: chunk.length != 0 ? chunk.readUInt32LE(12) : -1, Data: chunk.length != 0 ? chunk.slice(16) : null };\r\n        return (ret);\r\n    };\r\n\r\n    this.sendCommand = function sendCommand()\r\n    {\r\n        if (arguments.length < 3 || typeof (arguments[0]) != \'number\' || typeof (arguments[1]) != \'object\' || typeof (arguments[2]) != \'function\') { throw (\'invalid parameters\'); }\r\n        var args = [];\r\n        for (var i = 3; i < arguments.length; ++i) { args.push(arguments[i]); }\r\n\r\n        console.info1(\'sendCommand(\' + arguments[0] + \')\', this._hashCode());\r\n\r\n        var header = Buffer.from(\'010100000000000000000000\', \'hex\');\r\n        header.writeUInt32LE(arguments[0] | 0x04000000, 4);\r\n        header.writeUInt32LE(arguments[1] == null ? 0 : arguments[1].length, 8);\r\n\r\n        g_internal._rq.enQueue({ cmd: arguments[0], func: arguments[2], optional: args, send: (arguments[1] == null ? header : Buffer.concat([header, arguments[1]])) });\r\n        if (!g_internal._amt)\r\n        {\r\n            g_internal._setupPTHI();\r\n            g_internal._amt.connect(heci.GUIDS.AMT, { noPipeline: 1 });\r\n        }\r\n    }\r\n\r\n    this.getVersion = function getVersion(callback) {\r\n        var optional = [];\r\n        for (var i = 1; i < arguments.length; ++i) { optional.push(arguments[i]); }\r\n        this.sendCommand(26, null, function (header, fn, opt) {\r\n            if (header.Status == 0) {\r\n                var i, CodeVersion = header.Data, val = { BiosVersion: CodeVersion.slice(0, g_internal._amt.BiosVersionLen).toString(), Versions: [] }, v = CodeVersion.slice(g_internal._amt.BiosVersionLen + 4);\r\n                for (i = 0; i < CodeVersion.readUInt32LE(g_internal._amt.BiosVersionLen) ; ++i)\r\n                {\r\n                    val.Versions[i] = { Description: v.slice(2, v.readUInt16LE(0) + 2).toString(), Version: v.slice(4 + g_internal._amt.UnicodeStringLen, 4 + g_internal._amt.UnicodeStringLen + v.readUInt16LE(2 + g_internal._amt.UnicodeStringLen)).toString() };\r\n                    v = v.slice(4 + (2 * g_internal._amt.UnicodeStringLen));\r\n                }\r\n                if (val.BiosVersion.indexOf(\'\\0\') > 0) { val.BiosVersion = val.BiosVersion.substring(0, val.BiosVersion.indexOf(\'\\0\')); }\r\n                opt.unshift(val);\r\n            } else {\r\n                opt.unshift(null);\r\n            }\r\n            fn.apply(this, opt);\r\n        }, callback, optional);\r\n    };\r\n\r\n    // Fill the left with zeros until the string is of a given length\r\n    function zeroLeftPad(str, len) {\r\n        if ((len == null) && (typeof (len) != \'number\')) { return null; }\r\n        if (str == null) str = \'\'; // If null, this is to generate zero leftpad string\r\n        var zlp = \'\';\r\n        for (var i = 0; i < len - str.length; i++) { zlp += \'0\'; }\r\n        return zlp + str;\r\n    }\r\n\r\n    this.getUuid = function getUuid(callback) {\r\n        var optional = [];\r\n        for (var i = 1; i < arguments.length; ++i) { optional.push(arguments[i]); }\r\n        this.sendCommand(0x5c, null, function (header, fn, opt) {\r\n            if (header.Status == 0) {\r\n                var result = {};\r\n                result.uuid = [zeroLeftPad(header.Data.readUInt32LE(0).toString(16), 8),\r\n                    zeroLeftPad(header.Data.readUInt16LE(4).toString(16), 4),\r\n                    zeroLeftPad(header.Data.readUInt16LE(6).toString(16), 4),\r\n                    zeroLeftPad(header.Data.readUInt16BE(8).toString(16), 4),\r\n                    zeroLeftPad(header.Data.slice(10).toString(\'hex\').toLowerCase(), 12)].join(\'-\');\r\n                opt.unshift(result);\r\n            } else {\r\n                opt.unshift(null);\r\n            }\r\n            fn.apply(this, opt);\r\n        }, callback, optional);\r\n    };\r\n\r\n    this.getProvisioningState = function getProvisioningState(callback) {\r\n        var optional = [];\r\n        for (var i = 1; i < arguments.length; ++i) { optional.push(arguments[i]); }\r\n        this.sendCommand(17, null, function (header, fn, opt) {\r\n            if (header.Status == 0) {\r\n                var result = {};\r\n                result.state = header.Data.readUInt32LE(0);\r\n                if (result.state < 3) { result.stateStr = [\"PRE\", \"IN\", \"POST\"][result.state]; }\r\n                opt.unshift(result);\r\n            } else {\r\n                opt.unshift(null);\r\n            }\r\n            fn.apply(this, opt);\r\n        }, callback, optional);\r\n    };\r\n    this.getProvisioningMode = function getProvisioningMode(callback) {\r\n        var optional = [];\r\n        for (var i = 1; i < arguments.length; ++i) { optional.push(arguments[i]); }\r\n        this.sendCommand(8, null, function (header, fn, opt) {\r\n            if (header.Status == 0) {\r\n                var result = {};\r\n                result.mode = header.Data.readUInt32LE(0);\r\n                if (result.mode < 4) { result.modeStr = [\"NONE\", \"ENTERPRISE\", \"SMALL_BUSINESS\", \"REMOTE_ASSISTANCE\"][result.mode]; }\r\n                result.legacy = header.Data.readUInt32LE(4) == 0 ? false : true;\r\n                opt.unshift(result);\r\n            } else {\r\n                opt.unshift(null);\r\n            }\r\n            fn.apply(this, opt);\r\n        }, callback, optional);\r\n    };\r\n    this.getEHBCState = function getEHBCState(callback) {\r\n        var optional = [];\r\n        for (var i = 1; i < arguments.length; ++i) { optional.push(arguments[i]); }\r\n        this.sendCommand(132, null, function (header, fn, opt) {\r\n            if (header.Status == 0) {\r\n                opt.unshift({ EHBC: header.Data.readUInt32LE(0) != 0 });\r\n            } else {\r\n                opt.unshift(null);\r\n            }\r\n            fn.apply(this, opt);\r\n        }, callback, optional);\r\n    };\r\n    this.getControlMode = function getControlMode(callback) {\r\n        var optional = [];\r\n        for (var i = 1; i < arguments.length; ++i) { optional.push(arguments[i]); }\r\n        this.sendCommand(107, null, function (header, fn, opt) {\r\n            if (header.Status == 0) {\r\n                var result = {};\r\n                result.controlMode = header.Data.readUInt32LE(0);\r\n                if (result.controlMode < 3) { result.controlModeStr = [\"NONE_RPAT\", \"CLIENT\", \"ADMIN\", \"REMOTE_ASSISTANCE\"][result.controlMode]; }\r\n                opt.unshift(result);\r\n            } else {\r\n                opt.unshift(null);\r\n            }\r\n            fn.apply(this, opt);\r\n        }, callback, optional);\r\n    };\r\n    this.getMACAddresses = function getMACAddresses(callback) {\r\n        var optional = [];\r\n        for (var i = 1; i < arguments.length; ++i) { optional.push(arguments[i]); }\r\n        this.sendCommand(37, null, function (header, fn, opt) {\r\n            if (header.Status == 0) {\r\n                opt.unshift({ DedicatedMAC: header.Data.slice(0, 6).toString(\'hex:\'), HostMAC: header.Data.slice(6, 12).toString(\'hex:\') });\r\n            } else { opt.unshift({ DedicatedMAC: null, HostMAC: null }); }\r\n            fn.apply(this, opt);\r\n        }, callback, optional);\r\n    };\r\n    this.getDnsSuffix = function getDnsSuffix(callback) {\r\n        var optional = [];\r\n        for (var i = 1; i < arguments.length; ++i) { optional.push(arguments[i]); }\r\n        this.sendCommand(54, null, function (header, fn, opt) {\r\n            if (header.Status == 0) {\r\n                var resultLen = header.Data.readUInt16LE(0);\r\n                if (resultLen > 0) { opt.unshift(header.Data.slice(2, 2 + resultLen).toString()); } else { opt.unshift(null); }\r\n            } else {\r\n                opt.unshift(null);\r\n            }\r\n            fn.apply(this, opt);\r\n        }, callback, optional);\r\n    };\r\n    this.getHashHandles = function getHashHandles(callback) {\r\n        var optional = [];\r\n        for (var i = 1; i < arguments.length; ++i) { optional.push(arguments[i]); }\r\n        this.sendCommand(0x2C, null, function (header, fn, opt) {\r\n            var result = [];\r\n            if (header.Status == 0) {\r\n                var resultLen = header.Data.readUInt32LE(0);\r\n                for (var i = 0; i < resultLen; ++i) {\r\n                    result.push(header.Data.readUInt32LE(4 + (4 * i)));\r\n                }\r\n            }\r\n            opt.unshift(result);\r\n            fn.apply(this, opt);\r\n        }, callback, optional);\r\n    };\r\n    this.getCertHashEntry = function getCertHashEntry(handle, callback) {\r\n        var optional = [];\r\n        for (var i = 2; i < arguments.length; ++i) { optional.push(arguments[i]); }\r\n\r\n        var data = Buffer.alloc(4);\r\n        data.writeUInt32LE(handle, 0);\r\n\r\n        this.sendCommand(0x2D, data, function (header, fn, opt) {\r\n            if (header.Status == 0) {\r\n                var result = {};\r\n                result.isDefault = header.Data.readUInt32LE(0);\r\n                result.isActive = header.Data.readUInt32LE(4);\r\n                result.hashAlgorithm = header.Data.readUInt8(72);\r\n                if (result.hashAlgorithm < 4) {\r\n                    result.hashAlgorithmStr = [\"MD5\", \"SHA1\", \"SHA256\", \"SHA512\"][result.hashAlgorithm];\r\n                    result.hashAlgorithmSize = [16, 20, 32, 64][result.hashAlgorithm];\r\n                    result.certificateHash = header.Data.slice(8, 8 + result.hashAlgorithmSize).toString(\'hex\');\r\n                }\r\n                result.name = header.Data.slice(73 + 2, 73 + 2 + header.Data.readUInt16LE(73)).toString();\r\n                opt.unshift(result);\r\n            } else {\r\n                opt.unshift(null);\r\n            }\r\n            fn.apply(this, opt);\r\n        }, callback, optional);\r\n    };\r\n    this.getCertHashEntries = function getCertHashEntries(callback) {\r\n        var optional = [];\r\n        for (var i = 1; i < arguments.length; ++i) { optional.push(arguments[i]); }\r\n\r\n        this.getHashHandles(function (handles, fn, opt) {\r\n            var entries = [];\r\n            this.getCertHashEntry(handles.shift(), this._getHashEntrySink, fn, opt, entries, handles);\r\n        }, callback, optional);\r\n    };\r\n\r\n    this._getHashEntrySink = function _getHashEntrySink(result, fn, opt, entries, handles) {\r\n        entries.push(result);\r\n        if (handles.length > 0) {\r\n            this.getCertHashEntry(handles.shift(), this._getHashEntrySink, fn, opt, entries, handles);\r\n        } else {\r\n            opt.unshift(entries);\r\n            fn.apply(this, opt);\r\n        }\r\n    }\r\n    this.getLocalSystemAccount = function getLocalSystemAccount(callback) {\r\n        var optional = [];\r\n        for (var i = 1; i < arguments.length; ++i) { optional.push(arguments[i]); }\r\n        this.sendCommand(103, Buffer.alloc(40), function (header, fn, opt) {\r\n            if (header.Status == 0 && header.Data.length == 68) {\r\n                opt.unshift({ user: trim(header.Data.slice(0, 33).toString()), pass: trim(header.Data.slice(33, 67).toString()), raw: header.Data });\r\n            }\r\n            else {\r\n                opt.unshift(null);\r\n            }\r\n            fn.apply(this, opt);\r\n        }, callback, optional);\r\n    }\r\n    this.getLanInterfaceSettings = function getLanInterfaceSettings(index, callback) {\r\n        var optional = [];\r\n        for (var i = 2; i < arguments.length; ++i) { optional.push(arguments[i]); }\r\n        var ifx = Buffer.alloc(4);\r\n        ifx.writeUInt32LE(index);\r\n        this.sendCommand(0x48, ifx, function onGetLanInterfaceSettings(header, fn, opt) {\r\n            if (header.Status == 0) {\r\n                var info = {};\r\n                info.enabled = header.Data.readUInt32LE(0);\r\n                info.dhcpEnabled = header.Data.readUInt32LE(8);\r\n                switch (header.Data[12]) {\r\n                    case 1:\r\n                        info.dhcpMode = \'ACTIVE\'\r\n                        break;\r\n                    case 2:\r\n                        info.dhcpMode = \'PASSIVE\'\r\n                        break;\r\n                    default:\r\n                        info.dhcpMode = \'UNKNOWN\';\r\n                        break;\r\n                }\r\n                info.mac = header.Data.slice(14).toString(\'hex:\');\r\n\r\n                var addr = header.Data.readUInt32LE(4);\r\n                info.address = ((addr >> 24) & 255) + \'.\' + ((addr >> 16) & 255) + \'.\' + ((addr >> 8) & 255) + \'.\' + (addr & 255);\r\n                opt.unshift(info);\r\n                fn.apply(this, opt);\r\n            }\r\n            else {\r\n                opt.unshift(null);\r\n                fn.apply(this, opt);\r\n            }\r\n        }, callback, optional);\r\n\r\n    };\r\n    this.unprovision = function unprovision(mode, callback) {\r\n        var optional = [];\r\n        for (var i = 2; i < arguments.length; ++i) { optional.push(arguments[i]); }\r\n        var data = Buffer.alloc(4);\r\n        data.writeUInt32LE(mode, 0);\r\n        this.sendCommand(16, data, function (header, fn, opt) {\r\n            opt.unshift(header.Status);\r\n            fn.apply(this, opt);\r\n        }, callback, optional);\r\n    }\r\n    this.startConfiguration = function startConfiguration(callback) {\r\n        var optional = [];\r\n        for (var i = 1; i < arguments.length; ++i) { optional.push(arguments[i]); }\r\n        this.sendCommand(0x29, null, function (header, fn, opt) { opt.unshift(header.Status); fn.apply(this, opt); }, callback, optional);\r\n    }\r\n    this.stopConfiguration = function stopConfiguration(callback) {\r\n        var optional = [];\r\n        for (var i = 1; i < arguments.length; ++i) { optional.push(arguments[i]); }\r\n        this.sendCommand(0x5E, null, function (header, fn, opt) { opt.unshift(header.Status); fn.apply(this, opt); }, callback, optional);\r\n    }\r\n    this.openUserInitiatedConnection = function openUserInitiatedConnection(callback) {\r\n        var optional = [];\r\n        for (var i = 1; i < arguments.length; ++i) { optional.push(arguments[i]); }\r\n        this.sendCommand(0x44, null, function (header, fn, opt) { opt.unshift(header.Status); fn.apply(this, opt); }, callback, optional);\r\n    }\r\n    this.closeUserInitiatedConnection = function closeUnserInitiatedConnected(callback) {\r\n        var optional = [];\r\n        for (var i = 1; i < arguments.length; ++i) { optional.push(arguments[i]); }\r\n        this.sendCommand(0x45, null, function (header, fn, opt) { opt.unshift(header.Status); fn.apply(this, opt); }, callback, optional);\r\n    }\r\n    this.getRemoteAccessConnectionStatus = function getRemoteAccessConnectionStatus(callback) {\r\n        var optional = [];\r\n        for (var i = 1; i < arguments.length; ++i) { optional.push(arguments[i]); }\r\n        this.sendCommand(0x46, null, function (header, fn, opt) {\r\n            if (header.Status == 0) {\r\n                var hostname = header.Data.slice(14, header.Data.readUInt16LE(12) + 14).toString()\r\n                opt.unshift({ status: header.Status, networkStatus: header.Data.readUInt32LE(0), remoteAccessStatus: header.Data.readUInt32LE(4), remoteAccessTrigger: header.Data.readUInt32LE(8), mpsHostname: hostname, raw: header.Data });\r\n            } else {\r\n                opt.unshift({ status: header.Status });\r\n            }\r\n            fn.apply(this, opt);\r\n        }, callback, optional);\r\n    }\r\n    this.getProtocolVersion = function getProtocolVersion(callback) {\r\n        var optional = [];\r\n        for (var i = 1; i < arguments.length; ++i) { opt.push(arguments[i]); }\r\n\r\n        if (!this._tmpSession) { this._tmpSession = heci.create(); this._tmpSession.parent = this; }\r\n        this._tmpSession.doIoctl(heci.IOCTL.HECI_VERSION, Buffer.alloc(5), Buffer.alloc(5), function (status, buffer, self, fn, opt) {\r\n            if (status == 0) {\r\n                var result = buffer.readUInt8(0).toString() + \'.\' + buffer.readUInt8(1).toString() + \'.\' + buffer.readUInt8(2).toString() + \'.\' + buffer.readUInt16BE(3).toString();\r\n                opt.unshift(result);\r\n                fn.apply(self, opt);\r\n            }\r\n            else {\r\n                opt.unshift(null);\r\n                fn.apply(self, opt);\r\n            }\r\n\r\n        }, this, callback, optional);\r\n    }\r\n    this.startConfigurationHBased = function startConfigurationHBased(certHash, hostVpn, dnsSuffixList, func) {\r\n        if ((certHash == null) || ((certHash.length != 32) && (certHash.length != 48))) { func({ status: -101 }); }\r\n        this.stopConfiguration(function (status) {\r\n            if (status == 0) {\r\n                // We stopped the configuration, wait 20 seconds before starting up again.\r\n                var f = function tf() { delete tf.parent.xtimeout; tf.parent.startConfigurationHBasedEx(certHash, hostVpn, dnsSuffixList, func); }\r\n                f.parent = this;\r\n                this.xtimeout = setTimeout(f, 20000);\r\n            } else {\r\n                // We are not in the connect mode, this is good, start configuration right away.\r\n                this.startConfigurationHBasedEx(certHash, hostVpn, dnsSuffixList, func);\r\n            }\r\n        })\r\n    }\r\n    this.startConfigurationHBasedEx = function startConfigurationHBased(certHash, hostVpn, dnsSuffixList, func) {\r\n        var optional = [];\r\n        for (var i = 4; i < arguments.length; ++i) { optional.push(arguments[i]); }\r\n\r\n        // Format the command\r\n        var data = Buffer.alloc(1 + 64 + 4 + 4 + ((dnsSuffixList != null) ? 320 : 0));\r\n        data[0] = (certHash.length == 48) ? 3 : 2 // Write certificate hash type: SHA256 = 2, SHA384 = 3\r\n        certHash.copy(data, 1); // Write the hash\r\n        data.writeUInt32LE(hostVpn ? 1 : 0, 65); // Write is HostVPN is enabled\r\n        if (dnsSuffixList != null) {\r\n            data.writeUInt32LE(dnsSuffixList.length, 69); // Write the number of DNS Suffix, from 0 to 4\r\n            var ptr = 73;\r\n            for (var i = 0; i < dnsSuffixList.length; i++) { ptr += data.write(dnsSuffixList[i], ptr) + 1; } // Write up to 4 DNS Suffix with null seperation.\r\n        }\r\n\r\n        // Send the command\r\n        this.sendCommand(139, data, function (header, fn, opt) {\r\n            if (header.Status == 0) {\r\n                var amtHash = null;\r\n                if (header.Data[0] == 2) { amtHash = header.Data.slice(1, 33); } // SHA256\r\n                if (header.Data[0] == 3) { amtHash = header.Data.slice(1, 49); } // SHA384\r\n                opt.unshift({ status: header.Status, hash: amtHash.toString(\'hex\') });\r\n            } else {\r\n                opt.unshift({ status: header.Status });\r\n            }\r\n            fn.apply(this, opt);\r\n        }, func, optional);\r\n    }\r\n}\r\n\r\nmodule.exports = amt_heci;\r\n\r\n\r\n/*\r\nAMT_STATUS_SUCCESS = 0,\r\nAMT_STATUS_INTERNAL_ERROR = 1,\r\nAMT_STATUS_INVALID_AMT_MODE = 3,\r\nAMT_STATUS_INVALID_MESSAGE_LENGTH = 4,\r\nAMT_STATUS_MAX_LIMIT_REACHED = 23,\r\nAMT_STATUS_INVALID_PARAMETER = 36,\r\nAMT_STATUS_RNG_GENERATION_IN_PROGRESS = 47,\r\nAMT_STATUS_RNG_NOT_READY = 48,\r\nAMT_STATUS_CERTIFICATE_NOT_READY = 49,\r\nAMT_STATUS_INVALID_HANDLE = 2053\r\nAMT_STATUS_NOT_FOUND = 2068,\r\n*/"); addedModules.push("amt-mei"); } catch (ex) { }
try { addModule("computer-identifiers", "/*\r\nCopyright 2019-2021 Intel Corporation\r\n\r\nLicensed under the Apache License, Version 2.0 (the \"License\");\r\nyou may not use this file except in compliance with the License.\r\nYou may obtain a copy of the License at\r\n\r\n    http://www.apache.org/licenses/LICENSE-2.0\r\n\r\nUnless required by applicable law or agreed to in writing, software\r\ndistributed under the License is distributed on an \"AS IS\" BASIS,\r\nWITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.\r\nSee the License for the specific language governing permissions and\r\nlimitations under the License.\r\n*/\r\n\r\nfunction trimIdentifiers(val)\r\n{\r\n    for(var v in val)\r\n    {\r\n        if(typeof val[v] === \'string\') val[v] = val[v].trim();\r\n        if (!val[v] || val[v] == \'None\' || val[v] == \'\') { delete val[v]; }\r\n    }\r\n}\r\nfunction trimResults(val)\r\n{\r\n    var i, x;\r\n    for (i = 0; i < val.length; ++i)\r\n    {\r\n        for (x in val[i])\r\n        {\r\n            if (x.startsWith(\'_\'))\r\n            {\r\n                delete val[i][x];\r\n            }\r\n            else\r\n            {\r\n                if (val[i][x] == null || val[i][x] == 0)\r\n                {\r\n                    delete val[i][x];\r\n                }\r\n            }\r\n        }\r\n    }\r\n}\r\nfunction brief(headers, obj)\r\n{\r\n    var i, x;\r\n    for (x = 0; x < obj.length; ++x)\r\n    {\r\n        for (i in obj[x])\r\n        {\r\n            if (!headers.includes(i))\r\n            {\r\n                delete obj[x][i];\r\n            }\r\n        }\r\n    }\r\n    return (obj);\r\n}\r\n\r\nfunction dataHandler(c)\r\n{\r\n    this.str += c.toString();\r\n}\r\n\r\nfunction linux_identifiers()\r\n{\r\n    var identifiers = {};\r\n    var ret = {};\r\n    var values = {};\r\n    var child = null;\r\n    try {\r\n        identifiers[\'bios_vendor\'] = \'Unknown\';\r\n        if (!require(\'fs\').existsSync(\'/sys/class/dmi/id\')) {\r\n            if (require(\'fs\').existsSync(\'/etc/wsl.conf\')) {\r\n                identifiers[\'bios_vendor\'] = \'Microsoft\';\r\n                identifiers[\'bios_version\'] = \'WSL\';\r\n            } else {\r\n                if (require(\'fs\').existsSync(\'/sys/firmware/devicetree/base/model\')) {\r\n                    if (require(\'fs\').readFileSync(\'/sys/firmware/devicetree/base/model\').toString().trim().startsWith(\'Raspberry\')) {\r\n                        identifiers[\'board_vendor\'] = \'Raspberry Pi\';\r\n                        identifiers[\'board_name\'] = require(\'fs\').readFileSync(\'/sys/firmware/devicetree/base/model\').toString().trim();\r\n                        identifiers[\'board_serial\'] = require(\'fs\').readFileSync(\'/sys/firmware/devicetree/base/serial-number\').toString().trim();\r\n                        const memorySlots = [];\r\n                        child = require(\'child_process\').execFile(\'/bin/sh\', [\'sh\']);\r\n                        child.stdout.str = \'\'; child.stdout.on(\'data\', dataHandler);\r\n                        child.stdin.write(\'vcgencmd get_mem arm && vcgencmd get_mem gpu\\nexit\\n\');\r\n                        child.waitExit();\r\n                        try { \r\n                            const lines = child.stdout.str.trim().split(\'\\n\');\r\n                            if (lines.length == 2) {\r\n                                memorySlots.push({ Locator: \"ARM Memory\", Size: lines[0].split(\'=\')[1].trim() })\r\n                                memorySlots.push({ Locator: \"GPU Memory\", Size: lines[1].split(\'=\')[1].trim() })\r\n                                ret.memory = { Memory_Device: memorySlots };\r\n                            }\r\n                        } catch (xx) { }\r\n                    }\r\n                }\r\n            }\r\n        } else {\r\n            var entries = require(\'fs\').readdirSync(\'/sys/class/dmi/id\');\r\n            for (var i in entries) {\r\n                if (require(\'fs\').statSync(\'/sys/class/dmi/id/\' + entries[i]).isFile()) {\r\n                    try {\r\n                        ret[entries[i]] = require(\'fs\').readFileSync(\'/sys/class/dmi/id/\' + entries[i]).toString().trim();\r\n                    } catch(z) { }\r\n                    if (ret[entries[i]] == \'None\') { delete ret[entries[i]]; }\r\n                }\r\n            }\r\n            entries = null;\r\n\r\n            identifiers[\'bios_date\'] = ret[\'bios_date\'];\r\n            identifiers[\'bios_vendor\'] = ret[\'bios_vendor\'];\r\n            identifiers[\'bios_version\'] = ret[\'bios_version\'];\r\n            identifiers[\'bios_serial\'] = ret[\'product_serial\'];\r\n            identifiers[\'board_name\'] = ret[\'board_name\'];\r\n            identifiers[\'board_serial\'] = ret[\'board_serial\'];\r\n            identifiers[\'board_vendor\'] = ret[\'board_vendor\'];\r\n            identifiers[\'board_version\'] = ret[\'board_version\'];\r\n            identifiers[\'product_uuid\'] = ret[\'product_uuid\'];\r\n            identifiers[\'product_name\'] = ret[\'product_name\'];\r\n        }\r\n    } catch (e) { console.log(e && e.message ? e.message : e); }\r\n\r\n    // BIOS Mode\r\n    try {\r\n        var uefiExist = false;\r\n        var assumePi = false;\r\n\r\n        try { uefiExist = (require(\'fs\')).existsSync(\'/sys/firmware/efi\'); }\r\n        catch (ex) { uefiExist = false; }\r\n\r\n        try { assumePi = (require(\'fs\')).existsSync(\'/sys/firmware/devicetree/base/model\'); }\r\n        catch (ex) { assumePi = false; }\r\n\r\n        if (uefiExist) {\r\n            identifiers[\'bios_mode\'] = \'UEFI\';\r\n        } else if (assumePi) {\r\n            var modelBuffer = (require(\'fs\')).readFileSync(\'/sys/firmware/devicetree/base/model\');\r\n            var modelString = modelBuffer.toString().trim()\r\n\r\n            if (modelString.includes(\'Raspberry Pi\')) {\r\n                identifiers[\'bios_mode\'] = \'Raspberry Pi Firmware (Proprietary)\';\r\n            }\r\n        } else {\r\n            identifiers[\'bios_mode\'] = \'Legacy BIOS (MBR)\';\r\n        }\r\n    } catch (ex) { identifiers[\'bios_mode\'] = \'Legacy / Unknown\'; }\r\n\r\n    // CPU Model info\r\n    child = require(\'child_process\').execFile(\'/bin/sh\', [\'sh\']);\r\n    child.stdout.str = \'\'; child.stdout.on(\'data\', dataHandler);\r\n    child.stdin.write(\'cat /proc/cpuinfo | grep -i \"model name\" | \' + \"tr \'\\\\n\' \':\' | awk -F: \'{ print $2 }\'\\nexit\\n\");\r\n    child.waitExit();\r\n    try {\r\n        identifiers[\'cpu_name\'] = child.stdout.str.trim();\r\n        if (identifiers[\'cpu_name\'] == \"\") { // CPU BLANK, check lscpu instead\r\n            child = require(\'child_process\').execFile(\'/bin/sh\', [\'sh\']);\r\n            child.stdout.str = \'\'; child.stdout.on(\'data\', dataHandler);\r\n            child.stdin.write(\'lscpu | grep -i \"model name\" | \' + \"tr \'\\\\n\' \':\' | awk -F: \'{ print $2 }\'\\nexit\\n\");\r\n            child.waitExit();\r\n            try { identifiers[\'cpu_name\'] = child.stdout.str.trim(); } catch (xx) { }\r\n        }\r\n    } catch (xx) { }\r\n\r\n    // Kernel info\r\n    child = require(\'child_process\').execFile(\'/bin/sh\', [\'sh\']);\r\n    child.stdout.str = \'\'; child.stdout.on(\'data\', dataHandler);\r\n    child.stdin.write(\'uname -r\\nexit\\n\');\r\n    child.waitExit();\r\n    try { ret[\'kernel_release\'] = child.stdout.str.trim(); } catch (xx) { }\r\n    if (ret[\'kernel_release\'].indexOf(\'-WSL2\') !== -1) { identifiers[\'bios_version\'] = \'WSL2\'; }\r\n\r\n    child = require(\'child_process\').execFile(\'/bin/sh\', [\'sh\']);\r\n    child.stdout.str = \'\'; child.stdout.on(\'data\', dataHandler);\r\n    child.stdin.write(\'uname -v\\nexit\\n\');\r\n    child.waitExit();\r\n    try { ret[\'kernel_build\'] = child.stdout.str.trim(); } catch (xx) { }\r\n\r\n    child = require(\'child_process\').execFile(\'/bin/sh\', [\'sh\']);\r\n    child.stdout.str = \'\'; child.stdout.on(\'data\', dataHandler);\r\n    child.stdin.write(\'uname -m\\nexit\\n\');\r\n    child.waitExit();\r\n    try { ret[\'arch\'] = child.stdout.str.trim(); } catch (xx) { }\r\n\r\n    // Fetch GPU info\r\n    child = require(\'child_process\').execFile(\'/bin/sh\', [\'sh\']);\r\n    child.stdout.str = \'\'; child.stdout.on(\'data\', dataHandler);\r\n    child.stdin.write(\"lspci | grep \' VGA \' | tr \'\\\\n\' \'`\' | awk \'{ a=split($0,lines\" + \',\"`\"); printf \"[\"; for(i=1;i<a;++i) { split(lines[i],gpu,\"r: \"); printf \"%s\\\\\"%s\\\\\"\", (i==1?\"\":\",\"),gpu[2]; } printf \"]\"; }\\\'\\nexit\\n\');\r\n    child.waitExit();\r\n    try { identifiers[\'gpu_name\'] = JSON.parse(child.stdout.str.trim()); } catch (xx) { }\r\n\r\n    // Fetch Storage Info\r\n    child = require(\'child_process\').execFile(\'/bin/sh\', [\'sh\']);\r\n    child.stdout.str = \'\'; child.stdout.on(\'data\', dataHandler);\r\n    child.stdin.write(\"lshw -class disk -disable network | tr \'\\\\n\' \'`\' | awk \'\" + \'{ len=split($0,lines,\"*\"); printf \"[\"; for(i=2;i<=len;++i) { model=\"\"; caption=\"\"; size=\"\"; clen=split(lines[i],item,\"`\"); for(j=2;j<clen;++j) { split(item[j],tokens,\":\"); split(tokens[1],key,\" \"); if(key[1]==\"description\") { caption=substr(tokens[2],2); } if(key[1]==\"product\") { model=substr(tokens[2],2); } if(key[1]==\"size\") { size=substr(tokens[2],2);  } } if(model==\"\") { model=caption; } if(caption!=\"\" || model!=\"\") { printf \"%s{\\\\\"Caption\\\\\":\\\\\"%s\\\\\",\\\\\"Model\\\\\":\\\\\"%s\\\\\",\\\\\"Size\\\\\":\\\\\"%s\\\\\"}\",(i==2?\"\":\",\"),caption,model,size; }  } printf \"]\"; }\\\'\\nexit\\n\');\r\n    child.waitExit();\r\n    try { identifiers[\'storage_devices\'] = JSON.parse(child.stdout.str.trim()); } catch (xx) { }\r\n\r\n    // Fetch storage volumes using df\r\n    child = require(\'child_process\').execFile(\'/bin/sh\', [\'sh\']);\r\n    child.stdout.str = \'\'; child.stdout.on(\'data\', dataHandler);\r\n    child.stdin.write(\'df -T -x tmpfs -x devtmpfs -x efivarfs | awk \\\'NR==1 || $1 ~ \".+\"{print $3, $4, $5, $7, $2}\\\' | awk \\\'NR>1 {printf \"{\\\\\"size\\\\\":\\\\\"%s\\\\\",\\\\\"used\\\\\":\\\\\"%s\\\\\",\\\\\"available\\\\\":\\\\\"%s\\\\\",\\\\\"mount_point\\\\\":\\\\\"%s\\\\\",\\\\\"type\\\\\":\\\\\"%s\\\\\"},\", $1, $2, $3, $4, $5}\\\' | sed \\\'$ s/,$//\\\' | awk \\\'BEGIN {printf \"[\"} {printf \"%s\", $0} END {printf \"]\"}\\\'\\nexit\\n\');\r\n    child.waitExit();\r\n    try { ret.volumes = JSON.parse(child.stdout.str.trim()); } catch (xx) { }\r\n\r\n    values.identifiers = identifiers;\r\n    values.linux = ret;\r\n    trimIdentifiers(values.identifiers);\r\n\r\n    var dmidecode = require(\'lib-finder\').findBinary(\'dmidecode\');\r\n    if (dmidecode != null)\r\n    {\r\n        child = require(\'child_process\').execFile(\'/bin/sh\', [\'sh\']);\r\n        child.stdout.str = \'\'; child.stdout.on(\'data\', dataHandler);\r\n        child.stderr.str = \'\'; child.stderr.on(\'data\', dataHandler);\r\n        child.stdin.write(dmidecode + \" -t memory | tr \'\\\\n\' \'`\' | \");\r\n        child.stdin.write(\" awk \'{ \");\r\n        child.stdin.write(\'   printf(\"[\");\');\r\n        child.stdin.write(\'   comma=\"\";\');\r\n        child.stdin.write(\'   c=split($0, lines, \"``\");\');\r\n        child.stdin.write(\'   for(i=1;i<=c;++i)\');\r\n        child.stdin.write(\'   {\');\r\n        child.stdin.write(\'      d=split(lines[i], val, \"`\");\');\r\n        child.stdin.write(\'      split(val[1], tokens, \",\");\');\r\n        child.stdin.write(\'      split(tokens[2], dmitype, \" \");\');\r\n        child.stdin.write(\'      dmi = dmitype[3]+0; \');\r\n        child.stdin.write(\'      if(dmi == 5 || dmi == 6 || dmi == 16 || dmi == 17)\');\r\n        child.stdin.write(\'      {\');\r\n        child.stdin.write(\'          ccx=\"\";\');\r\n        child.stdin.write(\'          printf(\"%s{\\\\\"%s\\\\\": {\", comma, val[2]);\');\r\n        child.stdin.write(\'          for(j=3;j<d;++j)\');\r\n        child.stdin.write(\'          {\');\r\n        child.stdin.write(\'             sub(/^[ \\\\t]*/,\"\",val[j]);\');\r\n        child.stdin.write(\'             if(split(val[j],tmp,\":\")>1)\');\r\n        child.stdin.write(\'             {\');\r\n        child.stdin.write(\'                sub(/^[ \\\\t]*/,\"\",tmp[2]);\');\r\n        child.stdin.write(\'                gsub(/ /,\"\",tmp[1]);\');\r\n        child.stdin.write(\'                printf(\"%s\\\\\"%s\\\\\": \\\\\"%s\\\\\"\", ccx, tmp[1], tmp[2]);\');\r\n        child.stdin.write(\'                ccx=\",\";\');\r\n        child.stdin.write(\'             }\');\r\n        child.stdin.write(\'          }\');\r\n        child.stdin.write(\'          printf(\"}}\");\');\r\n        child.stdin.write(\'          comma=\",\";\');\r\n        child.stdin.write(\'      }\');\r\n        child.stdin.write(\'   }\');\r\n        child.stdin.write(\'   printf(\"]\");\');\r\n        child.stdin.write(\"}\'\\nexit\\n\");\r\n        child.waitExit();\r\n\r\n        try\r\n        {\r\n            var j = JSON.parse(child.stdout.str);\r\n            var i, key, key2;\r\n            for (i = 0; i < j.length; ++i)\r\n            {\r\n                for (key in j[i])\r\n                {\r\n                    delete j[i][key][\'ArrayHandle\'];\r\n                    delete j[i][key][\'ErrorInformationHandle\'];\r\n                    for (key2 in j[i][key])\r\n                    {\r\n                        if (j[i][key][key2] == \'Unknown\' || j[i][key][key2] == \'Not Specified\' || j[i][key][key2] == \'\')\r\n                        {\r\n                            delete j[i][key][key2];\r\n                        }\r\n                    }\r\n                }\r\n            }\r\n\r\n            if(j.length > 0){\r\n                var mem = {};\r\n                for (i = 0; i < j.length; ++i)\r\n                {\r\n                    for (key in j[i])\r\n                    {\r\n                        if (mem[key] == null) { mem[key] = []; }\r\n                        mem[key].push(j[i][key]);\r\n                    }\r\n                }\r\n                values.linux.memory = mem;\r\n            }\r\n        }\r\n        catch (e)\r\n        { }\r\n        child = null;\r\n    }\r\n\r\n    var usbdevices = require(\'lib-finder\').findBinary(\'usb-devices\');\r\n    if (usbdevices != null)\r\n    {\r\n        var child = require(\'child_process\').execFile(\'/bin/sh\', [\'sh\']);\r\n        child.stdout.str = \'\'; child.stdout.on(\'data\', dataHandler);\r\n        child.stderr.str = \'\'; child.stderr.on(\'data\', dataHandler);\r\n        child.stdin.write(usbdevices + \" | tr \'\\\\n\' \'`\' | \");\r\n        child.stdin.write(\" awk \'\");\r\n        child.stdin.write(\'{\');\r\n        child.stdin.write(\'   comma=\"\";\');\r\n        child.stdin.write(\'   printf(\"[\");\');\r\n        child.stdin.write(\'   len=split($0, group, \"``\");\');\r\n        child.stdin.write(\'   for(i=1;i<=len;++i)\');\r\n        child.stdin.write(\'   {\');\r\n        child.stdin.write(\'      comma2=\"\";\');\r\n        child.stdin.write(\'      xlen=split(group[i], line, \"`\");\');\r\n        child.stdin.write(\'      scount=0;\');\r\n        child.stdin.write(\'      for(x=1;x<xlen;++x)\');\r\n        child.stdin.write(\'      {\');\r\n        child.stdin.write(\'         if(line[x] ~ \"^S:\")\');\r\n        child.stdin.write(\'         {\');\r\n        child.stdin.write(\'            ++scount;\');\r\n        child.stdin.write(\'         }\');\r\n        child.stdin.write(\'      }\');\r\n        child.stdin.write(\'      if(scount>0)\');\r\n        child.stdin.write(\'      {\');\r\n        child.stdin.write(\'         printf(\"%s{\", comma); comma=\",\";\');\r\n        child.stdin.write(\'         for(x=1;x<xlen;++x)\');\r\n        child.stdin.write(\'         {\');\r\n        child.stdin.write(\'            if(line[x] ~ \"^T:\")\');\r\n        child.stdin.write(\'            {\');\r\n        child.stdin.write(\'               comma3=\"\";\');\r\n        child.stdin.write(\'               printf(\"%s\\\\\"hardware\\\\\": {\", comma2); comma2=\",\";\');\r\n        child.stdin.write(\'               sub(/^T:[ \\\\t]*/, \"\", line[x]);\');\r\n        child.stdin.write(\'               gsub(/= */, \"=\", line[x]);\');\r\n        child.stdin.write(\'               blen=split(line[x], tokens, \" \");\');\r\n        child.stdin.write(\'               for(y=1;y<blen;++y)\');\r\n        child.stdin.write(\'               {\');\r\n        child.stdin.write(\'                  match(tokens[y],/=/);\');\r\n        child.stdin.write(\'                  h=substr(tokens[y],1,RSTART-1);\');\r\n        child.stdin.write(\'                  v=substr(tokens[y],RSTART+1);\');\r\n        child.stdin.write(\'                  sub(/#/, \"\", h);\');\r\n        child.stdin.write(\'                  printf(\"%s\\\\\"%s\\\\\": \\\\\"%s\\\\\"\", comma3, h, v); comma3=\",\";\');\r\n        child.stdin.write(\'               }\');\r\n        child.stdin.write(\'               printf(\"}\");\');\r\n        child.stdin.write(\'            }\');\r\n        child.stdin.write(\'            if(line[x] ~ \"^S:\")\');\r\n        child.stdin.write(\'            {\');\r\n        child.stdin.write(\'               sub(/^S:[ \\\\t]*/, \"\", line[x]);\');\r\n        child.stdin.write(\'               match(line[x], /=/);\');\r\n        child.stdin.write(\'               h=substr(line[x],1,RSTART-1);\');\r\n        child.stdin.write(\'               v=substr(line[x],RSTART+1);\');\r\n        child.stdin.write(\'               printf(\"%s\\\\\"%s\\\\\": \\\\\"%s\\\\\"\", comma2, h,v); comma2=\",\";\');\r\n        child.stdin.write(\'            }\');\r\n        child.stdin.write(\'         }\');\r\n        child.stdin.write(\'         printf(\"}\");\');\r\n        child.stdin.write(\'      }\');\r\n        child.stdin.write(\'   }\');\r\n        child.stdin.write(\'   printf(\"]\");\');\r\n        child.stdin.write(\"}\'\\nexit\\n\");\r\n        child.waitExit();\r\n\r\n        try\r\n        {\r\n            values.linux.usb = JSON.parse(child.stdout.str);\r\n        }\r\n        catch(x)\r\n        { }\r\n        child = null;\r\n    }\r\n\r\n    var pcidevices = require(\'lib-finder\').findBinary(\'lspci\');\r\n    if (pcidevices != null)\r\n    {\r\n        var child = require(\'child_process\').execFile(\'/bin/sh\', [\'sh\']);\r\n        child.stdout.str = \'\'; child.stdout.on(\'data\', dataHandler);\r\n        child.stderr.str = \'\'; child.stderr.on(\'data\', dataHandler);\r\n        child.stdin.write(pcidevices + \" -m | tr \'\\\\n\' \'`\' | \");\r\n        child.stdin.write(\" awk \'\");\r\n        child.stdin.write(\'{\');\r\n        child.stdin.write(\'   printf(\"[\");\');\r\n        child.stdin.write(\'   comma=\"\";\');\r\n        child.stdin.write(\'   alen=split($0, lines, \"`\");\');\r\n        child.stdin.write(\'   for(a=1;a<alen;++a)\');\r\n        child.stdin.write(\'   {\');\r\n        child.stdin.write(\'      match(lines[a], / /);\');\r\n        child.stdin.write(\'      blen=split(lines[a], meta, \"\\\\\"\");\');\r\n        child.stdin.write(\'      bus=substr(lines[a], 1, RSTART);\');\r\n        child.stdin.write(\'      gsub(/ /, \"\", bus);\');\r\n        child.stdin.write(\'      printf(\"%s{\\\\\"bus\\\\\": \\\\\"%s\\\\\"\", comma, bus); comma=\",\";\');\r\n        child.stdin.write(\'      printf(\", \\\\\"device\\\\\": \\\\\"%s\\\\\"\", meta[2]);\');\r\n        child.stdin.write(\'      printf(\", \\\\\"manufacturer\\\\\": \\\\\"%s\\\\\"\", meta[4]);\');\r\n        child.stdin.write(\'      printf(\", \\\\\"description\\\\\": \\\\\"%s\\\\\"\", meta[6]);\');\r\n        child.stdin.write(\'      if(meta[8] != \"\")\');\r\n        child.stdin.write(\'      {\');\r\n        child.stdin.write(\'         printf(\", \\\\\"subsystem\\\\\": {\");\');\r\n        child.stdin.write(\'         printf(\"\\\\\"manufacturer\\\\\": \\\\\"%s\\\\\"\", meta[8]);\');\r\n        child.stdin.write(\'         printf(\", \\\\\"description\\\\\": \\\\\"%s\\\\\"\", meta[10]);\');\r\n        child.stdin.write(\'         printf(\"}\");\');\r\n        child.stdin.write(\'      }\');\r\n        child.stdin.write(\'      printf(\"}\");\');\r\n        child.stdin.write(\'   }\');\r\n        child.stdin.write(\'   printf(\"]\");\');\r\n        child.stdin.write(\"}\'\\nexit\\n\");\r\n        child.waitExit();\r\n\r\n        try\r\n        {\r\n            values.linux.pci = JSON.parse(child.stdout.str);\r\n        }\r\n        catch (x)\r\n        { }\r\n        child = null;\r\n    }\r\n\r\n    // Linux Last Boot Up Time\r\n    try {\r\n        child = require(\'child_process\').execFile(\'/usr/bin/uptime\', [\'\', \'-s\']); // must include blank value at begining for some reason?\r\n        child.stdout.str = \'\'; child.stdout.on(\'data\', function (c) { this.str += c.toString(); });\r\n        child.stderr.on(\'data\', function () { });\r\n        child.waitExit();\r\n        var regex = /^\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2}$/;\r\n        if (regex.test(child.stdout.str.trim())) {\r\n            values.linux.LastBootUpTime = child.stdout.str.trim();\r\n        } else {\r\n            child = require(\'child_process\').execFile(\'/bin/sh\', [\'sh\']);\r\n            child.stdout.str = \'\'; child.stdout.on(\'data\', function (c) { this.str += c.toString(); });\r\n            child.stdin.write(\'date -d \"@$(( $(date +%s) - $(awk \\\'{print int($1)}\\\' /proc/uptime) ))\" \"+%Y-%m-%d %H:%M:%S\"\\nexit\\n\');\r\n            child.waitExit();\r\n            if (regex.test(child.stdout.str.trim())) {\r\n                values.linux.LastBootUpTime = child.stdout.str.trim();\r\n            }\r\n        }\r\n        child = null;\r\n    } catch (ex) { }\r\n\r\n    // Linux TPM\r\n    try {\r\n        if (require(\'fs\').statSync(\'/sys/class/tpm/tpm0\').isDirectory()){\r\n            values.tpm = {\r\n                SpecVersion: require(\'fs\').readFileSync(\'/sys/class/tpm/tpm0/tpm_version_major\').toString().trim()\r\n            }\r\n        }\r\n    } catch (ex) { }\r\n\r\n    // Linux Batteries\r\n    try {\r\n        var batteries = require(\'fs\').readdirSync(\'/sys/class/power_supply/\');\r\n        if (batteries.length != 0) {\r\n            values.battery = [];\r\n            for (var i in batteries) {\r\n                const filesToRead = [\r\n                    \'capacity\', \'cycle_count\', \'energy_full\', \'energy_full_design\',\r\n                    \'energy_now\', \'manufacturer\', \'model_name\', \'power_now\',\r\n                    \'serial_number\', \'status\', \'technology\', \'voltage_now\'\r\n                ];\r\n                const thedata = {};\r\n                for (var x in filesToRead) {\r\n                    try {\r\n\t\t\t\t\t\tconst filePath = \'/sys/class/power_supply/\' + batteries[i] + \'/\' + filesToRead[x];\r\n\t\t\t\t\t\tif(require(\'fs\').existsSync(filePath)) {\r\n                        \tconst content = require(\'fs\').readFileSync(filePath).toString().trim();\r\n                        \tthedata[filesToRead[x]] = /^\\d+$/.test(content) ? parseInt(content, 10) : content;\r\n\t\t\t\t\t\t}\r\n                    } catch (err) { }\r\n                }\r\n                if (Object.keys(thedata).length === 0) continue; // No data read, skip\r\n                const status = (thedata.status || \'\').toLowerCase();\r\n                const isCharging = status === \'charging\';\r\n                const isDischarging = status === \'discharging\';\r\n                const toMilli = function (val) { return Math.round((val || 0) / 1000) }; // Convert from  units to m units (divide by 1000)\r\n                const batteryJson = {\r\n                    \"InstanceName\": batteries[i],\r\n                    \"CycleCount\": thedata.cycle_count || 0,\r\n                    \"FullChargedCapacity\": toMilli(thedata.energy_full),\r\n                    \"Chemistry\": (thedata.technology || \'\'),\r\n                    \"DesignedCapacity\": toMilli(thedata.energy_full_design),\r\n                    \"DeviceName\": thedata.model_name || \"Battery\",\r\n                    \"ManufactureName\": thedata.manufacturer || \"Unknown\",\r\n                    \"SerialNumber\": thedata.serial_number || \"unknown\",\r\n                    \"ChargeRate\": isCharging ? toMilli(thedata.power_now) : 0,\r\n                    \"Charging\": isCharging,\r\n                    \"DischargeRate\": isDischarging ? toMilli(thedata.power_now) : 0,\r\n                    \"Discharging\": isDischarging,\r\n                    \"RemainingCapacity\": toMilli(thedata.energy_now),\r\n                    \"Voltage\": toMilli(thedata.voltage_now),\r\n                    \"Health\": (thedata.energy_full && thedata.energy_full_design ? Math.floor((thedata.energy_full / thedata.energy_full_design) * 100) : 0),\r\n                    \"BatteryCharge\": (thedata.energy_now && thedata.energy_full ? Math.floor((thedata.energy_now / thedata.energy_full) * 100) : (thedata.capacity ? thedata.capacity : 0))\r\n                };\r\n                values.battery.push(batteryJson);\r\n            }\r\n            if (values.battery.length == 0) { delete values.battery; }\r\n        }\r\n    } catch (ex) { }\r\n\r\n    return (values);\r\n}\r\n\r\nfunction windows_wmic_results(str)\r\n{\r\n    var lines = str.trim().split(\'\\r\\n\');\r\n    var keys = lines[0].split(\',\');\r\n    var i, key, keyval;\r\n    var tokens;\r\n    var result = [];\r\n\r\n    console.log(\'Lines: \' + lines.length, \'Keys: \' + keys.length);\r\n\r\n    for (i = 1; i < lines.length; ++i)\r\n    {\r\n        var obj = {};\r\n        console.log(\'i: \' + i);\r\n        tokens = lines[i].split(\',\');\r\n        for (key = 0; key < keys.length; ++key)\r\n        {\r\n            var tmp = Buffer.from(tokens[key], \'binary\').toString();\r\n            console.log(tokens[key], tmp);\r\n            tokens[key] = tmp == null ? \'\' : tmp;\r\n            if (tokens[key].trim())\r\n            {\r\n                obj[keys[key].trim()] = tokens[key].trim();\r\n            }\r\n        }\r\n        delete obj.Node;\r\n        result.push(obj);\r\n    }\r\n    return (result);\r\n}\r\n\r\nfunction windows_identifiers()\r\n{\r\n    var ret = { windows: {} };\r\n    var items, item, i;\r\n\r\n    ret[\'identifiers\'] = {};\r\n\r\n    var values = require(\'win-wmi-fixed\').query(\'ROOT\\\\CIMV2\', \"SELECT * FROM Win32_Bios\", [\'ReleaseDate\', \'Manufacturer\', \'SMBIOSBIOSVersion\', \'SerialNumber\']);\r\n    if(values[0]){\r\n        ret[\'identifiers\'][\'bios_date\'] = values[0][\'ReleaseDate\'];\r\n        ret[\'identifiers\'][\'bios_vendor\'] = values[0][\'Manufacturer\'];\r\n        ret[\'identifiers\'][\'bios_version\'] = values[0][\'SMBIOSBIOSVersion\'];\r\n        ret[\'identifiers\'][\'bios_serial\'] = values[0][\'SerialNumber\'];\r\n    }\r\n    ret[\'identifiers\'][\'bios_mode\'] = \'Legacy\';\r\n\r\n    values = require(\'win-wmi-fixed\').query(\'ROOT\\\\CIMV2\', \"SELECT * FROM Win32_BaseBoard\", [\'Product\', \'SerialNumber\', \'Manufacturer\', \'Version\']);\r\n    if(values[0]){\r\n        ret[\'identifiers\'][\'board_name\'] = values[0][\'Product\'];\r\n        ret[\'identifiers\'][\'board_serial\'] = values[0][\'SerialNumber\'];\r\n        ret[\'identifiers\'][\'board_vendor\'] = values[0][\'Manufacturer\'];\r\n        ret[\'identifiers\'][\'board_version\'] = values[0][\'Version\'];\r\n    }\r\n\r\n    values = require(\'win-wmi-fixed\').query(\'ROOT\\\\CIMV2\', \"SELECT * FROM Win32_ComputerSystemProduct\", [\'UUID\', \'Name\']);\r\n    if(values[0]){\r\n        ret[\'identifiers\'][\'product_uuid\'] = values[0][\'UUID\'];\r\n        ret[\'identifiers\'][\'product_name\'] = values[0][\'Name\'];\r\n    }\r\n\r\n    values = require(\'win-wmi-fixed\').query(\'ROOT\\\\CIMV2\', \"SELECT * FROM Win32_SystemEnclosure\", [\'SerialNumber\', \'SMBIOSAssetTag\', \'Manufacturer\']);\r\n    if(values[0]){\r\n        ret[\'identifiers\'][\'chassis_serial\'] = values[0][\'SerialNumber\'];\r\n        ret[\'identifiers\'][\'chassis_assettag\'] = values[0][\'SMBIOSAssetTag\'];\r\n        ret[\'identifiers\'][\'chassis_manufacturer\'] = values[0][\'Manufacturer\'];\r\n    }\r\n\r\n    trimIdentifiers(ret.identifiers);\r\n\r\n    values = require(\'win-wmi-fixed\').query(\'ROOT\\\\CIMV2\', \"SELECT * FROM Win32_PhysicalMemory\");\r\n    if(values[0]){\r\n        trimResults(values);\r\n        ret.windows.memory = values;\r\n    }\r\n\r\n    values = require(\'win-wmi-fixed\').query(\'ROOT\\\\CIMV2\', \"SELECT * FROM Win32_OperatingSystem\");\r\n    if(values[0]){\r\n        trimResults(values);\r\n        ret.windows.osinfo = values[0];\r\n\t\t\r\n\t\ttry {\r\n            var reg = require(\'win-registry\');\r\n            var ubr = reg.QueryKey(reg.HKEY.LocalMachine, \'Software\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\', \'UBR\');\r\n            if(ubr && ret.windows.osinfo.Version){\r\n                ret.windows.osinfo.BuildRevision = ret.windows.osinfo.Version + \".\" + ubr \r\n            }\r\n        } catch (ex){}\r\n    }\r\n\r\n    values = require(\'win-wmi-fixed\').query(\'ROOT\\\\CIMV2\', \"SELECT * FROM Win32_DiskPartition\");\r\n    if(values[0]){\r\n        trimResults(values);\r\n        ret.windows.partitions = values;\r\n        for (var i in values) {\r\n            if (values[i].Type==\'GPT: System\') {\r\n                ret[\'identifiers\'][\'bios_mode\'] = \'UEFI\';\r\n            }\r\n        }\r\n    }\r\n\r\n    values = require(\'win-wmi-fixed\').query(\'ROOT\\\\CIMV2\', \"SELECT * FROM Win32_Processor\", [\'Caption\', \'DeviceID\', \'Manufacturer\', \'MaxClockSpeed\', \'Name\', \'SocketDesignation\']);\r\n    if(values[0]){\r\n        ret.windows.cpu = values;\r\n    }\r\n    \r\n    values = require(\'win-wmi-fixed\').query(\'ROOT\\\\CIMV2\', \"SELECT * FROM Win32_VideoController\", [\'Name\', \'CurrentHorizontalResolution\', \'CurrentVerticalResolution\']);\r\n    if(values[0]){\r\n        ret.windows.gpu = values;\r\n    }\r\n\r\n    values = require(\'win-wmi-fixed\').query(\'ROOT\\\\CIMV2\', \"SELECT * FROM Win32_DiskDrive\", [\'Caption\', \'DeviceID\', \'Model\', \'Partitions\', \'Size\', \'Status\']);\r\n    if(values[0]){\r\n        ret.windows.drives = values;\r\n    }\r\n    \r\n    // Insert GPU names\r\n    ret.identifiers.gpu_name = [];\r\n    for (var gpuinfo in ret.windows.gpu)\r\n    {\r\n        if (ret.windows.gpu[gpuinfo].Name) { ret.identifiers.gpu_name.push(ret.windows.gpu[gpuinfo].Name); }\r\n    }\r\n\r\n    // Insert Storage Devices\r\n    ret.identifiers.storage_devices = [];\r\n    for (var dv in ret.windows.drives)\r\n    {\r\n        ret.identifiers.storage_devices.push({ Caption: ret.windows.drives[dv].Caption, Model: ret.windows.drives[dv].Model, Size: ret.windows.drives[dv].Size });\r\n    }\r\n\r\n    try { ret.identifiers.cpu_name = ret.windows.cpu[0].Name; } catch (x) { }\r\n\r\n    // Windows TPM\r\n    IntToStr = function (v) { return String.fromCharCode((v >> 24) & 0xFF, (v >> 16) & 0xFF, (v >> 8) & 0xFF, v & 0xFF); };\r\n    try {\r\n        values = require(\'win-wmi-fixed\').query(\'ROOT\\\\CIMV2\\\\Security\\\\MicrosoftTpm\', \"SELECT * FROM Win32_Tpm\", [\'IsActivated_InitialValue\',\'IsEnabled_InitialValue\',\'IsOwned_InitialValue\',\'ManufacturerId\',\'ManufacturerVersion\',\'SpecVersion\']);\r\n        if(values[0]) {\r\n            ret.tpm = {\r\n                SpecVersion: values[0].SpecVersion.split(\",\")[0],\r\n                ManufacturerId: IntToStr(values[0].ManufacturerId).replace(/[^\\x00-\\x7F]/g, \"\"),\r\n                ManufacturerVersion: values[0].ManufacturerVersion,\r\n                IsActivated: values[0].IsActivated_InitialValue,\r\n                IsEnabled: values[0].IsEnabled_InitialValue,\r\n                IsOwned: values[0].IsOwned_InitialValue,\r\n            }\r\n        }\r\n    } catch (ex) { }\r\n\r\n    // Windows Batteries\r\n    IntToStrLE = function (v) { return String.fromCharCode(v & 0xFF, (v >> 8) & 0xFF, (v >> 16) & 0xFF, (v >> 24) & 0xFF); };\r\n    try {\r\n        function mergeJSONArrays() {\r\n            var resultMap = {};\r\n            var result = [];\r\n            // Loop through all arguments (arrays)\r\n            for (var i = 0; i < arguments.length; i++) {\r\n                var currentArray = arguments[i];\r\n                // Skip if not an array\r\n                if (!currentArray || currentArray.constructor !== Array) {\r\n                    continue;\r\n                }\r\n                // Process each object in the array\r\n                for (var j = 0; j < currentArray.length; j++) {\r\n                    var obj = currentArray[j];\r\n                    // Skip if not an object or missing InstanceName\r\n                    if (!obj || typeof obj !== \'object\' || !obj.InstanceName) {\r\n                        continue;\r\n                    }\r\n                    var name = obj.InstanceName;\r\n                    // Create new entry if it doesn\'t exist\r\n                    if (!resultMap[name]) {\r\n                        resultMap[name] = { InstanceName: name };\r\n                        result.push(resultMap[name]);\r\n                    }\r\n                    // Copy all properties except InstanceName\r\n                    for (var key in obj) {\r\n                        if (obj.hasOwnProperty(key) && key !== \'InstanceName\') {\r\n                            resultMap[name][key] = obj[key];\r\n                        }\r\n                    }\r\n                }\r\n            }\r\n            return result;\r\n        }\r\n        values = require(\'win-wmi-fixed\').query(\'ROOT\\\\WMI\', \"SELECT * FROM BatteryCycleCount\",[\'InstanceName\',\'CycleCount\']);\r\n        var values2 = require(\'win-wmi-fixed\').query(\'ROOT\\\\WMI\', \"SELECT * FROM BatteryFullChargedCapacity\",[\'InstanceName\',\'FullChargedCapacity\']);\r\n        var values3 = require(\'win-wmi-fixed\').query(\'ROOT\\\\WMI\', \"SELECT * FROM BatteryRuntime\",[\'InstanceName\',\'EstimatedRuntime\']);\r\n        var values4 = require(\'win-wmi-fixed\').query(\'ROOT\\\\WMI\', \"SELECT * FROM BatteryStaticData\",[\'InstanceName\',\'Chemistry\',\'DesignedCapacity\',\'DeviceName\',\'ManufactureDate\',\'ManufactureName\',\'SerialNumber\']);\r\n        for (i = 0; i < values4.length; ++i) {\r\n            if (values4[i].Chemistry) { values4[i].Chemistry = IntToStrLE(parseInt(values4[i].Chemistry)); }\r\n            if (values4[i].ManufactureDate) { if (values4[i].ManufactureDate.indexOf(\'*****\') != -1) delete values4[i].ManufactureDate; }\r\n        }\r\n        var values5 = require(\'win-wmi-fixed\').query(\'ROOT\\\\WMI\', \"SELECT * FROM BatteryStatus\",[\'InstanceName\',\'ChargeRate\',\'Charging\',\'DischargeRate\',\'Discharging\',\'RemainingCapacity\',\'Voltage\']);\r\n        var values6 = [];\r\n        if (values2.length > 0 && values4.length > 0) {\r\n            for (i = 0; i < values2.length; ++i) {\r\n                for (var j = 0; j < values4.length; ++j) {\r\n                    if (values2[i].InstanceName == values4[j].InstanceName) {\r\n                        if ((values4[j].DesignedCapacity && values4[j].DesignedCapacity > 0) && (values2[i].FullChargedCapacity && values2[i].FullChargedCapacity > 0)) {\r\n                            values6[i] = { \r\n                                Health: Math.floor((values2[i].FullChargedCapacity / values4[j].DesignedCapacity) * 100),\r\n                                InstanceName: values2[i].InstanceName\r\n                            };\r\n                            if (values6[i].Health > 100) { values6[i].Health = 100; }\r\n                        } else {\r\n                            values6[i] = { Health: 0, InstanceName: values2[i].InstanceName };\r\n                        }\r\n                        break;\r\n                    }\r\n                }\r\n            }\r\n        }\r\n        var values7 = [];\r\n        if (values2.length > 0 && values5.length > 0) {\r\n            for (i = 0; i < values2.length; ++i) {\r\n                for (var j = 0; j < values5.length; ++j) {\r\n                    if (values2[i].InstanceName == values5[j].InstanceName) {\r\n                        if ((values2[i].FullChargedCapacity && values2[i].FullChargedCapacity > 0) && (values5[j].RemainingCapacity && values5[j].RemainingCapacity > 0)) {\r\n                            values7[i] = { \r\n                                BatteryCharge: Math.floor((values5[j].RemainingCapacity / values2[i].FullChargedCapacity) * 100),\r\n                                InstanceName: values2[i].InstanceName\r\n                            };\r\n                        } else {\r\n                            values7[i] = { BatteryCharge: 0, InstanceName: values2[i].InstanceName };\r\n                        }\r\n                        break;\r\n                    }\r\n                }\r\n            }\r\n        }\r\n        ret.battery = mergeJSONArrays(values, values2, values3, values4, values5, values6, values7);\r\n    } catch (ex) { }\r\n\r\n    return (ret);\r\n}\r\nfunction macos_identifiers()\r\n{\r\n    var ret = { identifiers: {}, darwin: {} };\r\n    var child;\r\n\r\n    child = require(\'child_process\').execFile(\'/bin/sh\', [\'sh\']);\r\n    child.stdout.str = \'\'; child.stdout.on(\'data\', function (c) { this.str += c.toString(); });\r\n    child.stdin.write(\'ioreg -d2 -c IOPlatformExpertDevice | grep board-id | awk -F= \\\'{ split($2, res, \"\\\\\"\"); print res[2]; }\\\'\\nexit\\n\');\r\n    child.waitExit();\r\n    ret.identifiers.board_name = child.stdout.str.trim();\r\n\r\n    child = require(\'child_process\').execFile(\'/bin/sh\', [\'sh\']);\r\n    child.stdout.str = \'\'; child.stdout.on(\'data\', function (c) { this.str += c.toString(); });\r\n    child.stdin.write(\'ioreg -d2 -c IOPlatformExpertDevice | grep IOPlatformSerialNumber | awk -F= \\\'{ split($2, res, \"\\\\\"\"); print res[2]; }\\\'\\nexit\\n\');\r\n    child.waitExit();\r\n    ret.identifiers.board_serial = child.stdout.str.trim();\r\n\r\n    child = require(\'child_process\').execFile(\'/bin/sh\', [\'sh\']);\r\n    child.stdout.str = \'\'; child.stdout.on(\'data\', function (c) { this.str += c.toString(); });\r\n    child.stdin.write(\'ioreg -d2 -c IOPlatformExpertDevice | grep manufacturer | awk -F= \\\'{ split($2, res, \"\\\\\"\"); print res[2]; }\\\'\\nexit\\n\');\r\n    child.waitExit();\r\n    ret.identifiers.board_vendor = child.stdout.str.trim();\r\n\r\n    child = require(\'child_process\').execFile(\'/bin/sh\', [\'sh\']);\r\n    child.stdout.str = \'\'; child.stdout.on(\'data\', function (c) { this.str += c.toString(); });\r\n    child.stdin.write(\'ioreg -d2 -c IOPlatformExpertDevice | grep version | awk -F= \\\'{ split($2, res, \"\\\\\"\"); print res[2]; }\\\'\\nexit\\n\');\r\n    child.waitExit();\r\n    ret.identifiers.board_version = child.stdout.str.trim();\r\n\r\n    child = require(\'child_process\').execFile(\'/bin/sh\', [\'sh\']);\r\n    child.stdout.str = \'\'; child.stdout.on(\'data\', function (c) { this.str += c.toString(); });\r\n    child.stdin.write(\'ioreg -d2 -c IOPlatformExpertDevice | grep IOPlatformUUID | awk -F= \\\'{ split($2, res, \"\\\\\"\"); print res[2]; }\\\'\\nexit\\n\');\r\n    child.waitExit();\r\n    ret.identifiers.product_uuid = child.stdout.str.trim();\r\n\r\n    child = require(\'child_process\').execFile(\'/bin/sh\', [\'sh\']);\r\n    child.stdout.str = \'\'; child.stdout.on(\'data\', function (c) { this.str += c.toString(); });\r\n    child.stdin.write(\'sysctl -n machdep.cpu.brand_string\\nexit\\n\');\r\n    child.waitExit();\r\n    ret.identifiers.cpu_name = child.stdout.str.trim();\r\n\r\n    child = require(\'child_process\').execFile(\'/bin/sh\', [\'sh\']);\r\n    child.stdout.str = \'\'; child.stdout.on(\'data\', function (c) { this.str += c.toString(); });\r\n    child.stdin.write(\'system_profiler SPMemoryDataType\\nexit\\n\');\r\n    child.waitExit();\r\n    var lines = child.stdout.str.trim().split(\'\\n\');\r\n    if(lines.length > 0) {\r\n        const memorySlots = [];\r\n        if(lines[2].trim().includes(\'Memory Slots:\')) { // OLD MACS WITH SLOTS\r\n            var memorySlots1 = child.stdout.str.split(/\\n{2,}/).slice(3);\r\n            memorySlots1.forEach(function(slot,index) {\r\n                var lines = slot.split(\'\\n\');\r\n                if(lines.length == 1){ // start here\r\n                    if(lines[0].trim()!=\'\'){\r\n                        var slotObj = { DeviceLocator: lines[0].trim().replace(/:$/, \'\') }; // Initialize name as an empty string\r\n                        var nextline = memorySlots1[index+1].split(\'\\n\');\r\n                        nextline.forEach(function(line) {\r\n                            if (line.trim() !== \'\') {\r\n                                var parts = line.split(\':\');\r\n                                var key = parts[0].trim();\r\n                                var value = parts[1].trim();\r\n                                value = (key == \'Part Number\' || key == \'Manufacturer\') ? hexToAscii(parts[1].trim()) : parts[1].trim();\r\n                                slotObj[key.replace(\' \',\'\')] = value; // Store attribute in the slot object\r\n                            }\r\n                        });\r\n                        memorySlots.push(slotObj);\r\n                    }\r\n                }\r\n            });\r\n        } else { // NEW MACS WITHOUT SLOTS\r\n            memorySlots.push({ DeviceLocator: \"Onboard Memory\", Size: lines[2].split(\":\")[1].trim(), PartNumber: lines[3].split(\":\")[1].trim(), Manufacturer: lines[4].split(\":\")[1].trim() })\r\n        }\r\n        ret.darwin.memory = memorySlots;\r\n    }\r\n\r\n    child = require(\'child_process\').execFile(\'/bin/sh\', [\'sh\']);\r\n    child.stdout.str = \'\'; child.stdout.on(\'data\', function (c) { this.str += c.toString(); });\r\n    child.stdin.write(\'diskutil info -all\\nexit\\n\');\r\n    child.waitExit();\r\n    var sections = child.stdout.str.split(\'**********\\n\');\r\n    if(sections.length > 0){\r\n        var devices = [];\r\n        for (var i = 0; i < sections.length; i++) {\r\n            var lines = sections[i].split(\'\\n\');\r\n            var deviceInfo = {};\r\n            var wholeYes = false;\r\n            var physicalYes = false;\r\n            var oldmac = false;\r\n            for (var j = 0; j < lines.length; j++) {\r\n                var keyValue = lines[j].split(\':\');\r\n                var key = keyValue[0].trim();\r\n                var value = keyValue[1] ? keyValue[1].trim() : \'\';\r\n                if (key === \'Virtual\') oldmac = true;\r\n                if (key === \'Whole\' && value === \'Yes\') wholeYes = true;\r\n                if (key === \'Virtual\' && value === \'No\') physicalYes = true;\r\n                if(value && key === \'Device / Media Name\'){\r\n                    deviceInfo[\'Caption\'] = value;\r\n                }\r\n                if(value && key === \'Disk Size\'){\r\n                    deviceInfo[\'Size\'] = value.split(\' \')[0] + \' \' + value.split(\' \')[1];\r\n                }\r\n            }\r\n            if (wholeYes) {\r\n                if (oldmac) {\r\n                    if (physicalYes) devices.push(deviceInfo);\r\n                } else {\r\n                    devices.push(deviceInfo);\r\n                }\r\n            }\r\n        }\r\n        ret.identifiers.storage_devices = devices;\r\n    }\r\n\r\n    // Fetch storage volumes using df\r\n    child = require(\'child_process\').execFile(\'/bin/sh\', [\'sh\']);\r\n    child.stdout.str = \'\'; child.stdout.on(\'data\', dataHandler);\r\n    child.stdin.write(\'df -aHY | awk \\\'NR>1 {printf \"{\\\\\"size\\\\\":\\\\\"%s\\\\\",\\\\\"used\\\\\":\\\\\"%s\\\\\",\\\\\"available\\\\\":\\\\\"%s\\\\\",\\\\\"mount_point\\\\\":\\\\\"%s\\\\\",\\\\\"type\\\\\":\\\\\"%s\\\\\"},\", $3, $4, $5, $10, $2}\\\' | sed \\\'$ s/,$//\\\' | awk \\\'BEGIN {printf \"[\"} {printf \"%s\", $0} END {printf \"]\"}\\\'\\nexit\\n\');\r\n    child.waitExit();\r\n    try {\r\n        ret.darwin.volumes = JSON.parse(child.stdout.str.trim());\r\n        for (var index = 0; index < ret.darwin.volumes.length; index++) {\r\n            if (ret.darwin.volumes[index].type == \'auto_home\'){\r\n                ret.darwin.volumes.splice(index,1);\r\n            }\r\n        }\r\n        if (ret.darwin.volumes.length == 0) { // not sonima OS so dont show type for now\r\n            child = require(\'child_process\').execFile(\'/bin/sh\', [\'sh\']);\r\n            child.stdout.str = \'\'; child.stdout.on(\'data\', dataHandler);\r\n            child.stdin.write(\'df -aH | awk \\\'NR>1 {printf \"{\\\\\"size\\\\\":\\\\\"%s\\\\\",\\\\\"used\\\\\":\\\\\"%s\\\\\",\\\\\"available\\\\\":\\\\\"%s\\\\\",\\\\\"mount_point\\\\\":\\\\\"%s\\\\\"},\", $2, $3, $4, $9}\\\' | sed \\\'$ s/,$//\\\' | awk \\\'BEGIN {printf \"[\"} {printf \"%s\", $0} END {printf \"]\"}\\\'\\nexit\\n\');\r\n            child.waitExit();\r\n            try {\r\n                ret.darwin.volumes = JSON.parse(child.stdout.str.trim());\r\n                for (var index = 0; index < ret.darwin.volumes.length; index++) {\r\n                    if (ret.darwin.volumes[index].size == \'auto_home\'){\r\n                        ret.darwin.volumes.splice(index,1);\r\n                    }\r\n                }\r\n            } catch (xx) { }\r\n        }\r\n    } catch (xx) { }\r\n    child = null;\r\n\r\n    // MacOS Last Boot Up Time\r\n    try {\r\n        child = require(\'child_process\').execFile(\'/usr/sbin/sysctl\', [\'\', \'kern.boottime\']); // must include blank value at begining for some reason?\r\n        child.stdout.str = \'\'; child.stdout.on(\'data\', function (c) { this.str += c.toString(); });\r\n        child.stderr.on(\'data\', function () { });\r\n        child.waitExit();\r\n        const timestampMatch = /\\{ sec = (\\d+), usec = \\d+ \\}/.exec(child.stdout.str.trim());\r\n        if (!ret.darwin) {\r\n            ret.darwin = { LastBootUpTime: parseInt(timestampMatch[1]) };\r\n        } else {\r\n            ret.darwin.LastBootUpTime = parseInt(timestampMatch[1]);\r\n        }\r\n        child = null;\r\n    } catch (ex) { }\r\n\r\n    trimIdentifiers(ret.identifiers);\r\n\r\n    child = null;\r\n    return (ret);\r\n}\r\n\r\nfunction hexToAscii(hexString) {\r\n    if(!hexString.startsWith(\'0x\')) return hexString.trim();\r\n    hexString = hexString.startsWith(\'0x\') ? hexString.slice(2) : hexString;\r\n    var str = \'\';\r\n    for (var i = 0; i < hexString.length; i += 2) {\r\n        var hexPair = hexString.substr(i, 2);\r\n        str += String.fromCharCode(parseInt(hexPair, 16));\r\n    }\r\n    str = str.replace(/[\\u007F-\\uFFFF]/g, \'\'); // Remove characters from 0x0080 to 0xFFFF\r\n    return str.trim();\r\n}\r\n\r\nfunction win_chassisType()\r\n{\r\n    // use new win-wmi-fixed module to get arrays correctly for time being\r\n    try {\r\n        var tokens = require(\'win-wmi-fixed\').query(\'ROOT\\\\CIMV2\', \'SELECT ChassisTypes FROM Win32_SystemEnclosure\', [\'ChassisTypes\']);\r\n        if (tokens[0]) {\r\n            return (parseInt(tokens[0][\'ChassisTypes\'][0]));\r\n        }\r\n    } catch (e) {\r\n        return (2); // unknown\r\n    }\r\n}\r\n\r\nfunction win_systemType()\r\n{\r\n    try {\r\n        var tokens = require(\'win-wmi-fixed\').query(\'ROOT\\\\CIMV2\', \'SELECT PCSystemType FROM Win32_ComputerSystem\', [\'PCSystemType\']);\r\n        if (tokens[0]) {\r\n            return (parseInt(tokens[0][\'PCSystemType\']));\r\n        } else {\r\n            return (parseInt(1)); // default is desktop\r\n        }\r\n    } catch (ex) {\r\n        return (parseInt(1)); // default is desktop\r\n    }\r\n\r\n}\r\n\r\nfunction win_formFactor(chassistype)\r\n{\r\n    var ret = \'DESKTOP\';\r\n    switch (chassistype)\r\n    {\r\n        case 11:    // Handheld\r\n        case 30:    // Tablet\r\n        case 31:    // Convertible\r\n        case 32:    // Detachable\r\n            ret = \'TABLET\';\r\n            break;\r\n        case 9:     // Laptop\r\n        case 10:    // Notebook\r\n        case 14:    // Sub Notebook\r\n            ret = \'LAPTOP\';\r\n            break;\r\n        default:\r\n            ret = win_systemType() == 2 ? \'MOBILE\' : \'DESKTOP\';\r\n            break;\r\n    }\r\n\r\n    return (ret);\r\n}\r\n\r\nswitch(process.platform)\r\n{\r\n    case \'linux\':\r\n        module.exports = { _ObjectID: \'identifiers\', get: linux_identifiers };\r\n        break;\r\n    case \'win32\':\r\n        module.exports = { _ObjectID: \'identifiers\', get: windows_identifiers, chassisType: win_chassisType, formFactor: win_formFactor, systemType: win_systemType };\r\n        break;\r\n    case \'darwin\':\r\n        module.exports = { _ObjectID: \'identifiers\', get: macos_identifiers };\r\n        break;\r\n    default:\r\n        module.exports = { get: function () { throw (\'Unsupported Platform\'); } };\r\n        break;\r\n}\r\nmodule.exports.isDocker = function isDocker()\r\n{\r\n    if (process.platform != \'linux\') { return (false); }\r\n\r\n    var child = require(\'child_process\').execFile(\'/bin/sh\', [\'sh\']);\r\n    child.stdout.str = \'\'; child.stdout.on(\'data\', function (c) { this.str += c.toString(); });\r\n    child.stdin.write(\"cat /proc/self/cgroup | tr \'\\n\' \'`\' | awk -F\'`\' \'{ split($1, res, \" + \'\"/\"); if(res[2]==\"docker\"){print \"1\";} }\\\'\\nexit\\n\');\r\n    child.waitExit();\r\n    return (child.stdout.str != \'\');\r\n};\r\nmodule.exports.isBatteryPowered = function isBatteryOperated()\r\n{\r\n    var ret = false;\r\n    switch(process.platform)\r\n    {\r\n        default:\r\n            break;\r\n        case \'linux\':\r\n            var devices = require(\'fs\').readdirSync(\'/sys/class/power_supply\');\r\n            for (var i in devices)\r\n            {\r\n                if (require(\'fs\').readFileSync(\'/sys/class/power_supply/\' + devices[i] + \'/type\').toString().trim() == \'Battery\')\r\n                {\r\n                    ret = true;\r\n                    break;\r\n                }\r\n            }\r\n            break;\r\n        case \'win32\':\r\n            var GM = require(\'_GenericMarshal\');\r\n            var stats = GM.CreateVariable(12);\r\n            var kernel32 = GM.CreateNativeProxy(\'Kernel32.dll\');\r\n            kernel32.CreateMethod(\'GetSystemPowerStatus\');\r\n            if (kernel32.GetSystemPowerStatus(stats).Val != 0)\r\n            {\r\n                if(stats.toBuffer()[1] != 128 && stats.toBuffer()[1] != 255)\r\n                {\r\n                    ret = true;\r\n                }\r\n                else\r\n                {\r\n                    // No Battery detected, so lets check if there is supposed to be one\r\n                    var formFactor = win_formFactor(win_chassisType());\r\n                    return (formFactor == \'LAPTOP\' || formFactor == \'TABLET\' || formFactor == \'MOBILE\');\r\n                }\r\n            }\r\n            break;\r\n        case \'darwin\':\r\n            var child = require(\'child_process\').execFile(\'/bin/sh\', [\'sh\']);\r\n            child.stdout.str = \'\'; child.stdout.on(\'data\', function(c){ this.str += c.toString(); });\r\n            child.stderr.str = \'\'; child.stderr.on(\'data\', function(c){ this.str += c.toString(); });\r\n            child.stdin.write(\"pmset -g batt | tr \'\\\\n\' \'`\' | awk -F\'`\' \'{ if(NF>2) { print \\\"true\\\"; }}\'\\nexit\\n\");\r\n            child.waitExit();\r\n            if(child.stdout.str.trim() != \'\') { ret = true; }\r\n            break;\r\n    }\r\n    return (ret);\r\n};\r\nmodule.exports.isVM = function isVM()\r\n{\r\n    var ret = false;\r\n    var id = this.get();\r\n    if (id.linux && id.linux.sys_vendor)\r\n    {\r\n        switch (id.linux.sys_vendor)\r\n        {\r\n            case \'VMware, Inc.\':\r\n            case \'QEMU\':\r\n            case \'Xen\':\r\n                ret = true;\r\n                break;\r\n            default:\r\n                break;\r\n        }\r\n    }\r\n    if (id.identifiers.bios_vendor)\r\n    {\r\n        switch(id.identifiers.bios_vendor)\r\n        {\r\n            case \'VMware, Inc.\':\r\n            case \'Xen\':\r\n            case \'SeaBIOS\':\r\n            case \'EFI Development Kit II / OVMF\':\r\n            case \'Proxmox distribution of EDK II\':\r\n                ret = true;\r\n                break;\r\n            default:\r\n                break;\r\n        }\r\n    }\r\n    if (id.identifiers.board_vendor && id.identifiers.board_vendor == \'VMware, Inc.\') { ret = true; }\r\n    if (id.identifiers.board_name)\r\n    {\r\n        switch (id.identifiers.board_name)\r\n        {\r\n            case \'VirtualBox\':\r\n            case \'Virtual Machine\':\r\n                ret = true;\r\n                break;\r\n            default:\r\n                break;\r\n        }\r\n    }\r\n\r\n    if (process.platform == \'win32\' && !ret)\r\n    {\r\n        for(var i in id.identifiers.gpu_name)\r\n        {\r\n            if(id.identifiers.gpu_name[i].startsWith(\'VMware \'))\r\n            {\r\n                ret = true;\r\n                break;\r\n            }\r\n        }\r\n    }\r\n\r\n    if (id.identifiers.bios_vendor == \'Microsoft\' && id.identifiers.bios_version.slice(0,3) === \'WSL\') { ret = true; }\r\n\r\n    if (!ret) { ret = this.isDocker(); }\r\n    return (ret);\r\n};\r\n\r\n// bios_date = BIOS->ReleaseDate\r\n// bios_vendor = BIOS->Manufacturer\r\n// bios_version = BIOS->SMBIOSBIOSVersion\r\n// board_name = BASEBOARD->Product = ioreg/board-id\r\n// board_serial = BASEBOARD->SerialNumber = ioreg/serial-number | ioreg/IOPlatformSerialNumber\r\n// board_vendor = BASEBOARD->Manufacturer = ioreg/manufacturer\r\n// board_version = BASEBOARD->Version\r\n"); addedModules.push("computer-identifiers"); } catch (ex) { }
var coretranslations = JSON.parse('{\r\n  \"en\": {\r\n    \"allow\": \"Allow\",\r\n    \"deny\": \"Deny\",\r\n    \"autoAllowForFive\": \"Auto accept all connections for next 5 minutes\",\r\n    \"terminalConsent\": \"{0} requesting remote terminal access. Grant access?\",\r\n    \"desktopConsent\": \"{0} requesting remote desktop access. Grant access?\",\r\n    \"fileConsent\": \"{0} requesting remote file Access. Grant access?\",\r\n    \"terminalNotify\": \"{0} started a remote terminal session.\",\r\n    \"desktopNotify\": \"{0} started a remote desktop session.\",\r\n    \"fileNotify\": \"{0} started a remote file session.\",\r\n    \"privacyBar\": \"Sharing desktop with: {0}\"\r\n  },\r\n  \"cs\": {\r\n    \"allow\": \"Dovolit\",\r\n    \"deny\": \"Odmítnout\",\r\n    \"autoAllowForFive\": \"Automaticky přijímat všechna připojení na dalších 5 minut\",\r\n    \"terminalConsent\": \"{0} žádá o vzdálený terminálový přístup. Přístup povolen?\",\r\n    \"desktopConsent\": \"{0} žádá o přístup ke vzdálené ploše. Přístup povolen?\",\r\n    \"fileConsent\": \"{0} požaduje vzdálený přístup k souboru. Přístup povolen?\",\r\n    \"terminalNotify\": \"{0} zahájil relaci vzdáleného terminálu.\",\r\n    \"desktopNotify\": \"{0} zahájil relaci vzdálené plochy.\",\r\n    \"fileNotify\": \"{0} zahájil relaci vzdáleného souboru.\",\r\n    \"privacyBar\": \"Sdílení plochy s: {0}\"\r\n  },\r\n  \"de\": {\r\n    \"allow\": \"Erlauben\",\r\n    \"deny\": \"Verweigern\",\r\n    \"autoAllowForFive\": \"Alle Verbindungen für die nächsten 5 Minuten erlauben\",\r\n    \"terminalConsent\": \"{0} erbittet Fern-Terminalzugriff. Zugang erlauben?\",\r\n    \"desktopConsent\": \"{0} erbittet Fern-Desktopzugriff. Zugang erlauben?\",\r\n    \"fileConsent\": \"{0} erbittet Fern-Dateizugriff. Zugang erlauben?\",\r\n    \"terminalNotify\": \"{0} hat eine Fern-Terminalzugriff-Sitzung gestartet.\",\r\n    \"desktopNotify\": \"{0} hat eine Fern-Desktopzugriff-Sitzung gestartet.\",\r\n    \"fileNotify\": \"{0} hat eine Fern-Dateizugriff-Sitzung gestartet.\",\r\n    \"privacyBar\": \"Teile desktop mit: {0}\"\r\n  },\r\n  \"es\": {\r\n    \"allow\": \"Permitir\",\r\n    \"deny\": \"Negar\",\r\n    \"autoAllowForFive\": \"Aceptar automáticamente todas las conexiones durante los próximos 5 minutos\",\r\n    \"terminalConsent\": \"{0} solicitando acceso a terminal remoto. ¿Autorizará el acceso?\",\r\n    \"desktopConsent\": \"{0} solicita acceso a escritorio remoto. ¿Autorizará el acceso?\",\r\n    \"fileConsent\": \"{0} solicita acceso remoto al archivo. ¿Autorizará el acceso?\",\r\n    \"terminalNotify\": \"{0} inició una sesión de terminal remota.\",\r\n    \"desktopNotify\": \"{0} inició una sesión de escritorio remoto.\",\r\n    \"fileNotify\": \"{0} inició una sesión de archivo remoto.\",\r\n    \"privacyBar\": \"Compartir escritorio con: {0}\"\r\n  },\r\n  \"fi\": {\r\n    \"allow\": \"Sallia\",\r\n    \"deny\": \"Kieltää\",\r\n    \"autoAllowForFive\": \"Hyväksy automaattisesti kaikki yhteydet seuraavan 5 minuutin ajan\",\r\n    \"terminalConsent\": \"{0} pyytää etäpäätteen käyttöoikeutta. Myönnetäänkö käyttöoikeus?\",\r\n    \"desktopConsent\": \"{0} pyytää etätyöpöytäkäyttöä. Myönnetäänkö käyttöoikeus?\",\r\n    \"fileConsent\": \"{0} pyytää etäkäyttöoikeutta tiedostoon. Myönnetäänkö käyttöoikeus?\",\r\n    \"terminalNotify\": \"{0} aloitti etäpääteistunnon.\",\r\n    \"desktopNotify\": \"{0} aloitti etätyöpöytäistunnon.\",\r\n    \"fileNotify\": \"{0} aloitti etätiedostoistunnon.\",\r\n    \"privacyBar\": \"Työpöytä jaetaan seuraavien kanssa: {0}\"\r\n  },\r\n  \"fr\": {\r\n    \"allow\": \"Permettre\",\r\n    \"deny\": \"Refuser\",\r\n    \"autoAllowForFive\": \"Accepter automatiquement les connexions pendant les 5 prochaines minutes\",\r\n    \"terminalConsent\": \"{0} demande(nt) d\'utilisation du terminal à distance. Autoriser l\'accès ?\",\r\n    \"desktopConsent\": \"{0} demande(nt) l\'utilisation du bureau à distance. Autoriser l\'accès ?\",\r\n    \"fileConsent\": \"{0} demande(nt) d\'accès à un fichier à distance. Autoriser l\'accès ?\",\r\n    \"terminalNotify\": \"{0} a démarré une session de terminal distant.\",\r\n    \"desktopNotify\": \"{0} a démarré une session de bureau à distance.\",\r\n    \"fileNotify\": \"{0} a démarré une session de fichiers à distance.\",\r\n    \"privacyBar\": \"Partage du bureau avec : {0}\"\r\n  },\r\n  \"hi\": {\r\n    \"allow\": \"अनुमति\",\r\n    \"deny\": \"मना\",\r\n    \"autoAllowForFive\": \"अगले 5 मिनट के लिए सभी कनेक्शन स्वतः स्वीकार करें\",\r\n    \"terminalConsent\": \"{0} दूरस्थ टर्मिनल पहुंच का अनुरोध कर रहा है। अनुदान पहुँच?\",\r\n    \"desktopConsent\": \"{0} दूरस्थ डेस्कटॉप पहुंच का अनुरोध कर रहा है। अनुदान पहुँच?\",\r\n    \"fileConsent\": \"{0} दूरस्थ फ़ाइल एक्सेस का अनुरोध करना। अनुदान पहुँच?\",\r\n    \"terminalNotify\": \"{0} ने दूरस्थ टर्मिनल सत्र प्रारंभ किया।\",\r\n    \"desktopNotify\": \"{0} ने दूरस्थ डेस्कटॉप सत्र प्रारंभ किया।\",\r\n    \"fileNotify\": \"{0} ने दूरस्थ फ़ाइल सत्र प्रारंभ किया।\",\r\n    \"privacyBar\": \"इसके साथ डेस्कटॉप साझा करना: {0}\"\r\n  },\r\n  \"it\": {\r\n    \"allow\": \"Permettere\",\r\n    \"deny\": \"Negare\",\r\n    \"autoAllowForFive\": \"Accetta automaticamente tutte le connessioni per i prossimi 5 minuti\",\r\n    \"terminalConsent\": \"{0} che richiede l\'accesso al terminale remoto. Concedere l\'accesso?\",\r\n    \"desktopConsent\": \"{0} che richiede l\'accesso al desktop remoto. Concedere l\'accesso?\",\r\n    \"fileConsent\": \"{0} che richiede l\'accesso al file remoto. Concedere l\'accesso?\",\r\n    \"terminalNotify\": \"{0} ha avviato una sessione di terminale remoto.\",\r\n    \"desktopNotify\": \"{0} ha avviato una sessione desktop remoto.\",\r\n    \"fileNotify\": \"{0} ha avviato una sessione di file remota.\",\r\n    \"privacyBar\": \"Condivisione del desktop con: {0}\"\r\n  },\r\n  \"ja\": {\r\n    \"allow\": \"許可する\",\r\n    \"deny\": \"拒否\",\r\n    \"autoAllowForFive\": \"次の5分間はすべての接続を自動受け入れます\",\r\n    \"terminalConsent\": \"{0}リモート端末アクセスを要求しています。アクセス許可？\",\r\n    \"desktopConsent\": \"{0}リモートデスクトップアクセスを要求しています。アクセス許可？\",\r\n    \"fileConsent\": \"{0}リモートファイルアクセスを要求しています。アクセス許可？\",\r\n    \"terminalNotify\": \"{0}がリモートターミナルセッションを開始しました。\",\r\n    \"desktopNotify\": \"{0}はリモートデスクトップセッションを開始しました。\",\r\n    \"fileNotify\": \"{0}がリモートファイルセッションを開始しました。\",\r\n    \"privacyBar\": \"デスクトップの共有：{0}\"\r\n  },\r\n  \"ko\": {\r\n    \"allow\": \"허용하다\",\r\n    \"deny\": \"거부\",\r\n    \"terminalNotify\": \"{0}이(가) 원격 터미널 세션을 시작했습니다.\",\r\n    \"desktopNotify\": \"{0}이(가) 원격 데스크톱 세션을 시작했습니다.\",\r\n    \"fileNotify\": \"{0}이(가) 원격 파일 세션을 시작했습니다.\",\r\n    \"privacyBar\": \"다음과 데스크톱 공유: {0}\",\r\n    \"autoAllowForFive\": \"다음 5분 동안 모든 연결 자동 수락\",\r\n    \"terminalConsent\": \"{0} 원격 터미널 액세스를 요청합니다. 액세스 권한을 부여하시겠습니까?\",\r\n    \"desktopConsent\": \"{0} 원격 데스크톱 액세스를 요청합니다. 액세스 권한을 부여하시겠습니까?\",\r\n    \"fileConsent\": \"{0}이(가) 원격 파일 액세스를 요청합니다. 액세스 권한을 부여하시겠습니까?\"\r\n  },\r\n  \"nl\": {\r\n    \"allow\": \"Toestaan\",\r\n    \"deny\": \"Weigeren\",\r\n    \"autoAllowForFive\": \"Alle verbindingen automatisch accepteren voor de komende 5 minuten\",\r\n    \"terminalConsent\": \"{0} verzoekt om toegang tot externe terminal.Toegang verlenen?\",\r\n    \"desktopConsent\": \"{0} verzoekt om toegang tot extern bureaublad.Toegang verlenen?\",\r\n    \"fileConsent\": \"{0} verzoekt om externe bestandstoegang.Toegang verlenen?\",\r\n    \"terminalNotify\": \"{0} heeft een externe terminalsessie gestart.\",\r\n    \"desktopNotify\": \"{0} heeft een extern bureaubladsessie gestart.\",\r\n    \"fileNotify\": \"{0} heeft een externe bestandssessie gestart.\",\r\n    \"privacyBar\": \"Bureaublad delen met: {0}\"\r\n  },\r\n  \"pt\": {\r\n    \"allow\": \"Permitir\",\r\n    \"deny\": \"Negar\",\r\n    \"autoAllowForFive\": \"Aceita automaticamente todas as conexões pelos próximos 5 minutos\",\r\n    \"terminalConsent\": \"{0} está a pedir acesso ao terminal remoto. Conceder acesso?\",\r\n    \"desktopConsent\": \"{0} está a pedir acesso à área de trabalho remota. Conceder acesso?\",\r\n    \"fileConsent\": \"{0} está a pedir acesso remoto aos ficheiros. Conceder acesso?\",\r\n    \"terminalNotify\": \"{0} iniciou uma sessão de terminal remoto.\",\r\n    \"desktopNotify\": \"{0} iniciou uma sessão de área de trabalho remota.\",\r\n    \"fileNotify\": \"{0} iniciou uma sessão de ficheiro remoto.\",\r\n    \"privacyBar\": \"Compartilhando área de trabalho com: {0}\"\r\n  },\r\n  \"ru\": {\r\n    \"allow\": \"Разрешить\",\r\n    \"deny\": \"Отказать\",\r\n    \"autoAllowForFive\": \"Автоматически принимать все соединения в течение 5 минут\",\r\n    \"terminalConsent\": \"{0} запрашивает удаленный доступ к терминалу. Разрешить доступ?\",\r\n    \"desktopConsent\": \"{0} запрашивает удаленный доступ к рабочему столу. Разрешить доступ?\",\r\n    \"fileConsent\": \"{0} запрашивает удаленный доступ к файлам. Разрешить доступ?\",\r\n    \"terminalNotify\": \"{0} начал сеанс удаленного терминала.\",\r\n    \"desktopNotify\": \"{0} начал сеанс удаленного рабочего стола.\",\r\n    \"fileNotify\": \"{0} начал удаленный файловый сеанс.\",\r\n    \"privacyBar\": \"Доступ к рабочему столу предоставлен: {0}\"\r\n  },\r\n  \"sv\": {\r\n    \"allow\": \"Tillåta\",\r\n    \"deny\": \"Förneka\",\r\n    \"autoAllowForFive\": \"Acceptera alla anslutningar automatiskt under de kommande 5 minuterna\",\r\n    \"terminalConsent\": \"{0} begär åtkomst till fjärrterminal. Ge tillgång?\",\r\n    \"desktopConsent\": \"{0} begär åtkomst till fjärrskrivbord. Ge tillgång?\",\r\n    \"fileConsent\": \"{0} begär fjärråtkomst till fil. Ge tillgång?\",\r\n    \"terminalNotify\": \"{0} startade en fjärrterminalsession.\",\r\n    \"desktopNotify\": \"{0} startade en fjärrskrivbordssession.\",\r\n    \"fileNotify\": \"{0} startade en fjärrfilsession.\",\r\n    \"privacyBar\": \"Dela skrivbord med: {0}\"\r\n  },\r\n  \"tr\": {\r\n    \"allow\": \"İzin ver\",\r\n    \"deny\": \"İnkar etmek\",\r\n    \"autoAllowForFive\": \"Sonraki 5 dakika boyunca tüm bağlantıları otomatik olarak kabul et\",\r\n    \"terminalConsent\": \"{0} uzak terminal erişimi istiyor. Erişim izni veriyor musunuz?\",\r\n    \"desktopConsent\": \"{0} uzak masaüstü erişimi istiyor. Erişim izni veriyor musunuz?\",\r\n    \"fileConsent\": \"{0} uzak dosya Erişimi istiyor. Erişim izni veriyor musunuz?\",\r\n    \"terminalNotify\": \"{0} bir uzak terminal oturumu başlattı.\",\r\n    \"desktopNotify\": \"{0} bir uzak masaüstü oturumu başlattı.\",\r\n    \"fileNotify\": \"{0} bir uzak dosya oturumu başlattı.\",\r\n    \"privacyBar\": \"Masaüstünü şu kişilerle paylaşma: {0}\"\r\n  },\r\n  \"zh-chs\": {\r\n    \"allow\": \"允许\",\r\n    \"deny\": \"否定\",\r\n    \"autoAllowForFive\": \"在接下来的 5 分钟内自动接受所有连接\",\r\n    \"terminalConsent\": \"{0} 请求远程终端访问。授予访问权限？\",\r\n    \"desktopConsent\": \"{0} 请求远程桌面访问。授予访问权限？\",\r\n    \"fileConsent\": \"{0} 请求远程文件访问。授予访问权限？\",\r\n    \"terminalNotify\": \"{0} 启动了远程终端会话。\",\r\n    \"desktopNotify\": \"{0} 启动了远程桌面会话。\",\r\n    \"fileNotify\": \"{0} 启动了远程文件会话。\",\r\n    \"privacyBar\": \"与：{0} 共享桌面\"\r\n  },\r\n  \"da\": {\r\n    \"allow\": \"Tillad\",\r\n    \"deny\": \"Afslå\",\r\n    \"autoAllowForFive\": \"Accepter automatisk alle forbindelser i de næste 5 minutter\",\r\n    \"terminalConsent\": \"{0} anmoder om ekstern terminaladgang. Give adgang?\",\r\n    \"desktopConsent\": \"{0} anmoder om fjernskrivebordsadgang. Give adgang?\",\r\n    \"fileConsent\": \"{0} anmoder om fjernadgang til fil. Give adgang?\",\r\n    \"terminalNotify\": \"{0} startede en fjernterminalsession.\",\r\n    \"desktopNotify\": \"{0} startede en fjernskrivebordssession.\",\r\n    \"fileNotify\": \"{0} startede en ekstern filsession.\",\r\n    \"privacyBar\": \"Deler skrivebordet med: {0}\"\r\n  },\r\n  \"pl\": {\r\n    \"allow\": \"Zezwól\",\r\n    \"deny\": \"Odrzucono\",\r\n    \"autoAllowForFive\": \"Automatycznie akceptuj wszystkie połączenia przez następne 5 minut\",\r\n    \"terminalConsent\": \"{0} prosi o zdalny dostęp do terminala. Przyznać dostęp?\",\r\n    \"desktopConsent\": \"{0} prosi o zdalny dostęp do pulpitu. Przyznać dostęp?\",\r\n    \"fileConsent\": \"{0} prosi o zdalny dostęp do plików. Przyznać dostęp?\",\r\n    \"terminalNotify\": \"{0} rozpoczął sesję dostępu do terminala.\",\r\n    \"desktopNotify\": \"{0} rozpoczął sesję dostępu do pulpitu.\",\r\n    \"fileNotify\": \"{0} rozpoczął sesję dostępu do plików.\",\r\n    \"privacyBar\": \"Współdzielenie pulpitu z: {0}\"\r\n  },\r\n  \"pt-br\": {\r\n    \"allow\": \"Permitir\",\r\n    \"deny\": \"Negar\",\r\n    \"autoAllowForFive\": \"Aceitar todas conexões pelos próximos 5 minutos\",\r\n    \"terminalConsent\": \"{0} está solicitando acesso ao terminal. Permitir?\",\r\n    \"desktopConsent\": \"{0} está solicitando acesso a área de trabalho remota. Permitir?\",\r\n    \"fileConsent\": \"{0} está solicitando acesso aos arquivos. Permitir?\",\r\n    \"terminalNotify\": \"{0} iniciou uma sessão de terminal.\",\r\n    \"desktopNotify\": \"{0} iniciou uma sessão de área de trabalho remota.\",\r\n    \"fileNotify\": \"{0} {0} iniciou uma sessão de arquivos.\",\r\n    \"privacyBar\": \"Compartilhando área de trabalho com: {0}\"\r\n  },\r\n  \"zh-cht\": {\r\n    \"allow\": \"允許\",\r\n    \"deny\": \"否定\",\r\n    \"autoAllowForFive\": \"在接下來的 5 分鐘內自動接受所有連接\",\r\n    \"terminalConsent\": \"{0} 請求遠程終端訪問。授予訪問權限？\",\r\n    \"desktopConsent\": \"{0} 請求遠程桌面訪問。授予訪問權限？\",\r\n    \"fileConsent\": \"{0} 請求遠程文件訪問。授予訪問權限？\",\r\n    \"terminalNotify\": \"{0} 啟動了遠程終端會話。\",\r\n    \"desktopNotify\": \"{0} 啟動了遠程桌面會話。\",\r\n    \"fileNotify\": \"{0} 啟動了遠程文件會話。\",\r\n    \"privacyBar\": \"與：{0} 共享桌面\"\r\n  },\r\n  \"bs\": {\r\n    \"allow\": \"Dopustiti\",\r\n    \"deny\": \"Deny\",\r\n    \"autoAllowForFive\": \"Automatski prihvati sve veze u narednih 5 minuta\",\r\n    \"terminalConsent\": \"{0} zahtijeva pristup udaljenom terminalu. Odobriti pristup?\",\r\n    \"desktopConsent\": \"{0} zahtijeva pristup udaljenoj radnoj površini. Odobriti pristup?\",\r\n    \"fileConsent\": \"{0} zahtijeva udaljeni pristup fajlu. Odobriti pristup?\",\r\n    \"terminalNotify\": \"{0} je započeo sesiju udaljenog terminala.\",\r\n    \"desktopNotify\": \"{0} je započeo sesiju udaljene radne površine.\",\r\n    \"fileNotify\": \"{0} je započeo sesiju udaljenog fajla.\",\r\n    \"privacyBar\": \"Dijeljenje radne površine sa: {0}\"\r\n  },\r\n  \"hu\": {\r\n    \"allow\": \"Engedélyezés\",\r\n    \"deny\": \"Elutasítás\",\r\n    \"autoAllowForFive\": \"Csatlakozások automatikus elfogadása a következő 5 percben\",\r\n    \"terminalConsent\": \"{0} távoli parancssor,terminál hozzáférést kér. Engedélyezi a hozzáférést?\",\r\n    \"desktopConsent\": \"{0} távoli asztali hozzáférést kér. Engedélyezi a hozzáférést?\",\r\n    \"fileConsent\": \"{0} távoli fájlhozzáférést kér. Engedélyezi a hozzáférést?\",\r\n    \"terminalNotify\": \"{0} távoli parancssor munkamenetet indított.\",\r\n    \"desktopNotify\": \"{0} távoli asztali munkamenetet indított.\",\r\n    \"fileNotify\": \"{0} távoli fájlmunkamenetet indított.\",\r\n    \"privacyBar\": \"Asztal megosztás aktív: {0} felhasználóval\"\r\n  },\r\n  \"ca\": {\r\n    \"allow\": \"Permetre\",\r\n    \"deny\": \"Negar\",\r\n    \"autoAllowForFive\": \"Accepta automàticament totes les connexions durant els propers 5 minuts\",\r\n    \"terminalConsent\": \"{0} sol·licitant accés al terminal remot. Accés garantit?\",\r\n    \"desktopConsent\": \"{0} sol·licitant accés a l\'escriptori remot. Accés garantit?\",\r\n    \"fileConsent\": \"{0} sol·licitant accés remot al fitxer. Accés garantit?\",\r\n    \"terminalNotify\": \"{0} va iniciar una sessió de terminal remota.\",\r\n    \"desktopNotify\": \"{0} va iniciar una sessió d\'escriptori remot.\",\r\n    \"fileNotify\": \"{0} va iniciar una sessió de fitxer remota.\",\r\n    \"privacyBar\": \"Compartint escriptori amb: {0}\"\r\n  },\r\n  \"uk\": {\r\n    \"allow\": \"Дозволити\",\r\n    \"deny\": \"Відмовити\",\r\n    \"autoAllowForFive\": \"Автоматично підтверджувати всі підключення впродовж наступних 5 хвилин\",\r\n    \"terminalConsent\": \"{0} запитує дозвіл на віддалене використання вашого терміналу (командного рядка). Надати доступ?\",\r\n    \"desktopConsent\": \"{0} запитує дозвіл на віддалений доступ до робочого столу. Надати доступ?\",\r\n    \"fileConsent\": \"{0} запитує дозвіл на віддалене управління файлами. Надати доступ?\",\r\n    \"terminalNotify\": \"{0} почав віддалено використовувати ваш термінал (командний рядок).\",\r\n    \"desktopNotify\": \"{0} розпочав сеанс віддаленого робочого столу.\",\r\n    \"fileNotify\": \"{0} почав віддалене управління вашими файлами.\",\r\n    \"privacyBar\": \"Ви ділитесь робочим столом з: {0}\"\r\n  }\r\n}');
try { addModule("linux-dhcp", "/*\r\nCopyright 2021 Intel Corporation\r\n\r\nLicensed under the Apache License, Version 2.0 (the \"License\");\r\nyou may not use this file except in compliance with the License.\r\nYou may obtain a copy of the License at\r\n\r\n    http://www.apache.org/licenses/LICENSE-2.0\r\n\r\nUnless required by applicable law or agreed to in writing, software\r\ndistributed under the License is distributed on an \"AS IS\" BASIS,\r\nWITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.\r\nSee the License for the specific language governing permissions and\r\nlimitations under the License.\r\n\r\n* @description Mini DHCP Client Module, to fetch configuration data\r\n* @author Bryan Roe & Ylian Saint-Hilaire\r\n*/\r\n\r\n// DHCP Information\r\nif (Function.prototype.internal == null) { Object.defineProperty(Function.prototype, \'internal\', { get: function () { return (this); } }); }\r\nif (global._hide == null)\r\n{\r\n    global._hide = function _hide(v)\r\n    {\r\n        if(v==null || (v!=null && typeof(v)==\'boolean\'))\r\n        {\r\n            var ret = _hide.currentObject;\r\n            if (v) { _hide.currentObject = null; }\r\n            return (ret);\r\n        }\r\n        else\r\n        {\r\n            _hide.currentObject = v;\r\n        }\r\n    }\r\n}\r\naddModule(\'promise2\', Buffer.from(\'LyoNCkNvcHlyaWdodCAyMDE4IEludGVsIENvcnBvcmF0aW9uDQoNCkxpY2Vuc2VkIHVuZGVyIHRoZSBBcGFjaGUgTGljZW5zZSwgVmVyc2lvbiAyLjAgKHRoZSAiTGljZW5zZSIpOw0KeW91IG1heSBub3QgdXNlIHRoaXMgZmlsZSBleGNlcHQgaW4gY29tcGxpYW5jZSB3aXRoIHRoZSBMaWNlbnNlLg0KWW91IG1heSBvYnRhaW4gYSBjb3B5IG9mIHRoZSBMaWNlbnNlIGF0DQoNCiAgICBodHRwOi8vd3d3LmFwYWNoZS5vcmcvbGljZW5zZXMvTElDRU5TRS0yLjANCg0KVW5sZXNzIHJlcXVpcmVkIGJ5IGFwcGxpY2FibGUgbGF3IG9yIGFncmVlZCB0byBpbiB3cml0aW5nLCBzb2Z0d2FyZQ0KZGlzdHJpYnV0ZWQgdW5kZXIgdGhlIExpY2Vuc2UgaXMgZGlzdHJpYnV0ZWQgb24gYW4gIkFTIElTIiBCQVNJUywNCldJVEhPVVQgV0FSUkFOVElFUyBPUiBDT05ESVRJT05TIE9GIEFOWSBLSU5ELCBlaXRoZXIgZXhwcmVzcyBvciBpbXBsaWVkLg0KU2VlIHRoZSBMaWNlbnNlIGZvciB0aGUgc3BlY2lmaWMgbGFuZ3VhZ2UgZ292ZXJuaW5nIHBlcm1pc3Npb25zIGFuZA0KbGltaXRhdGlvbnMgdW5kZXIgdGhlIExpY2Vuc2UuDQoqLw0KDQp2YXIgcmVmVGFibGUgPSB7fTsNCg0KZnVuY3Rpb24gcHJvbWlzZUluaXRpYWxpemVyKHIsaikNCnsNCiAgICB0aGlzLl9yZXMgPSByOw0KICAgIHRoaXMuX3JlaiA9IGo7DQp9DQoNCmZ1bmN0aW9uIGdldFJvb3RQcm9taXNlKG9iaikNCnsNCiAgICB3aGlsZShvYmoucGFyZW50UHJvbWlzZSkNCiAgICB7DQogICAgICAgIG9iaiA9IG9iai5wYXJlbnRQcm9taXNlOw0KICAgIH0NCiAgICByZXR1cm4gKG9iaik7DQp9DQoNCmZ1bmN0aW9uIGV2ZW50X3N3aXRjaGVyKGRlc2lyZWRfY2FsbGVlLCB0YXJnZXQpDQp7DQogICAgcmV0dXJuICh7IF9PYmplY3RJRDogJ2V2ZW50X3N3aXRjaGVyJywgZnVuYzogdGFyZ2V0LmJpbmQoZGVzaXJlZF9jYWxsZWUpIH0pOw0KfQ0KDQpmdW5jdGlvbiBldmVudF9mb3J3YXJkZXIoc291cmNlT2JqLCBzb3VyY2VOYW1lLCB0YXJnZXRPYmosIHRhcmdldE5hbWUpDQp7DQogICAgc291cmNlT2JqLm9uKHNvdXJjZU5hbWUsIHRhcmdldE9iai5lbWl0LmJpbmQodGFyZ2V0T2JqKSk7DQp9DQoNCg0KZnVuY3Rpb24gcmV0dXJuX3Jlc29sdmVkKCkNCnsNCiAgICB2YXIgcGFybXMgPSBbJ3Jlc29sdmVkJ107DQogICAgZm9yICh2YXIgYWkgaW4gYXJndW1lbnRzKQ0KICAgIHsNCiAgICAgICAgcGFybXMucHVzaChhcmd1bWVudHNbYWldKTsNCiAgICB9DQogICAgdGhpcy5fWFNMRi5lbWl0LmFwcGx5KHRoaXMuX1hTTEYsIHBhcm1zKTsNCn0NCmZ1bmN0aW9uIHJldHVybl9yZWplY3RlZCgpDQp7DQogICAgdGhpcy5fWFNMRi5wcm9taXNlLl9fY2hpbGRQcm9taXNlLl9yZWooZSk7DQp9DQpmdW5jdGlvbiBlbWl0cmVqZWN0KGEpDQp7DQogICAgcHJvY2Vzcy5lbWl0KCd1bmNhdWdodEV4Y2VwdGlvbicsICdwcm9taXNlLnVuY2F1Z2h0UmVqZWN0aW9uOiAnICsgSlNPTi5zdHJpbmdpZnkoYSkpOw0KfQ0KZnVuY3Rpb24gUHJvbWlzZShwcm9taXNlRnVuYykNCnsNCiAgICB0aGlzLl9PYmplY3RJRCA9ICdwcm9taXNlJzsNCiAgICB0aGlzLnByb21pc2UgPSB0aGlzOw0KICAgIHRoaXMuX2ludGVybmFsID0geyBfT2JqZWN0SUQ6ICdwcm9taXNlLmludGVybmFsJywgcHJvbWlzZTogdGhpcywgY29tcGxldGVkOiBmYWxzZSwgZXJyb3JzOiBmYWxzZSwgY29tcGxldGVkQXJnczogW10sIGludGVybmFsQ291bnQ6IDAsIF91cDogbnVsbCB9Ow0KICAgIHJlcXVpcmUoJ2V2ZW50cycpLkV2ZW50RW1pdHRlci5jYWxsKHRoaXMuX2ludGVybmFsKTsNCiAgICBPYmplY3QuZGVmaW5lUHJvcGVydHkodGhpcywgInBhcmVudFByb21pc2UiLA0KICAgICAgICB7DQogICAgICAgICAgICBnZXQ6IGZ1bmN0aW9uICgpIHsgcmV0dXJuICh0aGlzLl91cCk7IH0sDQogICAgICAgICAgICBzZXQ6IGZ1bmN0aW9uICh2YWx1ZSkNCiAgICAgICAgICAgIHsNCiAgICAgICAgICAgICAgICBpZiAodmFsdWUgIT0gbnVsbCAmJiB0aGlzLl91cCA9PSBudWxsKQ0KICAgICAgICAgICAgICAgIHsNCiAgICAgICAgICAgICAgICAgICAgLy8gV2UgYXJlIG5vIGxvbmdlciBhbiBvcnBoYW4NCiAgICAgICAgICAgICAgICAgICAgaWYgKHRoaXMuX2ludGVybmFsLnVuY2F1Z2h0ICE9IG51bGwpDQogICAgICAgICAgICAgICAgICAgIHsNCiAgICAgICAgICAgICAgICAgICAgICAgIGNsZWFySW1tZWRpYXRlKHRoaXMuX2ludGVybmFsLnVuY2F1Z2h0KTsNCiAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMuX2ludGVybmFsLnVuY2F1Z2h0ID0gbnVsbDsNCiAgICAgICAgICAgICAgICAgICAgfQ0KICAgICAgICAgICAgICAgIH0NCiAgICAgICAgICAgICAgICB0aGlzLl91cCA9IHZhbHVlOw0KICAgICAgICAgICAgfQ0KICAgICAgICB9KTsNCiAgICBPYmplY3QuZGVmaW5lUHJvcGVydHkodGhpcywgImRlc2NyaXB0b3JNZXRhZGF0YSIsDQogICAgICAgIHsNCiAgICAgICAgICAgIGdldDogZnVuY3Rpb24gKCkNCiAgICAgICAgICAgIHsNCiAgICAgICAgICAgICAgICByZXR1cm4gKHJlcXVpcmUoJ2V2ZW50cycpLmdldFByb3BlcnR5LmNhbGwodGhpcy5faW50ZXJuYWwsICc/X0ZpbmFsaXplckRlYnVnTWVzc2FnZScpKTsNCiAgICAgICAgICAgIH0sDQogICAgICAgICAgICBzZXQ6IGZ1bmN0aW9uICh2YWx1ZSkNCiAgICAgICAgICAgIHsNCiAgICAgICAgICAgICAgICByZXF1aXJlKCdldmVudHMnKS5zZXRQcm9wZXJ0eS5jYWxsKHRoaXMuX2ludGVybmFsLCAnP19GaW5hbGl6ZXJEZWJ1Z01lc3NhZ2UnLCB2YWx1ZSk7DQogICAgICAgICAgICB9DQogICAgICAgIH0pOw0KICAgIHRoaXMuX2ludGVybmFsLm9uKCd+JywgZnVuY3Rpb24gKCkNCiAgICB7DQogICAgICAgIHRoaXMuY29tcGxldGVkQXJncyA9IFtdOw0KICAgIH0pOw0KICAgIHRoaXMuX2ludGVybmFsLm9uKCduZXdMaXN0ZW5lcjInLCAoZnVuY3Rpb24gKGV2ZW50TmFtZSwgZXZlbnRDYWxsYmFjaykNCiAgICB7DQogICAgICAgIC8vY29uc29sZS5sb2coJ25ld0xpc3RlbmVyJywgZXZlbnROYW1lLCAnZXJyb3JzLycgKyB0aGlzLmVycm9ycyArICcgY29tcGxldGVkLycgKyB0aGlzLmNvbXBsZXRlZCk7DQogICAgICAgIHZhciByID0gbnVsbDsNCg0KICAgICAgICBpZiAoZXZlbnROYW1lID09ICdyZXNvbHZlZCcgJiYgIXRoaXMuZXJyb3JzICYmIHRoaXMuY29tcGxldGVkKQ0KICAgICAgICB7DQogICAgICAgICAgICByID0gZXZlbnRDYWxsYmFjay5hcHBseSh0aGlzLCB0aGlzLmNvbXBsZXRlZEFyZ3MpOw0KICAgICAgICAgICAgaWYociE9bnVsbCkNCiAgICAgICAgICAgIHsNCiAgICAgICAgICAgICAgICB0aGlzLmVtaXRfcmV0dXJuVmFsdWUoJ3Jlc29sdmVkJywgcik7DQogICAgICAgICAgICB9DQogICAgICAgICAgICB0cnkgeyB0aGlzLnJlbW92ZUFsbExpc3RlbmVycygncmVzb2x2ZWQnKTsgfSBjYXRjaCAoeCkgeyB9DQogICAgICAgICAgICB0cnkgeyB0aGlzLnJlbW92ZUFsbExpc3RlbmVycygncmVqZWN0ZWQnKTsgfSBjYXRjaCAoeCkgeyB9DQogICAgICAgIH0NCg0KICAgICAgICAvL2lmIChldmVudE5hbWUgPT0gJ3JlamVjdGVkJyAmJiAoZXZlbnRDYWxsYmFjay5pbnRlcm5hbCA9PSBudWxsIHx8IGV2ZW50Q2FsbGJhY2suaW50ZXJuYWwgPT0gZmFsc2UpKQ0KICAgICAgICBpZiAoZXZlbnROYW1lID09ICdyZWplY3RlZCcpDQogICAgICAgIHsNCiAgICAgICAgICAgIGlmICh0aGlzLnVuY2F1Z2h0ICE9IG51bGwpDQogICAgICAgICAgICB7DQogICAgICAgICAgICAgICAgY2xlYXJJbW1lZGlhdGUodGhpcy51bmNhdWdodCk7DQogICAgICAgICAgICAgICAgdGhpcy51bmNhdWdodCA9IG51bGw7DQogICAgICAgICAgICB9DQogICAgICAgICAgICBpZiAodGhpcy5wcm9taXNlKQ0KICAgICAgICAgICAgew0KICAgICAgICAgICAgICAgIHZhciBycCA9IGdldFJvb3RQcm9taXNlKHRoaXMucHJvbWlzZSk7DQogICAgICAgICAgICAgICAgcnAuX2ludGVybmFsLmV4dGVybmFsID0gdHJ1ZTsNCiAgICAgICAgICAgICAgICBpZiAocnAuX2ludGVybmFsLnVuY2F1Z2h0ICE9IG51bGwpDQogICAgICAgICAgICAgICAgew0KICAgICAgICAgICAgICAgICAgICBjbGVhckltbWVkaWF0ZShycC5faW50ZXJuYWwudW5jYXVnaHQpOw0KICAgICAgICAgICAgICAgICAgICBycC5faW50ZXJuYWwudW5jYXVnaHQgPSBudWxsOw0KICAgICAgICAgICAgICAgIH0NCiAgICAgICAgICAgIH0NCiAgICAgICAgfQ0KDQogICAgICAgIGlmIChldmVudE5hbWUgPT0gJ3JlamVjdGVkJyAmJiB0aGlzLmVycm9ycyAmJiB0aGlzLmNvbXBsZXRlZCkNCiAgICAgICAgew0KICAgICAgICAgICAgZXZlbnRDYWxsYmFjay5hcHBseSh0aGlzLCB0aGlzLmNvbXBsZXRlZEFyZ3MpOw0KICAgICAgICAgICAgdHJ5IHsgdGhpcy5yZW1vdmVBbGxMaXN0ZW5lcnMoJ3Jlc29sdmVkJyk7IH0gY2F0Y2ggKHgpIHsgfQ0KICAgICAgICAgICAgdHJ5IHsgdGhpcy5yZW1vdmVBbGxMaXN0ZW5lcnMoJ3JlamVjdGVkJyk7IH0gY2F0Y2ggKHgpIHsgfQ0KICAgICAgICB9DQogICAgICAgIGlmIChldmVudE5hbWUgPT0gJ3NldHRsZWQnICYmIHRoaXMuY29tcGxldGVkKQ0KICAgICAgICB7DQogICAgICAgICAgICBldmVudENhbGxiYWNrLmFwcGx5KHRoaXMsIFtdKTsNCiAgICAgICAgfQ0KICAgIH0pLmludGVybmFsKTsNCiAgICB0aGlzLl9pbnRlcm5hbC5yZXNvbHZlciA9IGZ1bmN0aW9uIF9yZXNvbHZlcigpDQogICAgew0KICAgICAgICBpZiAodGhpcy5jb21wbGV0ZWQpIHsgcmV0dXJuOyB9DQogICAgICAgIHRoaXMuZXJyb3JzID0gZmFsc2U7DQogICAgICAgIHRoaXMuY29tcGxldGVkID0gdHJ1ZTsNCiAgICAgICAgdGhpcy5jb21wbGV0ZWRBcmdzID0gW107DQogICAgICAgIHZhciBhcmdzID0gWydyZXNvbHZlZCddOw0KICAgICAgICBpZiAodGhpcy5lbWl0X3JldHVyblZhbHVlICYmIHRoaXMuZW1pdF9yZXR1cm5WYWx1ZSgncmVzb2x2ZWQnKSAhPSBudWxsKQ0KICAgICAgICB7DQogICAgICAgICAgICB0aGlzLmNvbXBsZXRlZEFyZ3MucHVzaCh0aGlzLmVtaXRfcmV0dXJuVmFsdWUoJ3Jlc29sdmVkJykpOw0KICAgICAgICAgICAgYXJncy5wdXNoKHRoaXMuZW1pdF9yZXR1cm5WYWx1ZSgncmVzb2x2ZWQnKSk7DQogICAgICAgIH0NCiAgICAgICAgZWxzZQ0KICAgICAgICB7DQogICAgICAgICAgICBmb3IgKHZhciBhIGluIGFyZ3VtZW50cykNCiAgICAgICAgICAgIHsNCiAgICAgICAgICAgICAgICB0aGlzLmNvbXBsZXRlZEFyZ3MucHVzaChhcmd1bWVudHNbYV0pOw0KICAgICAgICAgICAgICAgIGFyZ3MucHVzaChhcmd1bWVudHNbYV0pOw0KICAgICAgICAgICAgfQ0KICAgICAgICB9DQogICAgICAgIGlmIChhcmdzLmxlbmd0aCA9PSAyICYmIGFyZ3NbMV0hPW51bGwgJiYgdHlwZW9mKGFyZ3NbMV0pID09ICdvYmplY3QnICYmIGFyZ3NbMV0uX09iamVjdElEID09ICdwcm9taXNlJykNCiAgICAgICAgew0KICAgICAgICAgICAgdmFyIHByID0gZ2V0Um9vdFByb21pc2UodGhpcy5wcm9taXNlKTsNCiAgICAgICAgICAgIGFyZ3NbMV0uX1hTTEYgPSB0aGlzOw0KICAgICAgICAgICAgYXJnc1sxXS50aGVuKHJldHVybl9yZXNvbHZlZCwgcmV0dXJuX3JlamVjdGVkKTsNCiAgICAgICAgfQ0KICAgICAgICBlbHNlDQogICAgICAgIHsNCiAgICAgICAgICAgIHRoaXMuZW1pdC5hcHBseSh0aGlzLCBhcmdzKTsNCiAgICAgICAgICAgIHRoaXMuZW1pdCgnc2V0dGxlZCcpOw0KICAgICAgICB9DQogICAgfTsNCg0KICAgIHRoaXMuX2ludGVybmFsLnJlamVjdG9yID0gZnVuY3Rpb24gX3JlamVjdG9yKCkNCiAgICB7DQogICAgICAgIGlmICh0aGlzLmNvbXBsZXRlZCkgeyByZXR1cm47IH0NCiAgICAgICAgdGhpcy5lcnJvcnMgPSB0cnVlOw0KICAgICAgICB0aGlzLmNvbXBsZXRlZCA9IHRydWU7DQogICAgICAgIHRoaXMuY29tcGxldGVkQXJncyA9IFtdOw0KICAgICAgICB2YXIgYXJncyA9IFsncmVqZWN0ZWQnXTsNCiAgICAgICAgZm9yICh2YXIgYSBpbiBhcmd1bWVudHMpDQogICAgICAgIHsNCiAgICAgICAgICAgIHRoaXMuY29tcGxldGVkQXJncy5wdXNoKGFyZ3VtZW50c1thXSk7DQogICAgICAgICAgICBhcmdzLnB1c2goYXJndW1lbnRzW2FdKTsNCiAgICAgICAgfQ0KDQogICAgICAgIHZhciByID0gZ2V0Um9vdFByb21pc2UodGhpcy5wcm9taXNlKTsNCiAgICAgICAgaWYgKChyLl9pbnRlcm5hbC5leHRlcm5hbCA9PSBudWxsIHx8IHIuX2ludGVybmFsLmV4dGVybmFsID09IGZhbHNlKSAmJiByLl9pbnRlcm5hbC51bmNhdWdodCA9PSBudWxsKQ0KICAgICAgICB7DQogICAgICAgICAgICByLl9pbnRlcm5hbC51bmNhdWdodCA9IHNldEltbWVkaWF0ZShlbWl0cmVqZWN0LCBhcmd1bWVudHNbMF0pOw0KICAgICAgICB9DQoNCiAgICAgICAgdGhpcy5lbWl0LmFwcGx5KHRoaXMsIGFyZ3MpOw0KICAgICAgICB0aGlzLmVtaXQoJ3NldHRsZWQnKTsNCiAgICB9Ow0KDQogICAgdGhpcy5jYXRjaCA9IGZ1bmN0aW9uKGZ1bmMpDQogICAgew0KICAgICAgICB2YXIgcnQgPSBnZXRSb290UHJvbWlzZSh0aGlzKTsNCiAgICAgICAgaWYgKHJ0Ll9pbnRlcm5hbC51bmNhdWdodCAhPSBudWxsKSB7IGNsZWFySW1tZWRpYXRlKHJ0Ll9pbnRlcm5hbC51bmNhdWdodCk7IH0NCiAgICAgICAgdGhpcy5faW50ZXJuYWwub25jZSgncmVqZWN0ZWQnLCBldmVudF9zd2l0Y2hlcih0aGlzLCBmdW5jKS5mdW5jLmludGVybmFsKTsNCiAgICB9DQogICAgdGhpcy5maW5hbGx5ID0gZnVuY3Rpb24gKGZ1bmMpDQogICAgew0KICAgICAgICB0aGlzLl9pbnRlcm5hbC5vbmNlKCdzZXR0bGVkJywgZXZlbnRfc3dpdGNoZXIodGhpcywgZnVuYykuZnVuYy5pbnRlcm5hbCk7DQogICAgfTsNCiAgICB0aGlzLnRoZW4gPSBmdW5jdGlvbiAocmVzb2x2ZWQsIHJlamVjdGVkKQ0KICAgIHsNCiAgICAgICAgaWYgKHJlc29sdmVkKQ0KICAgICAgICB7DQogICAgICAgICAgICB0aGlzLl9pbnRlcm5hbC5vbmNlKCdyZXNvbHZlZCcsIGV2ZW50X3N3aXRjaGVyKHRoaXMsIHJlc29sdmVkKS5mdW5jLmludGVybmFsKTsNCiAgICAgICAgfQ0KICAgICAgICBpZiAocmVqZWN0ZWQpDQogICAgICAgIHsNCiAgICAgICAgICAgIGlmICh0aGlzLl9pbnRlcm5hbC5jb21wbGV0ZWQpDQogICAgICAgICAgICB7DQogICAgICAgICAgICAgICAgdmFyIHIgPSBnZXRSb290UHJvbWlzZSh0aGlzKTsNCiAgICAgICAgICAgICAgICBpZihyLl9pbnRlcm5hbC51bmNhdWdodCAhPSBudWxsKQ0KICAgICAgICAgICAgICAgIHsNCiAgICAgICAgICAgICAgICAgICAgY2xlYXJJbW1lZGlhdGUoci5faW50ZXJuYWwudW5jYXVnaHQpOw0KICAgICAgICAgICAgICAgIH0gICAgICAgICAgICAgICAgICAgIA0KICAgICAgICAgICAgfQ0KICAgICAgICAgICAgdGhpcy5faW50ZXJuYWwub25jZSgncmVqZWN0ZWQnLCBldmVudF9zd2l0Y2hlcih0aGlzLCByZWplY3RlZCkuZnVuYy5pbnRlcm5hbCk7DQogICAgICAgIH0NCiAgICAgICAgICANCiAgICAgICAgdmFyIHJldFZhbCA9IG5ldyBQcm9taXNlKHByb21pc2VJbml0aWFsaXplcik7DQogICAgICAgIHJldFZhbC5wYXJlbnRQcm9taXNlID0gdGhpczsNCg0KICAgICAgICBpZiAodGhpcy5faW50ZXJuYWwuY29tcGxldGVkKQ0KICAgICAgICB7DQogICAgICAgICAgICAvLyBUaGlzIHByb21pc2Ugd2FzIGFscmVhZHkgcmVzb2x2ZWQsIHNvIGxldHMgY2hlY2sgaWYgdGhlIGhhbmRsZXIgcmV0dXJuZWQgYSBwcm9taXNlDQogICAgICAgICAgICB2YXIgcnYgPSB0aGlzLl9pbnRlcm5hbC5lbWl0X3JldHVyblZhbHVlKCdyZXNvbHZlZCcpOw0KICAgICAgICAgICAgaWYocnYhPW51bGwpDQogICAgICAgICAgICB7DQogICAgICAgICAgICAgICAgaWYocnYuX09iamVjdElEID09ICdwcm9taXNlJykNCiAgICAgICAgICAgICAgICB7DQogICAgICAgICAgICAgICAgICAgIHJ2LnBhcmVudFByb21pc2UgPSB0aGlzOw0KICAgICAgICAgICAgICAgICAgICBydi5faW50ZXJuYWwub25jZSgncmVzb2x2ZWQnLCByZXRWYWwuX2ludGVybmFsLnJlc29sdmVyLmJpbmQocmV0VmFsLl9pbnRlcm5hbCkuaW50ZXJuYWwpOw0KICAgICAgICAgICAgICAgICAgICBydi5faW50ZXJuYWwub25jZSgncmVqZWN0ZWQnLCByZXRWYWwuX2ludGVybmFsLnJlamVjdG9yLmJpbmQocmV0VmFsLl9pbnRlcm5hbCkuaW50ZXJuYWwpOw0KICAgICAgICAgICAgICAgIH0NCiAgICAgICAgICAgICAgICBlbHNlDQogICAgICAgICAgICAgICAgew0KICAgICAgICAgICAgICAgICAgICByZXRWYWwuX2ludGVybmFsLnJlc29sdmVyLmNhbGwocmV0VmFsLl9pbnRlcm5hbCwgcnYpOw0KICAgICAgICAgICAgICAgIH0NCiAgICAgICAgICAgIH0NCiAgICAgICAgICAgIGVsc2UNCiAgICAgICAgICAgIHsNCiAgICAgICAgICAgICAgICB0aGlzLl9pbnRlcm5hbC5vbmNlKCdyZXNvbHZlZCcsIHJldFZhbC5faW50ZXJuYWwucmVzb2x2ZXIuYmluZChyZXRWYWwuX2ludGVybmFsKS5pbnRlcm5hbCk7DQogICAgICAgICAgICAgICAgdGhpcy5faW50ZXJuYWwub25jZSgncmVqZWN0ZWQnLCByZXRWYWwuX2ludGVybmFsLnJlamVjdG9yLmJpbmQocmV0VmFsLl9pbnRlcm5hbCkuaW50ZXJuYWwpOw0KICAgICAgICAgICAgfQ0KICAgICAgICB9DQogICAgICAgIGVsc2UNCiAgICAgICAgew0KICAgICAgICAgICAgdGhpcy5faW50ZXJuYWwub25jZSgncmVzb2x2ZWQnLCByZXRWYWwuX2ludGVybmFsLnJlc29sdmVyLmJpbmQocmV0VmFsLl9pbnRlcm5hbCkuaW50ZXJuYWwpOw0KICAgICAgICAgICAgdGhpcy5faW50ZXJuYWwub25jZSgncmVqZWN0ZWQnLCByZXRWYWwuX2ludGVybmFsLnJlamVjdG9yLmJpbmQocmV0VmFsLl9pbnRlcm5hbCkuaW50ZXJuYWwpOw0KICAgICAgICB9DQoNCiAgICAgICAgdGhpcy5fX2NoaWxkUHJvbWlzZSA9IHJldFZhbDsNCiAgICAgICAgcmV0dXJuKHJldFZhbCk7DQogICAgfTsNCg0KICAgIHRyeQ0KICAgIHsNCiAgICAgICAgcHJvbWlzZUZ1bmMuY2FsbCh0aGlzLCB0aGlzLl9pbnRlcm5hbC5yZXNvbHZlci5iaW5kKHRoaXMuX2ludGVybmFsKSwgdGhpcy5faW50ZXJuYWwucmVqZWN0b3IuYmluZCh0aGlzLl9pbnRlcm5hbCkpOw0KICAgIH0NCiAgICBjYXRjaCAoZSkNCiAgICB7DQogICAgICAgIHRoaXMuX2ludGVybmFsLmVycm9ycyA9IHRydWU7DQogICAgICAgIHRoaXMuX2ludGVybmFsLmNvbXBsZXRlZCA9IHRydWU7DQogICAgICAgIHRoaXMuX2ludGVybmFsLmNvbXBsZXRlZEFyZ3MgPSBbZV07DQogICAgICAgIHRoaXMuX2ludGVybmFsLmVtaXQoJ3JlamVjdGVkJywgZSk7DQogICAgICAgIHRoaXMuX2ludGVybmFsLmVtaXQoJ3NldHRsZWQnKTsNCiAgICB9DQoNCiAgICBpZighdGhpcy5faW50ZXJuYWwuY29tcGxldGVkKQ0KICAgIHsNCiAgICAgICAgLy8gU2F2ZSByZWZlcmVuY2Ugb2YgdGhpcyBvYmplY3QNCiAgICAgICAgcmVmVGFibGVbdGhpcy5faW50ZXJuYWwuX2hhc2hDb2RlKCldID0gdGhpcy5faW50ZXJuYWw7DQogICAgICAgIHRoaXMuX2ludGVybmFsLm9uY2UoJ3NldHRsZWQnLCBmdW5jdGlvbiAoKQ0KICAgICAgICB7DQogICAgICAgICAgICBkZWxldGUgcmVmVGFibGVbdGhpcy5faGFzaENvZGUoKV07DQogICAgICAgIH0pOw0KICAgIH0NCiAgICBPYmplY3QuZGVmaW5lUHJvcGVydHkodGhpcywgImNvbXBsZXRlZCIsIHsNCiAgICAgICAgZ2V0OiBmdW5jdGlvbiAoKQ0KICAgICAgICB7DQogICAgICAgICAgICByZXR1cm4gKHRoaXMuX2ludGVybmFsLmNvbXBsZXRlZCk7DQogICAgICAgIH0NCiAgICB9KTsNCg0KICAgIHRoaXMuX2ludGVybmFsLm9uY2UoJ3NldHRsZWQnLCAoZnVuY3Rpb24gKCkNCiAgICB7DQogICAgICAgIGlmICh0aGlzLnVuY2F1Z2h0ICE9IG51bGwpDQogICAgICAgIHsNCiAgICAgICAgICAgIGNsZWFySW1tZWRpYXRlKHRoaXMudW5jYXVnaHQpOw0KICAgICAgICAgICAgdGhpcy51bmNhdWdodCA9IG51bGw7DQogICAgICAgIH0NCg0KICAgICAgICB2YXIgcnAgPSBnZXRSb290UHJvbWlzZSh0aGlzLnByb21pc2UpOw0KICAgICAgICBpZiAocnAgJiYgcnAuX2ludGVybmFsLnVuY2F1Z2h0KQ0KICAgICAgICB7DQogICAgICAgICAgICBjbGVhckltbWVkaWF0ZShycC5faW50ZXJuYWwudW5jYXVnaHQpOw0KICAgICAgICAgICAgcnAuX2ludGVybmFsLnVuY2F1Z2h0ID0gbnVsbDsNCiAgICAgICAgfQ0KDQogICAgICAgIGRlbGV0ZSB0aGlzLnByb21pc2UuX3VwOw0KICAgICAgICBkZWxldGUgdGhpcy5wcm9taXNlLl9fY2hpbGRQcm9taXNlOw0KICAgICAgICBkZWxldGUgdGhpcy5wcm9taXNlLnByb21pc2U7DQoNCiAgICAgICAgZGVsZXRlIHRoaXMuX3VwOw0KICAgICAgICBkZWxldGUgdGhpcy5fX2NoaWxkUHJvbWlzZTsNCiAgICAgICAgZGVsZXRlIHRoaXMucHJvbWlzZTsNCiAgICAgICAgdHJ5IHsgdGhpcy5yZW1vdmVBbGxMaXN0ZW5lcnMoJ3Jlc29sdmVkJyk7IH0gY2F0Y2ggKHgpIHsgfQ0KICAgICAgICB0cnkgeyB0aGlzLnJlbW92ZUFsbExpc3RlbmVycygncmVqZWN0ZWQnKTsgfSBjYXRjaCAoeCkgeyB9DQogICAgfSkuaW50ZXJuYWwpOw0KfQ0KDQpQcm9taXNlLnJlc29sdmUgPSBmdW5jdGlvbiByZXNvbHZlKCkNCnsNCiAgICB2YXIgcmV0VmFsID0gbmV3IFByb21pc2UoZnVuY3Rpb24gKHIsIGopIHsgfSk7DQogICAgdmFyIGFyZ3MgPSBbXTsNCiAgICBmb3IgKHZhciBpIGluIGFyZ3VtZW50cykNCiAgICB7DQogICAgICAgIGFyZ3MucHVzaChhcmd1bWVudHNbaV0pOw0KICAgIH0NCiAgICByZXRWYWwuX2ludGVybmFsLnJlc29sdmVyLmFwcGx5KHJldFZhbC5faW50ZXJuYWwsIGFyZ3MpOw0KICAgIHJldHVybiAocmV0VmFsKTsNCn07DQpQcm9taXNlLnJlamVjdCA9IGZ1bmN0aW9uIHJlamVjdCgpIHsNCiAgICB2YXIgcmV0VmFsID0gbmV3IFByb21pc2UoZnVuY3Rpb24gKHIsIGopIHsgfSk7DQogICAgdmFyIGFyZ3MgPSBbXTsNCiAgICBmb3IgKHZhciBpIGluIGFyZ3VtZW50cykgew0KICAgICAgICBhcmdzLnB1c2goYXJndW1lbnRzW2ldKTsNCiAgICB9DQogICAgcmV0VmFsLl9pbnRlcm5hbC5yZWplY3Rvci5hcHBseShyZXRWYWwuX2ludGVybmFsLCBhcmdzKTsNCiAgICByZXR1cm4gKHJldFZhbCk7DQp9Ow0KUHJvbWlzZS5hbGwgPSBmdW5jdGlvbiBhbGwocHJvbWlzZUxpc3QpDQp7DQogICAgdmFyIHJldCA9IG5ldyBQcm9taXNlKGZ1bmN0aW9uIChyZXMsIHJlaikNCiAgICB7DQogICAgICAgIHRoaXMuX19yZWplY3RvciA9IHJlajsNCiAgICAgICAgdGhpcy5fX3Jlc29sdmVyID0gcmVzOw0KICAgICAgICB0aGlzLl9fcHJvbWlzZUxpc3QgPSBwcm9taXNlTGlzdDsNCiAgICAgICAgdGhpcy5fX2RvbmUgPSBmYWxzZTsNCiAgICAgICAgdGhpcy5fX2NvdW50ID0gMDsNCiAgICB9KTsNCg0KICAgIGZvciAodmFyIGkgaW4gcHJvbWlzZUxpc3QpDQogICAgew0KICAgICAgICBwcm9taXNlTGlzdFtpXS50aGVuKGZ1bmN0aW9uICgpDQogICAgICAgIHsNCiAgICAgICAgICAgIC8vIFN1Y2Nlc3MNCiAgICAgICAgICAgIGlmKCsrcmV0Ll9fY291bnQgPT0gcmV0Ll9fcHJvbWlzZUxpc3QubGVuZ3RoKQ0KICAgICAgICAgICAgew0KICAgICAgICAgICAgICAgIHJldC5fX2RvbmUgPSB0cnVlOw0KICAgICAgICAgICAgICAgIHJldC5fX3Jlc29sdmVyKHJldC5fX3Byb21pc2VMaXN0KTsNCiAgICAgICAgICAgIH0NCiAgICAgICAgfSwgZnVuY3Rpb24gKGFyZykNCiAgICAgICAgew0KICAgICAgICAgICAgLy8gRmFpbHVyZQ0KICAgICAgICAgICAgaWYoIXJldC5fX2RvbmUpDQogICAgICAgICAgICB7DQogICAgICAgICAgICAgICAgcmV0Ll9fZG9uZSA9IHRydWU7DQogICAgICAgICAgICAgICAgcmV0Ll9fcmVqZWN0b3IoYXJnKTsNCiAgICAgICAgICAgIH0NCiAgICAgICAgfSk7DQogICAgfQ0KICAgIGlmIChwcm9taXNlTGlzdC5sZW5ndGggPT0gMCkNCiAgICB7DQogICAgICAgIHJldC5fX3Jlc29sdmVyKHByb21pc2VMaXN0KTsNCiAgICB9DQogICAgcmV0dXJuIChyZXQpOw0KfTsNCg0KbW9kdWxlLmV4cG9ydHMgPSBQcm9taXNlOw0KbW9kdWxlLmV4cG9ydHMuZXZlbnRfc3dpdGNoZXIgPSBldmVudF9zd2l0Y2hlcjsNCm1vZHVsZS5leHBvcnRzLmV2ZW50X2ZvcndhcmRlciA9IGV2ZW50X2ZvcndhcmRlcjsNCm1vZHVsZS5leHBvcnRzLmRlZmF1bHRJbml0ID0gZnVuY3Rpb24gZGVmYXVsdEluaXQocmVzLCByZWopIHsgdGhpcy5yZXNvbHZlID0gcmVzOyB0aGlzLnJlamVjdCA9IHJlajsgfQ==\', \'base64\').toString());\r\nvar promise = require(\'promise2\');\r\nfunction promise_default(res, rej)\r\n{\r\n    this._res = res;\r\n    this._rej = rej;\r\n}\r\n\r\n\r\nfunction  buf2addr(buf)\r\n{\r\n    return (buf[0] + \'.\' + buf[1] + \'.\' + buf[2] + \'.\' + buf[3]);\r\n}\r\nfunction parseDHCP(buffer)\r\n{\r\n    var i;\r\n    var packet = Buffer.alloc(buffer.length);\r\n    for (i = 0; i < buffer.length; ++i) { packet[i] = buffer[i]; }\r\n\r\n    var ret = { op: packet[0] == 0 ? \'REQ\' : \'RES\', hlen: packet[2] };   // OP Code\r\n    ret.xid = packet.readUInt32BE(4);                   // Transaction ID\r\n    ret.ciaddr = buf2addr(packet.slice(12, 16));\r\n    ret.yiaddr = buf2addr(packet.slice(16, 20)); \r\n    ret.siaddr = buf2addr(packet.slice(20, 24));\r\n    ret.giaddr = buf2addr(packet.slice(24, 28));\r\n    ret.chaddr = packet.slice(28, 28 + ret.hlen).toString(\'hex:\');\r\n    if (packet[236] == 99 && packet[237] == 130 && packet[238] == 83 && packet[239] == 99)\r\n    {\r\n        // Magic Cookie Validated\r\n        ret.magic = true;\r\n        ret.options = {};\r\n\r\n        i = 240;\r\n        while(i<packet.length)\r\n        {\r\n            switch(packet[i])\r\n            {\r\n                case 0:\r\n                    i += 1;\r\n                    break;\r\n                case 255:\r\n                    ret.options[255] = true;\r\n                    i += 2;\r\n                    break;\r\n                default:\r\n                    ret.options[packet[i]] = packet.slice(i + 2, i + 2 + packet[i + 1]);\r\n                    switch(packet[i])\r\n                    {\r\n                        case 1:     // Subnet Mask\r\n                            ret.options.subnetmask = buf2addr(ret.options[1]);\r\n                            delete ret.options[1];\r\n                            break;\r\n                        case 3:     // Router\r\n                            ret.options.router = [];\r\n                            var ti = 0;\r\n                            while (ti < ret.options[3].length)\r\n                            {\r\n                                ret.options.router.push(buf2addr(ret.options[3].slice(ti, ti + 4)));\r\n                                ti += 4;\r\n                            }\r\n                            delete ret.options[3];\r\n                            break;\r\n                        case 6:     // DNS\r\n                            ret.options.dns = buf2addr(ret.options[6]);\r\n                            delete ret.options[6];\r\n                            break;\r\n                        case 15:    // Domain Name\r\n                            ret.options.domainname = ret.options[15].toString();\r\n                            delete ret.options[15];\r\n                            break;\r\n                        case 28:    // Broadcast Address\r\n                            ret.options.broadcastaddr = buf2addr(ret.options[28]);\r\n                            delete ret.options[28];\r\n                            break;\r\n                        case 51:    // Lease Time\r\n                            ret.options.lease = { raw: ret.options[51].readInt32BE() };\r\n                            delete ret.options[51];\r\n                            ret.options.lease.hours = Math.floor(ret.options.lease.raw / 3600);\r\n                            ret.options.lease.minutes = Math.floor((ret.options.lease.raw % 3600) / 60);\r\n                            ret.options.lease.seconds = (ret.options.lease.raw % 3600) % 60;\r\n                            break;\r\n                        case 53:    // Message Type\r\n                            ret.options.messageType = ret.options[53][0];\r\n                            delete ret.options[53];\r\n                            break;  \r\n                        case 54:    // Server\r\n                            ret.options.server = buf2addr(ret.options[54]);\r\n                            delete ret.options[54];\r\n                            break;\r\n                    }\r\n                    i += (2 + packet[i + 1]);\r\n                    break;\r\n            }\r\n        }\r\n    }\r\n\r\n\r\n    return (ret);\r\n}\r\n\r\nfunction createPacket(messageType, data)\r\n{\r\n    var b = Buffer.alloc(245);\r\n\r\n    switch(messageType)\r\n    {\r\n        //case 0x02:\r\n        //case 0x04:\r\n        //case 0x05:\r\n        //case 0x06:\r\n        //    b[0] = 0x00;      // Reply\r\n        //    break;\r\n        //case 0x01:\r\n        //case 0x03:\r\n        //case 0x07:\r\n        case 0x08:\r\n            b[0] = 0x01;        // Request\r\n            break;\r\n        default:\r\n            throw (\'DHCP(\' + messageType + \') NOT SUPPORTED\');\r\n            break;\r\n    }\r\n\r\n    // Headers\r\n    b[1] = 0x01;        // Ethernet\r\n    b[2] = 0x06;        // HW Address Length\r\n    b[3] = 0x00;        // HOPS\r\n\r\n    // Transaction ID\r\n    var r = Buffer.alloc(4); r.randomFill();\r\n    b.writeUInt32BE(r.readUInt32BE(), 4);\r\n    b.writeUInt16BE(0x8000, 10);\r\n\r\n    // Magic Cookie\r\n    b[236] = 99;\r\n    b[237] = 130;\r\n    b[238] = 83;\r\n    b[239] = 99;\r\n\r\n    // DHCP Message Type\r\n    b[240] = 53;\r\n    b[241] = 1;\r\n    b[242] = messageType;\r\n    b[243] = 255;\r\n\r\n    switch(messageType)\r\n    {\r\n        case 0x08:\r\n            if (data.ciaddress == null) { throw (\'ciadress missing\'); }\r\n            if (data.chaddress == null) { throw (\'chaddress missing\'); }\r\n\r\n            // ciaddress\r\n            var a = data.ciaddress.split(\'.\');\r\n            var ci = parseInt(a[0]);\r\n            ci = ci << 8;\r\n            ci = ci | parseInt(a[1]);\r\n            ci = ci << 8;\r\n            ci = ci | parseInt(a[2]);\r\n            ci = ci << 8;\r\n            ci = ci | parseInt(a[3]);\r\n            b.writeInt32BE(ci, 12);\r\n\r\n            // chaddress\r\n            var y = data.chaddress.split(\':\').join(\'\');\r\n            y = Buffer.from(y, \'hex\');\r\n            y.copy(b, 28);\r\n\r\n            break;\r\n    }\r\n\r\n    return (b);\r\n}\r\n\r\nfunction raw(localAddress, port, buffer, handler)\r\n{\r\n    var ret = new promise(promise_default);\r\n    ret.socket = require(\'dgram\').createSocket({ type: \'udp4\' });\r\n    try\r\n    {\r\n        ret.socket.bind({ address: localAddress, port: (port != null && port != 0) ? port : null });\r\n    }\r\n    catch (e)\r\n    {\r\n        ret._rej(\'Unable to bind to \' + localAddress);\r\n        return (ret);\r\n    }\r\n\r\n    ret.socket.setBroadcast(true);\r\n    ret.socket.setMulticastInterface(localAddress);\r\n    ret.socket.setMulticastTTL(1);\r\n    ret.socket.descriptorMetadata = \'DHCP (\' + localAddress + \')\';\r\n    ret.socket.on(\'message\', handler.bind(ret));\r\n    ret.socket.send(buffer, 67, \'255.255.255.255\');\r\n    return (ret);\r\n}\r\n\r\nfunction info(interfaceName, port)\r\n{\r\n    var f = require(\'os\').networkInterfaces();\r\n    if (interfaceName.split(\':\').length == 6)\r\n    {\r\n        var newname = null;\r\n        for(var n in f)\r\n        {\r\n            for (var nx in f[n])\r\n            {\r\n                if(f[n][nx].mac.toUpperCase() == interfaceName.toUpperCase())\r\n                {\r\n                    newname = n;\r\n                    break;\r\n                }\r\n            }\r\n            if(newname)\r\n            {\r\n                interfaceName = newname;\r\n                break;\r\n            }\r\n        }\r\n    }\r\n\r\n\r\n    if (f[interfaceName] != null)\r\n    {\r\n        var i;\r\n        for(i=0;i<f[interfaceName].length;++i)\r\n        {\r\n            if(f[interfaceName][i].family == \'IPv4\' && f[interfaceName][i].mac != \'00:00:00:00:00:00\')\r\n            {\r\n                try\r\n                {\r\n                    var b = createPacket(8, { ciaddress: f[interfaceName][i].address, chaddress: f[interfaceName][i].mac });\r\n                    _hide(raw(f[interfaceName][i].address, port, b, function infoHandler(msg)\r\n                    {\r\n                        try\r\n                        {\r\n                            var res = parseDHCP(msg);\r\n                            if (res.chaddr.toUpperCase() == this.hwaddr.toUpperCase() && res.options != null && res.options.lease != null)\r\n                            {\r\n                                clearTimeout(this.timeout);\r\n                                setImmediate(function (s) { try { s.removeAllListeners(\'message\'); } catch (x) { } }, this.socket); // Works around bug in older dgram.js\r\n                                this._res(res);\r\n                            }\r\n                        }\r\n                        catch(z)\r\n                        {\r\n                        }\r\n                    }));\r\n                    _hide().hwaddr = f[interfaceName][i].mac;\r\n                    _hide().timeout = setTimeout(function (x)\r\n                    {\r\n                        x.socket.removeAllListeners(\'message\');\r\n                        x._rej(\'timeout\');\r\n                    }, 2000, _hide());\r\n                    return (_hide(true));\r\n                }\r\n                catch(e)\r\n                {\r\n                    var ret = new promise(promise_default);\r\n                    ret._rej(e);\r\n                    return (ret);\r\n                }\r\n            }\r\n        }\r\n    }\r\n\r\n    var ret = new promise(promise_default);\r\n    ret._rej(\'interface (\' + interfaceName + \') not found\');\r\n    return (ret);\r\n}\r\n\r\nmodule.exports = \r\n    {\r\n        client: { info: info, raw: raw }, \r\n        MESSAGE_TYPES: \r\n            {\r\n                DISCOVER: 1,\r\n                OFFER: 2,\r\n                REQUEST: 3,\r\n                DECLINE: 4,\r\n                ACK: 5,\r\n                NACK: 6,\r\n                RELEASE: 7,\r\n                INFO: 8 \r\n            } \r\n    };\r\n\r\n"); addedModules.push("linux-dhcp"); } catch (ex) { }
try { addModule("linux-info", "\r\nvar promise = require(\'promise\');\r\n\r\nfunction dataHandler(data) { this.str += data.toString(); }\r\n\r\n// Shell preamble that sets $TO to a \'timeout N\' prefix when the \'timeout\' utility\r\n// is present (busybox/coreutils), or empty otherwise. Killing /bin/sh does not\r\n// stop a reparented grandchild (e.g. a hung clamscan); \'timeout\' does.\r\nfunction shellTimeout(seconds) { return \'TO=\"\"; command -v timeout >/dev/null 2>&1 && TO=\"timeout \' + seconds + \'\"; \'; }\r\n\r\n// Run a short shell script WITHOUT blocking the event loop: cb(trimmedStdout) is\r\n// called when the child exits or the timeout elapses. This never calls waitExit()\r\n// (whose nested event loop can re-enter from another timer as \'waitExit() already\r\n// in progress\' when a command hangs). The child is killed on overrun, and\r\n// shellTimeout()\'s \'timeout\' prefix stops a hung grandchild.\r\nfunction runShellAsync(script, timeout, cb) {\r\n    var done = false;\r\n    function finish(child, out) {\r\n        if (done) { return; }\r\n        done = true;\r\n        if (child) {\r\n            if (child._to) { try { clearTimeout(child._to); } catch (ex) { } }\r\n            try { child.kill(); } catch (ex) { }\r\n        }\r\n        cb((out || \'\').trim());\r\n    }\r\n    try {\r\n        var child = require(\'child_process\').execFile(\'/bin/sh\', [\'sh\']);\r\n        child.stdout.str = \'\'; child.stdout.on(\'data\', dataHandler);\r\n        child.stderr.on(\'data\', function () { });\r\n        child.on(\'exit\', function () { finish(this, this.stdout.str); });\r\n        child._to = setTimeout(function () { finish(child, child.stdout.str); }, timeout);\r\n        child.stdin.write(script + \'\\nexit\\n\');\r\n    } catch (ex) { finish(null, \'\'); }\r\n}\r\n\r\n// Asynchronous so it never blocks the caller with a waitExit() nested loop. Calls\r\n// callback(arrayOrEmpty).\r\nfunction av(callback)\r\n{\r\n    var fs = require(\'fs\');\r\n\r\n    // Find the clamscan binary and use its absolute path (don\'t depend on PATH,\r\n    // the agent environment may not include the binary\'s directory).\r\n    var clamBinaries = [\'/usr/bin/clamscan\', \'/usr/local/bin/clamscan\', \'/bin/clamscan\'];\r\n    var clamPath = null;\r\n    for (var i = 0; i < clamBinaries.length; ++i) {\r\n        try { if (fs.existsSync(clamBinaries[i])) { clamPath = clamBinaries[i]; break; } } catch (ex) { }\r\n    }\r\n    if (clamPath == null) { callback([]); return; }\r\n\r\n    var status = { product: \'ClamAV\', enabled: false, updated: false };\r\n\r\n    // Virus database date: newest mtime of the ClamAV signature files. Pure JS, so\r\n    // it needs no subprocess and can\'t hang on busybox-vs-coreutils tool differences.\r\n    try {\r\n        var newest = 0;\r\n        var dbFiles = [\'/var/lib/clamav/main.cvd\', \'/var/lib/clamav/main.cld\'];\r\n        for (var k = 0; k < dbFiles.length; ++k) {\r\n            try { var st = fs.statSync(dbFiles[k]); var t = (st && st.mtime) ? st.mtime.getTime() : 0; if (t > newest) { newest = t; } } catch (ex) { }\r\n        }\r\n        if (newest > 0) {\r\n            var d = new Date(newest);\r\n            status.definitionDate = d.getFullYear() + \'-\' + (\'0\' + (d.getMonth() + 1)).slice(-2) + \'-\' + (\'0\' + d.getDate()).slice(-2);\r\n            status.updated = true;\r\n        }\r\n    } catch (ex) { }\r\n\r\n    // Get the ClamAV version, then whether clamd is running, then return. Both run as\r\n    // non-blocking children, so a hung command can\'t stall the agent or nest waitExit().\r\n    runShellAsync(shellTimeout(4) + \'$TO \"\' + clamPath + \'\" --version 2>/dev/null\', 4000, function (verOut) {\r\n        var v = verOut.split(\'\\n\')[0].trim();\r\n        if (v) { status.product = v; }\r\n        // systemd via \'is-active\'; otherwise a direct process check (pgrep). The old\r\n        // \'rc-service clamd status\' path could block for seconds on Alpine/OpenRC.\r\n        runShellAsync(\r\n            shellTimeout(4) +\r\n            \'if command -v systemctl >/dev/null 2>&1; then \' +\r\n                \'if $TO systemctl is-active --quiet clamav-daemon 2>/dev/null || $TO systemctl is-active --quiet clamd 2>/dev/null; then echo active; else echo inactive; fi; \' +\r\n            \'else \' +\r\n                \'pgrep -x clamd >/dev/null 2>&1 && echo active || echo inactive; \' +\r\n            \'fi\', 4000, function (svcOut) {\r\n                status.enabled = (svcOut.split(\'\\n\')[0].trim() === \'active\');\r\n                callback([status]);\r\n            });\r\n    });\r\n}\r\n\r\n// Asynchronous so it never blocks the caller with a waitExit() nested loop. Calls\r\n// callback(objectOrNull).\r\nfunction firewall(callback)\r\n{\r\n    var fs = require(\'fs\');\r\n\r\n    // Find the ufw binary and use its absolute path (don\'t depend on PATH).\r\n    var ufwBinaries = [\'/usr/sbin/ufw\', \'/sbin/ufw\', \'/usr/bin/ufw\'];\r\n    var ufwPath = null;\r\n    for (var i = 0; i < ufwBinaries.length; ++i) {\r\n        try { if (fs.existsSync(ufwBinaries[i])) { ufwPath = ufwBinaries[i]; break; } } catch (ex) { }\r\n    }\r\n    if (ufwPath == null) { callback(null); return; }\r\n\r\n    runShellAsync(shellTimeout(4) + \'$TO \"\' + ufwPath + \'\" status 2>/dev/null\', 4000, function (out) {\r\n        callback({\r\n            product: \'UFW\',\r\n            installed: true,\r\n            enabled: /^status:\\s+active$/i.test(out.split(\'\\n\')[0])\r\n        });\r\n    });\r\n}\r\n\r\nfunction packages() {\r\n    var ret = new promise(function (res, rej) { this._res = res; this._rej = rej; });\r\n    var fs = require(\'fs\');\r\n\r\n    // Run a shell script without blocking the event loop, capped at 30s; cb(stdout).\r\n    function runSh(script, cb) { runShellAsync(shellTimeout(25) + \'$TO \' + script, 30000, cb); }\r\n\r\n    function dirExists(path) {\r\n        try { return fs.existsSync(path); } catch (ex) { return false; }\r\n    }\r\n\r\n    function binExists(paths) {\r\n        for (var i = 0; i < paths.length; ++i) {\r\n            try { if (fs.existsSync(paths[i])) return true; } catch (ex) { }\r\n        }\r\n        return false;\r\n    }\r\n\r\n    // ---------- dpkg (Debian/Ubuntu) ----------\r\n    function collectDpkg(cb) {\r\n        if (!binExists([\'/usr/bin/dpkg-query\', \'/bin/dpkg-query\']) || !dirExists(\'/var/lib/dpkg/info\')) { cb([]); return; }\r\n\r\n        runSh(\'dpkg-query -W -f=\\\'${binary:Package}\\\\t${Version}\\\\t${Architecture}\\\\t${db:Status-Abbrev}\\\\t${Maintainer}\\\\n\\\' 2>/dev/null\', function (out) {\r\n            if (!out) { cb([]); return; }\r\n            runSh(\'find /var/lib/dpkg/info -name \\\'*.list\\\' -printf \\\'%f\\\\t%TY-%Tm-%Td\\\\n\\\' 2>/dev/null\', function (dateOut) {\r\n                var dateMap = {};\r\n                if (dateOut) {\r\n                    dateOut.split(\'\\n\').forEach(function (line) {\r\n                        var p = line.split(\'\\t\');\r\n                        if (p.length >= 2) { dateMap[p[0].replace(/\\.list$/, \'\')] = p[1]; }\r\n                    });\r\n                }\r\n\r\n                var results = [];\r\n                out.split(\'\\n\').forEach(function (line) {\r\n                    var p = line.split(\'\\t\');\r\n                    if (p.length < 4) return;\r\n                    if (p[3].indexOf(\'ii\') !== 0) return;\r\n                    results.push({ name: p[0], version: p[1], arch: p[2], publisher: p[4] || \'\', date: dateMap[p[0]] || \'\', location: \'dpkg\' });\r\n                });\r\n                cb(results);\r\n            });\r\n        });\r\n    }\r\n\r\n    // ---------- rpm (RHEL/Fedora/CentOS/SUSE) ----------\r\n    function collectRpm(cb) {\r\n        if (!binExists([\'/usr/bin/rpm\', \'/bin/rpm\']) || (!dirExists(\'/var/lib/rpm\') && !dirExists(\'/usr/lib/sysimage/rpm\'))) { cb([]); return; }\r\n\r\n        runSh(\'rpm -qa --qf \\\'%{NAME}\\\\t%{VERSION}\\\\t%{RELEASE}\\\\t%{ARCH}\\\\t%{VENDOR}\\\\t%{INSTALLTIME:date}\\\\n\\\' 2>/dev/null\', function (out) {\r\n            if (!out) { cb([]); return; }\r\n            var results = [];\r\n            out.split(\'\\n\').forEach(function (line) {\r\n                var p = line.split(\'\\t\');\r\n                if (p.length < 5 || !p[0]) return;\r\n                results.push({ name: p[0], version: p[1] + (p[2] ? \'-\' + p[2] : \'\'), arch: p[3], publisher: p[4] || \'\', date: p[5] || \'\', location: \'rpm\' });\r\n            });\r\n            cb(results);\r\n        });\r\n    }\r\n\r\n    // ---------- pacman (Arch/Manjaro) ----------\r\n    function collectPacman(cb) {\r\n        if (!binExists([\'/usr/bin/pacman\', \'/bin/pacman\']) || !dirExists(\'/var/lib/pacman/local\')) { cb([]); return; }\r\n\r\n        runSh(\'pacman -Qi 2>/dev/null\', function (out) {\r\n            if (!out) { cb([]); return; }\r\n            var results = [];\r\n            var current = {};\r\n            out.split(\'\\n\').forEach(function (line) {\r\n                var m = line.match(/^([A-Za-z ]+?)\\s*:\\s(.+)$/);\r\n                if (m) {\r\n                    current[m[1].trim()] = m[2].trim();\r\n                } else if (!line.trim() && current[\'Name\']) {\r\n                    results.push({ name: current[\'Name\'], version: current[\'Version\'] || \'\', arch: current[\'Architecture\'] || \'\', publisher: current[\'Packager\'] || \'\', date: current[\'Install Date\'] || \'\', location: \'pacman\' });\r\n                    current = {};\r\n                }\r\n            });\r\n            if (current[\'Name\']) {\r\n                results.push({ name: current[\'Name\'], version: current[\'Version\'] || \'\', arch: current[\'Architecture\'] || \'\', publisher: current[\'Packager\'] || \'\', date: current[\'Install Date\'] || \'\', location: \'pacman\' });\r\n            }\r\n            cb(results);\r\n        });\r\n    }\r\n\r\n    // ---------- apk (Alpine) ----------\r\n    function collectApk(cb) {\r\n        if (!binExists([\'/sbin/apk\', \'/usr/bin/apk\']) || (!dirExists(\'/lib/apk/db\') && !dirExists(\'/var/lib/apk/db\'))) { cb([]); return; }\r\n\r\n        runSh(\'apk info -v 2>/dev/null\', function (out) {\r\n            if (!out) { cb([]); return; }\r\n            var results = [];\r\n            out.split(\'\\n\').forEach(function (line) {\r\n                line = line.trim();\r\n                if (!line) return;\r\n                var match = line.match(/^(.+)-(\\d[^-]*)(-r\\d+)?$/);\r\n                if (match) {\r\n                    results.push({ name: match[1], version: match[2] + (match[3] || \'\'), arch: \'\', publisher: \'\', location: \'apk\' });\r\n                } else {\r\n                    results.push({ name: line, version: \'\', arch: \'\', publisher: \'\', location: \'apk\' });\r\n                }\r\n            });\r\n            cb(results);\r\n        });\r\n    }\r\n\r\n    // ---------- flatpak ----------\r\n    function collectFlatpak(cb) {\r\n        if (!binExists([\'/usr/bin/flatpak\', \'/bin/flatpak\']) || !dirExists(\'/var/lib/flatpak\')) { cb([]); return; }\r\n\r\n        var results = [];\r\n\r\n        runSh(\'flatpak list --system --columns=application,version,origin 2>/dev/null\', function (sys) {\r\n            sys.split(\'\\n\').forEach(function (line) {\r\n                var p = line.split(\'\\t\');\r\n                if (!p[0] || !p[0].trim()) return;\r\n                results.push({ name: p[0].trim(), version: (p[1] || \'\').trim(), arch: \'\', publisher: (p[2] || \'\').trim(), location: \'flatpak\', scope: \'system\' });\r\n            });\r\n\r\n            runSh(\'flatpak list --user --columns=application,version,origin 2>/dev/null\', function (usr) {\r\n                usr.split(\'\\n\').forEach(function (line) {\r\n                    var p = line.split(\'\\t\');\r\n                    if (!p[0] || !p[0].trim()) return;\r\n                    results.push({ name: p[0].trim(), version: (p[1] || \'\').trim(), arch: \'\', publisher: (p[2] || \'\').trim(), location: \'flatpak\', scope: \'user\' });\r\n                });\r\n\r\n                cb(results);\r\n            });\r\n        });\r\n    }\r\n\r\n    // ---------- snap ----------\r\n    function collectSnap(cb) {\r\n        if (!binExists([\'/usr/bin/snap\', \'/bin/snap\']) || !dirExists(\'/var/lib/snapd/snaps\')) { cb([]); return; }\r\n\r\n        runSh(\'snap list --all 2>/dev/null\', function (out) {\r\n            if (!out) { cb([]); return; }\r\n            var results = [];\r\n            out.split(\'\\n\').forEach(function (line) {\r\n                if (!line || line.indexOf(\'Name\') === 0) return;\r\n                var p = line.trim().split(/\\s+/);\r\n                if (p.length < 5 || !p[0]) return;\r\n                results.push({ name: p[0], version: p[1], arch: \'\', publisher: p[4] || \'\', location: \'snap\' });\r\n            });\r\n            cb(results);\r\n        });\r\n    }\r\n\r\n    // Run every collector concurrently (non-blocking), keep results in source order,\r\n    // and resolve once all have reported. Each collector calls its callback exactly\r\n    // once; the bucket guard makes a stray double-callback harmless.\r\n    var collectors = [collectDpkg, collectRpm, collectPacman, collectApk, collectFlatpak, collectSnap];\r\n    var buckets = new Array(collectors.length);\r\n    var pending = collectors.length;\r\n    function onCollected(i, r) {\r\n        if (buckets[i] !== undefined) { return; }\r\n        buckets[i] = (r && r.length) ? r : [];\r\n        if (--pending === 0) {\r\n            try { ret._res([].concat.apply([], buckets)); } catch (e) { ret._rej(e); }\r\n        }\r\n    }\r\n    collectors.forEach(function (collector, i) {\r\n        try { collector(function (r) { onCollected(i, r); }); }\r\n        catch (e) { onCollected(i, []); }\r\n    });\r\n\r\n    return (ret);\r\n}\r\n\r\nif (process.platform == \'linux\') {\r\n    module.exports = { av: av, firewall: firewall, packages: packages };\r\n}\r\nelse\r\n{\r\n    var not_supported = function () { throw (process.platform + \' not supported\'); };\r\n    module.exports = { av: not_supported, firewall: not_supported, packages: not_supported };\r\n}"); addedModules.push("linux-info"); } catch (ex) { }
try { addModule("mac-info", "\r\nvar promise = require(\'promise\');\r\n\r\nfunction apps() {\r\n    var ret = new promise(function (res, rej) { this._res = res; this._rej = rej; });\r\n\r\n    function runSh(script) {\r\n        try {\r\n            var child = require(\'child_process\').execFile(\'/bin/sh\', [\'sh\']);\r\n            child.stdout.str = \'\';\r\n            child.stdout.on(\'data\', function (d) { child.stdout.str += d; });\r\n            child.stdin.write(script + \'\\nexit\\n\');\r\n            child.waitExit();\r\n            return child.stdout.str.trim();\r\n        } catch (ex) { return \'\'; }\r\n    }\r\n\r\n    // Single shell process: PlistBuddy handles both XML and binary plists.\r\n    // Outputs tab-separated: name, version, publisher, date, scope  one app per line.\r\n    var script = [\r\n        \'PB=/usr/libexec/PlistBuddy\',\r\n        \'process_app() {\',\r\n        \'  app=\"$1\" scope=\"$2\"\',\r\n        \'  plist=\"$app/Contents/Info.plist\"\',\r\n        \'  [ -f \"$plist\" ] || return\',\r\n        \'  name=$(basename \"$app\" .app)\',\r\n        \'  version=$(\"$PB\" -c \"Print :CFBundleShortVersionString\" \"$plist\" 2>/dev/null)\',\r\n        \'  publisher=$(\"$PB\" -c \"Print :NSHumanReadableCopyright\" \"$plist\" 2>/dev/null)\',\r\n        \'  if [ -z \"$publisher\" ]; then\',\r\n        \'    bid=$(\"$PB\" -c \"Print :CFBundleIdentifier\" \"$plist\" 2>/dev/null)\',\r\n        \'    publisher=$(echo \"$bid\" | awk -F. \\\'{if(NF>=2){s=$2; print toupper(substr(s,1,1)) substr(s,2)}}\\\')\',\r\n        \'  fi\',\r\n        \'  date=$(stat -f \"%Sm\" -t \"%Y-%m-%d\" \"$app\" 2>/dev/null)\',\r\n        \'  arch=\"\"\',\r\n        \'  exe=$(\"$PB\" -c \"Print :CFBundleExecutable\" \"$plist\" 2>/dev/null)\',\r\n        \'  if [ -n \"$exe\" ]; then\',\r\n        \'    lipoout=$(lipo -info \"$app/Contents/MacOS/$exe\" 2>/dev/null)\',\r\n        \'    if echo \"$lipoout\" | grep -q \"x86_64\" && echo \"$lipoout\" | grep -q \"arm64\"; then\',\r\n        \'      arch=\"universal\"\',\r\n        \'    elif echo \"$lipoout\" | grep -q \"arm64\"; then\',\r\n        \'      arch=\"arm64\"\',\r\n        \'    elif echo \"$lipoout\" | grep -q \"x86_64\"; then\',\r\n        \'      arch=\"x86_64\"\',\r\n        \'    fi\',\r\n        \'  fi\',\r\n        \'  printf \"%s\\\\t%s\\\\t%s\\\\t%s\\\\t%s\\\\t%s\\\\n\" \\\\\',\r\n        \'    \"$(printf \"%s\" \"$name\"      | tr \"\\\\t\\\\n\" \"  \")\" \\\\\',\r\n        \'    \"$(printf \"%s\" \"$version\"   | tr \"\\\\t\\\\n\" \"  \")\" \\\\\',\r\n        \'    \"$(printf \"%s\" \"$publisher\" | tr \"\\\\t\\\\n\" \"  \")\" \\\\\',\r\n        \'    \"$date\" \"$arch\" \"$scope\"\',\r\n        \'}\',\r\n        \'for sysdir in /Applications /System/Applications /System/Applications/Utilities; do\',\r\n        \'  [ -d \"$sysdir\" ] || continue\',\r\n        \'  find \"$sysdir\" -maxdepth 1 -name \"*.app\" -type d 2>/dev/null | while IFS= read -r app; do\',\r\n        \'    process_app \"$app\" system\',\r\n        \'  done\',\r\n        \'done\',\r\n        \'for userdir in /Users/*/; do\',\r\n        \'  user=$(basename \"$userdir\")\',\r\n        \'  [ \"$user\" = Shared ] && continue\',\r\n        \'  case \"$user\" in .*) continue;; esac\',\r\n        \'  appsdir=\"${userdir}Applications\"\',\r\n        \'  [ -d \"$appsdir\" ] || continue\',\r\n        \'  find \"$appsdir\" -maxdepth 1 -name \"*.app\" -type d 2>/dev/null | while IFS= read -r app; do\',\r\n        \'    process_app \"$app\" user\',\r\n        \'  done\',\r\n        \'done\'\r\n    ].join(\'\\n\');\r\n\r\n    try {\r\n        var out = runSh(script);\r\n        var results = [];\r\n        if (out) {\r\n            out.split(\'\\n\').forEach(function (line) {\r\n                var p = line.split(\'\\t\');\r\n                if (p.length < 6 || !p[0]) return;\r\n                results.push({ name: p[0], version: p[1] || \'\', publisher: p[2] || \'\', date: p[3] || \'\', arch: p[4] || \'\', location: p[5] || \'system\' });\r\n            });\r\n        }\r\n        ret._res(results);\r\n    } catch (e) {\r\n        ret._rej(e);\r\n    }\r\n    return (ret);\r\n}\r\n\r\nif (process.platform == \'darwin\') {\r\n    module.exports = { apps: apps };\r\n} else {\r\n    var not_supported = function () { throw (process.platform + \' not supported\'); };\r\n    module.exports = { apps: not_supported };\r\n}\r\n"); addedModules.push("mac-info"); } catch (ex) { }
try { addModule("monitor-border", "/*\r\nCopyright 2018-2021 Intel Corporation\r\n\r\nLicensed under the Apache License, Version 2.0 (the \"License\");\r\nyou may not use this file except in compliance with the License.\r\nYou may obtain a copy of the License at\r\n\r\n    http://www.apache.org/licenses/LICENSE-2.0\r\n\r\nUnless required by applicable law or agreed to in writing, software\r\ndistributed under the License is distributed on an \"AS IS\" BASIS,\r\nWITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.\r\nSee the License for the specific language governing permissions and\r\nlimitations under the License.\r\n*/\r\n\r\nvar red = 0xFF;\r\nvar yellow = 0xFFFF;\r\nvar GXxor = 0x6; //\tsrc XOR dst\r\nvar GXclear = 0x0;\r\nvar ExposureMask = (1 << 15);\r\n\r\nfunction windows_monitorborder()\r\n{\r\n    this._ObjectID = \'monitor-info\';\r\n    var info = require(\'monitor-info\');\r\n    var gm = require(\'_GenericMarshal\');\r\n    var user32 = gm.CreateNativeProxy(\'user32.dll\');\r\n    \r\n    info.monitors = [];\r\n    user32.CreateMethod(\'GetDC\');\r\n    user32.CreateMethod(\'ReleaseDC\');\r\n    user32.CreateMethod(\'FillRect\');\r\n    user32.CreateMethod(\'InvalidateRect\');\r\n\r\n    var gdi32 = gm.CreateNativeProxy(\'gdi32.dll\');\r\n    gdi32.CreateMethod(\'CreateSolidBrush\');\r\n\r\n    var redBrush = gdi32.CreateSolidBrush(red);\r\n    var yellowBrush = gdi32.CreateSolidBrush(yellow);\r\n\r\n    require(\'events\').EventEmitter.call(this);\r\n    this.on(\'~\', function () { this.Stop(); });\r\n\r\n    this.Stop = function Stop()\r\n    {\r\n        info.redInterval = null;\r\n\r\n        var drawRect = gm.CreateVariable(16);\r\n        var drawRectBuffer = drawRect.toBuffer();\r\n\r\n        for (var i in info.monitors)\r\n        {\r\n            // Top\r\n            drawRectBuffer.writeInt32LE(info.monitors[i].left, 0);\r\n            drawRectBuffer.writeInt32LE(info.monitors[i].top, 4);\r\n            drawRectBuffer.writeInt32LE(info.monitors[i].left + (info.monitors[i].right - info.monitors[i].left), 8);\r\n            drawRectBuffer.writeInt32LE(info.monitors[i].bottom - info.monitors[i].top, 12);\r\n            user32.InvalidateRect(0, drawRect, 0);\r\n        }\r\n    }\r\n\r\n    this.Start = function Start()\r\n    {\r\n        info.getInfo().then(function (mon)\r\n        {\r\n            var drawRect = gm.CreateVariable(16);\r\n\r\n            info.monitors = mon;\r\n            info.dc = user32.GetDC(0);\r\n            info.state = 0;\r\n\r\n            info.redInterval = setInterval(function ()\r\n            {\r\n                info.state = (info.state + 1) % 8;\r\n\r\n                var drawRectBuffer = drawRect.toBuffer();\r\n                for(var i in info.monitors)\r\n                {\r\n                    drawRectBuffer.writeInt32LE(info.monitors[i].left, 0);\r\n                    drawRectBuffer.writeInt32LE(info.monitors[i].top, 4);\r\n                    drawRectBuffer.writeInt32LE(info.monitors[i].left + (info.monitors[i].right - info.monitors[i].left)/2, 8);\r\n                    drawRectBuffer.writeInt32LE(5, 12);\r\n                    user32.FillRect(info.dc, drawRect, (info.state == 0 || info.state == 4) ? yellowBrush : redBrush);\r\n                    drawRectBuffer.writeInt32LE(info.monitors[i].left + (info.monitors[i].right - info.monitors[i].left) / 2, 0);\r\n                    drawRectBuffer.writeInt32LE(info.monitors[i].top, 4);\r\n                    drawRectBuffer.writeInt32LE(info.monitors[i].right, 8);\r\n                    drawRectBuffer.writeInt32LE(5, 12);\r\n                    user32.FillRect(info.dc, drawRect, (info.state == 1 || info.state == 5) ? yellowBrush : redBrush);\r\n\r\n\r\n                    drawRectBuffer.writeInt32LE(info.monitors[i].right - 5, 0);\r\n                    drawRectBuffer.writeInt32LE(info.monitors[i].top, 4);\r\n                    drawRectBuffer.writeInt32LE(info.monitors[i].right, 8);\r\n                    drawRectBuffer.writeInt32LE(info.monitors[i].top + (info.monitors[i].bottom - info.monitors[i].top)/2, 12);\r\n                    user32.FillRect(info.dc, drawRect, (info.state == 2 || info.state == 6) ? yellowBrush : redBrush);\r\n                    drawRectBuffer.writeInt32LE(info.monitors[i].right - 5, 0);\r\n                    drawRectBuffer.writeInt32LE(info.monitors[i].top + (info.monitors[i].bottom - info.monitors[i].top) / 2, 4);\r\n                    drawRectBuffer.writeInt32LE(info.monitors[i].right, 8);\r\n                    drawRectBuffer.writeInt32LE(info.monitors[i].bottom, 12);\r\n                    user32.FillRect(info.dc, drawRect, (info.state == 3 || info.state == 7) ? yellowBrush : redBrush);\r\n\r\n\r\n                    drawRectBuffer.writeInt32LE(info.monitors[i].left + (info.monitors[i].right - info.monitors[i].left) / 2, 0);\r\n                    drawRectBuffer.writeInt32LE(info.monitors[i].bottom - 5, 4);\r\n                    drawRectBuffer.writeInt32LE(info.monitors[i].right, 8);\r\n                    drawRectBuffer.writeInt32LE(info.monitors[i].bottom, 12);\r\n                    user32.FillRect(info.dc, drawRect, (info.state == 4 || info.state == 0) ? yellowBrush : redBrush);\r\n                    drawRectBuffer.writeInt32LE(info.monitors[i].left, 0);\r\n                    drawRectBuffer.writeInt32LE(info.monitors[i].bottom - 5, 4);\r\n                    drawRectBuffer.writeInt32LE(info.monitors[i].left + (info.monitors[i].right - info.monitors[i].left) / 2, 8);\r\n                    drawRectBuffer.writeInt32LE(info.monitors[i].bottom, 12);\r\n                    user32.FillRect(info.dc, drawRect, (info.state == 5 || info.state == 1) ? yellowBrush : redBrush);\r\n\r\n\r\n                    drawRectBuffer.writeInt32LE(info.monitors[i].left, 0);\r\n                    drawRectBuffer.writeInt32LE(info.monitors[i].top + (info.monitors[i].bottom - info.monitors[i].top) / 2, 4);\r\n                    drawRectBuffer.writeInt32LE(info.monitors[i].left + 5, 8);\r\n                    drawRectBuffer.writeInt32LE(info.monitors[i].bottom, 12);\r\n                    user32.FillRect(info.dc, drawRect, (info.state == 6 || info.state == 2) ? yellowBrush : redBrush);\r\n                    drawRectBuffer.writeInt32LE(info.monitors[i].left, 0);\r\n                    drawRectBuffer.writeInt32LE(info.monitors[i].top, 4);\r\n                    drawRectBuffer.writeInt32LE(info.monitors[i].left + 5, 8);\r\n                    drawRectBuffer.writeInt32LE(info.monitors[i].top + (info.monitors[i].bottom - info.monitors[i].top) / 2, 12);\r\n                    user32.FillRect(info.dc, drawRect, (info.state == 7 || info.state == 3) ? yellowBrush : redBrush);\r\n                }\r\n            }, 450);\r\n        });\r\n    }\r\n}\r\n\r\nfunction linux_monitorborder()\r\n{\r\n    var self = this;\r\n    this.displays = [];\r\n    this._ObjectID = \'monitor-info\';\r\n    this._info = require(\'monitor-info\');\r\n    this._isUnity = this._info.isUnity();\r\n\r\n    console.log(\'isUnity = \' + this._isUnity);\r\n\r\n    require(\'events\').EventEmitter.call(this);\r\n    this.on(\'~\', function () { this.Stop(); });\r\n\r\n    this.Stop = function Stop()\r\n    {\r\n        this._timeout = null;\r\n        if(!this._isUnity)\r\n        {\r\n            for(var i=0; i < this.displays.length; ++i)\r\n            {\r\n                if(this.displays[i].GC1 && this.displays[i].rootWindow)\r\n                {\r\n                    self._info._X11.XSetFunction(self.displays[i].display, self.displays[i].GC1, GXclear);\r\n                    self._info._X11.XDrawLine(self.displays[i].display, self.displays[i].rootWindow, self.displays[i].GC1, 0, 0, self.displays[i].right, 0);\r\n                    self._info._X11.XDrawLine(self.displays[i].display, self.displays[i].rootWindow, self.displays[i].GC1, self.displays[i].right, 0, self.displays[i].right, self.displays[i].bottom);\r\n                    self._info._X11.XDrawLine(self.displays[i].display, self.displays[i].rootWindow, self.displays[i].GC1, 0, self.displays[i].bottom, self.displays[i].right, self.displays[i].bottom);\r\n                    self._info._X11.XDrawLine(self.displays[i].display, self.displays[i].rootWindow, self.displays[i].GC1, 0, 0, 0, self.displays[i].bottom);\r\n\r\n                    this._info._X11.XFlush(this.displays[i].display);\r\n                }\r\n            }\r\n        }\r\n    }\r\n    this.Start = function Start()\r\n    {\r\n        this._info.getInfo().then(function (mon)\r\n        {\r\n            self.displays = mon;\r\n            console.log(mon.length + \' displays\');\r\n            for(var i = 0; i<mon.length; ++i)\r\n            {\r\n                console.log(\'Width: \' + mon[i].right + \', Height: \' + mon[i].bottom);\r\n                mon[i].rootWindow = self._info._X11.XRootWindow(mon[i].display, mon[i].screenId);\r\n\r\n                if (self._isUnity)\r\n                {\r\n                    // We are unity, so we have to fake the borders with borderless windows\r\n                    var white = self._info._X11.XWhitePixel(mon[i].display, mon[i].screenId).Val;\r\n\r\n                    // Top\r\n                    mon[i].window_top = self._info._X11.XCreateSimpleWindow(mon[i].display, mon[i].rootWindow, 0, 0, mon[i].right, 5, 0, white, white);\r\n                    mon[i].window_top.gc = self._info._X11.XCreateGC(mon[i].display, mon[i].window_top, 0, 0);\r\n                    self._info._X11.XSetLineAttributes(mon[i].display, mon[i].window_top.gc, 10, 0, 1, 1);\r\n                    self._info._X11.XSetSubwindowMode(mon[i].display, mon[i].window_top.gc, 1);\r\n                    self._info.unDecorateWindow(mon[i].display, mon[i].window_top);\r\n                    self._info.setWindowSizeHints(mon[i].display, mon[i].window_top, 0, 0, mon[i].right, 5);\r\n\r\n                    // Right\r\n                    mon[i].window_right = self._info._X11.XCreateSimpleWindow(mon[i].display, mon[i].rootWindow, mon[i].right - 5, 0, 5, mon[i].bottom, 0, white, white);\r\n                    mon[i].window_right.gc = self._info._X11.XCreateGC(mon[i].display, mon[i].window_right, 0, 0);\r\n                    self._info._X11.XSetLineAttributes(mon[i].display, mon[i].window_right.gc, 10, 0, 1, 1);\r\n                    self._info._X11.XSetSubwindowMode(mon[i].display, mon[i].window_right.gc, 1);\r\n                    self._info.unDecorateWindow(mon[i].display, mon[i].window_right);\r\n                    self._info.setWindowSizeHints(mon[i].display, mon[i].window_right, mon[i].right - 5, 0, 5, mon[i].bottom);\r\n\r\n                    // Left\r\n                    mon[i].window_left = self._info._X11.XCreateSimpleWindow(mon[i].display, mon[i].rootWindow, 0, 0, 5, mon[i].bottom, 0, white, white);\r\n                    mon[i].window_left.gc = self._info._X11.XCreateGC(mon[i].display, mon[i].window_left, 0, 0);\r\n                    self._info._X11.XSetLineAttributes(mon[i].display, mon[i].window_left.gc, 10, 0, 1, 1);\r\n                    self._info._X11.XSetSubwindowMode(mon[i].display, mon[i].window_left.gc, 1);\r\n                    self._info.unDecorateWindow(mon[i].display, mon[i].window_left);\r\n                    self._info.setWindowSizeHints(mon[i].display, mon[i].window_left, 0, 0, 5, mon[i].bottom);\r\n\r\n                    // Bottom\r\n                    mon[i].window_bottom = self._info._X11.XCreateSimpleWindow(mon[i].display, mon[i].rootWindow, 0, mon[i].bottom - 5, mon[i].right, 5, 0, white, white);\r\n                    mon[i].window_bottom.gc = self._info._X11.XCreateGC(mon[i].display, mon[i].window_bottom, 0, 0);\r\n                    self._info._X11.XSetLineAttributes(mon[i].display, mon[i].window_bottom.gc, 10, 0, 1, 1);\r\n                    self._info._X11.XSetSubwindowMode(mon[i].display, mon[i].window_bottom.gc, 1);\r\n                    self._info.unDecorateWindow(mon[i].display, mon[i].window_bottom);\r\n                    self._info.setWindowSizeHints(mon[i].display, mon[i].window_bottom, 0, mon[i].bottom - 5, mon[i].right, 5);\r\n\r\n                    self._info._X11.XMapWindow(mon[i].display, mon[i].window_top);\r\n                    self._info._X11.XMapWindow(mon[i].display, mon[i].window_right);\r\n                    self._info._X11.XMapWindow(mon[i].display, mon[i].window_left);\r\n                    self._info._X11.XMapWindow(mon[i].display, mon[i].window_bottom);\r\n\r\n                    self._info.setAlwaysOnTop(mon[i].display, mon[i].rootWindow, mon[i].window_top);\r\n                    self._info.hideWindowIcon(mon[i].display, mon[i].rootWindow, mon[i].window_top);\r\n                    self._info.setAlwaysOnTop(mon[i].display, mon[i].rootWindow, mon[i].window_right);\r\n                    self._info.hideWindowIcon(mon[i].display, mon[i].rootWindow, mon[i].window_right);\r\n                    self._info.setAlwaysOnTop(mon[i].display, mon[i].rootWindow, mon[i].window_left);\r\n                    self._info.hideWindowIcon(mon[i].display, mon[i].rootWindow, mon[i].window_left);\r\n                    self._info.setAlwaysOnTop(mon[i].display, mon[i].rootWindow, mon[i].window_bottom);\r\n                    self._info.hideWindowIcon(mon[i].display, mon[i].rootWindow, mon[i].window_bottom);\r\n\r\n                    self._info._X11.XFlush(mon[i].display);\r\n                    mon[i].borderState = 0;\r\n                }\r\n                else\r\n                {\r\n                    // If we aren\'t unity, then we can just draw\r\n                    mon[i].GC1 = self._info._X11.XCreateGC(mon[i].display, mon[i].rootWindow, 0, 0);\r\n                    mon[i].borderState = 0;\r\n\r\n                    self._info._X11.XSetForeground(mon[i].display, mon[i].GC1, self._info._X11.XWhitePixel(mon[i].display, mon[i].screenId).Val); // White\r\n                    self._info._X11.XSetLineAttributes(mon[i].display, mon[i].GC1, 10, 0, 1, 1);\r\n                    self._info._X11.XSetSubwindowMode(mon[i].display, mon[i].GC1, 1);\r\n                }\r\n            }\r\n            self._info._XEvent = self._info._gm.CreateVariable(192);\r\n            self._timeout = setTimeout(self._isUnity ? self.unity_drawBorder : self.timeoutHandler, 250);\r\n        });\r\n    }\r\n\r\n    this.timeoutHandler = function()\r\n    {\r\n        for (var i = 0; i < self.displays.length; ++i) {\r\n            self.displays[i].borderState = (self.displays[i].borderState + 1) % 8;\r\n\r\n            // Top\r\n            self._info._X11.XSetForeground(self.displays[i].display, self.displays[i].GC1, (self.displays[i].borderState == 0 || self.displays[i].borderState == 4) ? 0xffff00 : 0xff0000);\r\n            self._info._X11.XDrawLine(self.displays[i].display, self.displays[i].rootWindow, self.displays[i].GC1, 0, 0, self.displays[i].right / 2, 0);\r\n            self._info._X11.XSetForeground(self.displays[i].display, self.displays[i].GC1, (self.displays[i].borderState == 1 || self.displays[i].borderState == 5) ? 0xffff00 : 0xff0000);\r\n            self._info._X11.XDrawLine(self.displays[i].display, self.displays[i].rootWindow, self.displays[i].GC1, self.displays[i].right / 2, 0, self.displays[i].right, 0);\r\n\r\n            // Right\r\n            self._info._X11.XSetForeground(self.displays[i].display, self.displays[i].GC1, (self.displays[i].borderState == 2 || self.displays[i].borderState == 6) ? 0xffff00 : 0xff0000);\r\n            self._info._X11.XDrawLine(self.displays[i].display, self.displays[i].rootWindow, self.displays[i].GC1, self.displays[i].right, 0, self.displays[i].right, self.displays[i].bottom / 2);\r\n            self._info._X11.XSetForeground(self.displays[i].display, self.displays[i].GC1, (self.displays[i].borderState == 3 || self.displays[i].borderState == 7) ? 0xffff00 : 0xff0000);\r\n            self._info._X11.XDrawLine(self.displays[i].display, self.displays[i].rootWindow, self.displays[i].GC1, self.displays[i].right, self.displays[i].bottom / 2, self.displays[i].right, self.displays[i].bottom);\r\n\r\n            // Bottom\r\n            self._info._X11.XSetForeground(self.displays[i].display, self.displays[i].GC1, (self.displays[i].borderState == 5 || self.displays[i].borderState == 1) ? 0xffff00 : 0xff0000);\r\n            self._info._X11.XDrawLine(self.displays[i].display, self.displays[i].rootWindow, self.displays[i].GC1, 0, self.displays[i].bottom, self.displays[i].right / 2, self.displays[i].bottom);\r\n            self._info._X11.XSetForeground(self.displays[i].display, self.displays[i].GC1, (self.displays[i].borderState == 4 || self.displays[i].borderState == 0) ? 0xffff00 : 0xff0000);\r\n            self._info._X11.XDrawLine(self.displays[i].display, self.displays[i].rootWindow, self.displays[i].GC1, self.displays[i].right / 2, self.displays[i].bottom, self.displays[i].right, self.displays[i].bottom);\r\n\r\n            // Left\r\n            self._info._X11.XSetForeground(self.displays[i].display, self.displays[i].GC1, (self.displays[i].borderState == 7 || self.displays[i].borderState == 3) ? 0xffff00 : 0xff0000);\r\n            self._info._X11.XDrawLine(self.displays[i].display, self.displays[i].rootWindow, self.displays[i].GC1, 0, 0, 0, self.displays[i].bottom / 2);\r\n            self._info._X11.XSetForeground(self.displays[i].display, self.displays[i].GC1, (self.displays[i].borderState == 6 || self.displays[i].borderState == 2) ? 0xffff00 : 0xff0000);\r\n            self._info._X11.XDrawLine(self.displays[i].display, self.displays[i].rootWindow, self.displays[i].GC1, 0, self.displays[i].bottom / 2, 0, self.displays[i].bottom);\r\n\r\n\r\n            self._info._X11.XFlush(self.displays[i].display);\r\n        }\r\n        self._timeout = setTimeout(self._isUnity ? self.unity_drawBorder : self.timeoutHandler, 400);\r\n    }\r\n    this.unity_drawBorder = function unity_drawBorder()\r\n    {\r\n        for (var i = 0; i < self.displays.length; ++i)\r\n        {\r\n            self.displays[i].borderState = (self.displays[i].borderState + 1) % 8;\r\n\r\n            // Top\r\n            self._info._X11.XSetForeground(self.displays[i].display, self.displays[i].window_top.gc, (self.displays[i].borderState == 0 || self.displays[i].borderState == 4) ? 0xffff00 : 0xff0000);\r\n            self._info._X11.XDrawLine(self.displays[i].display, self.displays[i].window_top, self.displays[i].window_top.gc, 0, 0, self.displays[i].right / 2, 0);\r\n            self._info._X11.XSetForeground(self.displays[i].display, self.displays[i].window_top.gc, (self.displays[i].borderState == 1 || self.displays[i].borderState == 5) ? 0xffff00 : 0xff0000);\r\n            self._info._X11.XDrawLine(self.displays[i].display, self.displays[i].window_top, self.displays[i].window_top.gc, self.displays[i].right / 2, 0, self.displays[i].right, 0);\r\n            self._info._X11.XFlush(self.displays[i].display);\r\n\r\n            // Right\r\n            self._info._X11.XSetForeground(self.displays[i].display, self.displays[i].window_right.gc, (self.displays[i].borderState == 2 || self.displays[i].borderState == 6) ? 0xffff00 : 0xff0000);\r\n            self._info._X11.XDrawLine(self.displays[i].display, self.displays[i].window_right, self.displays[i].window_right.gc, 0, 0, 0, self.displays[i].bottom / 2);\r\n            self._info._X11.XSetForeground(self.displays[i].display, self.displays[i].window_right.gc, (self.displays[i].borderState == 3 || self.displays[i].borderState == 7) ? 0xffff00 : 0xff0000);\r\n            self._info._X11.XDrawLine(self.displays[i].display, self.displays[i].window_right, self.displays[i].window_right.gc, 0, self.displays[i].bottom / 2, 0, self.displays[i].bottom);\r\n            self._info._X11.XFlush(self.displays[i].display);\r\n\r\n            // Bottom\r\n            self._info._X11.XSetForeground(self.displays[i].display, self.displays[i].window_bottom.gc, (self.displays[i].borderState == 5 || self.displays[i].borderState == 1) ? 0xffff00 : 0xff0000);\r\n            self._info._X11.XDrawLine(self.displays[i].display, self.displays[i].window_bottom, self.displays[i].window_bottom.gc, 0, 0, self.displays[i].right / 2, 0);\r\n            self._info._X11.XSetForeground(self.displays[i].display, self.displays[i].window_bottom.gc, (self.displays[i].borderState == 4 || self.displays[i].borderState == 0) ? 0xffff00 : 0xff0000);\r\n            self._info._X11.XDrawLine(self.displays[i].display, self.displays[i].window_bottom, self.displays[i].window_bottom.gc, self.displays[i].right / 2, 0, self.displays[i].right, 0);\r\n            self._info._X11.XFlush(self.displays[i].display);\r\n\r\n            // Left\r\n            self._info._X11.XSetForeground(self.displays[i].display, self.displays[i].window_left.gc, (self.displays[i].borderState == 7 || self.displays[i].borderState == 3) ? 0xffff00 : 0xff0000);\r\n            self._info._X11.XDrawLine(self.displays[i].display, self.displays[i].window_left, self.displays[i].window_left.gc, 0, 0, 0, self.displays[i].bottom / 2);\r\n            self._info._X11.XSetForeground(self.displays[i].display, self.displays[i].window_left.gc, (self.displays[i].borderState == 6 || self.displays[i].borderState == 2) ? 0xffff00 : 0xff0000);\r\n            self._info._X11.XDrawLine(self.displays[i].display, self.displays[i].window_left, self.displays[i].window_left.gc, 0, self.displays[i].bottom / 2, 0, self.displays[i].bottom);\r\n            self._info._X11.XFlush(self.displays[i].display);\r\n        }\r\n        self._timeout = setTimeout(self._isUnity ? self.unity_drawBorder : self.timeoutHandler, 400);\r\n    }\r\n}\r\n\r\nswitch(process.platform)\r\n{\r\n    case \'win32\':\r\n        module.exports = new windows_monitorborder();\r\n        break;\r\n    case \'linux\':\r\n        module.exports = new linux_monitorborder();\r\n        break;\r\n    default:\r\n        break;\r\n}\r\n\r\n\r\n\r\n\r\n\r\n\r\n\r\n"); addedModules.push("monitor-border"); } catch (ex) { }
try { addModule("relay-range-scanner", "\"use strict\";\r\n\r\nconst MAX_SCAN_ADDRESSES = 1024;\r\n\r\nfunction parseIpv4Address(address) {\r\n    if (typeof address != \'string\') return null;\r\n    const parts = address.split(\'.\');\r\n    if (parts.length != 4) return null;\r\n    var value = 0;\r\n    for (var i = 0; i < parts.length; i++) {\r\n        if (!/^(0|[1-9][0-9]{0,2})$/.test(parts[i])) return null;\r\n        const octet = parseInt(parts[i], 10);\r\n        if (octet > 255) return null;\r\n        value = (value * 256) + octet;\r\n    }\r\n    return value;\r\n}\r\n\r\nfunction ipv4NumberToString(value) {\r\n    return Math.floor(value / 16777216) + \'.\' + Math.floor((value % 16777216) / 65536) + \'.\' + Math.floor((value % 65536) / 256) + \'.\' + (value % 256);\r\n}\r\n\r\nfunction parseRange(range) {\r\n    if ((typeof range != \'string\') || (range.length == 0) || (range.length > 64)) return null;\r\n    var min = null, max = null;\r\n    const rangeParts = range.split(\'-\');\r\n    if (rangeParts.length == 2) {\r\n        min = parseIpv4Address(rangeParts[0]);\r\n        max = parseIpv4Address(rangeParts[1]);\r\n    } else {\r\n        const cidrParts = range.split(\'/\');\r\n        if (cidrParts.length == 2) {\r\n            const address = parseIpv4Address(cidrParts[0]);\r\n            if (!/^(1[7-9]|2[0-9]|3[0-2])$/.test(cidrParts[1])) return null;\r\n            const size = Math.pow(2, 32 - parseInt(cidrParts[1], 10));\r\n            min = Math.floor(address / size) * size;\r\n            max = min + size - 1;\r\n        } else if (rangeParts.length == 1) {\r\n            min = max = parseIpv4Address(range);\r\n        }\r\n    }\r\n    if ((min == null) || (max == null) || (min > max) || ((max - min + 1) > MAX_SCAN_ADDRESSES)) return null;\r\n    return { min: min, max: max };\r\n}\r\n\r\nfunction parseResponse(data, address, results) {\r\n    if ((data == null) || (data.length < 22)) return;\r\n    if (((data[12] == 0) || (data[13] != 0) || (data[14] != 1) || (data[15] != 0x57)) && (data[21] & 32)) {\r\n        const state = data[19] & 0x03;\r\n        if (state > 2) return;\r\n        const port = (data[16] * 256) + data[17];\r\n        results[address] = { ver: (data[18] >> 4) + \'.\' + (data[18] & 0x0F), tls: ((port == 16993) || ((data[19] & 0x04) != 0)) ? 1 : 0, state: state, hostname: address, hosttype: \'addr\' };\r\n    }\r\n}\r\n\r\nmodule.exports.parseRange = parseRange;\r\n\r\nmodule.exports.scan = function (range, timeout, callback, options) {\r\n    const parsedRange = parseRange(range);\r\n    if (parsedRange == null) return false;\r\n    if (options == null) options = {};\r\n    const dgram = options.dgram || require(\'dgram\');\r\n    const setScanTimeout = options.setTimeout || setTimeout;\r\n    const socket = dgram.createSocket({ type: \'udp4\' });\r\n    const results = {};\r\n    const packet = Buffer.from(\'06000006000011BE80000000\', \'hex\');\r\n\r\n    socket.on(\'error\', function () { });\r\n    socket.on(\'message\', function (data, rinfo) { parseResponse(data, rinfo.address, results); });\r\n    socket.on(\'listening\', function () {\r\n        for (var address = parsedRange.min; address <= parsedRange.max; address++) {\r\n            try { socket.send(packet, 623, ipv4NumberToString(address)); } catch (ex) { }\r\n        }\r\n    });\r\n    socket.bind({ address: \'0.0.0.0\' });\r\n    setScanTimeout(function () {\r\n        try { socket.close(); } catch (ex) { }\r\n        callback(results);\r\n    }, timeout);\r\n    return true;\r\n};"); addedModules.push("relay-range-scanner"); } catch (ex) { }
try { addModule("smbios", "/*\r\nCopyright 2018 Intel Corporation\r\n\r\nLicensed under the Apache License, Version 2.0 (the \"License\");\r\nyou may not use this file except in compliance with the License.\r\nYou may obtain a copy of the License at\r\n\r\n    http://www.apache.org/licenses/LICENSE-2.0\r\n\r\nUnless required by applicable law or agreed to in writing, software\r\ndistributed under the License is distributed on an \"AS IS\" BASIS,\r\nWITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.\r\nSee the License for the specific language governing permissions and\r\nlimitations under the License.\r\n*/\r\n\r\ntry { Object.defineProperty(Array.prototype, \"peek\", { value: function () { return (this.length > 0 ? this[this.length - 1] : undefined); } }); } catch (e) { }\r\ntry { Object.defineProperty(String.prototype, \"replaceAll\", { value: function replaceAll(oldVal, newVal) { return (this.split(oldVal).join(newVal)); } }); } catch (e) { }\r\n\r\nvar RSMB = 1381190978;\r\nvar memoryLocation = { 0x1: \'Other\', 0x2: \'Unknown\', 0x3: \'System Board\', 0x4: \'ISA\', 0x5: \'EISA\', 0x6: \'PCI\', 0x7: \'MCA\', 0x8: \'PCMCIA\', 0x9: \'Proprietary\', 0xA: \'NuBus\', 0xA0: \'PC-98/C20\', 0xA1: \'PC-98/C24\', 0xA2: \'PC-98/E\', 0xA3: \'PC-98/LB\' };\r\nvar wakeReason = [\'Reserved\', \'Other\', \'Unknown\', \'APM Timer\', \'Modem Ring\', \'LAN\', \'Power Switch\', \'PCI\', \'AC Power\'];\r\n\r\n// Fill the left with zeros until the string is of a given length\r\nfunction zeroLeftPad(str, len)\r\n{\r\n    if ((len == null) && (typeof (len) != \'number\')) { return null; }\r\n    if (str == null) str = \'\'; // If null, this is to generate zero leftpad string\r\n    var zlp = \'\';\r\n    for (var i = 0; i < len - str.length; i++) { zlp += \'0\'; }\r\n    return zlp + str;\r\n}\r\n\r\nfunction SMBiosTables()\r\n{\r\n    this._ObjectID = \'SMBiosTable\';\r\n    if (process.platform == \'win32\') {\r\n        this._marshal = require(\'_GenericMarshal\');\r\n        this._native = this._marshal.CreateNativeProxy(\"Kernel32.dll\");\r\n\r\n        this._native.CreateMethod(\'EnumSystemFirmwareTables\');\r\n        this._native.CreateMethod(\'GetSystemFirmwareTable\');\r\n    }\r\n    if (process.platform == \'linux\') {\r\n        this._canonicalizeData = function _canonicalizeData(data) {\r\n            var lines = data.toString().split(\'Header and Data:\\x0A\');\r\n            var MemoryStream = require(\'MemoryStream\');\r\n            var ms = new MemoryStream();\r\n\r\n            for (var i = 1; i < lines.length; ++i) {\r\n                var tokens = lines[i].split(\'Strings:\\x0A\');\r\n                var header = tokens[0].split(\'\\x0A\\x0A\')[0].replaceAll(\'\\x0A\', \'\').trim().replaceAll(\' \', \'\').replaceAll(\'\\x09\', \'\');\r\n                ms.write(Buffer.from(header, \'hex\'));\r\n                if (tokens.length > 1) {\r\n                    var strings = tokens[1].split(\'\\x0A\\x0A\')[0].split(\'\\x0A\');\r\n                    var stringsFinal = [];\r\n                    for (var strx in strings) {\r\n                        var tmp = strings[strx].trim().replaceAll(\' \', \'\').replaceAll(\'\\x09\', \'\');\r\n                        if (tmp && tmp[0] !== \'\"\' && /^[0-9a-fA-F]+$/.test(tmp)) { stringsFinal.push(tmp); }\r\n                    }\r\n                    ms.write(Buffer.from(stringsFinal.join(\'\'), \'hex\'));\r\n                    ms.write(Buffer.from(\'00\', \'hex\'));\r\n                }\r\n                else {\r\n                    ms.write(Buffer.from(\'0000\', \'hex\'));\r\n                }\r\n            }\r\n            var retVal = ms.buffer;\r\n            retVal.ms = ms;\r\n            return (retVal);\r\n        };\r\n    }\r\n    this._parse = function _parse(SMData) {\r\n        var ret = {};\r\n        var pbyte;\r\n        var i = 0\r\n        var SMData;\r\n        var structcount = 0;\r\n\r\n        while (SMData && i < SMData.length)\r\n        {\r\n            var SMtype = SMData[i];\r\n            var SMlength = SMData[i + 1];\r\n\r\n            if (!ret[SMtype]) { ret[SMtype] = []; }\r\n            ret[SMtype].push(SMData.slice(i + 4, i + SMlength));\r\n            if (process.platform == \'win32\') { ret[SMtype].peek()._ext = pbyte; }\r\n            i += SMlength;\r\n\r\n            ret[SMtype].peek()._strings = [];\r\n\r\n            while (SMData[i] != 0 && i <= SMData.length)\r\n            {\r\n                var strstart = i;\r\n\r\n                // Start of String, find end of string\r\n                while (SMData[i++] != 0 && i <= SMData.length);\r\n                try\r\n                {\r\n                    ret[SMtype].peek()._strings.push(SMData.slice(strstart, i).toString().trim());\r\n                }\r\n                catch (ee)\r\n                {\r\n                }\r\n            }\r\n            i += (ret[SMtype].peek()._strings.length == 0) ? 2 : 1;\r\n            ++structcount;\r\n            //console.log(\'End of Table[\' + SMtype + \']: \' + i);\r\n        }\r\n        //console.log(\'Struct Count = \' + structcount);\r\n        return (ret);\r\n    };\r\n    this.get = function get(callback) {\r\n        if (process.platform == \'win32\') {\r\n            var size = this._native.GetSystemFirmwareTable(RSMB, 0, 0, 0).Val;\r\n            //console.log(\'Table Size: \' + size);\r\n\r\n            var PtrSize = this._marshal.CreatePointer()._size;\r\n            var buffer = this._marshal.CreateVariable(size);\r\n            var written = this._native.GetSystemFirmwareTable(RSMB, 0, buffer, size).Val;\r\n            //console.log(\'Written Size: \' + written);\r\n\r\n            var rawBuffer = buffer.toBuffer();\r\n            var length = buffer.Deref(4, 4).toBuffer().readUInt32LE(0);\r\n\r\n            pbyte = buffer.Deref(8, length);\r\n            SMData = pbyte.toBuffer();\r\n\r\n            if (callback) { callback.apply(this, [this._parse(SMData)]); return; } else { return (this._parse(SMData)); }\r\n        }\r\n        if (process.platform == \'linux\') {\r\n            var MemoryStream = require(\'MemoryStream\');\r\n            this.child = require(\'child_process\').execFile(\'/usr/sbin/dmidecode\', [\'dmidecode\', \'-u\']);\r\n            this.child.SMBiosTable = this;\r\n            this.child.ms = new MemoryStream();\r\n            this.child.ms.callback = callback;\r\n            this.child.ms.child = this.child;\r\n            this.child.stdout.on(\'data\', function (buffer) { this.parent.ms.write(buffer); });\r\n            this.child.on(\'exit\', function () { this.ms.end(); });\r\n            this.child.ms.on(\'end\', function () {\r\n                //console.log(\'read \' + this.buffer.length + \' bytes\');\r\n                if (this.buffer.length < 300) {\r\n                    //console.log(\'Not enough permission to read SMBiosTable\');\r\n                    if (this.callback) { this.callback.apply(this.child.SMBiosTable, []); }\r\n                }\r\n                else {\r\n                    var SMData = this.child.SMBiosTable._canonicalizeData(this.buffer);\r\n                    var j = this.child.SMBiosTable._parse(SMData);\r\n                    if (this.callback) { this.callback.apply(this.child.SMBiosTable, [j]); }\r\n                }\r\n            });\r\n            return;\r\n        }\r\n        if (callback) { callback.apply(this, [null]); return; } else { return (null); }\r\n    };\r\n    this.parse = function parse(data) {\r\n        var r = {};\r\n        try\r\n        {\r\n            r.processorInfo = this.processorInfo(data);\r\n        }\r\n        catch(e)\r\n        {\r\n        }\r\n        try\r\n        {\r\n            r.memoryInfo = this.memoryInfo(data);\r\n        }\r\n        catch(e)\r\n        {\r\n        }\r\n        try\r\n        {\r\n            r.systemInfo = this.systemInfo(data);\r\n        }\r\n        catch(e)\r\n        {\r\n        }\r\n        try\r\n        {\r\n            r.systemSlots = this.systemSlots(data);\r\n        }\r\n        catch(e)\r\n        {\r\n        }\r\n        try\r\n        {\r\n            r.amtInfo = this.amtInfo(data);\r\n        }\r\n        catch(e)\r\n        {\r\n        }\r\n        try\r\n        {\r\n            if (JSON.stringify(r).length > 65535) { r = {}; }\r\n        }\r\n        catch(ee)\r\n        {}\r\n        return r;\r\n    }\r\n    this.processorInfo = function processorInfo(data) {\r\n        if (!data) { throw (\'no data\'); }\r\n        var ret = [];\r\n        var ptype = [\'ERROR\', \'Other\', \'Unknown\', \'CPU\', \'ALU\', \'DSP\', \'GPU\'];\r\n        var statusString = [\'Unknown\', \'Enabled\', \'Disabled by user\', \'Disabled by BIOS\', \'Idle\', \'Reserved\', \'Reserved\', \'Other\'];\r\n        var cpuid = 0;\r\n        while (data[4] && data[4].length > 0) {\r\n            var p = data[4].pop();\r\n            var populated = p[20] & 0x40;\r\n            var status = p[20] & 0x07\r\n            if (populated) {\r\n                var j = { _ObjectID: \'SMBiosTables.processorInfo\' };\r\n                j.Processor = ptype[p[1]];\r\n                j.MaxSpeed = p.readUInt16LE(16) + \' Mhz\';\r\n                if (p[31]) { j.Cores = p[31]; }\r\n                if (p[33]) { j.Threads = p[33]; }\r\n                j.Populated = 1;\r\n                j.Status = statusString[status];\r\n                j.Socket = p._strings[p[0] - 1];\r\n                j.Manufacturer = p._strings[p[3] - 1];\r\n                j.Version = p._strings[p[12] - 1];\r\n                ret.push(j);\r\n            }\r\n        }\r\n        return (ret);\r\n    };\r\n    this.memoryInfo = function memoryInfo(data) {\r\n        if (!data) { throw (\'no data\'); }\r\n        var retVal = { _ObjectID: \'SMBiosTables.memoryInfo\' };\r\n        if (data[16]) {\r\n            var m = data[16].peek();\r\n            retVal.location = memoryLocation[m[0]];\r\n            if ((retVal.maxCapacityKb = m.readUInt32LE(3)) == 0x80000000) {\r\n                retVal.maxCapacityKb = \'A really big number\';\r\n            }\r\n        }\r\n        return (retVal);\r\n    };\r\n    this.systemInfo = function systemInfo(data)\r\n    {\r\n        if (!data) { throw (\'no data\'); }\r\n        var retVal = { _ObjectID: \'SMBiosTables.systemInfo\' };\r\n        if (data[1])\r\n        {\r\n            var si = data[1].peek();\r\n            var uuid = si.slice(4, 20);\r\n\r\n            retVal.uuid = [zeroLeftPad(uuid.readUInt32LE(0).toString(16), 8),\r\n            zeroLeftPad(uuid.readUInt16LE(4).toString(16), 4),\r\n            zeroLeftPad(uuid.readUInt16LE(6).toString(16), 4),\r\n            zeroLeftPad(uuid.readUInt16BE(8).toString(16), 4),\r\n            zeroLeftPad(uuid.slice(10).toString(\'hex\').toLowerCase(), 12)].join(\'-\');\r\n\r\n            retVal.wakeReason = wakeReason[si[20]];\r\n        }\r\n        return (retVal);\r\n    };\r\n    this.systemSlots = function systemSlots(data) {\r\n        if (!data) { throw (\'no data\'); }\r\n        var retVal = [];\r\n        if (data[9]) {\r\n            while (data[9].length > 0) {\r\n                var ss = data[9].pop();\r\n                retVal.push({ name: ss._strings[ss[0] - 1] });\r\n            }\r\n        }\r\n        return (retVal);\r\n    };\r\n    this.amtInfo = function amtInfo(data) {\r\n        if (!data) { throw (\'no data\'); }\r\n        var retVal = { AMT: false };\r\n        if (data[130] && data[130].peek().slice(0, 4).toString() == \'$AMT\')\r\n        {\r\n            var amt = data[130].peek();\r\n            retVal.AMT = amt[4] ? true : false;\r\n            if (retVal.AMT)\r\n            {\r\n                retVal.enabled = amt[5] ? true : false;\r\n                retVal.storageRedirection = amt[6] ? true : false;\r\n                retVal.serialOverLan = amt[7] ? true : false;\r\n                retVal.kvm = amt[14] ? true : false;\r\n                if (data[131].peek() && data[131].peek().slice(52, 56).toString() == \'vPro\')\r\n                {\r\n                    var settings = data[131].peek();\r\n                    if (settings[0] & 0x04) { retVal.TXT = (settings[0] & 0x08) ? true : false; }\r\n                    if (settings[0] & 0x10) { retVal.VMX = (settings[0] & 0x20) ? true : false; }\r\n                    retVal.MEBX = settings.readUInt16LE(4).toString() + \'.\' + settings.readUInt16LE(6).toString() + \'.\' + settings.readUInt16LE(8).toString() + \'.\' + settings.readUInt16LE(10).toString();\r\n\r\n                    var mecap = settings.slice(20, 32);\r\n                    retVal.ManagementEngine = mecap.readUInt16LE(6).toString() + \'.\' + mecap.readUInt16LE(4).toString() + \'.\' + mecap.readUInt16LE(10).toString() + \'.\' + mecap.readUInt16LE(8).toString();\r\n\r\n                    //var lan = settings.slice(36, 48);\r\n                    //console.log(lan.toString(\'hex\'));\r\n                    //retVal.LAN = (lan.readUInt16LE(10) & 0x03).toString() + \'/\' + ((lan.readUInt16LE(10) & 0xF8) >> 3).toString();\r\n\r\n                    //console.log(lan.readUInt16LE(3));\r\n                    //retVal.WLAN = (lan.readUInt16LE(3) & 0x07).toString() + \'/\' + ((lan.readUInt16LE(3) & 0xF8) >> 3).toString() + \'/\' + (lan.readUInt16LE(3) >> 8).toString();\r\n                }\r\n            }\r\n        }\r\n        if (!retVal.AMT)\r\n        {\r\n            if (data[131].peek() && data[131].peek().slice(52, 56).toString() == \'vPro\')\r\n            {\r\n                var settings = data[131].peek();\r\n                if ((settings[20] & 0x08) == 0x08) { retVal.AMT = true; }\r\n            }\r\n        }\r\n        return (retVal);\r\n    };\r\n    this.smTableTypes = {\r\n        0: \'BIOS information\',\r\n        1: \'System information\',\r\n        2: \'Baseboard (or Module) information\',\r\n        4: \'Processor information\',\r\n        5: \'memory controller information\',\r\n        6: \'Memory module information\',\r\n        7: \'Cache information\',\r\n        8: \'Port connector information\',\r\n        9: \'System slots\',\r\n        10: \'On board devices information\',\r\n        11: \'OEM strings\',\r\n        12: \'System configuration options\',\r\n        13: \'BIOS language information\',\r\n        14: \'Group associations\',\r\n        15: \'System event log\',\r\n        16: \'Physical memory array\',\r\n        17: \'Memory device\',\r\n        18: \'32bit memory error information\',\r\n        19: \'Memory array mapped address\',\r\n        20: \'Memory device mapped address\',\r\n        21: \'Built-in pointing device\',\r\n        22: \'Portable battery\',\r\n        23: \'System reset\',\r\n        24: \'Hardware security\',\r\n        25: \'System power controls\',\r\n        26: \'Voltage probe\',\r\n        27: \'Cooling device\',\r\n        28: \'Temperature probe\',\r\n        29: \'Electrical current probe\',\r\n        30: \'Out-of-band remote access\',\r\n        31: \'Boot integrity services (BIS) entry point\',\r\n        32: \'System boot information\',\r\n        33: \'64bit memory error information\',\r\n        34: \'Management device\',\r\n        35: \'Management device component\',\r\n        36: \'Management device threshold data\',\r\n        37: \'Memory channel\',\r\n        38: \'IPMI device information\',\r\n        39: \'System power supply\',\r\n        40: \'Additional information\',\r\n        41: \'Onboard devices extended information\',\r\n        42: \'Management controller host interface\',\r\n        126: \'Inactive\',\r\n        127: \'End-of-table\'\r\n    }\r\n}\r\n\r\nmodule.exports = new SMBiosTables();"); addedModules.push("smbios"); } catch (ex) { }
try { addModule("sysinfo", "/*\r\nCopyright 2019-2021 Intel Corporation\r\n\r\nLicensed under the Apache License, Version 2.0 (the \"License\");\r\nyou may not use this file except in compliance with the License.\r\nYou may obtain a copy of the License at\r\n\r\n    http://www.apache.org/licenses/LICENSE-2.0\r\n\r\nUnless required by applicable law or agreed to in writing, software\r\ndistributed under the License is distributed on an \"AS IS\" BASIS,\r\nWITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.\r\nSee the License for the specific language governing permissions and\r\nlimitations under the License.\r\n*/\r\n\r\nvar PDH_FMT_LONG = 0x00000100;\r\nvar PDH_FMT_DOUBLE = 0x00000200;\r\n\r\nvar promise = require(\'promise\');\r\nif (process.platform == \'win32\')\r\n{\r\n    var GM = require(\'_GenericMarshal\');\r\n    GM.kernel32 = GM.CreateNativeProxy(\'kernel32.dll\');\r\n    GM.kernel32.CreateMethod(\'GlobalMemoryStatusEx\');\r\n\r\n    GM.pdh = GM.CreateNativeProxy(\'pdh.dll\');\r\n    GM.pdh.CreateMethod(\'PdhAddEnglishCounterA\');\r\n    GM.pdh.CreateMethod(\'PdhCloseQuery\');\r\n    GM.pdh.CreateMethod(\'PdhCollectQueryData\');\r\n    GM.pdh.CreateMethod(\'PdhGetFormattedCounterValue\');\r\n    GM.pdh.CreateMethod(\'PdhGetFormattedCounterArrayA\');\r\n    GM.pdh.CreateMethod(\'PdhOpenQueryA\');\r\n    GM.pdh.CreateMethod(\'PdhRemoveCounter\');\r\n}\r\n\r\nfunction windows_cpuUtilization()\r\n{\r\n    var p = new promise(function (res, rej) { this._res = res; this._rej = rej; });\r\n    p.counter = GM.CreateVariable(16);\r\n    p.cpu = GM.CreatePointer();\r\n    p.cpuTotal = GM.CreatePointer();\r\n    var err = 0;\r\n    if ((err = GM.pdh.PdhOpenQueryA(0, 0, p.cpu).Val) != 0) { p._rej(err); return; }\r\n\r\n    // This gets the CPU Utilization for each proc\r\n    if ((err = GM.pdh.PdhAddEnglishCounterA(p.cpu.Deref(), GM.CreateVariable(\'\\\\Processor(*)\\\\% Processor Time\'), 0, p.cpuTotal).Val) != 0) { p._rej(err); return; }\r\n\r\n    if ((err = GM.pdh.PdhCollectQueryData(p.cpu.Deref()).Val != 0)) { p._rej(err); return; }\r\n    p._timeout = setTimeout(function (po)\r\n    {\r\n        var u = { cpus: [] };\r\n        var bufSize = GM.CreateVariable(4);\r\n        var itemCount = GM.CreateVariable(4);\r\n        var buffer, szName, item;\r\n        var e;\r\n        if ((e = GM.pdh.PdhCollectQueryData(po.cpu.Deref()).Val != 0)) { po._rej(e); return; }\r\n\r\n        if ((e = GM.pdh.PdhGetFormattedCounterArrayA(po.cpuTotal.Deref(), PDH_FMT_DOUBLE, bufSize, itemCount, 0).Val) == -2147481646)\r\n        {\r\n            buffer = GM.CreateVariable(bufSize.toBuffer().readUInt32LE());\r\n        }\r\n        else\r\n        {\r\n            po._rej(e);\r\n            return;\r\n        }\r\n        if ((e = GM.pdh.PdhGetFormattedCounterArrayA(po.cpuTotal.Deref(), PDH_FMT_DOUBLE, bufSize, itemCount, buffer).Val) != 0) { po._rej(e); return; }\r\n        for(var i=0;i<itemCount.toBuffer().readUInt32LE();++i)\r\n        {\r\n            item = buffer.Deref(i * 24, 24);\r\n            szName = item.Deref(0, GM.PointerSize).Deref();\r\n            if (szName.String == \'_Total\')\r\n            {\r\n                u.total = item.Deref(16, 8).toBuffer().readDoubleLE();\r\n            }\r\n            else\r\n            {\r\n                u.cpus[parseInt(szName.String)] = item.Deref(16, 8).toBuffer().readDoubleLE();\r\n            }\r\n        }\r\n\r\n        GM.pdh.PdhRemoveCounter(po.cpuTotal.Deref());\r\n        GM.pdh.PdhCloseQuery(po.cpu.Deref());\r\n        p._res(u);\r\n    }, 100, p);\r\n\r\n    return (p);\r\n}\r\nfunction windows_memUtilization()\r\n{\r\n    var info = GM.CreateVariable(64);\r\n    info.Deref(0, 4).toBuffer().writeUInt32LE(64);\r\n    GM.kernel32.GlobalMemoryStatusEx(info);\r\n\r\n    var ret =\r\n        {\r\n            MemTotal: require(\'bignum\').fromBuffer(info.Deref(8, 8).toBuffer(), { endian: \'little\' }),\r\n            MemFree: require(\'bignum\').fromBuffer(info.Deref(16, 8).toBuffer(), { endian: \'little\' })\r\n        };\r\n\r\n    ret.percentFree = ((ret.MemFree.div(require(\'bignum\')(\'1048576\')).toNumber() / ret.MemTotal.div(require(\'bignum\')(\'1048576\')).toNumber()) * 100);//.toFixed(2);\r\n    ret.percentConsumed = ((ret.MemTotal.sub(ret.MemFree).div(require(\'bignum\')(\'1048576\')).toNumber() / ret.MemTotal.div(require(\'bignum\')(\'1048576\')).toNumber()) * 100);//.toFixed(2);\r\n    ret.MemTotal = ret.MemTotal.toString();\r\n    ret.MemFree = ret.MemFree.toString();\r\n    return (ret);\r\n}\r\n\r\nvar cpuLastIdle = [];\r\nvar cpuLastSum = [];\r\nfunction linux_cpuUtilization() {\r\n    var ret = { cpus: [] };\r\n    var info = require(\'fs\').readFileSync(\'/proc/stat\');\r\n    var lines = info.toString().split(\'\\n\');\r\n    var columns;\r\n    var x, y;\r\n    var cpuNo = 0;\r\n    var currSum, currIdle, utilization;\r\n    for (var i in lines) {\r\n        columns = lines[i].split(\' \');\r\n        if (!columns[0].startsWith(\'cpu\')) { break; }\r\n\r\n        x = 0, currSum = 0;\r\n        while (columns[++x] == \'\');\r\n        for (y = x; y < columns.length; ++y) { currSum += parseInt(columns[y]); }\r\n        currIdle = parseInt(columns[3 + x]);\r\n\r\n        var diffIdle = currIdle - cpuLastIdle[cpuNo];\r\n        var diffSum = currSum - cpuLastSum[cpuNo];\r\n\r\n        utilization = (100 - ((diffIdle / diffSum) * 100));\r\n\r\n        cpuLastSum[cpuNo] = currSum;\r\n        cpuLastIdle[cpuNo] = currIdle;\r\n\r\n        if (!ret.total) {\r\n            ret.total = utilization;\r\n        } else {\r\n            ret.cpus.push(utilization);\r\n        }\r\n        ++cpuNo;\r\n    }\r\n\r\n    var p = new promise(function (res, rej) { this._res = res; this._rej = rej; });\r\n    p._res(ret);\r\n    return (p);\r\n}\r\nfunction linux_memUtilization()\r\n{\r\n    var ret = {};\r\n\r\n    var info = require(\'fs\').readFileSync(\'/proc/meminfo\').toString().split(\'\\n\');\r\n    var tokens;\r\n    for(var i in info)\r\n    {\r\n        tokens = info[i].split(\' \');\r\n        switch(tokens[0])\r\n        {\r\n            case \'MemTotal:\':\r\n                ret.total = parseInt(tokens[tokens.length - 2]);\r\n                break;\r\n            case \'MemAvailable:\':\r\n                ret.free = parseInt(tokens[tokens.length - 2]);\r\n                break;\r\n        }\r\n    }\r\n    ret.percentFree = ((ret.free / ret.total) * 100);//.toFixed(2);\r\n    ret.percentConsumed = (((ret.total - ret.free) / ret.total) * 100);//.toFixed(2);\r\n    return (ret);\r\n}\r\n\r\nfunction macos_cpuUtilization()\r\n{\r\n    var ret = new promise(function (res, rej) { this._res = res; this._rej = rej; });\r\n    var child = require(\'child_process\').execFile(\'/bin/sh\', [\'sh\']);\r\n    child.stdout.str = \'\';\r\n    child.stdout.on(\'data\', function (chunk) { this.str += chunk.toString(); });\r\n    child.stdin.write(\'top -l 1 | grep -E \"^CPU\"\\nexit\\n\');\r\n    child.waitExit();\r\n\r\n    var lines = child.stdout.str.split(\'\\n\');\r\n    if (lines[0].length > 0)\r\n    {\r\n        var usage = lines[0].split(\':\')[1];\r\n        var bdown = usage.split(\',\');\r\n\r\n        var tot = parseFloat(bdown[0].split(\'%\')[0].trim()) + parseFloat(bdown[1].split(\'%\')[0].trim());\r\n        ret._res({total: tot, cpus: []});\r\n    }\r\n    else\r\n    {\r\n        ret._rej(\'parse error\');\r\n    }\r\n\r\n    return (ret);\r\n}\r\nfunction macos_memUtilization()\r\n{\r\n    var mem = { };\r\n    var ret = new promise(function (res, rej) { this._res = res; this._rej = rej; });\r\n    var child = require(\'child_process\').execFile(\'/bin/sh\', [\'sh\']);\r\n    child.stdout.str = \'\';\r\n    child.stdout.on(\'data\', function (chunk) { this.str += chunk.toString(); });\r\n    child.stdin.write(\'top -l 1 | grep -E \"^Phys\"\\nexit\\n\');\r\n    child.waitExit();\r\n\r\n    var lines = child.stdout.str.split(\'\\n\');\r\n    if (lines[0].length > 0)\r\n    {\r\n        var usage = lines[0].split(\':\')[1];\r\n        var bdown = usage.split(\',\');\r\n        if (bdown.length > 2){ // new style - PhysMem: 5750M used (1130M wired, 634M compressor), 1918M unused.\r\n            mem.MemFree = parseInt(bdown[2].trim().split(\' \')[0]);\r\n        } else { // old style - PhysMem: 6683M used (1606M wired), 9699M unused.\r\n            mem.MemFree = parseInt(bdown[1].trim().split(\' \')[0]);\r\n        }\r\n        mem.MemUsed = parseInt(bdown[0].trim().split(\' \')[0]);\r\n        mem.MemTotal = (mem.MemFree + mem.MemUsed);\r\n        mem.percentFree = ((mem.MemFree / mem.MemTotal) * 100);//.toFixed(2);\r\n        mem.percentConsumed = (((mem.MemTotal - mem.MemFree) / mem.MemTotal) * 100);//.toFixed(2);\r\n        return (mem);\r\n    }\r\n    else\r\n    {\r\n        throw (\'Parse Error\');\r\n    }\r\n}\r\n\r\nfunction windows_thermals()\r\n{\r\n    var ret = [];\r\n    try {\r\n        ret = require(\'win-wmi-fixed\').query(\'ROOT\\\\WMI\', \'SELECT CurrentTemperature,InstanceName FROM MSAcpi_ThermalZoneTemperature\',[\'CurrentTemperature\',\'InstanceName\']);\r\n        if (ret[0]) {\r\n            for (var i = 0; i < ret.length; ++i) {\r\n                ret[i][\'CurrentTemperature\'] = ((parseFloat(ret[i][\'CurrentTemperature\']) / 10) - 273.15).toFixed(2);\r\n            }\r\n        }\r\n    } catch (ex) { }\r\n    return (ret);\r\n}\r\n\r\nfunction linux_thermals()\r\n{\r\n    var ret = [];\r\n    child = require(\'child_process\').execFile(\'/bin/sh\', [\'sh\']);\r\n    child.stdout.str = \'\'; child.stdout.on(\'data\', function (c) { this.str += c.toString(); });\r\n    child.stderr.str = \'\'; child.stderr.on(\'data\', function (c) { this.str += c.toString(); });\r\n    child.stdin.write(\"for folder in /sys/class/thermal/thermal_zone*/; do [ -e \\\"$folder/temp\\\" ] && echo \\\"$(cat \\\"$folder/temp\\\"),$(cat \\\"$folder/type\\\")\\\"; done\\nexit\\n\");\r\n    child.waitExit();\r\n    if(child.stdout.str.trim()!=\'\')\r\n    {\r\n        var lines = child.stdout.str.trim().split(\'\\n\');\r\n        for (var i = 0; i < lines.length; ++i)\r\n        {\r\n            var line = lines[i].trim().split(\',\');\r\n            ret.push({CurrentTemperature: (parseFloat(line[0])/1000), InstanceName: line[1]});\r\n        }\r\n    }\r\n    child = require(\'child_process\').execFile(\'/bin/sh\', [\'sh\']);\r\n    child.stdout.str = \'\'; child.stdout.on(\'data\', function (c) { this.str += c.toString(); });\r\n    child.stderr.str = \'\'; child.stderr.on(\'data\', function (c) { this.str += c.toString(); });\r\n    child.stdin.write(\"for mon in /sys/class/hwmon/hwmon*; do for label in \\\"$mon\\\"/temp*_label; do if [ -f $label ]; then echo $(cat \\\"$label\\\")___$(cat \\\"${label%_*}_input\\\"); fi; done; done;\\nexit\\n\");\r\n    child.waitExit();\r\n    if(child.stdout.str.trim()!=\'\')\r\n    {\r\n        var lines = child.stdout.str.trim().split(\'\\n\');\r\n        for (var i = 0; i < lines.length; ++i)\r\n        {\r\n            var line = lines[i].trim().split(\'___\');\r\n            ret.push({ CurrentTemperature: (parseFloat(line[1])/1000), InstanceName: line[0] });\r\n        }\r\n    }\r\n    return (ret);\r\n}\r\n\r\nfunction macos_thermals()\r\n{\r\n    var ret = [];\r\n    var child = require(\'child_process\').execFile(\'/bin/sh\', [\'sh\']);\r\n    child.stdout.str = \'\'; child.stdout.on(\'data\', function (c) { this.str += c.toString(); });\r\n    child.stderr.on(\'data\', function () { });\r\n    child.stdin.write(\'powermetrics --help | grep SMC\\nexit\\n\');\r\n    child.waitExit();\r\n    if (child.stdout.str.trim() != \'\')\r\n    {\r\n        child = require(\'child_process\').execFile(\'/bin/sh\', [\'sh\']);\r\n        child.stdout.str = \'\'; child.stdout.on(\'data\', function (c)\r\n        {\r\n            this.str += c.toString();\r\n            var tokens = this.str.trim().split(\'\\n\');\r\n            for (var i in tokens)\r\n            {\r\n                if (tokens[i].split(\' die temperature: \').length > 1)\r\n                {\r\n                    ret.push({CurrentTemperature: tokens[i].split(\' \')[3], InstanceName: tokens[i].split(\' \')[0]});\r\n                    this.parent.kill();\r\n                }\r\n            }\r\n        });\r\n        child.stderr.on(\'data\', function (c) {\r\n            if (c.toString().split(\'unable to get smc values\').length > 1) { // error getting sensors so just kill\r\n                this.parent.kill();\r\n                return;\r\n            }\r\n        });\r\n        child.stdin.write(\'powermetrics -s smc -i 500 -n 1\\n\');\r\n        child.waitExit(2000);\r\n    }\r\n    return (ret);\r\n}\r\n\r\nswitch(process.platform)\r\n{\r\n    case \'linux\':\r\n        module.exports = { cpuUtilization: linux_cpuUtilization, memUtilization: linux_memUtilization, thermals: linux_thermals };\r\n        break;\r\n    case \'win32\':\r\n        module.exports = { cpuUtilization: windows_cpuUtilization, memUtilization: windows_memUtilization, thermals: windows_thermals };\r\n        break;\r\n    case \'darwin\':\r\n        module.exports = { cpuUtilization: macos_cpuUtilization, memUtilization: macos_memUtilization, thermals: macos_thermals };\r\n        break;\r\n}\r\n\r\n"); addedModules.push("sysinfo"); } catch (ex) { }
try { addModule("util-agentlog", "/*\r\nCopyright 2021 Intel Corporation\r\n\r\nLicensed under the Apache License, Version 2.0 (the \"License\");\r\nyou may not use this file except in compliance with the License.\r\nYou may obtain a copy of the License at\r\n\r\n    http://www.apache.org/licenses/LICENSE-2.0\r\n\r\nUnless required by applicable law or agreed to in writing, software\r\ndistributed under the License is distributed on an \"AS IS\" BASIS,\r\nWITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.\r\nSee the License for the specific language governing permissions and\r\nlimitations under the License.\r\n*/\r\n\r\n\r\nfunction parseLine(entry)\r\n{\r\n    var test = entry.match(/^\\[.*M\\]/);\r\n    if (test == null)\r\n    {\r\n        test = entry.match(/\\[.+ => .+:[0-9]+\\]/);\r\n        if (test != null)\r\n        {\r\n            // Windows Crash Entry\r\n            var file = test[0].substring(1).match(/(?!.+ ).+(?=:)/);\r\n            var line = test[0].match(/(?!:)[0-9]+(?=\\]$)/);\r\n            var fn = test[0].match(/(?!\\[).+(?= =>)/);\r\n\r\n            if (file != null) { this.results.peek().f = file[0].trim(); }\r\n            if (line != null) { this.results.peek().l = line[0]; }\r\n            if (fn != null) { this.results.peek().fn = fn[0]; }\r\n        }\r\n        else\r\n        {\r\n            test = entry.match(/^[\\.\\/].+\\(\\) \\[0x[0-9a-fA-F]+\\]$/);\r\n            if (test != null)\r\n            {\r\n                // Linux Crash Stack with no symbols\r\n                test = test[0].match(/(?!\\[)0x[0-9a-fA-F]+(?=\\]$)/);\r\n                if (test != null)\r\n                {\r\n                    if (this.results.peek().sx == null) { this.results.peek().sx = []; }\r\n                    this.results.peek().sx.unshift(test[0]);\r\n                }\r\n            }\r\n            else\r\n            {\r\n                test = entry.match(/^\\[.+_[0-9a-fA-F]{16}\\]$/);\r\n                if(test!=null)\r\n                {\r\n                    // Linux Crash ID\r\n                    test = test[0].match(/(?!_)[0-9a-fA-F]{16}(?=\\]$)/);\r\n                    this.results.peek().h = test[0];\r\n                }\r\n            }\r\n\r\n            test = entry.match(/(?!^=>)\\/+.+:[0-9]+$/);\r\n            if(test!=null)\r\n            {\r\n                // Linux Crash Entry\r\n                if (this.results.peek().s == null) { this.results.peek().s = []; }\r\n                this.results.peek().s.unshift(test[0]);\r\n            }\r\n            \r\n        }\r\n        return;\r\n    }\r\n    test = test[0];\r\n\r\n    var dd = test.substring(1, test.length -1);\r\n    var c = dd.split(\' \');\r\n    var t = c[1].split(\':\');\r\n    if (c[2] == \'PM\') { t[0] = parseInt(t[0]) + 12; if (t[0] == 24) { t[0] = 0; } }\r\n\r\n    var d = Date.parse(c[0] + \'T\' + t.join(\':\'));\r\n    var msg = entry.substring(test.length).trim();\r\n    var hash = msg.match(/^\\[[0-9a-fA-F]{16}\\]/);\r\n    if (hash != null)\r\n    {\r\n        hash = hash[0].substring(1, hash[0].length - 1);\r\n        msg = msg.substring(hash.length + 2).trim();\r\n    }\r\n    else\r\n    {\r\n        hash = msg.match(/^\\[\\]/);\r\n        if(hash!=null)\r\n        {\r\n            msg = msg.substring(2).trim();\r\n            hash = null;\r\n        }\r\n    }\r\n\r\n    var log = { t: Math.floor(d / 1000), m: msg };\r\n    if (hash != null) { log.h = hash; }\r\n\r\n    // Check for File/Line in generic log entry\r\n    test = msg.match(/^.+:[0-9]+ \\([0-9]+,[0-9]+\\)/);\r\n    if (test != null)\r\n    {\r\n        log.m = log.m.substring(test[0].length).trim();\r\n        log.f = test[0].match(/^.+(?=:[0-9]+)/)[0];\r\n        log.l = test[0].match(/(?!:)[0-9]+(?= \\([0-9]+,[0-9]+\\)$)/)[0];\r\n    }\r\n\r\n    this.results.push(log);\r\n}\r\n\r\nfunction readLog_data(buffer)\r\n{\r\n    var lines = buffer.toString();\r\n    if (this.buffered != null) { lines = this.buffered + lines; }\r\n    lines = lines.split(\'\\n\');\r\n    var i;\r\n\r\n    for (i = 0; i < (lines.length - 1) ; ++i)\r\n    {\r\n        parseLine.call(this, lines[i]);\r\n    }\r\n\r\n    if (lines.length == 1)\r\n    {\r\n        parseLine.call(this, lines[0]);\r\n        this.buffered = null;\r\n    }\r\n    else\r\n    {\r\n        this.buffered = lines[lines.length - 1];\r\n    }\r\n}\r\n\r\nfunction readLogEx(path)\r\n{\r\n    var ret = [];\r\n    try\r\n    {\r\n        var s = require(\'fs\').createReadStream(path);\r\n        s.buffered = null;\r\n        s.results = ret;\r\n        s.on(\'data\', readLog_data);\r\n        s.resume();\r\n        if (s.buffered != null) { readLog_data.call(s, s.buffered); s.buffered = null; }\r\n        s.removeAllListeners(\'data\');\r\n        s = null;\r\n    }\r\n    catch(z)\r\n    {\r\n    }\r\n\r\n    return (ret);\r\n}\r\n\r\nfunction readLog(criteria, path)\r\n{\r\n    var objects = readLogEx(path == null ? (process.execPath.split(\'.exe\').join(\'\') + \'.log\') : path);\r\n    var ret = [];\r\n\r\n    if (typeof (criteria) == \'string\')\r\n    {\r\n        try\r\n        {\r\n            var dstring = Date.parse(criteria);\r\n            criteria = Math.floor(dstring / 1000);\r\n        }\r\n        catch(z)\r\n        {\r\n        }\r\n    }\r\n\r\n    if (typeof (criteria) == \'number\')\r\n    {\r\n        if(criteria < 1000)\r\n        {\r\n            // Return the last xxx entries\r\n            ret = objects.slice(objects.length - ((criteria > objects.length) ? objects.length : criteria));\r\n        }\r\n        else\r\n        {\r\n            // Return entries that are newer than xxx\r\n            var i;\r\n            for (i = 0; i < objects.length && objects[i].t <= criteria; ++i) { }\r\n            ret = objects.slice(i);\r\n        }\r\n    }\r\n    else\r\n    {\r\n        ret = objects;\r\n    }\r\n\r\n    return (ret);\r\n}\r\n\r\nmodule.exports = { read: readLog, readEx: readLogEx }\r\n\r\n"); addedModules.push("util-agentlog"); } catch (ex) { }
try { addModule("wifi-scanner-windows", "/*\r\nCopyright 2018-2021 Intel Corporation\r\n\r\nLicensed under the Apache License, Version 2.0 (the \"License\");\r\nyou may not use this file except in compliance with the License.\r\nYou may obtain a copy of the License at\r\n\r\n    http://www.apache.org/licenses/LICENSE-2.0\r\n\r\nUnless required by applicable law or agreed to in writing, software\r\ndistributed under the License is distributed on an \"AS IS\" BASIS,\r\nWITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.\r\nSee the License for the specific language governing permissions and\r\nlimitations under the License.\r\n*/\r\n\r\nfunction _Scan()\r\n{\r\n    var wlanInterfaces = this.Marshal.CreatePointer();\r\n    this.Native.WlanEnumInterfaces(this.Handle, 0, wlanInterfaces);\r\n\r\n    var count = wlanInterfaces.Deref().Deref(0, 4).toBuffer().readUInt32LE(0);\r\n\r\n    var info = wlanInterfaces.Deref().Deref(8, 532);\r\n    var iname = info.Deref(16, 512).AnsiString;\r\n\r\n    var istate;\r\n    switch (info.Deref(528, 4).toBuffer().readUInt32LE(0))\r\n    {\r\n        case 0:\r\n            istate = \"NOT READY\";\r\n            break;\r\n        case 1:\r\n            istate = \"CONNECTED\";\r\n            break;\r\n        case 2:\r\n            istate = \"AD-HOC\";\r\n            break;\r\n        case 3:\r\n            istate = \"DISCONNECTING\";\r\n            break;\r\n        case 4:\r\n            istate = \"DISCONNECTED\";\r\n            break;\r\n        case 5:\r\n            istate = \"ASSOCIATING\";\r\n            break;\r\n        case 6:\r\n            istate = \"DISCOVERING\";\r\n            break;\r\n        case 7:\r\n            istate = \"AUTHENTICATING\";\r\n            break;\r\n        default:\r\n            istate = \"UNKNOWN\";\r\n            break;\r\n    }\r\n\r\n    var iguid = info.Deref(0, 16);\r\n    if (this.Native.WlanScan(this.Handle, iguid, 0, 0, 0).Val == 0)\r\n    {\r\n        return (true);\r\n    }\r\n    else\r\n    {\r\n        return (false);\r\n    }\r\n}\r\n\r\nfunction AccessPoint(_ssid, _bssid, _rssi, _lq)\r\n{\r\n    this.ssid = _ssid;\r\n    this.bssid = _bssid;\r\n    this.rssi = _rssi;\r\n    this.lq = _lq;\r\n}\r\nAccessPoint.prototype.toString = function()\r\n{\r\n    return (this.ssid + \" [\" + this.bssid + \"]: \" + this.lq);\r\n}\r\n\r\nfunction OnNotify(NotificationData)\r\n{\r\n    var NotificationSource = NotificationData.Deref(0, 4).toBuffer().readUInt32LE(0);\r\n    var NotificationCode = NotificationData.Deref(4, 4).toBuffer().readUInt32LE(0);\r\n    var dataGuid = NotificationData.Deref(8, 16);\r\n\r\n    if ((NotificationSource & 0X00000008) && (NotificationCode == 7))\r\n    {\r\n        var bss = this.Parent.Marshal.CreatePointer();\r\n        var result = this.Parent.Native.GetBSSList(this.Parent.Handle, dataGuid, 0, 3, 0, 0, bss).Val;\r\n        if (result == 0)\r\n        {\r\n            var totalSize = bss.Deref().Deref(0, 4).toBuffer().readUInt32LE(0);\r\n            var numItems = bss.Deref().Deref(4, 4).toBuffer().readUInt32LE(0);\r\n            for (i = 0; i < numItems; ++i)\r\n            {\r\n                var item = bss.Deref().Deref(8 + (360 * i), 360);\r\n                var ssid = item.Deref(4, 32).String.trim();\r\n                var bssid = item.Deref(40, 6).HexString2;\r\n                var rssi = item.Deref(56, 4).toBuffer().readUInt32LE(0);\r\n                var lq = item.Deref(60, 4).toBuffer().readUInt32LE(0);\r\n\r\n                this.Parent.emit(\'Scan\', new AccessPoint(ssid, bssid, rssi, lq));\r\n            }\r\n        }\r\n\r\n    }\r\n}\r\n\r\nfunction Wireless()\r\n{\r\n    var emitterUtils = require(\'events\').inherits(this);\r\n\r\n    this.Marshal = require(\'_GenericMarshal\');\r\n    this.Native = this.Marshal.CreateNativeProxy(\"wlanapi.dll\");\r\n    this.Native.CreateMethod(\"WlanOpenHandle\");\r\n    this.Native.CreateMethod(\"WlanGetNetworkBssList\", \"GetBSSList\");\r\n    this.Native.CreateMethod(\"WlanRegisterNotification\");\r\n    this.Native.CreateMethod(\"WlanEnumInterfaces\");\r\n    this.Native.CreateMethod(\"WlanScan\");\r\n    this.Native.CreateMethod(\"WlanQueryInterface\");\r\n\r\n    var negotiated = this.Marshal.CreatePointer();\r\n    var h = this.Marshal.CreatePointer();\r\n\r\n    this.Native.WlanOpenHandle(2, 0, negotiated, h);\r\n    this.Handle = h.Deref();\r\n\r\n    this._NOTIFY_PROXY_OBJECT = this.Marshal.CreateCallbackProxy(OnNotify, 2);\r\n    this._NOTIFY_PROXY_OBJECT.Parent = this;\r\n    var PrevSource = this.Marshal.CreatePointer();\r\n    var result = this.Native.WlanRegisterNotification(this.Handle, 0X0000FFFF, 0, this._NOTIFY_PROXY_OBJECT.Callback, this._NOTIFY_PROXY_OBJECT.State, 0, PrevSource);\r\n\r\n    emitterUtils.createEvent(\'Scan\');\r\n    emitterUtils.addMethod(\'Scan\', _Scan);\r\n\r\n    this.GetConnectedNetwork = function ()\r\n    {\r\n        var interfaces = this.Marshal.CreatePointer();\r\n\r\n        console.log(\'Success = \' + this.Native.WlanEnumInterfaces(this.Handle, 0, interfaces).Val);\r\n        var count = interfaces.Deref().Deref(0, 4).toBuffer().readUInt32LE(0);\r\n        var info = interfaces.Deref().Deref(8, 532);\r\n        var iname = info.Deref(16, 512).AnsiString;\r\n        var istate = info.Deref(528, 4).toBuffer().readUInt32LE(0);\r\n        if(info.Deref(528, 4).toBuffer().readUInt32LE(0) == 1) // CONNECTED\r\n        {\r\n            var dataSize = this.Marshal.CreatePointer();\r\n            var pData = this.Marshal.CreatePointer();\r\n            var valueType = this.Marshal.CreatePointer();\r\n            var iguid = info.Deref(0, 16);\r\n            var retVal = this.Native.WlanQueryInterface(this.Handle, iguid, 7, 0, dataSize, pData, valueType).Val;\r\n            if (retVal == 0)\r\n            {\r\n                var associatedSSID = pData.Deref().Deref(524, 32).String;\r\n                var bssid = pData.Deref().Deref(560, 6).HexString;\r\n                var lq = pData.Deref().Deref(576, 4).toBuffer().readUInt32LE(0);\r\n\r\n                return (new AccessPoint(associatedSSID, bssid, 0, lq));\r\n            }\r\n        }\r\n        throw (\"GetConnectedNetworks: FAILED (not associated to a network)\");\r\n    };\r\n\r\n\r\n    return (this);\r\n}\r\n\r\nmodule.exports = new Wireless();\r\n"); addedModules.push("wifi-scanner-windows"); } catch (ex) { }
try { addModule("wifi-scanner", "/*\r\nCopyright 2018-2021 Intel Corporation\r\n\r\nLicensed under the Apache License, Version 2.0 (the \"License\");\r\nyou may not use this file except in compliance with the License.\r\nYou may obtain a copy of the License at\r\n\r\n    http://www.apache.org/licenses/LICENSE-2.0\r\n\r\nUnless required by applicable law or agreed to in writing, software\r\ndistributed under the License is distributed on an \"AS IS\" BASIS,\r\nWITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.\r\nSee the License for the specific language governing permissions and\r\nlimitations under the License.\r\n*/\r\n\r\nvar MemoryStream = require(\'MemoryStream\');\r\nvar WindowsChildScript = \'var parent = require(\"ScriptContainer\");var Wireless = require(\"wifi-scanner-windows\");Wireless.on(\"Scan\", function (ap) { parent.send(ap); });Wireless.Scan();\';\r\n\r\n\r\nfunction AccessPoint(_ssid, _bssid, _lq)\r\n{\r\n    this.ssid = _ssid;\r\n    this.bssid = _bssid;\r\n    this.lq = _lq;\r\n}\r\nAccessPoint.prototype.toString = function ()\r\n{\r\n    return (\"[\" + this.bssid + \"]: \" + this.ssid + \" (\" + this.lq + \")\");\r\n    //return (this.ssid + \" [\" + this.bssid + \"]: \" + this.lq);\r\n}\r\n\r\nfunction WiFiScanner()\r\n{\r\n    var emitterUtils = require(\'events\').inherits(this);\r\n    emitterUtils.createEvent(\'accessPoint\');\r\n\r\n    this.hasWireless = function ()\r\n    {\r\n        var retVal = false;\r\n        var interfaces = require(\'os\').networkInterfaces();\r\n        for (var name in interfaces)\r\n        {\r\n            if (interfaces[name][0].type == \'wireless\') { retVal = true; break; }\r\n        }\r\n        return (retVal);\r\n    };\r\n\r\n    this.Scan = function ()\r\n    {\r\n        if (process.platform == \'win32\')\r\n        {\r\n            this.main = require(\'ScriptContainer\').Create(15, ContainerPermissions.DEFAULT);\r\n            this.main.parent = this;\r\n            this.main.on(\'data\', function (j) { this.parent.emit(\'accessPoint\', new AccessPoint(j.ssid, j.bssid, j.lq)); });\r\n\r\n            this.main.addModule(\'wifi-scanner-windows\', getJSModule(\'wifi-scanner-windows\'));\r\n            this.main.ExecuteString(WindowsChildScript);\r\n        }\r\n        else if (process.platform == \'linux\')\r\n        {\r\n            // Need to get the wireless interface name\r\n            var interfaces = require(\'os\').networkInterfaces();\r\n            var wlan = null;\r\n            for (var i in interfaces)\r\n            {\r\n                if (interfaces[i][0].type == \'wireless\')\r\n                {\r\n                    wlan = i;\r\n                    break;\r\n                }\r\n            }\r\n            if (wlan != null)\r\n            {\r\n                this.child = require(\'child_process\').execFile(\'/sbin/iwlist\', [\'iwlist\', wlan, \'scan\']);\r\n                this.child.parent = this;\r\n                this.child.ms = new MemoryStream();\r\n                this.child.ms.parent = this.child;\r\n                this.child.stdout.on(\'data\', function (buffer) { this.parent.ms.write(buffer); });\r\n                this.child.on(\'exit\', function () { this.ms.end(); });\r\n                this.child.ms.on(\'end\', function ()\r\n                {\r\n                    var str = this.buffer.toString();\r\n                    tokens = str.split(\' - Address: \');\r\n                    for (var block in tokens)\r\n                    {\r\n                        if (block == 0) continue;\r\n                        var ln = tokens[block].split(\'\\n\');\r\n                        var _bssid = ln[0];\r\n                        var _lq;\r\n                        var _ssid;\r\n\r\n                        for (var lnblock in ln)\r\n                        {\r\n                            lnblock = ln[lnblock].trim();\r\n                            lnblock = lnblock.trim();\r\n                            if (lnblock.startsWith(\'ESSID:\'))\r\n                            {\r\n                                _ssid = lnblock.slice(7, lnblock.length - 1);\r\n                                if (_ssid == \'<hidden>\') { _ssid = \'\'; }\r\n                            }\r\n                            if (lnblock.startsWith(\'Signal level=\'))\r\n                            {\r\n                                _lq = lnblock.slice(13,lnblock.length-4);\r\n                            }\r\n                            else if (lnblock.startsWith(\'Quality=\'))\r\n                            {\r\n                                _lq = lnblock.slice(8, 10);\r\n                                var scale = lnblock.slice(11, 13);\r\n                            }\r\n                        }\r\n                        this.parent.parent.emit(\'accessPoint\', new AccessPoint(_ssid, _bssid, _lq));\r\n                    }\r\n                });\r\n            }\r\n        }\r\n    }\r\n}\r\n\r\nmodule.exports = WiFiScanner;\r\n\r\n\r\n\r\n\r\n\r\n\r\n\r\n"); addedModules.push("wifi-scanner"); } catch (ex) { }
/*
Copyright 2018-2022 Intel Corporation

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

process.on('uncaughtException', function (ex) {
    require('MeshAgent').SendCommand({ action: 'msg', type: 'console', value: "uncaughtException1: " + ex });
});
if (process.platform == 'win32' && require('user-sessions').getDomain == null) {
    require('user-sessions').getDomain = function getDomain(uid) {
        return (this.getSessionAttribute(uid, this.InfoClass.WTSDomainName));
    };
}

var promise = require('promise');

// Mesh Rights
var MNG_ERROR = 65;
var MESHRIGHT_EDITMESH = 1;
var MESHRIGHT_MANAGEUSERS = 2;
var MESHRIGHT_MANAGECOMPUTERS = 4;
var MESHRIGHT_REMOTECONTROL = 8;
var MESHRIGHT_AGENTCONSOLE = 16;
var MESHRIGHT_SERVERFILES = 32;
var MESHRIGHT_WAKEDEVICE = 64;
var MESHRIGHT_SETNOTES = 128;
var MESHRIGHT_REMOTEVIEW = 256; // Remote View Only
var MESHRIGHT_NOTERMINAL = 512;
var MESHRIGHT_NOFILES = 1024;
var MESHRIGHT_NOAMT = 2048;
var MESHRIGHT_LIMITEDINPUT = 4096;
var MESHRIGHT_LIMITEVENTS = 8192;
var MESHRIGHT_CHATNOTIFY = 16384;
var MESHRIGHT_UNINSTALL = 32768;
var MESHRIGHT_NODESKTOP = 65536;
var MESHRIGHT_ADMIN = 0xFFFFFFFF;

var pendingSetClip = false; // This is a temporary hack to prevent multiple setclips at the same time to stop the agent from crashing.

//
// This is a helper function used by the 32 bit Windows Agent, when running on 64 bit windows. It will check if the agent is already patched for this
// and will use this helper if it is not. This helper will inject 'sysnative' into the results when calling readdirSync() on %windir%.
//
function __readdirSync_fix(path)
{
    var sysnative = false;
    pathstr = require('fs')._fixwinpath(path);
    if (pathstr.split('\\*').join('').toLowerCase() == process.env['windir'].toLowerCase()) { sysnative = true; }

    var ret = require('fs').__readdirSync_old(path);
    if (sysnative) { ret.push('sysnative'); }
    return (ret);
}

if (process.platform == 'win32' && require('_GenericMarshal').PointerSize == 4 && require('os').arch() == 'x64')
{
    if (require('fs').readdirSync.version == null)
    {
        //
        // 32 Bit Windows Agent on 64 bit Windows has not been patched for sysnative issue, so lets use our own solution
        //
        require('fs').__readdirSync_old = require('fs').readdirSync;
        require('fs').readdirSync = __readdirSync_fix;
    }
}

function bcdOK() {
    if (process.platform != 'win32') { return (false); }
    if (require('os').arch() == 'x64') {
        return (require('_GenericMarshal').PointerSize == 8);
    }
    return (true);
}
function getDomainInfo() {
    var hostname = require('os').hostname();
    var ret = { Name: hostname, Domain: "", PartOfDomain: false };

    switch (process.platform) {
        case 'win32':
            try {
                ret = require('win-wmi-fixed').query('ROOT\\CIMV2', 'SELECT * FROM Win32_ComputerSystem', ['Name', 'Domain', 'PartOfDomain'])[0];
            }
            catch (x) {
            }
            break;
        case 'linux':
            var hasrealm = false;

            try {
                hasrealm = require('lib-finder').hasBinary('realm');
            }
            catch (x) {
            }
            if (hasrealm) {
                var child = require('child_process').execFile('/bin/sh', ['sh']);
                child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
                child.stdin.write("realm list | grep domain-name: | tr '\\n' '`' | ");
                child.stdin.write("awk -F'`' '{ ");
                child.stdin.write('        printf("[");');
                child.stdin.write('        ST="";');
                child.stdin.write('        for(i=1;i<NF;++i)');
                child.stdin.write('        {');
                child.stdin.write('            match($i,/domain-name: /);');
                child.stdin.write('            printf("%s\\"%s\\"", ST, substr($i, RSTART+RLENGTH));');
                child.stdin.write('            ST=",";');
                child.stdin.write('        }');
                child.stdin.write('        printf("]");');
                child.stdin.write("     }'");
                child.stdin.write('\nexit\n');
                child.waitExit();
                var names = [];
                try {
                    names = JSON.parse(child.stdout.str);
                }
                catch (e) {
                }
                while (names.length > 0) {
                    if (hostname.endsWith('.' + names.peek())) {
                        ret = { Name: hostname.substring(0, hostname.length - names.peek().length - 1), Domain: names.peek(), PartOfDomain: true };
                        break;
                    }
                    names.pop();
                }
            }
            break;
    }
    return (ret);
}

function getLoggedOnUserBySessionId(sessionId) {
    try {
        const result = require('win-registry').QueryKey(require('win-registry').HKEY.LocalMachine,
            ("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\LogonUI\\SessionData\\" + sessionId), 'LoggedOnUser'
        );

        if (result) {
            return result.replace(/^[^\\]+\\/, '');
        }

        return null;

    } catch (err) {
        return null;
    }
}

function getLogonCacheKeys() {
    var registry = require('win-registry');
    var HKLM = registry.HKEY.LocalMachine;

    var userObj = [];

    function readSubKeys(path) {
        var vals = registry.QueryKey(HKLM, path);
        if (!vals) return;

        // Extract IdentityName, SAMName, SID if they exist
        var identityName = null, samName = null, sid = null;

        for (var i = 0; i in vals.values; i++) {
            if (vals.values[i].toLowerCase() === 'identityname' && identityName === null) {
                identityName = registry.QueryKey(HKLM, path, vals.values[i]);
            }
            if (vals.values[i].toLowerCase() === 'samname' && samName === null) {
                samName = registry.QueryKey(HKLM, path, vals.values[i]); 
            }
            if (vals.values[i].toLowerCase() === 'sid' && sid === null) {
                sid = registry.QueryKey(HKLM, path, vals.values[i]);
            }
        }

        // If IdentityName exists, add to userObj
        if (identityName) {
            userObj.push({
                UPN: identityName,
                SAM: samName,
                SID: sid
            });
        }

        // Recurse into subkeys if any
        if (vals.subkeys && vals.subkeys.length > 0) {
            for (var j = 0; j < vals.subkeys.length; j++) {
                readSubKeys(path + '\\' + vals.subkeys[j]);
            }
        }
    }

    // Start recursion from the LogonCache root
    readSubKeys('SOFTWARE\\Microsoft\\IdentityStore\\LogonCache');

    var grouped = {};

    function pushUnique(arr, val) {
        if (val && arr.indexOf(val) === -1) arr.push(val);
    }

    // Group by UPN and merge values
    for (var i = 0; i < userObj.length; i++) {
        var u = userObj[i];

        if (!grouped[u.UPN]) grouped[u.UPN] = {UPN: u.UPN, SID: [], SAM: []};

        pushUnique(grouped[u.UPN].SID, u.SID);
        pushUnique(grouped[u.UPN].SAM, u.SAM);
    }

    userObj = [];
    // Convert grouped object to array
    for (var k in grouped) if (grouped.hasOwnProperty(k)) userObj.push(grouped[k]);

    return userObj;

}

function getJoinState() {
    if (process.platform != 'win32') { return -1; }
    var isAzureAD = false;
    var isOnPrem = false;
    var isHybrid = false;
    var isMicrosoft = false;
    // 1 Azure AD / Entra ID
    try {
        const joinInfo = require('win-registry').QueryKey(require('win-registry').HKEY.LocalMachine, 'SYSTEM\\CurrentControlSet\\Control\\CloudDomainJoin\\JoinInfo');
        isAzureAD = Array.isArray(joinInfo.subkeys) && joinInfo.subkeys.length > 0;
    } catch (e) {}
    // 2 On-prem AD
    try {
        const tcpip = require('win-registry').QueryKey(require('win-registry').HKEY.LocalMachine, 'SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters','Domain');
        isOnPrem = !!(tcpip !== "" || null);
    } catch (e) {}
    // 3 Hybrid AD
    isHybrid = isAzureAD && isOnPrem;
    // 4 Microsoft Account
    try {
        const userAccounts = require('win-registry').QueryKey(require('win-registry').HKEY.LocalMachine, 'SOFTWARE\\Microsoft\\IdentityStore\\LogonCache\\D7F9888F-E3FC-49b0-9EA6-A85B5F392A4F');
        isMicrosoft = Array.isArray(userAccounts.subkeys) && userAccounts.subkeys.length > 0;
    } catch (e) {}
    if (isMicrosoft) return 4;
    if (isHybrid) return 3;
    if (isOnPrem) return 2;
    if (isAzureAD) return 1;
    return 0;

}


try {
    Object.defineProperty(Array.prototype, 'findIndex', {
        value: function (func) {
            var i = 0;
            for (i = 0; i < this.length; ++i) {
                if (func(this[i], i, this)) {
                    return (i);
                }
            }
            return (-1);
        }
    });
} catch (ex) { }

if (require('MeshAgent').ARCHID == null) {
    var id = null;
    switch (process.platform) {
        case 'win32':
            id = require('_GenericMarshal').PointerSize == 4 ? 3 : 4;
            break;
        case 'freebsd':
            id = require('_GenericMarshal').PointerSize == 4 ? 31 : 30;
            break;
        case 'darwin':
            try {
                id = require('os').arch() == 'x64' ? 16 : 29;
            } catch (ex) { id = 16; }
            break;
    }
    if (id != null) { Object.defineProperty(require('MeshAgent'), 'ARCHID', { value: id }); }
}

function setDefaultCoreTranslation(obj, field, value) {
    if (obj[field] == null || obj[field] == '') { obj[field] = value; }
}

function getCoreTranslation() {
    var ret = {};
    if (global.coretranslations != null) {
        try {
            var lang = require('util-language').current;
            if (coretranslations[lang] == null) { lang = lang.split('-')[0]; }
            if (coretranslations[lang] == null) { lang = 'en'; }
            if (coretranslations[lang] != null) { ret = coretranslations[lang]; }
        }
        catch (ex) { }
    }

    setDefaultCoreTranslation(ret, 'allow', 'Allow');
    setDefaultCoreTranslation(ret, 'deny', 'Deny');
    setDefaultCoreTranslation(ret, 'autoAllowForFive', 'Auto accept all connections for next 5 minutes');
    setDefaultCoreTranslation(ret, 'terminalConsent', '{0} requesting remote terminal access. Grant access?');
    setDefaultCoreTranslation(ret, 'desktopConsent', '{0} requesting remote desktop access. Grant access?');
    setDefaultCoreTranslation(ret, 'fileConsent', '{0} requesting remote file Access. Grant access?');
    setDefaultCoreTranslation(ret, 'registryConsent', '{0} requesting remote registry access. Grant access?');
    setDefaultCoreTranslation(ret, 'terminalNotify', '{0} started a remote terminal session.');
    setDefaultCoreTranslation(ret, 'desktopNotify', '{0} started a remote desktop session.');
    setDefaultCoreTranslation(ret, 'fileNotify', '{0} started a remote file session.');
    setDefaultCoreTranslation(ret, 'registryNotify', '{0} started a remote registry session.');
    setDefaultCoreTranslation(ret, 'privacyBar', 'Sharing desktop with: {0}');

    return (ret);
}
var currentTranslation = getCoreTranslation();

try {
    require('kvm-helper');
}
catch (e) {
    var j =
        {
            users: function () {
                var r = {};
                require('user-sessions').Current(function (c) { r = c; });
                if (process.platform != 'win32') {
                    for (var i in r) {
                        r[i].SessionId = r[i].uid;
                    }
                }
                return (r);
            }
        };
    addModuleObject('kvm-helper', j);
}


function lockDesktop(uid) {
    switch (process.platform) {
        case 'linux':
            if (uid != null) {
                var name = require('user-sessions').getUsername(uid);
                var child = require('child_process').execFile('/bin/sh', ['sh']);
                child.stdout.str = ''; child.stdout.on('data', function (chunk) { this.str += chunk.toString(); });
                child.stderr.str = ''; child.stderr.on('data', function (chunk) { this.str += chunk.toString(); });
                child.stdin.write('loginctl show-user -p Sessions ' + name + " | awk '{");
                child.stdin.write('gsub(/^Sessions=/,"",$0);');
                child.stdin.write('cmd = sprintf("loginctl lock-session %s",$0);');
                child.stdin.write('system(cmd);');
                child.stdin.write("}'\nexit\n");
                child.waitExit();
            }
            else {
                var child = require('child_process').execFile('/bin/sh', ['sh']);
                child.stdout.str = ''; child.stdout.on('data', function (chunk) { this.str += chunk.toString(); });
                child.stderr.str = ''; child.stderr.on('data', function (chunk) { this.str += chunk.toString(); });
                child.stdin.write('loginctl lock-sessions\nexit\n');
                child.waitExit();
            }
            break;
        case 'win32':
            {
                var options = { type: 1, uid: uid };
                var child = require('child_process').execFile(process.env['windir'] + '\\system32\\cmd.exe', ['/c', 'RunDll32.exe user32.dll,LockWorkStation'], options);
                child.waitExit();
            }
            break;
        default:
            break;
    }
}
var writable = require('stream').Writable;
function destopLockHelper_pipe(httprequest) {
    if (process.platform != 'linux' && process.platform != 'freebsd') { return; }

    if (httprequest.unlockerHelper == null && httprequest.desktop != null && httprequest.desktop.kvm != null) {
        httprequest.unlockerHelper = new writable(
            {
                'write': function (chunk, flush) {
                    if (chunk.readUInt16BE(0) == 65) {
                        delete this.request.autolock;
                    }
                    flush();
                    return (true);
                },
                'final': function (flush) {
                    flush();
                }
            });
        httprequest.unlockerHelper.request = httprequest;
        httprequest.desktop.kvm.pipe(httprequest.unlockerHelper);
    }
}

var obj = { serverInfo: {} };
var agentFileHttpRequests = {}; // Currently active agent HTTPS GET requests from the server.
var agentFileHttpPendingRequests = []; // Pending HTTPS GET requests from the server.
var debugConsole = (global._MSH && (_MSH().debugConsole == 1));

var color_options =
    {
        background: (global._MSH != null) ? global._MSH().background : '0,54,105',
        foreground: (global._MSH != null) ? global._MSH().foreground : '255,255,255'
    };

if (process.platform == 'win32' && require('user-sessions').isRoot()) {
    // Check the Agent Uninstall MetaData for correctness, as the installer may have written an incorrect value
    try {
        var writtenSize = 0, actualSize = Math.floor(require('fs').statSync(process.execPath).size / 1024);
        var serviceName =  (_MSH().serviceName ?  _MSH().serviceName : (require('_agentNodeId').serviceName() ? require('_agentNodeId').serviceName() : 'Mesh Agent'));
        try { writtenSize = require('win-registry').QueryKey(require('win-registry').HKEY.LocalMachine, 'Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\' + serviceName, 'EstimatedSize'); } catch (ex) { }
        if (writtenSize != actualSize) { try { require('win-registry').WriteKey(require('win-registry').HKEY.LocalMachine, 'Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\' + serviceName, 'EstimatedSize', actualSize); } catch (ex) { } }
    } catch (ex) { }

    // Check to see if we are the Installed Mesh Agent Service, if we are, make sure we can run in Safe Mode
    var svcname = process.platform == 'win32' ? 'Mesh Agent' : 'meshagent';
    try {
        svcname = require('MeshAgent').serviceName;
    } catch (ex) { }

    try {
        var meshCheck = false;
        try { meshCheck = require('service-manager').manager.getService(svcname).isMe(); } catch (ex) { }
        if (meshCheck && require('win-bcd').isSafeModeService && !require('win-bcd').isSafeModeService(svcname)) { require('win-bcd').enableSafeModeService(svcname); }
    } catch (ex) { }

    // Check the Agent Uninstall MetaData for DisplayVersion and update if not the same and only on windows
    if (process.platform == 'win32') {
        try {
            var writtenDisplayVersion = 0, actualDisplayVersion = process.versions.commitDate.toString();
            var serviceName =  (_MSH().serviceName ?  _MSH().serviceName : (require('_agentNodeId').serviceName() ? require('_agentNodeId').serviceName() : 'Mesh Agent'));
            try { writtenDisplayVersion = require('win-registry').QueryKey(require('win-registry').HKEY.LocalMachine, 'Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\' + serviceName, 'DisplayVersion'); } catch (ex) { }
            if (writtenDisplayVersion != actualDisplayVersion) { try { require('win-registry').WriteKey(require('win-registry').HKEY.LocalMachine, 'Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\' + serviceName, 'DisplayVersion', actualDisplayVersion); } catch (ex) { } }
        } catch (ex) { }
    }
}

if (process.platform != 'win32') {
    var ch = require('child_process');
    ch._execFile = ch.execFile;
    ch.execFile = function execFile(path, args, options) {
        if (options && options.type && options.type == ch.SpawnTypes.TERM && options.env) {
            options.env['TERM'] = 'xterm-256color';
        }
        return (this._execFile(path, args, options));
    };
}


if (process.platform == 'darwin' && !process.versions) {
    // This is an older MacOS Agent, so we'll need to check the service definition so that Auto-Update will function correctly
    var child = require('child_process').execFile('/bin/sh', ['sh']);
    child.stdout.str = '';
    child.stdout.on('data', function (chunk) { this.str += chunk.toString(); });
    child.stdin.write("cat /Library/LaunchDaemons/meshagent_osx64_LaunchDaemon.plist | tr '\n' '\.' | awk '{split($0, a, \"<key>KeepAlive</key>\"); split(a[2], b, \"<\"); split(b[2], c, \">\"); ");
    child.stdin.write(" if(c[1]==\"dict\"){ split(a[2], d, \"</dict>\"); if(split(d[1], truval, \"<true/>\")>1) { split(truval[1], kn1, \"<key>\"); split(kn1[2], kn2, \"</key>\"); print kn2[1]; } }");
    child.stdin.write(" else { split(c[1], ka, \"/\"); if(ka[1]==\"true\") {print \"ALWAYS\";} } }'\nexit\n");
    child.waitExit();
    if (child.stdout.str.trim() == 'Crashed') {
        child = require('child_process').execFile('/bin/sh', ['sh']);
        child.stdout.str = '';
        child.stdout.on('data', function (chunk) { this.str += chunk.toString(); });
        child.stdin.write("launchctl list | grep 'meshagent' | awk '{ if($3==\"meshagent\"){print $1;}}'\nexit\n");
        child.waitExit();

        if (parseInt(child.stdout.str.trim()) == process.pid) {
            // The currently running MeshAgent is us, so we can continue with the update
            var plist = require('fs').readFileSync('/Library/LaunchDaemons/meshagent_osx64_LaunchDaemon.plist').toString();
            var tokens = plist.split('<key>KeepAlive</key>');
            if (tokens[1].split('>')[0].split('<')[1] == 'dict') {
                var tmp = tokens[1].split('</dict>');
                tmp.shift();
                tokens[1] = '\n    <true/>' + tmp.join('</dict>');
                tokens = tokens.join('<key>KeepAlive</key>');

                require('fs').writeFileSync('/Library/LaunchDaemons/meshagent_osx64_LaunchDaemon.plist', tokens);

                var fix = '';
                fix += ("function macosRepair()\n");
                fix += ("{\n");
                fix += ("    var child = require('child_process').execFile('/bin/sh', ['sh']);\n");
                fix += ("    child.stdout.str = '';\n");
                fix += ("    child.stdout.on('data', function (chunk) { this.str += chunk.toString(); });\n");
                fix += ("    child.stderr.on('data', function (chunk) { });\n");
                fix += ("    child.stdin.write('launchctl unload /Library/LaunchDaemons/meshagent_osx64_LaunchDaemon.plist\\n');\n");
                fix += ("    child.stdin.write('launchctl load /Library/LaunchDaemons/meshagent_osx64_LaunchDaemon.plist\\n');\n");
                fix += ("    child.stdin.write('rm /Library/LaunchDaemons/meshagentRepair.plist\\n');\n");
                fix += ("    child.stdin.write('rm " + process.cwd() + "/macosRepair.js\\n');\n");
                fix += ("    child.stdin.write('launchctl stop meshagentRepair\\nexit\\n');\n");
                fix += ("    child.waitExit();\n");
                fix += ("}\n");
                fix += ("macosRepair();\n");
                fix += ("process.exit();\n");
                require('fs').writeFileSync(process.cwd() + '/macosRepair.js', fix);

                var plist = '<?xml version="1.0" encoding="UTF-8"?>\n';
                plist += '<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n';
                plist += '<plist version="1.0">\n';
                plist += '  <dict>\n';
                plist += '      <key>Label</key>\n';
                plist += ('     <string>meshagentRepair</string>\n');
                plist += '      <key>ProgramArguments</key>\n';
                plist += '      <array>\n';
                plist += ('        <string>' + process.execPath + '</string>\n');
                plist += '        <string>macosRepair.js</string>\n';
                plist += '      </array>\n';
                plist += '      <key>WorkingDirectory</key>\n';
                plist += ('     <string>' + process.cwd() + '</string>\n');
                plist += '      <key>RunAtLoad</key>\n';
                plist += '      <true/>\n';
                plist += '  </dict>\n';
                plist += '</plist>';
                require('fs').writeFileSync('/Library/LaunchDaemons/meshagentRepair.plist', plist);

                child = require('child_process').execFile('/bin/sh', ['sh']);
                child.stdout.str = '';
                child.stdout.on('data', function (chunk) { this.str += chunk.toString(); });
                child.stdin.write("launchctl load /Library/LaunchDaemons/meshagentRepair.plist\nexit\n");
                child.waitExit();
            }
        }
    }
}

// Add an Intel AMT event to the log
function addAmtEvent(msg) {
    if (obj.amtevents == null) { obj.amtevents = []; }
    var d = new Date(), e = zeroPad(d.getHours(), 2) + ':' + zeroPad(d.getMinutes(), 2) + ':' + zeroPad(d.getSeconds(), 2) + ', ' + msg;
    obj.amtevents.push(e);
    if (obj.amtevents.length > 100) { obj.amtevents.splice(0, obj.amtevents.length - 100); }
    if (obj.showamtevent) { require('MeshAgent').SendCommand({ action: 'msg', type: 'console', value: e }); }
}
function zeroPad(num, size) { var s = '000000000' + num; return s.substr(s.length - size); }
function trimResults(val) {
    var i, x;
    for (i = 0; i < val.length; ++i) {
        for (x in val[i]) {
            if (x.startsWith('_')) {
                delete val[i][x];
            } else {
                if (val[i][x] == null || val[i][x] == 0) { delete val[i][x]; }
            }
        }
    }
}


// Create Secure IPC for Diagnostic Agent Communications
obj.DAIPC = require('net').createServer();
if (process.platform != 'win32') { try { require('fs').unlinkSync(process.cwd() + '/DAIPC'); } catch (ex) { } }
obj.DAIPC.IPCPATH = process.platform == 'win32' ? ('\\\\.\\pipe\\' + require('_agentNodeId')() + '-DAIPC') : (process.cwd() + '/DAIPC');
try { obj.DAIPC.listen({ path: obj.DAIPC.IPCPATH, writableAll: true, maxConnections: 5 }); } catch (ex) { }
obj.DAIPC._daipc = [];
obj.DAIPC.on('connection', function (c) {
    c._send = function (j) {
        var data = JSON.stringify(j);
        var packet = Buffer.alloc(data.length + 4);
        packet.writeUInt32LE(data.length + 4, 0);
        Buffer.from(data).copy(packet, 4);
        this.write(packet);
    };
    this._daipc.push(c);
    c.parent = this;
    c.on('end', function () { removeRegisteredApp(this); });
    c.on('data', function (chunk) {
        if (chunk.length < 4) { this.unshift(chunk); return; }
        var len = chunk.readUInt32LE(0);
        if (len > 8192) { removeRegisteredApp(this); this.end(); return; }
        if (chunk.length < len) { this.unshift(chunk); return; }

        var data = chunk.slice(4, len);
        try { data = JSON.parse(data.toString()); } catch (ex) { }
        if ((data == null) || (typeof data.cmd != 'string')) return;

        try {
            switch (data.cmd) {
                case 'requesthelp':
                    if (this._registered == null) return;
                    sendConsoleText('Request Help (' + this._registered + '): ' + data.value);
                    var help = {};
                    help[this._registered] = data.value;
                    try { mesh.SendCommand({ action: 'sessions', type: 'help', value: help }); } catch (ex) { }
                    MeshServerLogEx(98, [this._registered, data.value], "Help Requested, user: " + this._registered + ", details: " + data.value, null);
                    break;
                case 'cancelhelp':
                    if (this._registered == null) return;
                    sendConsoleText('Cancel Help (' + this._registered + ')');
                    try { mesh.SendCommand({ action: 'sessions', type: 'help', value: {} }); } catch (ex) { }
                    break;
                case 'register':
                    if (typeof data.value == 'string') {
                        this._registered = data.value;
                        var apps = {};
                        apps[data.value] = 1;
                        try { mesh.SendCommand({ action: 'sessions', type: 'app', value: apps }); } catch (ex) { }
                        this._send({ cmd: 'serverstate', value: meshServerConnectionState, url: require('MeshAgent').ConnectedServer, amt: (amt != null) });
                    }
                    break;
                case 'query':
                    switch (data.value) {
                        case 'connection':
                            data.result = require('MeshAgent').ConnectedServer;
                            this._send(data);
                            break;
                        case 'descriptors':
                            require('ChainViewer').getSnapshot().then(function (f) {
                                this.tag.payload.result = f;
                                this.tag.ipc._send(this.tag.payload);
                            }).parentPromise.tag = { ipc: this, payload: data };
                            break;
                        case 'timerinfo':
                            data.result = require('ChainViewer').getTimerInfo();
                            this._send(data);
                            break;
                    }
                    break;
                case 'amtstate':
                    if (amt == null) return;
                    var func = function amtStateFunc(state) { if (state != null) { amtStateFunc.pipe._send({ cmd: 'amtstate', value: state }); } }
                    func.pipe = this;
                    amt.getMeiState(11, func);
                    break;
                case 'sessions':
                    this._send({ cmd: 'sessions', sessions: tunnelUserCount });
                    break;
                case 'meshToolInfo':
                    try { mesh.SendCommand({ action: 'meshToolInfo', name: data.name, hash: data.hash, cookie: data.cookie ? true : false, pipe: true }); } catch (ex) { }
                    break;
                case 'getUserImage':
                    try { mesh.SendCommand({ action: 'getUserImage', userid: data.userid, pipe: true }); } catch (ex) { }
                    break;
                case 'console':
                    if (debugConsole) {
                        var args = splitArgs(data.value);
                        processConsoleCommand(args[0].toLowerCase(), parseArgs(args), 0, 'pipe');
                    }
                    break;
            }
        }
        catch (ex) { removeRegisteredApp(this); this.end(); return; }
    });
});

// Send current sessions to registered apps
function broadcastSessionsToRegisteredApps(x) {
    var p = {}, i;
    for (i = 0; sendAgentMessage.messages != null && i < sendAgentMessage.messages.length; ++i) {
        p[i] = sendAgentMessage.messages[i];
    }
    tunnelUserCount.msg = p;
    broadcastToRegisteredApps({ cmd: 'sessions', sessions: tunnelUserCount });
    tunnelUserCount.msg = {};
}

// Send this object to all registered local applications
function broadcastToRegisteredApps(x) {
    if ((obj.DAIPC == null) || (obj.DAIPC._daipc == null)) return;
    for (var i in obj.DAIPC._daipc) {
        if (obj.DAIPC._daipc[i]._registered != null) { obj.DAIPC._daipc[i]._send(x); }
    }
}

// Send this object to a specific registered local applications
function sendToRegisteredApp(appid, x) {
    if ((obj.DAIPC == null) || (obj.DAIPC._daipc == null)) return;
    for (var i in obj.DAIPC._daipc) { if (obj.DAIPC._daipc[i]._registered == appid) { obj.DAIPC._daipc[i]._send(x); } }
}

// Send list of registered apps to the server
function updateRegisteredAppsToServer() {
    if ((obj.DAIPC == null) || (obj.DAIPC._daipc == null)) return;
    var apps = {};
    for (var i in obj.DAIPC._daipc) { if (apps[obj.DAIPC._daipc[i]._registered] == null) { apps[obj.DAIPC._daipc[i]._registered] = 1; } else { apps[obj.DAIPC._daipc[i]._registered]++; } }
    try { mesh.SendCommand({ action: 'sessions', type: 'app', value: apps }); } catch (ex) { }
}

// Remove a registered app
function removeRegisteredApp(pipe) {
    for (var i = obj.DAIPC._daipc.length - 1; i >= 0; i--) { if (obj.DAIPC._daipc[i] === pipe) { obj.DAIPC._daipc.splice(i, 1); } }
    if (pipe._registered != null) updateRegisteredAppsToServer();
}

function diagnosticAgent_uninstall() {
    require('service-manager').manager.uninstallService('meshagentDiagnostic');
    require('task-scheduler').delete('meshagentDiagnostic/periodicStart'); // TODO: Using "delete" here breaks the minifier since this is a reserved keyword
}
function diagnosticAgent_installCheck(install) {
    try {
        var diag = require('service-manager').manager.getService('meshagentDiagnostic');
        return (diag);
    } catch (ex) { }
    if (!install) { return null; }

    var svc = null;
    try {
        require('service-manager').manager.installService(
            {
                name: 'meshagentDiagnostic',
                displayName: "Mesh Agent Diagnostic Service",
                description: "Mesh Agent Diagnostic Service",
                servicePath: process.execPath,
                parameters: ['-recovery']
                //files: [{ newName: 'diagnostic.js', _buffer: Buffer.from('LyoNCkNvcHlyaWdodCAyMDE5IEludGVsIENvcnBvcmF0aW9uDQoNCkxpY2Vuc2VkIHVuZGVyIHRoZSBBcGFjaGUgTGljZW5zZSwgVmVyc2lvbiAyLjAgKHRoZSAiTGljZW5zZSIpOw0KeW91IG1heSBub3QgdXNlIHRoaXMgZmlsZSBleGNlcHQgaW4gY29tcGxpYW5jZSB3aXRoIHRoZSBMaWNlbnNlLg0KWW91IG1heSBvYnRhaW4gYSBjb3B5IG9mIHRoZSBMaWNlbnNlIGF0DQoNCiAgICBodHRwOi8vd3d3LmFwYWNoZS5vcmcvbGljZW5zZXMvTElDRU5TRS0yLjANCg0KVW5sZXNzIHJlcXVpcmVkIGJ5IGFwcGxpY2FibGUgbGF3IG9yIGFncmVlZCB0byBpbiB3cml0aW5nLCBzb2Z0d2FyZQ0KZGlzdHJpYnV0ZWQgdW5kZXIgdGhlIExpY2Vuc2UgaXMgZGlzdHJpYnV0ZWQgb24gYW4gIkFTIElTIiBCQVNJUywNCldJVEhPVVQgV0FSUkFOVElFUyBPUiBDT05ESVRJT05TIE9GIEFOWSBLSU5ELCBlaXRoZXIgZXhwcmVzcyBvciBpbXBsaWVkLg0KU2VlIHRoZSBMaWNlbnNlIGZvciB0aGUgc3BlY2lmaWMgbGFuZ3VhZ2UgZ292ZXJuaW5nIHBlcm1pc3Npb25zIGFuZA0KbGltaXRhdGlvbnMgdW5kZXIgdGhlIExpY2Vuc2UuDQoqLw0KDQp2YXIgaG9zdCA9IHJlcXVpcmUoJ3NlcnZpY2UtaG9zdCcpLmNyZWF0ZSgnbWVzaGFnZW50RGlhZ25vc3RpYycpOw0KdmFyIFJlY292ZXJ5QWdlbnQgPSByZXF1aXJlKCdNZXNoQWdlbnQnKTsNCg0KaG9zdC5vbignc2VydmljZVN0YXJ0JywgZnVuY3Rpb24gKCkNCnsNCiAgICBjb25zb2xlLnNldERlc3RpbmF0aW9uKGNvbnNvbGUuRGVzdGluYXRpb25zLkxPR0ZJTEUpOw0KICAgIGhvc3Quc3RvcCA9IGZ1bmN0aW9uKCkNCiAgICB7DQogICAgICAgIHJlcXVpcmUoJ3NlcnZpY2UtbWFuYWdlcicpLm1hbmFnZXIuZ2V0U2VydmljZSgnbWVzaGFnZW50RGlhZ25vc3RpYycpLnN0b3AoKTsNCiAgICB9DQogICAgUmVjb3ZlcnlBZ2VudC5vbignQ29ubmVjdGVkJywgZnVuY3Rpb24gKHN0YXR1cykNCiAgICB7DQogICAgICAgIGlmIChzdGF0dXMgPT0gMCkNCiAgICAgICAgew0KICAgICAgICAgICAgY29uc29sZS5sb2coJ0RpYWdub3N0aWMgQWdlbnQ6IFNlcnZlciBjb25uZWN0aW9uIGxvc3QuLi4nKTsNCiAgICAgICAgICAgIHJldHVybjsNCiAgICAgICAgfQ0KICAgICAgICBjb25zb2xlLmxvZygnRGlhZ25vc3RpYyBBZ2VudDogQ29ubmVjdGlvbiBFc3RhYmxpc2hlZCB3aXRoIFNlcnZlcicpOw0KICAgICAgICBzdGFydCgpOw0KICAgIH0pOw0KfSk7DQpob3N0Lm9uKCdub3JtYWxTdGFydCcsIGZ1bmN0aW9uICgpDQp7DQogICAgaG9zdC5zdG9wID0gZnVuY3Rpb24gKCkNCiAgICB7DQogICAgICAgIHByb2Nlc3MuZXhpdCgpOw0KICAgIH0NCiAgICBjb25zb2xlLmxvZygnTm9uIFNlcnZpY2UgTW9kZScpOw0KICAgIFJlY292ZXJ5QWdlbnQub24oJ0Nvbm5lY3RlZCcsIGZ1bmN0aW9uIChzdGF0dXMpDQogICAgew0KICAgICAgICBpZiAoc3RhdHVzID09IDApDQogICAgICAgIHsNCiAgICAgICAgICAgIGNvbnNvbGUubG9nKCdEaWFnbm9zdGljIEFnZW50OiBTZXJ2ZXIgY29ubmVjdGlvbiBsb3N0Li4uJyk7DQogICAgICAgICAgICByZXR1cm47DQogICAgICAgIH0NCiAgICAgICAgY29uc29sZS5sb2coJ0RpYWdub3N0aWMgQWdlbnQ6IENvbm5lY3Rpb24gRXN0YWJsaXNoZWQgd2l0aCBTZXJ2ZXInKTsNCiAgICAgICAgc3RhcnQoKTsNCiAgICB9KTsNCn0pOw0KaG9zdC5vbignc2VydmljZVN0b3AnLCBmdW5jdGlvbiAoKSB7IHByb2Nlc3MuZXhpdCgpOyB9KTsNCmhvc3QucnVuKCk7DQoNCg0KZnVuY3Rpb24gc3RhcnQoKQ0Kew0KDQp9Ow0K', 'base64') }]
            });
        svc = require('service-manager').manager.getService('meshagentDiagnostic');
    }
    catch (ex) { return null; }
    var proxyConfig = require('global-tunnel').proxyConfig;
    var cert = require('MeshAgent').GenerateAgentCertificate('CN=MeshNodeDiagnosticCertificate');
    var nodeid = require('tls').loadCertificate(cert.root).getKeyHash().toString('base64');
    ddb = require('SimpleDataStore').Create(svc.appWorkingDirectory().replace('\\', '/') + '/meshagentDiagnostic.db');
    ddb.Put('disableUpdate', '1');
    ddb.Put('MeshID', Buffer.from(require('MeshAgent').ServerInfo.MeshID, 'hex'));
    ddb.Put('ServerID', require('MeshAgent').ServerInfo.ServerID);
    ddb.Put('MeshServer', require('MeshAgent').ServerInfo.ServerUri);
    if (cert.root.pfx) { ddb.Put('SelfNodeCert', cert.root.pfx); }
    if (cert.tls) { ddb.Put('SelfNodeTlsCert', cert.tls.pfx); }
    if (proxyConfig) {
        ddb.Put('WebProxy', proxyConfig.host + ':' + proxyConfig.port);
    } else {
        ddb.Put('ignoreProxyFile', '1');
    }

    require('MeshAgent').SendCommand({ action: 'diagnostic', value: { command: 'register', value: nodeid } });
    require('MeshAgent').SendCommand({ action: 'msg', type: 'console', value: "Diagnostic Agent Registered [" + nodeid.length + "/" + nodeid + "]" });

    delete ddb;

    // Set a recurrent task, to run the Diagnostic Agent every 2 days
    require('task-scheduler').create({ name: 'meshagentDiagnostic/periodicStart', daily: 2, time: require('tls').generateRandomInteger('0', '23') + ':' + require('tls').generateRandomInteger('0', '59').padStart(2, '0'), service: 'meshagentDiagnostic' });
    //require('task-scheduler').create({ name: 'meshagentDiagnostic/periodicStart', daily: '1', time: '17:16', service: 'meshagentDiagnostic' });

    return (svc);
}

// Monitor the file 'batterystate.txt' in the agent's folder and sends battery update when this file is changed.
if ((require('fs').existsSync(process.cwd() + 'batterystate.txt')) && (require('fs').watch != null)) {
    // Setup manual battery monitoring
    require('MeshAgent')._batteryFileWatcher = require('fs').watch(process.cwd(), function () {
        if (require('MeshAgent')._batteryFileTimer != null) return;
        require('MeshAgent')._batteryFileTimer = setTimeout(function () {
            try {
                require('MeshAgent')._batteryFileTimer = null;
                var data = null;
                try { data = require('fs').readFileSync(process.cwd() + 'batterystate.txt').toString(); } catch (ex) { }
                if ((data != null) && (data.length < 10)) {
                    data = data.split(',');
                    if ((data.length == 2) && ((data[0] == 'ac') || (data[0] == 'dc'))) {
                        var level = parseInt(data[1]);
                        if ((level >= 0) && (level <= 100)) { require('MeshAgent').SendCommand({ action: 'battery', state: data[0], level: level }); }
                    }
                }
            } catch (ex) { }
        }, 1000);
    });
}
else {
    try {
        // Setup normal battery monitoring
        if (require('computer-identifiers').isBatteryPowered && require('computer-identifiers').isBatteryPowered()) {
            require('MeshAgent')._battLevelChanged = function _battLevelChanged(val) {
                _battLevelChanged.self._currentBatteryLevel = val;
                _battLevelChanged.self.SendCommand({ action: 'battery', state: _battLevelChanged.self._currentPowerState, level: val });
            };
            require('MeshAgent')._battLevelChanged.self = require('MeshAgent');
            require('MeshAgent')._powerChanged = function _powerChanged(val) {
                _powerChanged.self._currentPowerState = (val == 'AC' ? 'ac' : 'dc');
                _powerChanged.self.SendCommand({ action: 'battery', state: (val == 'AC' ? 'ac' : 'dc'), level: _powerChanged.self._currentBatteryLevel });
            };
            require('MeshAgent')._powerChanged.self = require('MeshAgent');
            require('MeshAgent').on('Connected', function (status) {
                if (status == 0) {
                    require('power-monitor').removeListener('acdc', this._powerChanged);
                    require('power-monitor').removeListener('batteryLevel', this._battLevelChanged);
                } else {
                    require('power-monitor').on('acdc', this._powerChanged);
                    require('power-monitor').on('batteryLevel', this._battLevelChanged);
                }
            });
        }
    }
    catch (ex) { }
}


// MeshAgent JavaScript Core Module. This code is sent to and running on the mesh agent.
var meshCoreObj = { action: 'coreinfo', value: (require('MeshAgent').coreHash ? ((process.versions.compileTime ? process.versions.compileTime : '').split(', ')[1].replace('  ', ' ') + ', ' + crc32c(require('MeshAgent').coreHash)) : ('MeshCore v6')), caps: 14, root: require('user-sessions').isRoot() }; // Capability bitmask: 1 = Desktop, 2 = Terminal, 4 = Files, 8 = Console, 16 = JavaScript, 32 = Temporary Agent, 64 = Recovery Agent

// Get the operating system description string
try { require('os').name().then(function (v) { meshCoreObj.osdesc = v; meshCoreObjChanged(); }); } catch (ex) { }

// Setup logged in user monitoring (THIS IS BROKEN IN WIN7)
function onUserSessionChanged(user, locked) {
    userSession.enumerateUsers().then(function (users) {
        if (process.platform == 'linux') {
            if (userSession._startTime == null) {
                userSession._startTime = Date.now();
                userSession._count = users.length;
            }
            else if (Date.now() - userSession._startTime < 10000 && users.length == userSession._count) {
                userSession.removeAllListeners('changed');
                return;
            }
        }

        var u = [], a = users.Active;
        if(meshCoreObj.lusers == null) { meshCoreObj.lusers = []; }
        if(meshCoreObj.upnusers == null) { meshCoreObj.upnusers = []; }
        var ret = getDomainInfo();
        for (var i = 0; i < a.length; i++) {
            var un = a[i].Domain ? (a[i].Domain + '\\' + a[i].Username) : (a[i].Username);
            if (user && locked && (JSON.stringify(a[i]) === JSON.stringify(user))) { if (meshCoreObj.lusers.indexOf(un) == -1) { meshCoreObj.lusers.push(un); } }
            else if (user && !locked && (JSON.stringify(a[i]) === JSON.stringify(user))) { meshCoreObj.lusers.splice(meshCoreObj.lusers.indexOf(un), 1); }
            if (u.indexOf(un) == -1) { u.push(un); } // Only push users in the list once.
            if ((a[i].Domain != null && a[i].Domain == 'AzureAD') || getJoinState() == 1 ){
				var userobj = getLogonCacheKeys();
                if(userobj && userobj.length > 0){
                    for (var j = 0; j < userobj.length; j++) {
                        if (userobj[j] && userobj[j].SAM && userobj[j].SAM[0].trim() === a[i].Username) {
                            if (meshCoreObj.upnusers.indexOf(userobj[j].UPN) === -1) { meshCoreObj.upnusers.push(userobj[j].UPN); }
                            break;
                        }
                    }
                }  
            } else if (a[i].Domain != null) {
                if (ret != null && ret.PartOfDomain === true) {
					var loggedOnUser = getLoggedOnUserBySessionId(a[i].SessionId);
                    if(loggedOnUser == null || (/^[^@]+@[^@]+\.[^@]+$/.test(loggedOnUser) == false)){
                        loggedOnUser = a[i].Username + '@' + ret.Domain;
                    }
                    meshCoreObj.upnusers.push(loggedOnUser);
                } else if (getJoinState() == 4) { // One account with Microsoft Account
                    var userobj = getLogonCacheKeys();
                    if(userobj && userobj.length > 0){
                        for (var j = 0; j < userobj.length; j++) {
                            if (userobj[j] && userobj[j].SAM && userobj[j].SAM.length == 0 && userobj[j].UPN && userobj[j].UPN != '') {
                                if (meshCoreObj.upnusers.indexOf(userobj[j].UPN) === -1) { meshCoreObj.upnusers.push(userobj[j].UPN); }
                                break;
                            }
                        }
                    }  
                }
            }
        }
        meshCoreObj.lusers = meshCoreObj.lusers;
        meshCoreObj.users = u;
        meshCoreObjChanged();
    });
}

try {
    var userSession = require('user-sessions');
    userSession.on('changed', function () { onUserSessionChanged(null, false); });
    userSession.emit('changed');
    userSession.on('locked', function (user) { if(user != undefined && user != null) { onUserSessionChanged(user, true); } });
    userSession.on('unlocked', function (user) { if(user != undefined && user != null) { onUserSessionChanged(user, false); } });
} catch (ex) { }

var meshServerConnectionState = 0;
var tunnels = {};
var lastNetworkInfo = null;
var lastPublicLocationInfo = null;
var selfInfoUpdateTimer = null;
var http = require('http');
var net = require('net');
var fs = require('fs');
var rtc = require('ILibWebRTC');
var amt = null;
var processManager = require('process-manager');
var wifiScannerLib = null;
var wifiScanner = null;
var networkMonitor = null;
var nextTunnelIndex = 1;
var apftunnel = null;
var tunnelUserCount = { terminal: {}, files: {}, registry: {}, tcp: {}, udp: {}, msg: {} }; // List of userid->count sessions for terminal, files, registry and TCP/UDP routing


// Add to the server event log
function MeshServerLog(msg, state) {
    if (typeof msg == 'string') { msg = { action: 'log', msg: msg }; } else { msg.action = 'log'; }
    if (state) {
        if (state.userid) { msg.userid = state.userid; }
        if (state.username) { msg.username = state.username; }
        if (state.sessionid) { msg.sessionid = state.sessionid; }
        if (state.remoteaddr) { msg.remoteaddr = state.remoteaddr; }
        if (state.guestname) { msg.guestname = state.guestname; }
    }
    mesh.SendCommand(msg);
}

// Add to the server event log, use internationalized events
function MeshServerLogEx(id, args, msg, state) {
    var msg = { action: 'log', msgid: id, msgArgs: args, msg: msg };
    if (state) {
        if (state.userid) { msg.userid = state.userid; }
        if (state.xuserid) { msg.xuserid = state.xuserid; }
        if (state.username) { msg.username = state.username; }
        if (state.sessionid) { msg.sessionid = state.sessionid; }
        if (state.remoteaddr) { msg.remoteaddr = state.remoteaddr; }
        if (state.guestname) { msg.guestname = state.guestname; }
    }
    mesh.SendCommand(msg);
}

// Import libraries
db = require('SimpleDataStore').Shared();
sha = require('SHA256Stream');
mesh = require('MeshAgent');
childProcess = require('child_process');

if (mesh.hasKVM == 1) {   // if the agent is compiled with KVM support
    // Check if this computer supports a desktop
    try {
        if ((process.platform == 'win32') || (process.platform == 'darwin') || (require('monitor-info').kvm_x11_support)) {
            meshCoreObj.caps |= 1; meshCoreObjChanged();
        } else if (process.platform == 'linux' || process.platform == 'freebsd') {
            require('monitor-info').on('kvmSupportDetected', function (value) { meshCoreObj.caps |= 1; meshCoreObjChanged(); });
        }
    } catch (ex) { }
}
mesh.DAIPC = obj.DAIPC;

/*
// Try to load up the network monitor
try {
    networkMonitor = require('NetworkMonitor');
    networkMonitor.on('change', function () { sendNetworkUpdateNagle(); });
    networkMonitor.on('add', function (addr) { sendNetworkUpdateNagle(); });
    networkMonitor.on('remove', function (addr) { sendNetworkUpdateNagle(); });
} catch (ex) { networkMonitor = null; }
*/

// Fetch the SMBios Tables
var SMBiosTables = null;
var SMBiosTablesRaw = null;
try {
    var SMBiosModule = null;
    try { SMBiosModule = require('smbios'); } catch (ex) { }
    if (SMBiosModule != null) {
        SMBiosModule.get(function (data) {
            if (data != null) {
                SMBiosTablesRaw = data;
                SMBiosTables = require('smbios').parse(data)
                if (mesh.isControlChannelConnected) { mesh.SendCommand({ action: 'smbios', value: SMBiosTablesRaw }); }

                // If SMBios tables say that Intel AMT is present, try to connect MEI
                if (SMBiosTables.amtInfo && (SMBiosTables.amtInfo.AMT == true)) {
                    var amtmodule = require('amt-manage');
                    amt = new amtmodule(mesh, db, false);
                    amt.on('portBinding_LMS', function (map) { mesh.SendCommand({ action: 'lmsinfo', value: { ports: map.keys() } }); });
                    amt.on('stateChange_LMS', function (v) { if (!meshCoreObj.intelamt) { meshCoreObj.intelamt = {}; } meshCoreObj.intelamt.microlms = v; meshCoreObjChanged(); }); // 0 = Disabled, 1 = Connecting, 2 = Connected
                    amt.onStateChange = function (state) { if (state == 2) { sendPeriodicServerUpdate(1); } } // MEI State
                    amt.reset();
                }
            }
        });
    }
} catch (ex) { sendConsoleText("ex1: " + ex); }

// Try to load up the WIFI scanner
try {
    var wifiScannerLib = require('wifi-scanner');
    wifiScanner = new wifiScannerLib();
    wifiScanner.on('accessPoint', function (data) { sendConsoleText("wifiScanner: " + data); });
} catch (ex) { wifiScannerLib = null; wifiScanner = null; }

// Get our location (lat/long) using our public IP address
var getIpLocationDataExInProgress = false;
var getIpLocationDataExCounts = [0, 0];
function getIpLocationDataEx(func) {
    if (getIpLocationDataExInProgress == true) { return false; }
        getIpLocationDataExInProgress = true;
        getIpLocationDataExCounts[0]++;

    function tryEndpoint(url, fallback) {
        var options = http.parseUri(url);
        options.method = 'GET';
        http.request(options, function (resp) {
            var geoData = '';
            resp.data = function (chunk) { geoData += chunk; };
                resp.end = function () {
                    try {
                        var result = JSON.parse(geoData);
                        if (result.ip && result.loc) {
                            getIpLocationDataExInProgress = false;
                            getIpLocationDataExCounts[1]++;
                            func(result);
                            return;
                        }
                    } catch (ex) { }
                    if (fallback) { fallback(); } else { done(null); }
                };
            if (resp.statusCode != 200) { if (fallback) { fallback(); } else { done(null); } }
        }).on('error', function () {
            if (fallback) { fallback(); } else { done(null); }
        }).end();
    }

    function done(result) {
        getIpLocationDataExInProgress = false;
        if (func) { func(result); }
    }

    tryEndpoint('http://v6.ipinfo.io/json', function () {
        tryEndpoint('http://ipinfo.io/json', null);
    });

    return true;
}

// Remove all Gateway MAC addresses for interface list. This is useful because the gateway MAC is not always populated reliably.
function clearGatewayMac(str) {
    if (typeof str != 'string') return null;
    var x = JSON.parse(str);
    for (var i in x.netif) { try { if (x.netif[i].gatewaymac) { delete x.netif[i].gatewaymac } } catch (ex) { } }
    return JSON.stringify(x);
}

function getIpLocationData(func) {
    // Get the location information for the cache if possible
    var publicLocationInfo = db.Get('publicLocationInfo');
    if (publicLocationInfo != null) { publicLocationInfo = JSON.parse(publicLocationInfo); }
    if (publicLocationInfo == null) {
        // Nothing in the cache, fetch the data
        getIpLocationDataEx(function (locationData) {
            if (locationData != null) {
                publicLocationInfo = {};
                publicLocationInfo.netInfoStr = lastNetworkInfo;
                publicLocationInfo.locationData = locationData;
                var x = db.Put('publicLocationInfo', JSON.stringify(publicLocationInfo)); // Save to database
                if (func) func(locationData); // Report the new location
            }
            else {
                if (func) func(null); // Report no location
            }
        });
    }
    else {
        // Check the cache
        if (clearGatewayMac(publicLocationInfo.netInfoStr) == clearGatewayMac(lastNetworkInfo)) {
            // Cache match
            if (func) func(publicLocationInfo.locationData);
        }
        else {
            // Cache mismatch
            getIpLocationDataEx(function (locationData) {
                if (locationData != null) {
                    publicLocationInfo = {};
                    publicLocationInfo.netInfoStr = lastNetworkInfo;
                    publicLocationInfo.locationData = locationData;
                    var x = db.Put('publicLocationInfo', JSON.stringify(publicLocationInfo)); // Save to database
                    if (func) func(locationData); // Report the new location
                }
                else {
                    if (func) func(publicLocationInfo.locationData); // Can't get new location, report the old location
                }
            });
        }
    }
}

// Polyfill String.endsWith
if (!String.prototype.endsWith) {
    String.prototype.endsWith = function (searchString, position) {
        var subjectString = this.toString();
        if (typeof position !== 'number' || !isFinite(position) || Math.floor(position) !== position || position > subjectString.length) { position = subjectString.length; }
        position -= searchString.length;
        var lastIndex = subjectString.lastIndexOf(searchString, position);
        return lastIndex !== -1 && lastIndex === position;
    };
}

// Polyfill path.join
obj.path =
    {
        join: function () {
            var x = [];
            for (var i in arguments) {
                var w = arguments[i];
                if (w != null) {
                    while (w.endsWith('/') || w.endsWith('\\')) { w = w.substring(0, w.length - 1); }
                    if (i != 0) {
                        while (w.startsWith('/') || w.startsWith('\\')) { w = w.substring(1); }
                    }
                    x.push(w);
                }
            }
            if (x.length == 0) return '/';
            return x.join('/');
        }
    };

// Replace a string with a number if the string is an exact number
function toNumberIfNumber(x) { if ((typeof x == 'string') && (+parseInt(x) === x)) { x = parseInt(x); } return x; }

// Convert decimal to hex
function char2hex(i) { return (i + 0x100).toString(16).substr(-2).toUpperCase(); }

// Convert a raw string to a hex string
function rstr2hex(input) { var r = '', i; for (i = 0; i < input.length; i++) { r += char2hex(input.charCodeAt(i)); } return r; }

// Convert a buffer into a string
function buf2rstr(buf) { var r = ''; for (var i = 0; i < buf.length; i++) { r += String.fromCharCode(buf[i]); } return r; }

// Convert a hex string to a raw string // TODO: Do this using Buffer(), will be MUCH faster
function hex2rstr(d) {
    if (typeof d != "string" || d.length == 0) return '';
    var r = '', m = ('' + d).match(/../g), t;
    while (t = m.shift()) r += String.fromCharCode('0x' + t);
    return r
}

// Convert an object to string with all functions
function objToString(x, p, pad, ret) {
    if (ret == undefined) ret = '';
    if (p == undefined) p = 0;
    if (x == null) { return '[null]'; }
    if (p > 8) { return '[...]'; }
    if (x == undefined) { return '[undefined]'; }
    if (typeof x == 'string') { if (p == 0) return x; return '"' + x + '"'; }
    if (typeof x == 'buffer') { return '[buffer]'; }
    if (typeof x != 'object') { return x; }
    var r = '{' + (ret ? '\r\n' : ' ');
    for (var i in x) { if (i != '_ObjectID') { r += (addPad(p + 2, pad) + i + ': ' + objToString(x[i], p + 2, pad, ret) + (ret ? '\r\n' : ' ')); } }
    return r + addPad(p, pad) + '}';
}

// Return p number of spaces 
function addPad(p, ret) { var r = ''; for (var i = 0; i < p; i++) { r += ret; } return r; }

// Split a string taking into account the quoats. Used for command line parsing
function splitArgs(str) {
    var myArray = [], myRegexp = /[^\s"]+|"([^"]*)"/gi;
    do { var match = myRegexp.exec(str); if (match != null) { myArray.push(match[1] ? match[1] : match[0]); } } while (match != null);
    return myArray;
}

// Parse arguments string array into an object
function parseArgs(argv) {
    var results = { '_': [] }, current = null;
    for (var i = 1, len = argv.length; i < len; i++) {
        var x = argv[i];
        if (x.length > 2 && x[0] == '-' && x[1] == '-') {
            if (current != null) { results[current] = true; }
            current = x.substring(2);
        } else {
            if (current != null) { results[current] = toNumberIfNumber(x); current = null; } else { results['_'].push(toNumberIfNumber(x)); }
        }
    }
    if (current != null) { results[current] = true; }
    return results;
}

// Get server target url with a custom path
function getServerTargetUrl(path) {
    var x = mesh.ServerUrl;
    //sendConsoleText("mesh.ServerUrl: " + mesh.ServerUrl);
    if (x == null) { return null; }
    if (path == null) { path = ''; }
    x = http.parseUri(x);
    if (x == null) return null;
    return x.protocol + '//' + x.host + ':' + x.port + '/' + path;
}

// Get server url. If the url starts with "*/..." change it, it not use the url as is.
function getServerTargetUrlEx(url) {
    if (url.substring(0, 2) == '*/') { return getServerTargetUrl(url.substring(2)); }
    return url;
}

function sendWakeOnLanEx_interval() {
    var t = require('MeshAgent').wakesockets;
    if (t.list.length == 0) {
        clearInterval(t);
        delete require('MeshAgent').wakesockets;
        return;
    }

    var mac = t.list.shift().split(':').join('')
    var magic = 'FFFFFFFFFFFF';
    for (var x = 1; x <= 16; ++x) { magic += mac; }
    var magicbin = Buffer.from(magic, 'hex');

    for (var i in t.sockets) {
        t.sockets[i].send(magicbin, 7, '255.255.255.255');
        //sendConsoleText('Sending wake packet on ' + JSON.stringify(t.sockets[i].address()));
    }
}
function sendWakeOnLanEx(hexMacList) {
    var ret = 0;

    if (require('MeshAgent').wakesockets == null) {
        // Create a new interval timer
        require('MeshAgent').wakesockets = setInterval(sendWakeOnLanEx_interval, 10);
        require('MeshAgent').wakesockets.sockets = [];
        require('MeshAgent').wakesockets.list = hexMacList;

        var interfaces = require('os').networkInterfaces();
        for (var adapter in interfaces) {
            if (interfaces.hasOwnProperty(adapter)) {
                for (var i = 0; i < interfaces[adapter].length; ++i) {
                    var addr = interfaces[adapter][i];
                    if ((addr.family == 'IPv4') && (addr.mac != '00:00:00:00:00:00')) {
                        try {
                            var socket = require('dgram').createSocket({ type: 'udp4' });
                            socket.bind({ address: addr.address });
                            socket.setBroadcast(true);
                            socket.setMulticastInterface(addr.address);
                            socket.setMulticastTTL(1);
                            socket.descriptorMetadata = 'WoL (' + addr.address + ')';
                            require('MeshAgent').wakesockets.sockets.push(socket);
                            ++ret;
                        }
                        catch (ex) { }
                    }
                }
            }
        }
    }
    else {
        // Append to an existing interval timer
        for (var i in hexMacList) {
            require('MeshAgent').wakesockets.list.push(hexMacList[i]);
        }
        ret = require('MeshAgent').wakesockets.sockets.length;
    }

    return ret;
}

function server_promise_default(res, rej) {
    this.resolve = res;
    this.reject = rej;
}
function server_getUserImage(userid) {
    var xpromise = require('promise');
    var ret = new xpromise(server_promise_default);

    if (require('MeshAgent')._promises == null) { require('MeshAgent')._promises = {}; }
    require('MeshAgent')._promises[ret._hashCode()] = ret;
    require('MeshAgent').SendCommand({ action: 'getUserImage', userid: userid, promise: ret._hashCode(), sentDefault: true });
    return ret;
}
require('MeshAgent')._consentTimers = {};
function server_set_consentTimer(id) {
    require('MeshAgent')._consentTimers[id] = new Date();
}
function server_check_consentTimer(id) {
    if (require('MeshAgent')._consentTimers[id] != null) {
        if ((new Date()) - require('MeshAgent')._consentTimers[id] < (60000 * 5)) return true;
        require('MeshAgent')._consentTimers[id] = null;
    }
    return false;
}

function tunnel_finalized()
{
    console.info1('Tunnel Request Finalized');
}
function tunnel_checkServerIdentity(certs)
{
    /*
    try { sendConsoleText("certs[0].digest: " + certs[0].digest); } catch (ex) { sendConsoleText(ex); }
    try { sendConsoleText("certs[0].fingerprint: " + certs[0].fingerprint); } catch (ex) { sendConsoleText(ex); }
    try { sendConsoleText("control-digest: " + require('MeshAgent').ServerInfo.ControlChannelCertificate.digest); } catch (ex) { sendConsoleText(ex); }
    try { sendConsoleText("control-fingerprint: " + require('MeshAgent').ServerInfo.ControlChannelCertificate.fingerprint); } catch (ex) { sendConsoleText(ex); }
    */

    // Check if this is an old agent, no certificate checks are possible in this situation. Display a warning.
    if ((require('MeshAgent').ServerInfo == null) || (require('MeshAgent').ServerInfo.ControlChannelCertificate == null) || (certs[0].digest == null)) { sendAgentMessage("This agent is using insecure tunnels, consider updating.", 3, 119, true); return; }

    // If the tunnel certificate matches the control channel certificate, accept the connection
    if (require('MeshAgent').ServerInfo.ControlChannelCertificate.digest == certs[0].digest) return; // Control channel certificate matches using full cert hash
    if ((certs[0].fingerprint != null) && (require('MeshAgent').ServerInfo.ControlChannelCertificate.fingerprint == certs[0].fingerprint)) return; // Control channel certificate matches using public key hash

    // Check that the certificate is the one expected by the server, fail if not.
    if ((tunnel_checkServerIdentity.servertlshash != null) && (tunnel_checkServerIdentity.servertlshash.toLowerCase() != certs[0].digest.split(':').join('').toLowerCase())) { throw new Error('BadCert') }
}

function tunnel_onError()
{
    sendConsoleText("ERROR: Unable to connect relay tunnel to: " + this.url + ", " + JSON.stringify(e));
}

// Handle a mesh agent command
function handleServerCommand(data) {
    if (typeof data == 'object') {
        // If this is a console command, parse it and call the console handler
        switch (data.action) {
            case 'agentupdate':
                agentUpdate_Start(data.url, { hash: data.hash, tlshash: data.servertlshash, sessionid: data.sessionid });
                break;
            case 'amtRangeScan': {
                if ((typeof data.scanid != 'string') || (data.scanid.length != 32) || (typeof data.range != 'string')) break;
                try {
                    const scanner = require('relay-range-scanner');
                    if (scanner.scan(data.range, 3000, function (results) { mesh.SendCommand({ action: 'amtRangeScan', scanid: data.scanid, results: results }); }) == false) {
                        mesh.SendCommand({ action: 'amtRangeScan', scanid: data.scanid, results: null });
                    }
                } catch (ex) {
                    mesh.SendCommand({ action: 'amtRangeScan', scanid: data.scanid, results: null });
                }
                break;
            }
            case 'msg': {
                switch (data.type) {
                    case 'console': { // Process a console command
                        if ((typeof data.rights != 'number') || ((data.rights & 8) == 0) || ((data.rights & 16) == 0)) break; // Check console rights (Remote Control and Console)
                        if (data.value && data.sessionid) {
                            MeshServerLogEx(17, [data.value], "Processing console command: " + data.value, data);
                            var args = splitArgs(data.value);
                            processConsoleCommand(args[0].toLowerCase(), parseArgs(args), data.rights, data.sessionid);
                        }
                        break;
                    }
                    case 'tunnel':
                        {
                        if (data.value != null) { // Process a new tunnel connection request
                            // Create a new tunnel object
                            var xurl = getServerTargetUrlEx(data.value);
                            if (xurl != null) {
                                xurl = xurl.split('$').join('%24').split('@').join('%40'); // Escape the $ and @ characters
                                var woptions = http.parseUri(xurl);
                                woptions.perMessageDeflate = false;
                                if (typeof data.perMessageDeflate == 'boolean') { woptions.perMessageDeflate = data.perMessageDeflate; }

                                // Perform manual server TLS certificate checking based on the certificate hash given by the server.
                                woptions.rejectUnauthorized = 0;
                                woptions.checkServerIdentity = tunnel_checkServerIdentity;
                                woptions.checkServerIdentity.servertlshash = data.servertlshash;

                                //sendConsoleText(JSON.stringify(woptions));
                                //sendConsoleText('TUNNEL: ' + JSON.stringify(data, null, 2));

                                var tunnel = http.request(woptions);
                                tunnel.upgrade = onTunnelUpgrade;
                                tunnel.on('error', tunnel_onError);
                                tunnel.sessionid = data.sessionid;
                                tunnel.rights = data.rights;
                                tunnel.consent = data.consent;
                                if (global._MSH && _MSH().LocalConsent != null) { tunnel.consent |= parseInt(_MSH().LocalConsent); }
                                tunnel.privacybartext = data.privacybartext ? data.privacybartext : currentTranslation['privacyBar'];
                                tunnel.username = data.username + (data.guestname ? (' - ' + data.guestname) : '');
                                tunnel.realname = (data.realname ? data.realname : data.username) + (data.guestname ? (' - ' + data.guestname) : '');
                                tunnel.guestuserid = data.guestuserid;
                                tunnel.guestname = data.guestname;
                                tunnel.userid = data.userid;
                                if (server_check_consentTimer(tunnel.userid)) { tunnel.consent = (tunnel.consent & -57); } // Deleting Consent Requirement
                                tunnel.desktopviewonly = data.desktopviewonly;
                                tunnel.remoteaddr = data.remoteaddr;
                                tunnel.state = 0;
                                tunnel.url = xurl;
                                tunnel.protocol = 0;
                                tunnel.soptions = data.soptions;
                                tunnel.consentTimeout = (tunnel.soptions && tunnel.soptions.consentTimeout) ? tunnel.soptions.consentTimeout : 30;
                                tunnel.consentAutoAccept = (tunnel.soptions && (tunnel.soptions.consentAutoAccept === true));
                                tunnel.consentAutoAcceptIfNoUser = (tunnel.soptions && (tunnel.soptions.consentAutoAcceptIfNoUser === true));
                                tunnel.consentAutoAcceptIfDesktopNoUser = (tunnel.soptions && (tunnel.soptions.consentAutoAcceptIfDesktopNoUser === true));
                                tunnel.consentAutoAcceptIfTerminalNoUser = (tunnel.soptions && (tunnel.soptions.consentAutoAcceptIfTerminalNoUser === true));
                                tunnel.consentAutoAcceptIfFileNoUser = (tunnel.soptions && (tunnel.soptions.consentAutoAcceptIfFileNoUser === true));
                                tunnel.consentAutoAcceptIfLocked = (tunnel.soptions && (tunnel.soptions.consentAutoAcceptIfLocked === true));
                                tunnel.consentAutoAcceptIfDesktopLocked = (tunnel.soptions && (tunnel.soptions.consentAutoAcceptIfDesktopLocked === true));
                                tunnel.consentAutoAcceptIfTerminalLocked = (tunnel.soptions && (tunnel.soptions.consentAutoAcceptIfTerminalLocked === true));
                                tunnel.consentAutoAcceptIfFileLocked = (tunnel.soptions && (tunnel.soptions.consentAutoAcceptIfFileLocked === true));
                                tunnel.oldStyle = (tunnel.soptions && tunnel.soptions.oldStyle) ? tunnel.soptions.oldStyle : false;
                                tunnel.terminalUserVariable = (tunnel.soptions && tunnel.soptions.terminalUserVariable) ? tunnel.soptions.terminalUserVariable : false;
                                tunnel.tcpaddr = data.tcpaddr;
                                tunnel.tcpport = data.tcpport;
                                tunnel.udpaddr = data.udpaddr;
                                tunnel.udpport = data.udpport;

                                // Put the tunnel in the tunnels list
                                var index = nextTunnelIndex++;
                                tunnel.index = index;
                                tunnels[index] = tunnel;
                                tunnel.once('~', tunnel_finalized);
                                tunnel.end();

                                //sendConsoleText('New tunnel connection #' + index + ': ' + tunnel.url + ', rights: ' + tunnel.rights, data.sessionid);
                            }
                        }
                        break;
                    }
                    case 'endtunnel': {
                        // Terminate one or more tunnels
                        if ((data.rights != 4294967295) && (data.xuserid != data.userid)) return; // This command requires full admin rights on the device or user self-closes it's own sessions
                        for (var i in tunnels) {
                            if ((tunnels[i].userid == data.xuserid) && (tunnels[i].guestname == data.guestname)) {
                                var disconnect = false, msgid = 0;
                                if ((data.protocol == 'kvm') && (tunnels[i].protocol == 2)) { msgid = 134; disconnect = true; }
                                else if ((data.protocol == 'terminal') && (tunnels[i].protocol == 1)) { msgid = 135; disconnect = true; }
                                else if ((data.protocol == 'files') && (tunnels[i].protocol == 5)) { msgid = 136; disconnect = true; }
                                else if ((data.protocol == 'tcp') && (tunnels[i].tcpport != null)) { msgid = 137; disconnect = true; }
                                else if ((data.protocol == 'udp') && (tunnels[i].udpport != null)) { msgid = 137; disconnect = true; }
                                if (disconnect) {
                                    if (tunnels[i].s != null) { tunnels[i].s.end(); } else { tunnels[i].end(); }

                                    // Log tunnel disconnection
                                    var xusername = data.xuserid.split('/')[2];
                                    if (data.guestname != null) { xusername += '/' + guestname; }
                                    MeshServerLogEx(msgid, [xusername], "Forcibly disconnected session of user: " + xusername, data);
                                }
                            }
                        }
                        break;
                    }
                    case 'messagebox': {
                        // Display a message box
                        if (data.title && data.msg) {
                            MeshServerLogEx(18, [data.title, data.msg], "Displaying message box, title=" + data.title + ", message=" + data.msg, data);
                            if (process.platform == 'win32') {
                                if (global._clientmessage) {
                                    global._clientmessage.addMessage(data.msg);
                                }
                                else {
                                    try {
                                        require('win-dialog');
                                        var ipr = server_getUserImage(data.userid);
                                        ipr.title = data.title;
                                        ipr.message = data.msg;
                                        ipr.username = data.username;
                                        if (data.realname && (data.realname != '')) { ipr.username = data.realname; }
                                        ipr.timeout = (typeof data.timeout === 'number' ? data.timeout : 120000);
                                        global._clientmessage = ipr.then(function (img) {
                                            var options = { b64Image: img.split(',').pop(), background: color_options.background, foreground: color_options.foreground }
                                            if (this.timeout != 0) { options.timeout = this.timeout; }
                                            this.messagebox = require('win-dialog').create(this.title, this.message, this.username, options);
                                            this.__childPromise.addMessage = this.messagebox.addMessage.bind(this.messagebox);
                                            return (this.messagebox);
                                        });

                                        global._clientmessage.then(function () { global._clientmessage = null; });
                                    }
                                    catch (z) {
                                        try { require('message-box').create(data.title, data.msg, 120).then(function () { }).catch(function () { }); } catch (ex) { }
                                    }
                                }
                            }
                            else {
                                try { require('message-box').create(data.title, data.msg, 120).then(function () { }).catch(function () { }); } catch (ex) { }
                            }
                        }
                        break;
                    }
                    case 'ps': {
                        // Return the list of running processes
                        if (data.sessionid) {
                            processManager.getProcesses(function (plist) {
                                mesh.SendCommand({ action: 'msg', type: 'ps', value: JSON.stringify(plist), sessionid: data.sessionid });
                            });
                        }
                        break;
                    }
                    case 'psinfo': {
                        // Requestion details information about a process
                        if (data.pid) {
                            var info = {}; // TODO: Replace with real data. Feel free not to give all values if not available.
                            try {
                                info = processManager.getProcessInfo(data.pid);
                            }catch(e){ }
                            /*
                            info.processUser = "User"; // String
                            info.processDomain = "Domain"; // String
                            info.cmd = "abc"; // String
                            info.processName = "dummydata";
                            info.privateMemorySize = 123; // Bytes
                            info.virtualMemorySize = 123; // Bytes
                            info.workingSet = 123; // Bytes
                            info.totalProcessorTime = 123; // Seconds
                            info.userProcessorTime = 123; // Seconds
                            info.startTime = "2012-12-30T23:59:59.000Z"; // Time in UTC ISO format
                            info.sessionId = 123; // Number
                            info.privilegedProcessorTime = 123; // Seconds
                            info.PriorityBoostEnabled = true; // Boolean
                            info.peakWorkingSet = 123; // Bytes
                            info.peakVirtualMemorySize = 123; // Bytes
                            info.peakPagedMemorySize = 123; // Bytes
                            info.pagedSystemMemorySize = 123; // Bytes
                            info.pagedMemorySize = 123; // Bytes
                            info.nonpagedSystemMemorySize = 123; // Bytes
                            info.mainWindowTitle = "dummydata"; // String
                            info.machineName = "dummydata"; // Only set this if machine name is not "."
                            info.handleCount = 123; // Number
                            */
                            mesh.SendCommand({ action: 'msg', type: 'psinfo', pid: data.pid, sessionid: data.sessionid, value: info });
                        }
                        break;
                    }
                    case 'pskill': {
                        // Kill a process
                        if (data.value) {
                            var info = data.value.split('|'), pid = data.value, msg = " (Unknown)";
                            if (info.length > 1) { pid = info[0]; msg = " (" + info[1] + ")"; } else { info[1] = "Unknown"; }
                            MeshServerLogEx(19, info, "Killing process " + pid + msg, data);
                            try { process.kill(parseInt(pid)); } catch (ex) { sendConsoleText("pskill: " + JSON.stringify(ex)); }
                        }
                        break;
                    }
                    case 'service': {
                        // return information about the service
                        try {
                            var service = require('service-manager').manager.getService(data.serviceName);
                            if (service != null) {
                                var reply = {
                                    name: (service.name ? service.name : ''),
                                    status: (service.status ? service.status : ''),
                                    startType: (service.startType ? service.startType : ''),
                                    failureActions: (service.failureActions ? service.failureActions : ''),
                                    installedDate: (service.installedDate ? service.installedDate : ''),
                                    installedBy: (service.installedBy ? service.installedBy : '') ,
                                    user: (service.user ? service.user : '')
                                };
                                if(reply.installedBy.indexOf('S-1-5') != -1) {
                                    var cmd = "(Get-WmiObject -Class win32_userAccount -Filter \"SID='"+service.installedBy+"'\").Caption";
                                    var replydata = "";
                                    var pws = require('child_process').execFile(process.env['windir'] + '\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', ['powershell', '-noprofile', '-nologo', '-command', '-'], {});
                                    pws.descriptorMetadata = 'UserSIDPowerShell';
                                    pws.stdout.on('data', function (c) { replydata += c.toString(); });
                                    pws.stderr.on('data', function (c) { replydata += c.toString(); });
                                    pws.stdin.write(cmd + '\r\nexit\r\n');
                                    pws.on('exit', function () { 
                                        if (replydata != "") reply.installedBy = replydata;
                                        mesh.SendCommand({ action: 'msg', type: 'service', value: JSON.stringify(reply), sessionid: data.sessionid });
                                        delete pws;
                                    });
                                } else {
                                    mesh.SendCommand({ action: 'msg', type: 'service', value: JSON.stringify(reply), sessionid: data.sessionid });
                                }
                            }
                        } catch (ex) { 
                            mesh.SendCommand({ action: 'msg', type: 'service', error: ex, sessionid: data.sessionid })
                        }
                    }
                    case 'services': {
                        // Return the list of installed services
                        var services = null;
                        try { services = require('service-manager').manager.enumerateService(); } catch (ex) { }
                        if (services != null) { mesh.SendCommand({ action: 'msg', type: 'services', value: JSON.stringify(services), sessionid: data.sessionid }); }
                        break;
                    }
                    case 'serviceStop': {
                        // Stop a service
                        try {
                            var service = require('service-manager').manager.getService(data.serviceName);
                            if (service != null) { service.stop(); }
                        } catch (ex) { }
                        break;
                    }
                    case 'serviceStart': {
                        // Start a service
                        try {
                            var service = require('service-manager').manager.getService(data.serviceName);
                            if (service != null) { service.start(); }
                        } catch (ex) { }
                        break;
                    }
                    case 'serviceRestart': {
                        // Restart a service
                        try {
                            var service = require('service-manager').manager.getService(data.serviceName);
                            if (service != null) { service.restart(); }
                        } catch (ex) { }
                        break;
                    }
                    case 'deskBackground':
                        {
                            // Toggle desktop background
                            try {
                                if (process.platform == 'win32') {
                                    var stype = require('user-sessions').getProcessOwnerName(process.pid).tsid == 0 ? 1 : 0;
                                    var sid = undefined;
                                    if (stype == 1) {
                                        if (require('MeshAgent')._tsid != null) {
                                            stype = 5;
                                            sid = require('MeshAgent')._tsid;
                                        }
                                    }
                                    var id = require('user-sessions').getProcessOwnerName(process.pid).tsid == 0 ? 1 : 0;
                                    var child = require('child_process').execFile(process.execPath, [process.execPath.split('\\').pop(), '-b64exec', 'dmFyIFNQSV9HRVRERVNLV0FMTFBBUEVSID0gMHgwMDczOwp2YXIgU1BJX1NFVERFU0tXQUxMUEFQRVIgPSAweDAwMTQ7CnZhciBHTSA9IHJlcXVpcmUoJ19HZW5lcmljTWFyc2hhbCcpOwp2YXIgdXNlcjMyID0gR00uQ3JlYXRlTmF0aXZlUHJveHkoJ3VzZXIzMi5kbGwnKTsKdXNlcjMyLkNyZWF0ZU1ldGhvZCgnU3lzdGVtUGFyYW1ldGVyc0luZm9BJyk7CgppZiAocHJvY2Vzcy5hcmd2Lmxlbmd0aCA9PSAzKQp7CiAgICB2YXIgdiA9IEdNLkNyZWF0ZVZhcmlhYmxlKDEwMjQpOwogICAgdXNlcjMyLlN5c3RlbVBhcmFtZXRlcnNJbmZvQShTUElfR0VUREVTS1dBTExQQVBFUiwgdi5fc2l6ZSwgdiwgMCk7CiAgICBjb25zb2xlLmxvZyh2LlN0cmluZyk7CiAgICBwcm9jZXNzLmV4aXQoKTsKfQplbHNlCnsKICAgIHZhciBuYiA9IEdNLkNyZWF0ZVZhcmlhYmxlKHByb2Nlc3MuYXJndlszXSk7CiAgICB1c2VyMzIuU3lzdGVtUGFyYW1ldGVyc0luZm9BKFNQSV9TRVRERVNLV0FMTFBBUEVSLCBuYi5fc2l6ZSwgbmIsIDApOwogICAgcHJvY2Vzcy5leGl0KCk7Cn0='], { type: stype, uid: sid });
                                    child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
                                    child.stderr.on('data', function () { });
                                    child.waitExit();
                                    var current = child.stdout.str.trim();
                                    if (current != '') { require('MeshAgent')._wallpaper = current; }
                                    child = require('child_process').execFile(process.execPath, [process.execPath.split('\\').pop(), '-b64exec', 'dmFyIFNQSV9HRVRERVNLV0FMTFBBUEVSID0gMHgwMDczOwp2YXIgU1BJX1NFVERFU0tXQUxMUEFQRVIgPSAweDAwMTQ7CnZhciBHTSA9IHJlcXVpcmUoJ19HZW5lcmljTWFyc2hhbCcpOwp2YXIgdXNlcjMyID0gR00uQ3JlYXRlTmF0aXZlUHJveHkoJ3VzZXIzMi5kbGwnKTsKdXNlcjMyLkNyZWF0ZU1ldGhvZCgnU3lzdGVtUGFyYW1ldGVyc0luZm9BJyk7CgppZiAocHJvY2Vzcy5hcmd2Lmxlbmd0aCA9PSAzKQp7CiAgICB2YXIgdiA9IEdNLkNyZWF0ZVZhcmlhYmxlKDEwMjQpOwogICAgdXNlcjMyLlN5c3RlbVBhcmFtZXRlcnNJbmZvQShTUElfR0VUREVTS1dBTExQQVBFUiwgdi5fc2l6ZSwgdiwgMCk7CiAgICBjb25zb2xlLmxvZyh2LlN0cmluZyk7CiAgICBwcm9jZXNzLmV4aXQoKTsKfQplbHNlCnsKICAgIHZhciBuYiA9IEdNLkNyZWF0ZVZhcmlhYmxlKHByb2Nlc3MuYXJndlszXSk7CiAgICB1c2VyMzIuU3lzdGVtUGFyYW1ldGVyc0luZm9BKFNQSV9TRVRERVNLV0FMTFBBUEVSLCBuYi5fc2l6ZSwgbmIsIDApOwogICAgcHJvY2Vzcy5leGl0KCk7Cn0=', current != '' ? '""' : require('MeshAgent')._wallpaper], { type: stype, uid: sid });
                                    child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
                                    child.stderr.on('data', function () { });
                                    child.waitExit();
                                    mesh.SendCommand({ action: 'msg', type: 'deskBackground', sessionid: data.sessionid, data: (current != '' ? "" : require('MeshAgent')._wallpaper), });
                                } else {
                                    var id = require('user-sessions').consoleUid();
                                    var current = require('linux-gnome-helpers').getDesktopWallpaper(id);
                                    if (current != '/dev/null') { require('MeshAgent')._wallpaper = current; }
                                    require('linux-gnome-helpers').setDesktopWallpaper(id, current != '/dev/null' ? undefined : require('MeshAgent')._wallpaper);
                                    mesh.SendCommand({ action: 'msg', type: 'deskBackground', sessionid: data.sessionid, data: (current != '/dev/null' ? "" : require('MeshAgent')._wallpaper), });
                                }
                            } catch (ex) {
                                sendConsoleText(ex);
                            }
                            break;
                        }
                    case 'openUrl': {
                        // Open a local web browser and return success/fail
                        MeshServerLogEx(20, [data.url], "Opening: " + data.url, data);
                        sendConsoleText("OpenURL: " + data.url);
                        if (data.url) { mesh.SendCommand({ action: 'msg', type: 'openUrl', url: data.url, sessionid: data.sessionid, success: (openUserDesktopUrl(data.url) != null) }); }
                        break;
                    }
                    case 'getclip': {
                        // Send the load clipboard back to the user
                        //sendConsoleText('getClip: ' + JSON.stringify(data));
                        if (require('MeshAgent').isService) {
                            require('clipboard').dispatchRead().then(function (str) {
                                if (str) {
                                    if (data.tag != 3) { MeshServerLogEx(21, [str.length], "Getting clipboard content, " + str.length + " byte(s)", data); }
                                    mesh.SendCommand({ action: 'msg', type: 'getclip', sessionid: data.sessionid, data: str, tag: data.tag });
                                }
                            });
                        } else {
                            require('clipboard').read().then(function (str) {
                                if (str) {
                                    if (data.tag != 3) { MeshServerLogEx(21, [str.length], "Getting clipboard content, " + str.length + " byte(s)", data); }
                                    mesh.SendCommand({ action: 'msg', type: 'getclip', sessionid: data.sessionid, data: str, tag: data.tag });
                                }
                            });
                        }
                        break;
                    }
                    case 'setclip': {
                        if (pendingSetClip) return;
                        // Set the load clipboard to a user value
                        if (typeof data.data == 'string') {
                            MeshServerLogEx(22, [data.data.length], "Setting clipboard content, " + data.data.length + " byte(s)", data);
                            if (require('MeshAgent').isService) {
                                if (process.platform != 'win32') {
                                    require('clipboard').dispatchWrite(data.data);
                                    mesh.SendCommand({ action: 'msg', type: 'setclip', sessionid: data.sessionid, success: true });
                                }
                                else {
                                    var clipargs = data.data;
                                    var uid = require('user-sessions').consoleUid();
                                    var user = require('user-sessions').getUsername(uid);
                                    var domain = require('user-sessions').getDomain(uid);
                                    user = (domain + '\\' + user);

                                    if (this._dispatcher) { this._dispatcher.close(); }
                                    this._dispatcher = require('win-dispatcher').dispatch({ user: user, modules: [{ name: 'clip-dispatch', script: "module.exports = { dispatch: function dispatch(val) { require('clipboard')(val); process.exit(); } };" }], launch: { module: 'clip-dispatch', method: 'dispatch', args: [clipargs] } });
                                    this._dispatcher.parent = this;
                                    //require('events').setFinalizerMetadata.call(this._dispatcher, 'clip-dispatch');
                                    pendingSetClip = true;
                                    this._dispatcher.on('connection', function (c) {
                                        this._c = c;
                                        this._c.root = this.parent;
                                        this._c.on('end', function ()
                                        {
                                            pendingSetClip = false;
                                            try { this.root._dispatcher.close(); } catch (ex) { }
                                            this.root._dispatcher = null;
                                            this.root = null;
                                            mesh.SendCommand({ action: 'msg', type: 'setclip', sessionid: data.sessionid, success: true });
                                        });
                                    });
                                }
                            }
                            else {
                                require('clipboard')(data.data);
                                mesh.SendCommand({ action: 'msg', type: 'setclip', sessionid: data.sessionid, success: true });
                            } // Set the clipboard
                        }
                        break;
                    }
                    case 'userSessions': {
                        mesh.SendCommand({ action: 'msg', type: 'userSessions', sessionid: data.sessionid, data: require('kvm-helper').users(), tag: data.tag });
                        break;
                    }
                    case 'cpuinfo':
                        // CPU & memory utilization
                        var cpuuse = require('sysinfo').cpuUtilization();
                        cpuuse.sessionid = data.sessionid;
                        cpuuse.tag = data.tag;
                        cpuuse.then(function (data) {
                            mesh.SendCommand(JSON.stringify(
                                {
                                    action: 'msg',
                                    type: 'cpuinfo',
                                    cpu: data,
                                    memory: require('sysinfo').memUtilization(),
                                    thermals: require('sysinfo').thermals == null ? [] : require('sysinfo').thermals(),
                                    sessionid: this.sessionid,
                                    tag: this.tag
                                }));
                        }, function (ex) { });
                        break;
                    case 'localapp':
                        // Send a message to a local application
                        sendConsoleText('localappMsg: ' + data.appid + ', ' + JSON.stringify(data.value));
                        if (data.appid != null) { sendToRegisteredApp(data.appid, data.value); } else { broadcastToRegisteredApps(data.value); }
                        break;
                    case 'alertbox': {
                        // Display an old style alert box
                        if (data.title && data.msg) {
                            MeshServerLogEx(158, [data.title, data.msg], "Displaying alert box, title=" + data.title + ", message=" + data.msg, data);
                            try { require('message-box').create(data.title, data.msg, 9999, 1).then(function () { }).catch(function () { }); } catch (ex) { }
                        }
                        break;
                    }
                    case 'sysinfo': {
                        // Send system information
                        getSystemInformation(function (results) {
                            if ((results != null) && (data.hash != results.hash)) { mesh.SendCommand({ action: 'sysinfo', sessionid: this.sessionid, data: results }); }
                        });
                        break;
                    }
                    default:
                        // Unknown action, ignore it.
                        break;
                }
                break;
            }
            case 'software': {
                var sendSoftwareResponse = function(responseData) {
                    mesh.SendCommand({ 
                        action: 'software', 
                        value: (typeof responseData === 'string') ? responseData : JSON.stringify(responseData), 
                        sessionid: data.sessionid 
                    });
                };
                if (data.type == 'installedapps') {
                    if (process.platform == 'win32') {
                        try {
                            if (require('win-info').installedApps) {
                                require('win-info').installedApps().then(sendSoftwareResponse).catch(function(e) { sendSoftwareResponse({ error: e.toString() }); });
                            } else { sendSoftwareResponse({ error: "Not supported" }); }
                        } catch (e) { sendSoftwareResponse({ error: e.toString() }); }
                    } else if (process.platform == 'linux') {
                        try {
                            if (require('linux-info').packages) {
                                require('linux-info').packages().then(sendSoftwareResponse).catch(function(e) { sendSoftwareResponse({ error: e.toString() }); });
                            } else { sendSoftwareResponse({ error: "Not supported" }); }
                        } catch (e) { sendSoftwareResponse({ error: e.toString() }); }
                    } else if (process.platform == 'darwin') {
                        try {
                            if (require('mac-info').apps) {
                                require('mac-info').apps().then(sendSoftwareResponse).catch(function(e) { sendSoftwareResponse({ error: e.toString() }); });
                            } else { sendSoftwareResponse({ error: "Not supported" }); }
                        } catch (e) { sendSoftwareResponse({ error: e.toString() }); }
                    } else {
                        sendSoftwareResponse({ success: false, error: "Not supported" });
                    }
                } else if (data.type == 'installedstoreapps') {
                    if (process.platform != 'win32') {
                        sendSoftwareResponse({ success: false, error: "Installed Store Apps is only supported on Windows devices" });
                        return;
                    }
                    try {
                        if (require('win-info').installedStoreApps) {
                            require('win-info').installedStoreApps().then(sendSoftwareResponse).catch(function(e) { sendSoftwareResponse({ error: e.toString() }); });
                        }
                    } catch (e) { sendSoftwareResponse({ error: e.toString() }); }
                } else if (data.type == 'uninstallapp' && (typeof data.value == 'string' && data.value != '')) {
                    if (process.platform != 'win32') {
                        sendSoftwareResponse({ success: false, error: "Uninstall is only supported on Windows devices" });
                        return;
                    }
                    var base64Cmd = data.value.trim();
                    var uninstallCmd = '';
                    try {
                        var b = Buffer.from(base64Cmd, 'base64');
                        var decoded = b.toString();
                        var lc = decoded ? decoded.toLowerCase() : '';
                        if (decoded && decoded.length > 0 && (lc.indexOf('msiexec') >= 0 || lc.indexOf('.exe') >= 0)) { uninstallCmd = decoded; } else { uninstallCmd = base64Cmd; }
                    } catch (e) { uninstallCmd = base64Cmd; }
                    if (!uninstallCmd || uninstallCmd.trim() === '' || uninstallCmd.trim() === '\\') {
                        sendSoftwareResponse({ success: false, error: 'No valid uninstall command available' });
                    } else {
                        var logDir = (process.env['ProgramData'] || 'C:\\ProgramData') + '\\MeshAgent';
                        try { if (!require('fs').existsSync(logDir)) { require('fs').mkdirSync(logDir); } } catch (e) { }
                        var logFile = logDir + '\\MeshAgent_Uninstall.log';
                        var child_process = require('child_process');
                        var cmdPath = process.env['windir'] + '\\system32\\cmd.exe';
                        var writeLog = function(message, callback) {
                            try {
                                var timestamp = new Date().toISOString();
                                var logLine = timestamp + ' | ' + message;
                                logLine = logLine.replace(/"/g, '""').replace(/&/g, '^&').replace(/</g, '^<').replace(/>/g, '^>').replace(/\|/g, '^|');
                                var logChild = child_process.execFile(cmdPath, ['cmd', '/c', 'echo ' + logLine + ' >> "' + logFile + '"'], { timeout: 5000 });
                                logChild.on('exit', function() { if (callback) callback(); });
                            } catch (e) { if (callback) callback(); }
                        };
                        try {
                            writeLog('UNINSTALL START - Command: ' + uninstallCmd.replace(/\\/g, '/'));
                            var originalCmd = uninstallCmd;
                            if (uninstallCmd.toLowerCase().indexOf('msiexec') >= 0) {
                                uninstallCmd = uninstallCmd.replace(/\/I\s*(\{[^}]+\})/gi, '/X $1'); // change /I to /X  for uninstall, fixes 7zip example
                                uninstallCmd = uninstallCmd.replace(/\/q[nbrf]?/gi, '');
                                if (uninstallCmd.indexOf('/QN') < 0) { uninstallCmd = uninstallCmd + ' /QN /norestart'; }
                            } else {
                                if (uninstallCmd.toLowerCase().indexOf('/s') < 0) { uninstallCmd = uninstallCmd + ' /S /silent /SILENT /VERYSILENT /quiet /norestart'; }
                            }
                            uninstallCmd = uninstallCmd.replace(/\s+/g, ' ').trim();
                            var child = child_process.execFile(cmdPath, ['cmd', '/c', uninstallCmd], { timeout: 300000 });
                            child.stdout.str = ''; child.stderr.str = '';
                            child._cmd = uninstallCmd;
                            child.stdout.on('data', function(c) { this.str += c.toString(); });
                            child.stderr.on('data', function(c) { this.str += c.toString(); });
                            child.on('exit', function(code) {
                                var success = (code === 0 || code === null || code === 3010);
                                var status = success ? 'SUCCESS' : 'FAILED';
                                writeLog('UNINSTALL ' + status + ' - ExitCode: ' + code);
                                var result = { success: success, exitCode: code, command: child._cmd };
                                if (child.stdout.str) result.stdout = child.stdout.str.trim().substring(0, 500);
                                if (child.stderr.str) result.stderr = child.stderr.str.trim().substring(0, 500);
                                sendSoftwareResponse(result);
                            });
                            sendSoftwareResponse({ status: 'Silent uninstall started', command: uninstallCmd });
                        } catch (ex) {
                            writeLog('UNINSTALL ERROR - ' + ex.toString());
                            sendSoftwareResponse({ error: ex.toString() });
                        }
                    }
                } else if (data.type == 'uninstallstoreapp' && (typeof data.value === 'string' && data.value != '')) {
                    if (process.platform != 'win32') {
                        sendSoftwareResponse({ success: false, error: "Uninstall is only supported on Windows devices" });
                        return;
                    }
                    var rawName = data.value.trim();
                    var packageName = rawName.replace(/"/g, "").replace(/'/g, ""); 
                    var logDir = (process.env['ProgramData'] || 'C:\\ProgramData') + '\\MeshAgent';
                    try { if (!require('fs').existsSync(logDir)) { require('fs').mkdirSync(logDir); } } catch (e) { }
                    var logFile = logDir + '\\MeshAgent_StoreUninstall.log';
                    try {
                        var psPath = (process.env['SystemRoot'] || 'C:\\Windows') + '\\System32\\WindowsPowerShell\\v1.0\\powershell.exe';
                        var child_process = require('child_process');
                        var completionMarker = '###DONE###' + Date.now();
                        var child = child_process.execFile(psPath, ['powershell', '-NoProfile', '-NoLogo', '-ExecutionPolicy', 'Bypass', '-Command', '-'], {});
                        child.stdout.str = ''; child.stderr.str = '';
                        child._completed = false;
                        child.stdout.on('data', function(c) { 
                            this.str += c.toString();
                            if (!child._completed && this.str.indexOf(completionMarker) >= 0) {
                                child._completed = true;
                                var output = this.str.split(completionMarker)[0].trim();
                                sendSoftwareResponse({ status: 'Finished', output: output });
                            }
                        });
                        child.stderr.on('data', function(c) { this.str += c.toString(); });
                        var script = [
                            "$LogFile = '" + logFile + "'",
                            "$TargetName = '" + packageName + "'",
                            "function Write-Log { param([string]$Msg); $Line = \"$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - $Msg\"; Add-Content -Path $LogFile -Value $Line -ErrorAction SilentlyContinue; Write-Output $Msg }",
                            "",
                            "Write-Log \"STORE UNINSTALL START: $TargetName\"",
                            "Write-Log \"Running as: $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)\"",
                            "",
                            "$foundCount = 0",
                            "$pkgs = Get-AppxPackage -AllUsers -Name \"*$TargetName*\"",
                            "if ($pkgs) {",
                            "    if ($pkgs -isnot [array]) { $pkgs = @($pkgs) }",
                            "    Write-Log \"Found (AllUsers): $($pkgs.Count) packages\"",
                            "    foreach ($p in $pkgs) {",
                            "        Write-Log \"Removing: $($p.PackageFullName)\"",
                            "        try {",
                            "            Remove-AppxPackage -Package $p.PackageFullName -AllUsers -ErrorAction Stop",
                            "            Write-Log \"SUCCESS: Removed with -AllUsers\"",
                            "            $foundCount++",
                            "        } catch {",
                            "            Write-Log \"WARN: AllUsers failed, trying current user only. Error: $($_.Exception.Message)\"",
                            "            try {",
                            "                Remove-AppxPackage -Package $p.PackageFullName -ErrorAction Stop",
                            "                Write-Log \"SUCCESS: Removed from CurrentUser\"",
                            "                $foundCount++",
                            "            } catch {",
                            "                Write-Log \"ERROR: Failed to remove $($p.PackageFullName). Error: $($_.Exception.Message)\"",
                            "            }",
                            "        }",
                            "    }",
                            "} else { Write-Log \"Found (AllUsers): 0 packages\" }",
                            "",
                            "$prov = Get-AppxProvisionedPackage -Online | Where-Object { $_.PackageName -like \"*$TargetName*\" }",
                            "if ($prov) {",
                            "    if ($prov -isnot [array]) { $prov = @($prov) }",
                            "    Write-Log \"Found provisioned: $($prov.Count) packages\"",
                            "    foreach ($pr in $prov) {",
                            "        Write-Log \"Deprovisioning: $($pr.DisplayName)\"",
                            "        try {",
                            "            Remove-AppxProvisionedPackage -Online -PackageName $pr.PackageName -ErrorAction Stop | Out-Null",
                            "            Write-Log \"SUCCESS: Deprovisioned\"",
                            "        } catch {",
                            "            Write-Log \"ERROR: Failed to deprovision. Error: $($_.Exception.Message)\"",
                            "        }",
                            "    }",
                            "} else { Write-Log \"Found provisioned: 0 packages\" }",
                            "",
                            "'" + completionMarker + "'",
                            "exit"
                        ].join("\r\n");
                        child.stdin.write(script + "\r\n");
                        setTimeout(function() { if (!child._completed) { child.kill(); sendSoftwareResponse({ error: 'Timeout' }); } }, 60000);
                        sendSoftwareResponse({ status: 'Store app removal started', package: packageName });
                    } catch (ex) {
                        sendSoftwareResponse({ error: ex.toString() });
                    }
                }
                break;
            }
            case 'acmactivate': {
                if (amt != null) {
                    MeshServerLogEx(23, null, "Attempting Intel AMT ACM mode activation", data);
                    amt.setAcmResponse(data);
                }
                break;
            }
            case 'wakeonlan': {
                // Send wake-on-lan on all interfaces for all MAC addresses in data.macs array. The array is a list of HEX MAC addresses.
                //sendConsoleText("Server requesting wake-on-lan for: " + data.macs.join(', '));
                sendWakeOnLanEx(data.macs);
                sendWakeOnLanEx(data.macs);
                sendWakeOnLanEx(data.macs);
                break;
            }
            case 'runcommands': {
                if (mesh.cmdchild != null) { sendConsoleText("Run commands can't execute, already busy."); break; }
                if (!data.reply) sendConsoleText("Run commands (" + data.runAsUser + "): " + data.cmds);

                // data.runAsUser: 0=Agent,1=UserOrAgent,2=UserOnly
                var options = {};
                if (data.runAsUser > 0) {
                    try { options.uid = require('user-sessions').consoleUid(); } catch (ex) { }
                    options.type = require('child_process').SpawnTypes.TERM;
                }
                if (data.runAsUser == 2) {
                    if (options.uid == null) break;
                    if (((require('user-sessions').minUid != null) && (options.uid < require('user-sessions').minUid()))) break; // This command can only run as user.
                }
                var replydata = "";
                if (process.platform == 'win32') {
                    if (data.type == 1) {
                        // Windows command shell
                        mesh.cmdchild = require('child_process').execFile(process.env['windir'] + '\\system32\\cmd.exe', ['cmd'], options);
                        mesh.cmdchild.descriptorMetadata = 'UserCommandsShell';
                        mesh.cmdchild.stdout.on('data', function (c) { replydata += c.toString(); sendConsoleText(c.toString()); });
                        mesh.cmdchild.stderr.on('data', function (c) { replydata += c.toString(); sendConsoleText(c.toString()); });
                        mesh.cmdchild.stdin.write(data.cmds + '\r\nexit\r\n');
                        mesh.cmdchild.on('exit', function () {
                            if (data.reply) {
                                mesh.SendCommand({ action: 'msg', type: 'runcommands', result: replydata, sessionid: data.sessionid, responseid: data.responseid });
                            } else {
                                sendConsoleText("Run commands completed.");
                            }
                            delete mesh.cmdchild;
                        });
                    } else if (data.type == 2) {
                        // Windows Powershell
                        mesh.cmdchild = require('child_process').execFile(process.env['windir'] + '\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', ['powershell', '-noprofile', '-nologo', '-command', '-'], options);
                        mesh.cmdchild.descriptorMetadata = 'UserCommandsPowerShell';
                        mesh.cmdchild.stdout.on('data', function (c) { replydata += c.toString(); sendConsoleText(c.toString()); });
                        mesh.cmdchild.stderr.on('data', function (c) { replydata += c.toString(); sendConsoleText(c.toString()); });
                        mesh.cmdchild.stdin.write(data.cmds + '\r\nexit\r\n');
                        mesh.cmdchild.on('exit', function () {
                            if (data.reply) {
                                mesh.SendCommand({ action: 'msg', type: 'runcommands', result: replydata, sessionid: data.sessionid, responseid: data.responseid });
                            } else {
                                sendConsoleText("Run commands completed.");
                            }
                            delete mesh.cmdchild;
                        });
                    }
                } else if (data.type == 3) {
                    // Linux shell
                    mesh.cmdchild = require('child_process').execFile('/bin/sh', ['sh'], options);
                    mesh.cmdchild.descriptorMetadata = 'UserCommandsShell';
                    mesh.cmdchild.stdout.on('data', function (c) { replydata += c.toString(); sendConsoleText(c.toString()); });
                    mesh.cmdchild.stderr.on('data', function (c) { replydata += c.toString(); sendConsoleText(c.toString()); });
                    mesh.cmdchild.stdin.write(data.cmds.split('\r').join('') + '\nexit\n');
                    mesh.cmdchild.on('exit', function () {
                        if (data.reply) {
                            mesh.SendCommand({ action: 'msg', type: 'runcommands', result: replydata, sessionid: data.sessionid, responseid: data.responseid });
                        } else {
                            sendConsoleText("Run commands completed.");
                        }
                        delete mesh.cmdchild;
                    });
                }
                break;
            }
            case 'uninstallagent':
                // Uninstall this agent
                var agentName = process.platform == 'win32' ? 'Mesh Agent' : 'meshagent';
                try {
                    agentName = require('MeshAgent').serviceName;
                } catch (ex) { }

                if (require('service-manager').manager.getService(agentName).isMe()) {
                    try { diagnosticAgent_uninstall(); } catch (ex) { }
                    var js = "require('service-manager').manager.getService('" + agentName + "').stop(); require('service-manager').manager.uninstallService('" + agentName + "'); process.exit();";
                    this.child = require('child_process').execFile(process.execPath, [process.platform == 'win32' ? (process.execPath.split('\\').pop()) : (process.execPath.split('/').pop()), '-b64exec', Buffer.from(js).toString('base64')], { type: 4, detached: true });
                }
                break;
            case 'poweraction': {
                // Server telling us to execute a power action
                if ((mesh.ExecPowerState != undefined) && (data.actiontype)) {
                    var forced = 0;
                    if (data.forced == 1) { forced = 1; }
                    data.actiontype = parseInt(data.actiontype);
                    MeshServerLogEx(25, [data.actiontype, forced], "Performing power action=" + data.actiontype + ", forced=" + forced, data);
                    sendConsoleText("Performing power action=" + data.actiontype + ", forced=" + forced + '.');
                    var r = mesh.ExecPowerState(data.actiontype, forced);
                    sendConsoleText("ExecPowerState returned code: " + r);
                }
                break;
            }
            case 'iplocation': {
                // Update the IP location information of this node. Only do this when requested by the server since we have a limited amount of time we can call this per day
                getIpLocationData(function (location) { mesh.SendCommand({ action: 'iplocation', type: 'publicip', value: location }); });
                break;
            }
            case 'toast': {
                // Display a toast message
                if (data.title && data.msg) {
                    MeshServerLogEx(26, [data.title, data.msg], "Displaying toast message, title=" + data.title + ", message=" + data.msg, data);
                    data.msg = data.msg.split('\r').join('\\r').split('\n').join('\\n');
                    try { require('toaster').Toast(data.title, data.msg); } catch (ex) { }
                }
                break;
            }
            case 'openUrl': {
                // Open a local web browser and return success/fail
                //sendConsoleText('OpenURL: ' + data.url);
                MeshServerLogEx(20, [data.url], "Opening: " + data.url, data);
                if (data.url) { mesh.SendCommand({ action: 'openUrl', url: data.url, sessionid: data.sessionid, success: (openUserDesktopUrl(data.url) != null) }); }
                break;
            }
            case 'amtconfig': {
                // Perform Intel AMT activation and/or configuration
                if ((apftunnel != null) || (amt == null) || (typeof data.user != 'string') || (typeof data.pass != 'string')) break;
                amt.getMeiState(15, function (state) {
                    if ((apftunnel != null) || (amt == null)) return;
                    if ((state == null) || (state.ProvisioningState == null)) return;
                    if ((state.UUID == null) || (state.UUID.length != 36)) return; // Bad UUID
                    getAmtOsDnsSuffix(state, function () {
                        var apfarg = {
                            mpsurl: mesh.ServerUrl.replace('/agent.ashx', '/apf.ashx'),
                            mpsuser: data.user, // Agent user name
                            mpspass: data.pass, // Encrypted login cookie
                            mpskeepalive: 60000,
                            clientname: state.OsHostname,
                            clientaddress: '127.0.0.1',
                            clientuuid: state.UUID,
                            conntype: 2, // 0 = CIRA, 1 = Relay, 2 = LMS. The correct value is 2 since we are performing an LMS relay, other values for testing.
                            meiState: state // MEI state will be passed to MPS server
                        };
                        addAmtEvent('LMS tunnel start.');
                        apftunnel = require('amt-apfclient')({ debug: false }, apfarg);
                        apftunnel.onJsonControl = handleApfJsonControl;
                        apftunnel.onChannelClosed = function () { addAmtEvent('LMS tunnel closed.'); apftunnel = null; }
                        try { apftunnel.connect(); } catch (ex) { }
                    });
                });
                break;
            }
            case 'sysinfo': {
                // Fetch system information
                getSystemInformation(function (results) {
                    if ((results != null) && (data.hash != results.hash)) { mesh.SendCommand({ action: 'sysinfo', sessionid: this.sessionid, data: results }); }
                });
                break;
            }
            case 'ping': { mesh.SendCommand('{"action":"pong"}'); break; }
            case 'pong': { break; }
            case 'plugin': {
                try { require(data.plugin).consoleaction(data, data.rights, data.sessionid, this); } catch (ex) { throw ex; }
                break;
            }
            case 'coredump':
                // Set the current agent coredump situation.s
                if (data.value === true) {
                    if (process.platform == 'win32') {
                        // TODO: This replace() below is not ideal, would be better to remove the .exe at the end instead of replace.
                        process.coreDumpLocation = process.execPath.replace('.exe', '.dmp');
                    } else {
                        process.coreDumpLocation = (process.cwd() != '//') ? (process.cwd() + 'core') : null;
                    }
                } else if (data.value === false) {
                    process.coreDumpLocation = null;
                }
                break;
            case 'getcoredump':
                // Ask the agent if a core dump is currently available, if yes, also return the hash of the agent.
                var r = { action: 'getcoredump', value: (process.coreDumpLocation != null) };
                var coreDumpPath = null;
                if (process.platform == 'win32') { coreDumpPath = process.coreDumpLocation; } else { coreDumpPath = (process.cwd() != '//') ? fs.existsSync(process.cwd() + 'core') : null; }
                if ((coreDumpPath != null) && (fs.existsSync(coreDumpPath))) {
                    try {
                        var coredate = fs.statSync(coreDumpPath).mtime;
                        var coretime = new Date(coredate).getTime();
                        var agenttime = new Date(fs.statSync(process.execPath).mtime).getTime();
                        if (coretime > agenttime) { r.exists = (db.Get('CoreDumpTime') != coredate); }
                    } catch (ex) { }
                }
                if (r.exists == true) {
                    r.agenthashhex = getSHA384FileHash(process.execPath).toString('hex'); // Hash of current agent
                    r.corehashhex = getSHA384FileHash(coreDumpPath).toString('hex'); // Hash of core dump file
                }
                mesh.SendCommand(JSON.stringify(r));
                break;
            case 'meshToolInfo':
                if (data.pipe == true) { delete data.pipe; delete data.action; data.cmd = 'meshToolInfo'; broadcastToRegisteredApps(data); }
                if (data.tag == 'info') { sendConsoleText(JSON.stringify(data, null, 2)); }
                if (data.tag == 'install') {
                    data.func = function (options, success) {
                        sendConsoleText('Download of MeshCentral Assistant ' + (success ? 'succeed' : 'failed'));
                        if (success) {
                            // TODO: Install & Run
                        }
                    }
                    data.filename = 'MeshAssistant.exe';
                    downloadFile(data);
                }
                break;
            case 'getUserImage':
                if (data.pipe == true) { delete data.pipe; delete data.action; data.cmd = 'getUserImage'; broadcastToRegisteredApps(data); }
                if (data.tag == 'info') { sendConsoleText(JSON.stringify(data, null, 2)); }
                if (data.promise != null && require('MeshAgent')._promises[data.promise] != null) {
                    var p = require('MeshAgent')._promises[data.promise];
                    delete require('MeshAgent')._promises[data.promise];
                    p.resolve(data.image);
                }
                break;
            case 'wget': // Server uses this command to tell the agent to download a file using HTTPS/GET and place it in a given path. This is used for one-to-many file uploads.
                agentFileHttpPendingRequests.push(data);
                serverFetchFile();
                break;
            case 'serverInfo': // Server information
                obj.serverInfo = data;
                delete obj.serverInfo.action;
                break;
            case 'errorlog': // Return agent error log
                try { mesh.SendCommand(JSON.stringify({ action: 'errorlog', log: require('util-agentlog').read(data.startTime) })); } catch (ex) { }
                break;
            default:
                // Unknown action, ignore it.
                break;
        }
    }
}

// On non-Windows platforms, we need to query the DHCP server for the DNS suffix
function getAmtOsDnsSuffix(mestate, func) {
    if ((process.platform == 'win32') || (mestate.net0 == null) || (mestate.net0.mac == null)) { func(mestate); return; }
    try { require('linux-dhcp') } catch (ex) { func(mestate); return; }
    require('linux-dhcp').client.info(mestate.net0.mac).then(function (d) {
        if ((typeof d.options == 'object') && (typeof d.options.domainname == 'string')) { mestate.OsDnsSuffix = d.options.domainname; }
        func(mestate);
    }, function (e) {
        console.log('DHCP error', e);
        func(mestate);
    });
}

// Download a file from the server and check the hash.
// This download is similar to the one used for meshcore self-update.
var trustedDownloads = {};
function downloadFile(downloadoptions) {
    var options = require('http').parseUri(downloadoptions.url);
    options.rejectUnauthorized = false;
    options.checkServerIdentity = function checkServerIdentity(certs) {
        // If the tunnel certificate matches the control channel certificate, accept the connection
        try { if (require('MeshAgent').ServerInfo.ControlChannelCertificate.digest == certs[0].digest) return; } catch (ex) { }
        try { if (require('MeshAgent').ServerInfo.ControlChannelCertificate.fingerprint == certs[0].fingerprint) return; } catch (ex) { }
        // Check that the certificate is the one expected by the server, fail if not.
        if (checkServerIdentity.servertlshash == null) { if (require('MeshAgent').ServerInfo == null || require('MeshAgent').ServerInfo.ControlChannelCertificate == null) return; throw new Error('BadCert'); }
        if (certs[0].digest == null) return;
        if ((checkServerIdentity.servertlshash != null) && (checkServerIdentity.servertlshash.toLowerCase() != certs[0].digest.split(':').join('').toLowerCase())) { throw new Error('BadCert') }
    }
    //options.checkServerIdentity.servertlshash = downloadoptions.serverhash;
    trustedDownloads[downloadoptions.name] = downloadoptions;
    trustedDownloads[downloadoptions.name].dl = require('https').get(options);
    trustedDownloads[downloadoptions.name].dl.on('error', function (e) { downloadoptions.func(downloadoptions, false); delete trustedDownloads[downloadoptions.name]; });
    trustedDownloads[downloadoptions.name].dl.on('response', function (img) {
        this._file = require('fs').createWriteStream(trustedDownloads[downloadoptions.name].filename, { flags: 'wb' });
        this._filehash = require('SHA384Stream').create();
        this._filehash.on('hash', function (h) { if ((downloadoptions.hash != null) && (downloadoptions.hash.toLowerCase() != h.toString('hex').toLowerCase())) { downloadoptions.func(downloadoptions, false); delete trustedDownloads[downloadoptions.name]; return; } downloadoptions.func(downloadoptions, true); });
        img.pipe(this._file);
        img.pipe(this._filehash);
    });
}

// Handle APF JSON control commands
function handleApfJsonControl(data) {
    if (data.action == 'console') { addAmtEvent(data.msg); } // Add console message to AMT event log
    if (data.action == 'mestate') { amt.getMeiState(15, function (state) { apftunnel.updateMeiState(state); }); } // Update the MEI state
    if (data.action == 'close') { try { apftunnel.disconnect(); } catch (ex) { } apftunnel = null; } // Close the CIRA-LMS connection
    if (amt.amtMei != null) {
        if (data.action == 'deactivate') { // Request CCM deactivation
            amt.amtMei.unprovision(1, function (status) { if (apftunnel) apftunnel.sendMeiDeactivationState(status); }); // 0 = Success
        }
        if (data.action == 'startTlsHostConfig') { // Request start of host based TLS ACM activation
            amt.amtMei.startConfigurationHBased(Buffer.from(data.hash, 'hex'), data.hostVpn, data.dnsSuffixList, function (response) { apftunnel.sendStartTlsHostConfigResponse(response); });
        }
        if (data.action == 'stopConfiguration') { // Request Intel AMT stop configuration.
            amt.amtMei.stopConfiguration(function (status) { apftunnel.sendStopConfigurationResponse(status); });
        }
    }
}

// Agent just get a file from the server and save it locally.
function serverFetchFile() {
    if ((Object.keys(agentFileHttpRequests).length > 4) || (agentFileHttpPendingRequests.length == 0)) return; // No more than 4 active HTTPS requests to the server.
    var data = agentFileHttpPendingRequests.shift();
    if ((data.overwrite !== true) && fs.existsSync(data.path)) return; // Don't overwrite an existing file.
    if (data.createFolder) { try { fs.mkdirSync(data.folder); } catch (ex) { } } // If requested, create the local folder.
    data.url = 'http' + getServerTargetUrlEx('*/').substring(2);
    var agentFileHttpOptions = http.parseUri(data.url);
    agentFileHttpOptions.path = data.urlpath;

    // Perform manual server TLS certificate checking based on the certificate hash given by the server.
    agentFileHttpOptions.rejectUnauthorized = 0;
    agentFileHttpOptions.checkServerIdentity = function checkServerIdentity(certs) {
        // If the tunnel certificate matches the control channel certificate, accept the connection
        try { if (require('MeshAgent').ServerInfo.ControlChannelCertificate.digest == certs[0].digest) return; } catch (ex) { }
        try { if (require('MeshAgent').ServerInfo.ControlChannelCertificate.fingerprint == certs[0].fingerprint) return; } catch (ex) { }
        // Check that the certificate is the one expected by the server, fail if not.
        if ((checkServerIdentity.servertlshash != null) && (checkServerIdentity.servertlshash.toLowerCase() != certs[0].digest.split(':').join('').toLowerCase())) { throw new Error('BadCert') }
    }
    agentFileHttpOptions.checkServerIdentity.servertlshash = data.servertlshash;

    if (agentFileHttpOptions == null) return;
    var agentFileHttpRequest = http.request(agentFileHttpOptions,
        function (response) {
            response.xparent = this;
            try {
                response.xfile = fs.createWriteStream(this.xpath, { flags: 'wbN' })
                response.pipe(response.xfile);
                response.end = function () { delete agentFileHttpRequests[this.xparent.xurlpath]; delete this.xparent; serverFetchFile(); }
            } catch (ex) { delete agentFileHttpRequests[this.xurlpath]; delete response.xparent; serverFetchFile(); return; }
        }
    );
    agentFileHttpRequest.on('error', function (ex) { sendConsoleText(ex); delete agentFileHttpRequests[this.xurlpath]; serverFetchFile(); });
    agentFileHttpRequest.end();
    agentFileHttpRequest.xurlpath = data.urlpath;
    agentFileHttpRequest.xpath = data.path;
    agentFileHttpRequests[data.urlpath] = agentFileHttpRequest;
}

// Called when a file changed in the file system
/*
function onFileWatcher(a, b) {
    console.log('onFileWatcher', a, b, this.path);
    var response = getDirectoryInfo(this.path);
    if ((response != undefined) && (response != null)) { this.tunnel.s.write(JSON.stringify(response)); }
}
*/

// Replace all key name spaces with _ in an object recursively.
// This is a workaround since require('computer-identifiers').get() returns key names with spaces in them on Linux.
function replaceSpacesWithUnderscoresRec(o) {
    if (typeof o != 'object') return;
    for (var i in o) { if (i.indexOf(' ') >= 0) { o[i.split(' ').join('_')] = o[i]; delete o[i]; } replaceSpacesWithUnderscoresRec(o[i]); }
}

function getSystemInformation(func) {
    try {
        var results = { hardware: require('computer-identifiers').get() }; // Hardware info
        if (results.hardware && results.hardware.windows) {
            // Remove extra entries and things that change quickly
            var x = results.hardware.windows.osinfo;
            try { delete x.FreePhysicalMemory; } catch (ex) { }
            try { delete x.FreeSpaceInPagingFiles; } catch (ex) { }
            try { delete x.FreeVirtualMemory; } catch (ex) { }
            try { delete x.LocalDateTime; } catch (ex) { }
            try { delete x.MaxProcessMemorySize; } catch (ex) { }
            try { delete x.TotalVirtualMemorySize; } catch (ex) { }
            try { delete x.TotalVisibleMemorySize; } catch (ex) { }
            try {
                if (results.hardware.windows.memory) { for (var i in results.hardware.windows.memory) { delete results.hardware.windows.memory[i].Node; } }
                if (results.hardware.windows.osinfo) { 
                    delete results.hardware.windows.osinfo.Node;
                    results.hardware.windows.osinfo.Domain = getDomainInfo().Domain;
                    results.hardware.windows.osinfo.PartOfDomain = getDomainInfo().PartOfDomain;
                    results.hardware.windows.osinfo.DomainState = getJoinState();
                }
                if (results.hardware.windows.partitions) { for (var i in results.hardware.windows.partitions) { delete results.hardware.windows.partitions[i].Node; } }
            } catch (ex) { }
            if (x.LastBootUpTime) { // detect windows uptime
                var thedate = {
                    year: parseInt(x.LastBootUpTime.substring(0, 4)),
                    month: parseInt(x.LastBootUpTime.substring(4, 6)) - 1, // Months are 0-based in JavaScript (0 - January, 11 - December)
                    day: parseInt(x.LastBootUpTime.substring(6, 8)),
                    hours: parseInt(x.LastBootUpTime.substring(8, 10)),
                    minutes: parseInt(x.LastBootUpTime.substring(10, 12)),
                    seconds: parseInt(x.LastBootUpTime.substring(12, 14)),
                };
                var thelastbootuptime = new Date(thedate.year, thedate.month, thedate.day, thedate.hours, thedate.minutes, thedate.seconds);
                meshCoreObj.lastbootuptime = thelastbootuptime.getTime(); // store the last boot up time in coreinfo for columns
                meshCoreObjChanged();
                var nowtime = new Date();
                var differenceInMilliseconds = Math.abs(thelastbootuptime - nowtime);
                if (differenceInMilliseconds < 300000) { // computer uptime less than 5 minutes
                    MeshServerLogEx(159, [thelastbootuptime.toString()], "Device Powered On", null);
                }
            }
        }
        if(results.hardware && results.hardware.linux) {
            if(results.hardware.linux.LastBootUpTime) {
                var thelastbootuptime = new Date(results.hardware.linux.LastBootUpTime);
                meshCoreObj.lastbootuptime = thelastbootuptime.getTime(); // store the last boot up time in coreinfo for columns
                meshCoreObjChanged();
                var nowtime = new Date();
                var differenceInMilliseconds = Math.abs(thelastbootuptime - nowtime);
                if (differenceInMilliseconds < 300000) { // computer uptime less than 5 minutes
                    MeshServerLogEx(159, [thelastbootuptime.toString()], "Device Powered On", null);
                }
            }
        }
        if(results.hardware && results.hardware.darwin){
            if(results.hardware.darwin.LastBootUpTime) {
                var thelastbootuptime = new Date(results.hardware.darwin.LastBootUpTime * 1000); // must times by 1000 even tho timestamp is correct?
                meshCoreObj.lastbootuptime = thelastbootuptime.getTime(); // store the last boot up time in coreinfo for columns
                meshCoreObjChanged();
                var nowtime = new Date();
                var differenceInMilliseconds = Math.abs(thelastbootuptime - nowtime);
                if (differenceInMilliseconds < 300000) { // computer uptime less than 5 minutes
                    MeshServerLogEx(159, [thelastbootuptime.toString()], "Device Powered On", null);
                }
            }
        }    
        results.hardware.agentvers = process.versions;
        results.hardware.network = { dns: require('os').dns() }; 
        replaceSpacesWithUnderscoresRec(results);
        var hasher = require('SHA384Stream').create();

        var finalizeResults = function ()
        {
            results.hash = hasher.syncHash(JSON.stringify(results)).toString('hex');
            func(results);
        };

        // On Windows platforms, get volume information - Needs more testing.
        if (process.platform == 'win32')
        {
            results.pendingReboot = require('win-info').pendingReboot(); // Pending reboot
            if (require('win-volumes').volumes_promise != null)
            {
                var p = require('win-volumes').volumes_promise();
                p.then(function (res) {
                    if (res && res.drives) { try { results.hardware.windows.volumes = cleanGetBitLockerVolumeInfo(res.drives); } catch (ex) { } }
                    finalizeResults();
                });
            }
            else
            {
                finalizeResults();
            }
        }
        else
        {
            finalizeResults();
        }
        
    } catch (ex) { func(null, ex); }
}

// Get a formatted response for a given directory path
function getDirectoryInfo(reqpath) {
    var response = { path: reqpath, dir: [] };
    if (((reqpath == undefined) || (reqpath == '')) && (process.platform == 'win32')) {
        // List all the drives in the root, or the root itself
        var results = null;
        try { results = fs.readDrivesSync(); } catch (ex) { }
        if (results != null) {
            for (var i = 0; i < results.length; ++i) {
                var drive = { n: results[i].name, t: 1, dt: results[i].type, s: (results[i].size ? results[i].size : 0), f: (results[i].free ? results[i].free : 0) };
                response.dir.push(drive);
            }
        }
    } else {
        // List all the files and folders in this path
        if (reqpath == '') { reqpath = '/'; }
        var results = null, xpath = obj.path.join(reqpath, '*');
        //if (process.platform == "win32") { xpath = xpath.split('/').join('\\'); }
        try { results = fs.readdirSync(xpath); } catch (ex) { }
        try { if ((results != null) && (results.length == 0) && (fs.existsSync(reqpath) == false)) { results = null; } } catch (ex) { }
        if (results != null) {
            for (var i = 0; i < results.length; ++i) {
                if ((results[i] != '.') && (results[i] != '..')) {
                    var stat = null, p = obj.path.join(reqpath, results[i]);
                    //if (process.platform == "win32") { p = p.split('/').join('\\'); }
                    try { stat = fs.statSync(p); } catch (ex) { } // TODO: Get file size/date
                    if ((stat != null) && (stat != undefined)) {
                        if (stat.isDirectory() == true) {
                            response.dir.push({ n: results[i], t: 2, d: stat.mtime });
                        } else {
                            response.dir.push({ n: results[i], t: 3, s: stat.size, d: stat.mtime });
                        }
                    }
                }
            }
        } else {
            response.dir = null;
        }
    }
    return response;
}

function tunnel_s_finalized()
{
    console.info1('Tunnel Socket Finalized');
}


function tunnel_onIdleTimeout()
{
    this.ping();
    this.setTimeout(require('MeshAgent').idleTimeout * 1000);
}

// Tunnel callback operations
function onTunnelUpgrade(response, s, head)
{

    this.s = s;
    s.once('~', tunnel_s_finalized);
    s.httprequest = this;
    s.end = onTunnelClosed;
    s.tunnel = this;
    s.descriptorMetadata = "MeshAgent_relayTunnel";


    if (require('MeshAgent').idleTimeout != null)
    {
        s.setTimeout(require('MeshAgent').idleTimeout * 1000);
        s.on('timeout', tunnel_onIdleTimeout);
    }

    //sendConsoleText('onTunnelUpgrade - ' + this.tcpport + ' - ' + this.udpport);

    if (this.tcpport != null) {
        // This is a TCP relay connection, pause now and try to connect to the target.
        s.pause();
        s.data = onTcpRelayServerTunnelData;
        var connectionOptions = { port: parseInt(this.tcpport) };
        if (this.tcpaddr != null) { connectionOptions.host = this.tcpaddr; } else { connectionOptions.host = '127.0.0.1'; }
        s.tcprelay = net.createConnection(connectionOptions, onTcpRelayTargetTunnelConnect);
        s.tcprelay.peerindex = this.index;

        // Add the TCP session to the count and update the server
        if (s.httprequest.userid != null) {
            var userid = getUserIdAndGuestNameFromHttpRequest(s.httprequest);
            if (tunnelUserCount.tcp[userid] == null) { tunnelUserCount.tcp[userid] = 1; } else { tunnelUserCount.tcp[userid]++; }
            try { mesh.SendCommand({ action: 'sessions', type: 'tcp', value: tunnelUserCount.tcp }); } catch (ex) { }
            broadcastSessionsToRegisteredApps();
        }
    }
    if (this.udpport != null) {
        // This is a UDP relay connection, get the UDP socket setup. // TODO: ***************
        s.data = onUdpRelayServerTunnelData;
        s.udprelay = require('dgram').createSocket({ type: 'udp4' });
        s.udprelay.bind({ port: 0 });
        s.udprelay.peerindex = this.index;
        s.udprelay.on('message', onUdpRelayTargetTunnelConnect);
        s.udprelay.udpport = this.udpport;
        s.udprelay.udpaddr = this.udpaddr;
        s.udprelay.first = true;

        // Add the UDP session to the count and update the server
        if (s.httprequest.userid != null) {
            var userid = getUserIdAndGuestNameFromHttpRequest(s.httprequest);
            if (tunnelUserCount.udp[userid] == null) { tunnelUserCount.udp[userid] = 1; } else { tunnelUserCount.udp[userid]++; }
            try { mesh.SendCommand({ action: 'sessions', type: 'udp', value: tunnelUserCount.tcp }); } catch (ex) { }
            broadcastSessionsToRegisteredApps();
        }
    }
    else {
        // This is a normal connect for KVM/Terminal/Files
        s.data = onTunnelData;
    }
}

// If the HTTP Request has a guest name, we need to form a userid that includes the guest name in hex.
// This is so we can tell the server that a session is for a given userid/guest sharing pair.
function getUserIdAndGuestNameFromHttpRequest(request) {
    if (request.guestname == null) return request.userid; else return request.guestuserid + '/guest:' + Buffer.from(request.guestname).toString('base64');
}

// Called when UDP relay data is received // TODO****
function onUdpRelayTargetTunnelConnect(data) {
    var peerTunnel = tunnels[this.peerindex];
    peerTunnel.s.write(data);
}

// Called when we get data from the server for a TCP relay (We have to skip the first received 'c' and pipe the rest)
function onUdpRelayServerTunnelData(data) {
    if (this.udprelay.first === true) {
        delete this.udprelay.first; // Skip the first 'c' that is received.
    } else {
        this.udprelay.send(data, parseInt(this.udprelay.udpport), this.udprelay.udpaddr ? this.udprelay.udpaddr : '127.0.0.1');
    }
}

// Called when the TCP relay target is connected
function onTcpRelayTargetTunnelConnect() {
    var peerTunnel = tunnels[this.peerindex];
    this.pipe(peerTunnel.s); // Pipe Target --> Server
    peerTunnel.s.first = true;
    peerTunnel.s.resume();
}

// Called when we get data from the server for a TCP relay (We have to skip the first received 'c' and pipe the rest)
function onTcpRelayServerTunnelData(data) {
    if (this.first == true) {
        this.first = false;
        this.pipe(this.tcprelay, { dataTypeSkip: 1 }); // Pipe Server --> Target (don't pipe text type websocket frames)
    }
}

function onTunnelClosed()
{
    if (this.httprequest._dispatcher != null && this.httprequest.term == null)
    {
        // Windows Dispatcher was created to spawn a child connection, but the child didn't connect yet, so we have to shutdown the dispatcher, otherwise the child may end up hanging
        if (this.httprequest._dispatcher.close) { this.httprequest._dispatcher.close(); }
        this.httprequest._dispatcher = null;
    }

    if (this.tunnel)
    {
        if (tunnels[this.httprequest.index] == null)
        {
            this.tunnel.s = null;
            this.tunnel = null;
            return;
        }
    }

    var tunnel = tunnels[this.httprequest.index];
    if (tunnel == null) return; // Stop duplicate calls.

    // Perform display locking on disconnect
    if ((this.httprequest.protocol == 2) && (this.httprequest.autolock === true)) {
        // Look for a TSID
        var tsid = null;
        if ((this.httprequest.xoptions != null) && (typeof this.httprequest.xoptions.tsid == 'number')) { tsid = this.httprequest.xoptions.tsid; }

        // Lock the current user out of the desktop
        MeshServerLogEx(53, null, "Locking remote user out of desktop", this.httprequest);
        lockDesktop(tsid);
    }

    // If this is a routing session, clean up and send the new session counts.
    if (this.httprequest.userid != null) {
        if (this.httprequest.tcpport != null) {
            var userid = getUserIdAndGuestNameFromHttpRequest(this.httprequest);
            if (tunnelUserCount.tcp[userid] != null) { tunnelUserCount.tcp[userid]--; if (tunnelUserCount.tcp[userid] <= 0) { delete tunnelUserCount.tcp[userid]; } }
            try { mesh.SendCommand({ action: 'sessions', type: 'tcp', value: tunnelUserCount.tcp }); } catch (ex) { }
            broadcastSessionsToRegisteredApps();
        } else if (this.httprequest.udpport != null) {
            var userid = getUserIdAndGuestNameFromHttpRequest(this.httprequest);
            if (tunnelUserCount.udp[userid] != null) { tunnelUserCount.udp[userid]--; if (tunnelUserCount.udp[userid] <= 0) { delete tunnelUserCount.udp[userid]; } }
            try { mesh.SendCommand({ action: 'sessions', type: 'udp', value: tunnelUserCount.udp }); } catch (ex) { }
            broadcastSessionsToRegisteredApps();
        }
    }

    try {
        // Sent tunnel statistics to the server, only send this if compression was used.
        if ((this.bytesSent_uncompressed) && (this.bytesSent_uncompressed.toString() != this.bytesSent_actual.toString())) {
            mesh.SendCommand({
                action: 'tunnelCloseStats',
                url: tunnel.url,
                userid: tunnel.userid,
                protocol: tunnel.protocol,
                sessionid: tunnel.sessionid,
                sent: this.bytesSent_uncompressed.toString(),
                sentActual: this.bytesSent_actual.toString(),
                sentRatio: this.bytesSent_ratio,
                received: this.bytesReceived_uncompressed.toString(),
                receivedActual: this.bytesReceived_actual.toString(),
                receivedRatio: this.bytesReceived_ratio
            });
        }
    } catch (ex) { }

    //sendConsoleText("Tunnel #" + this.httprequest.index + " closed. Sent -> " + this.bytesSent_uncompressed + ' bytes (uncompressed), ' + this.bytesSent_actual + ' bytes (actual), ' + this.bytesSent_ratio + '% compression', this.httprequest.sessionid);
    

    /*
    // Close the watcher if required
    if (this.httprequest.watcher != undefined) {
        //console.log('Closing watcher: ' + this.httprequest.watcher.path);
        //this.httprequest.watcher.close(); // TODO: This line causes the agent to crash!!!!
        delete this.httprequest.watcher;
    }
    */

    // If there is a upload or download active on this connection, close the file
    if (this.httprequest.uploadFile) { fs.closeSync(this.httprequest.uploadFile); delete this.httprequest.uploadFile; delete this.httprequest.uploadFileid; delete this.httprequest.uploadFilePath; delete this.httprequest.uploadFileSize; }
    if (this.httprequest.downloadFile) { delete this.httprequest.downloadFile; }

    // Clean up WebRTC
    if (this.webrtc != null) {
        if (this.webrtc.rtcchannel) { try { this.webrtc.rtcchannel.close(); } catch (ex) { } this.webrtc.rtcchannel.removeAllListeners('data'); this.webrtc.rtcchannel.removeAllListeners('end'); delete this.webrtc.rtcchannel; }
        if (this.webrtc.websocket) { delete this.webrtc.websocket; }
        try { this.webrtc.close(); } catch (ex) { }
        this.webrtc.removeAllListeners('connected');
        this.webrtc.removeAllListeners('disconnected');
        this.webrtc.removeAllListeners('dataChannel');
        delete this.webrtc;
    }

    // Clean up WebSocket
    delete tunnels[this.httprequest.index];
    tunnel = null;
    this.tunnel.s = null;
    this.tunnel = null;
    this.removeAllListeners('data');
}
function onTunnelSendOk() { /*sendConsoleText("Tunnel #" + this.index + " SendOK.", this.sessionid);*/ }

function terminal_onconnection (c)
{
    if (this.httprequest.connectionPromise.completed) 
    {
        c.end(); 
    }
    else
    {
        this.httprequest.connectionPromise._res(c);
    }
}
function terminal_user_onconnection(c)
{
    console.info1('completed-2: ' + this.connectionPromise.completed);

    if (this.connectionPromise.completed)
    {
        c.end();
    }
    else
    {
        this.connectionPromise._res(c);
    }
}
function terminal_stderr_ondata(c)
{
    this.stdout.write(c);
}
function terminal_onend()
{
    this.httprequest.process.kill();
}

function terminal_onexit()
{
    this.tunnel.end();
}
function terminal_onfinalized()
{
    this.httprequest = null;
    console.info1('Dispatcher Finalized');
}
function terminal_end()
{
    if (this.httprequest == null) { return; }
    if (this.httprequest.tpromise._consent) { this.httprequest.tpromise._consent.close(); }
    if (this.httprequest.connectionPromise) { this.httprequest.connectionPromise._rej('Closed'); }

    // Remove the terminal session to the count to update the server
    if (this.httprequest.userid != null)
    {
        var userid = getUserIdAndGuestNameFromHttpRequest(this.httprequest);
        if (tunnelUserCount.terminal[userid] != null) { tunnelUserCount.terminal[userid]--; if (tunnelUserCount.terminal[userid] <= 0) { delete tunnelUserCount.terminal[userid]; } }
        try { mesh.SendCommand({ action: 'sessions', type: 'terminal', value: tunnelUserCount.terminal }); } catch (ex) { }
        broadcastSessionsToRegisteredApps();
    }

    if (process.platform == 'win32')
    {
        // Unpipe the web socket
        this.unpipe(this.httprequest._term);
        if (this.httprequest._term) { this.httprequest._term.unpipe(this); }

        // Unpipe the WebRTC channel if needed (This will also be done when the WebRTC channel ends).
        if (this.rtcchannel)
        {
            this.rtcchannel.unpipe(this.httprequest._term);
            if (this.httprequest._term) { this.httprequest._term.unpipe(this.rtcchannel); }
        }

        // Clean up
        if (this.httprequest._term) { this.httprequest._term.end(); }
        this.httprequest._term = null;
        this.httprequest._dispatcher = null;
    }

    this.httprequest = null;

}

function terminal_consent_ask(ws) {
    ws.write(JSON.stringify({ ctrlChannel: '102938', type: 'console', msg: "Waiting for user to grant access...", msgid: 1 }));
    var consentMessage = currentTranslation['terminalConsent'].replace(/\{0\}/g, ws.httprequest.realname).replace(/\{1\}/g, ws.httprequest.username);
    var consentTitle = 'MeshCentral';
    if (ws.httprequest.soptions != null) {
        if (ws.httprequest.soptions.consentTitle != null) { consentTitle = ws.httprequest.soptions.consentTitle; }
        if (ws.httprequest.soptions.consentMsgTerminal != null) { consentMessage = ws.httprequest.soptions.consentMsgTerminal.replace(/\{0\}/g, ws.httprequest.realname).replace(/\{1\}/g, ws.httprequest.username); }
    }
    if (process.platform == 'win32') {
        var enhanced = false;
        if (ws.httprequest.oldStyle === false) {
            try { require('win-userconsent'); enhanced = true; } catch (ex) { }
        }
        if (enhanced) {
            var ipr = server_getUserImage(ws.httprequest.userid);
            ipr.consentTitle = consentTitle;
            ipr.consentMessage = consentMessage;
            ipr.consentTimeout = ws.httprequest.consentTimeout;
            ipr.consentAutoAccept = ws.httprequest.consentAutoAccept;
            ipr.username = ws.httprequest.realname;
            ipr.tsid = ws.tsid;
            ipr.translations = { Allow: currentTranslation['allow'], Deny: currentTranslation['deny'], Auto: currentTranslation['autoAllowForFive'], Caption: consentMessage };
            ws.httprequest.tpromise._consent = ipr.then(function (img) {
                this.consent = require('win-userconsent').create(this.consentTitle, this.consentMessage, this.username, { b64Image: img.split(',').pop(), uid: this.tsid, timeout: this.consentTimeout * 1000, timeoutAutoAccept: this.consentAutoAccept, translations: this.translations, background: color_options.background, foreground: color_options.foreground });
                this.__childPromise.close = this.consent.close.bind(this.consent);
                return (this.consent);
            });
        } else {
            ws.httprequest.tpromise._consent = require('message-box').create(consentTitle, consentMessage, ws.httprequest.consentTimeout);
        }
    } else {
        ws.httprequest.tpromise._consent = require('message-box').create(consentTitle, consentMessage, ws.httprequest.consentTimeout);
    }
    ws.httprequest.tpromise._consent.retPromise = ws.httprequest.tpromise;
    ws.httprequest.tpromise._consent.then(function (always) {
        if (always && process.platform == 'win32') { server_set_consentTimer(this.retPromise.httprequest.userid); }
        // Success
        MeshServerLogEx(27, null, "Local user accepted remote terminal request (" + this.retPromise.httprequest.remoteaddr + ")", this.retPromise.that.httprequest);
        this.retPromise.that.write(JSON.stringify({ ctrlChannel: '102938', type: 'console', msg: null, msgid: 0 }));
        this.retPromise._consent = null;
        this.retPromise._res();
    }, function (e) {
        if (this.retPromise.that) {
            if(this.retPromise.that.httprequest){ // User Consent Denied
                MeshServerLogEx(28, null, "Local user rejected remote terminal request (" + this.retPromise.that.httprequest.remoteaddr + ")", this.retPromise.that.httprequest);
            } else { } // Connection was closed server side, maybe log some messages somewhere?
            this.retPromise._consent = null;
            this.retPromise.that.write(JSON.stringify({ ctrlChannel: '102938', type: 'console', msg: e.toString(), msgid: 2 }));
        } else { } // no websocket, maybe log some messages somewhere?
        this.retPromise._rej(e.toString());
    });
}

function terminal_promise_connection_rejected(e)
{
    // FAILED to connect terminal
    this.ws.write(JSON.stringify({ ctrlChannel: '102938', type: 'console', msg: e.toString(), msgid: 2 }));
    this.ws.end();
}

function terminal_promise_connection_resolved(term)
{
    this._internal.completedArgs = [];

    // SUCCESS
    var stdoutstream;
    var stdinstream;
    if (process.platform == 'win32')
    {
        this.ws.httprequest._term = term;
        this.ws.httprequest._term.tunnel = this.ws;
        stdoutstream = stdinstream = term;
    }
    else
    {
        term.descriptorMetadata = 'Remote Terminal';
        this.ws.httprequest.process = term;
        this.ws.httprequest.process.tunnel = this.ws;
        term.stderr.stdout = term.stdout;
        term.stderr.on('data', terminal_stderr_ondata);
        stdoutstream = term.stdout;
        stdinstream = term.stdin;
        this.ws.prependListener('end', terminal_onend);
        term.prependListener('exit', terminal_onexit);
    }

    this.ws.removeAllListeners('data');
    this.ws.on('data', onTunnelControlData);

    stdoutstream.pipe(this.ws, { dataTypeSkip: 1 });            // 0 = Binary, 1 = Text.
    this.ws.pipe(stdinstream, { dataTypeSkip: 1, end: false }); // 0 = Binary, 1 = Text. 

    // Add the terminal session to the count to update the server
    if (this.ws.httprequest.userid != null)
    {
        var userid = getUserIdAndGuestNameFromHttpRequest(this.ws.httprequest);
        if (tunnelUserCount.terminal[userid] == null) { tunnelUserCount.terminal[userid] = 1; } else { tunnelUserCount.terminal[userid]++; }
        try { mesh.SendCommand({ action: 'sessions', type: 'terminal', value: tunnelUserCount.terminal }); } catch (ex) { }
        broadcastSessionsToRegisteredApps();
    }

    // Toast Notification, if required
    if (this.ws.httprequest.consent && (this.ws.httprequest.consent & 2))
    {
        // User Notifications is required
        var notifyMessage = currentTranslation['terminalNotify'].replace(/\{0\}/g, this.ws.httprequest.realname ? this.ws.httprequest.realname : this.ws.httprequest.username);
        var notifyTitle = "MeshCentral";
        if (this.ws.httprequest.soptions != null)
        {
            if (this.ws.httprequest.soptions.notifyTitle != null) { notifyTitle = this.ws.httprequest.soptions.notifyTitle; }
            if (this.ws.httprequest.soptions.notifyMsgTerminal != null) { notifyMessage = this.ws.httprequest.soptions.notifyMsgTerminal.replace(/\{0\}/g, this.ws.httprequest.realname).replace(/\{1\}/g, this.ws.httprequest.username); }
        }
        try { require('toaster').Toast(notifyTitle, notifyMessage); } catch (ex) { }
    }
    this.ws = null;
}
function terminal_promise_consent_rejected(e)
{
    // DO NOT start terminal
    if (this.that) {
        if(this.that.httprequest){ // User Consent Denied
            if ((this.that.httprequest.oldStyle === true) && (this.that.httprequest.consentAutoAccept === true) && (e.toString() != "7")) {
                terminal_promise_consent_resolved.call(this); // oldStyle prompt timed out and User Consent is not required so connect anyway
                return;
            }
        } else { } // Connection was closed server side, maybe log some messages somewhere?
        this.that.write(JSON.stringify({ ctrlChannel: '102938', type: 'console', msg: e.toString(), msgid: 2 }));
        this.that.end();
        
        this.that = null;
        this.httprequest = null;
    } else { } // no websocket, maybe log some messages somewhere?
}
function promise_init(res, rej) { this._res = res; this._rej = rej; }
function terminal_userpromise_resolved(u)
{

    var that = this.that;
    if (u.Active.length > 0)
    {
        var tmp;
        var username = '"' + u.Active[0].Domain + '\\' + u.Active[0].Username + '"';


        if (require('win-virtual-terminal').supported)
        {
            // ConPTY PseudoTerminal
            tmp = require('win-dispatcher').dispatch({ user: username, modules: [{ name: 'win-virtual-terminal', script: getJSModule('win-virtual-terminal') }], launch: { module: 'win-virtual-terminal', method: (that.httprequest.protocol == 9 ? 'StartPowerShell' : 'Start'), args: [this.cols, this.rows] } });
        }
        else
        {
            // Legacy Terminal
            tmp = require('win-dispatcher').dispatch({ user: username, modules: [{ name: 'win-terminal', script: getJSModule('win-terminal') }], launch: { module: 'win-terminal', method: (that.httprequest.protocol == 9 ? 'StartPowerShell' : 'Start'), args: [this.cols, this.rows] } });
        }
        that.httprequest._dispatcher = tmp;
        that.httprequest._dispatcher.connectionPromise = that.httprequest.connectionPromise;
        that.httprequest._dispatcher.on('connection', terminal_user_onconnection);
        that.httprequest._dispatcher.on('~', terminal_onfinalized);
    }
    this.that = null;
    that = null;
}

function terminal_promise_consent_resolved()
{
    this.httprequest.connectionPromise = new promise(promise_init);
    this.httprequest.connectionPromise.ws = this.that;

    // Start Terminal
    if (process.platform == 'win32')
    {
        try
        {
            var cols = 80, rows = 25;
            if (this.httprequest.xoptions)
            {
                if (this.httprequest.xoptions.rows) { rows = this.httprequest.xoptions.rows; }
                if (this.httprequest.xoptions.cols) { cols = this.httprequest.xoptions.cols; }
            }

            if ((this.httprequest.protocol == 1) || (this.httprequest.protocol == 6))
            {
                // Admin Terminal
                if (require('win-virtual-terminal').supported)
                {
                    // ConPTY PseudoTerminal
                    // this.httprequest._term = require('win-virtual-terminal')[this.httprequest.protocol == 6 ? 'StartPowerShell' : 'Start'](80, 25);

                    // The above line is commented out, because there is a bug with ClosePseudoConsole() API, so this is the workaround
                    this.httprequest._dispatcher = require('win-dispatcher').dispatch({ modules: [{ name: 'win-virtual-terminal', script: getJSModule('win-virtual-terminal') }], launch: { module: 'win-virtual-terminal', method: (this.httprequest.protocol == 6 ? 'StartPowerShell' : 'Start'), args: [cols, rows] } });
                    this.httprequest._dispatcher.httprequest = this.httprequest;
                    this.httprequest._dispatcher.on('connection', terminal_onconnection);
                    this.httprequest._dispatcher.on('~', terminal_onfinalized);
                }
                else
                {
                    // Legacy Terminal
                    this.httprequest.connectionPromise._res(require('win-terminal')[this.httprequest.protocol == 6 ? 'StartPowerShell' : 'Start'](cols, rows));
                }
            }
            else
            {
                // Logged in user
                var userPromise = require('user-sessions').enumerateUsers();
                userPromise.that = this;
                userPromise.cols = cols;
                userPromise.rows = rows;
                userPromise.then(terminal_userpromise_resolved);
            }
        } catch (ex)
        {
            this.httprequest.connectionPromise._rej('Failed to start remote terminal session, ' + ex.toString());
        }
    }
    else
    {
        try
        {
            var bash = fs.existsSync('/bin/bash') ? '/bin/bash' : false;
            var sh = fs.existsSync('/bin/sh') ? '/bin/sh' : false;
            var login = process.platform == 'linux' ? '/bin/login' : '/usr/bin/login';

            var env = { HISTCONTROL: 'ignoreboth' };
            if (process.env['LANG']) { env['LANG'] = process.env['LANG']; }
            if (process.env['PATH']) { env['PATH'] = process.env['PATH']; }
            if (typeof this.httprequest.terminalUserVariable == 'string' && this.httprequest.terminalUserVariable != '') {
                if (this.httprequest.terminalUserVariable == 'realname') {
                    env['MESHCENTRAL_USER'] = (this.httprequest.realname ? this.httprequest.realname : 'unknown');
                } else if (this.httprequest.terminalUserVariable == 'identifier') {
                    env['MESHCENTRAL_USER'] = (this.httprequest.userid ? this.httprequest.userid : (this.httprequest.guestuserid ? 'deviceshare:' + this.httprequest.guestuserid : 'unknown'));
                } else if (this.httprequest.terminalUserVariable == 'username') {
                    env['MESHCENTRAL_USER'] = (this.httprequest.username ? this.httprequest.username : 'unknown');
                }
            }
            if (this.httprequest.xoptions)
            {
                if (this.httprequest.xoptions.rows) { env.LINES = ('' + this.httprequest.xoptions.rows); }
                if (this.httprequest.xoptions.cols) { env.COLUMNS = ('' + this.httprequest.xoptions.cols); }
            }
            var options = { type: childProcess.SpawnTypes.TERM, uid: (this.httprequest.protocol == 8) ? require('user-sessions').consoleUid() : null, env: env };
            if (this.httprequest.xoptions && this.httprequest.xoptions.requireLogin)
            {
                if (!require('fs').existsSync(login)) { throw ('Unable to spawn login process'); }
                this.httprequest.connectionPromise._res(childProcess.execFile(login, ['login'], options)); // Start login shell
            }
            else if (bash)
            {
                var p = childProcess.execFile(bash, ['bash'], options); // Start bash
                // Spaces at the beginning of lines are needed to hide commands from the command history
                if ((obj.serverInfo.termlaunchcommand != null) && (typeof obj.serverInfo.termlaunchcommand[process.platform] == 'string'))
                {
                    if (obj.serverInfo.termlaunchcommand[process.platform] != '') { p.stdin.write(obj.serverInfo.termlaunchcommand[process.platform]); }
                } else if (process.platform == 'linux') { p.stdin.write(' alias ls=\'ls --color=auto\';clear\n'); }
                this.httprequest.connectionPromise._res(p);
            }
            else if (sh)
            {
                var p = childProcess.execFile(sh, ['sh'], options); // Start sh
                // Spaces at the beginning of lines are needed to hide commands from the command history
                if ((obj.serverInfo.termlaunchcommand != null) && (typeof obj.serverInfo.termlaunchcommand[process.platform] == 'string'))
                {
                    if (obj.serverInfo.termlaunchcommand[process.platform] != '') { p.stdin.write(obj.serverInfo.termlaunchcommand[process.platform]); }
                } else if (process.platform == 'linux') { p.stdin.write(' alias ls=\'ls --color=auto\';clear\n'); }
                this.httprequest.connectionPromise._res(p);
            }
            else
            {
                this.httprequest.connectionPromise._rej('Failed to start remote terminal session, no shell found');
            }
        } catch (ex)
        {
            this.httprequest.connectionPromise._rej('Failed to start remote terminal session, ' + ex.toString());
        }
    }

    this.httprequest.connectionPromise.then(terminal_promise_connection_resolved, terminal_promise_connection_rejected);
    this.that = null;
    this.httprequest = null;
}
function tunnel_kvm_end()
{
    --this.desktop.kvm.connectionCount;

    // Remove ourself from the list of remote desktop session
    var i = this.desktop.kvm.tunnels.indexOf(this);
    if (i >= 0) { this.desktop.kvm.tunnels.splice(i, 1); }

    // Send a metadata update to all desktop sessions
    var users = {};
    if (this.httprequest.desktop.kvm.tunnels != null)
    {
        for (var i in this.httprequest.desktop.kvm.tunnels)
        {
            try
            {
                var userid = getUserIdAndGuestNameFromHttpRequest(this.httprequest.desktop.kvm.tunnels[i].httprequest);
                if (users[userid] == null) { users[userid] = 1; } else { users[userid]++; }
            } catch (ex) { sendConsoleText(ex); }
        }
        for (var i in this.httprequest.desktop.kvm.tunnels)
        {
            try { this.httprequest.desktop.kvm.tunnels[i].write(JSON.stringify({ ctrlChannel: '102938', type: 'metadata', users: users })); } catch (ex) { }
        }
        tunnelUserCount.desktop = users;
        try { mesh.SendCommand({ action: 'sessions', type: 'kvm', value: users }); } catch (ex) { }
        broadcastSessionsToRegisteredApps();
    }

    // Unpipe the web socket
    try
    {
        this.unpipe(this.httprequest.desktop.kvm);
        this.httprequest.desktop.kvm.unpipe(this);
    } catch (ex) { }

    // Unpipe the WebRTC channel if needed (This will also be done when the WebRTC channel ends).
    if (this.rtcchannel)
    {
        try
        {
            this.rtcchannel.unpipe(this.httprequest.desktop.kvm);
            this.httprequest.desktop.kvm.unpipe(this.rtcchannel);
        }
        catch (ex) { }
    }

    // Place wallpaper back if needed
    // TODO

    if (this.desktop.kvm.connectionCount == 0)
    {
        // Display a toast message. This may not be supported on all platforms.
        // try { require('toaster').Toast('MeshCentral', 'Remote Desktop Control Ended.'); } catch (ex) { }

        this.httprequest.desktop.kvm.end();
        if (this.httprequest.desktop.kvm.connectionBar)
        {
            this.httprequest.desktop.kvm.connectionBar.removeAllListeners('close');
            this.httprequest.desktop.kvm.connectionBar.close();
            this.httprequest.desktop.kvm.connectionBar = null;
        }
    } else
    {
        for (var i in this.httprequest.desktop.kvm.users)
        {
            if ((this.httprequest.desktop.kvm.users[i] == this.httprequest.username) && this.httprequest.desktop.kvm.connectionBar)
            {
                for (var j in this.httprequest.desktop.kvm.rusers) { if (this.httprequest.desktop.kvm.rusers[j] == this.httprequest.realname) { this.httprequest.desktop.kvm.rusers.splice(j, 1); break; } }
                this.httprequest.desktop.kvm.users.splice(i, 1);
                this.httprequest.desktop.kvm.connectionBar.removeAllListeners('close');
                this.httprequest.desktop.kvm.connectionBar.close();
                this.httprequest.desktop.kvm.connectionBar = require('notifybar-desktop')(this.httprequest.privacybartext.replace(/\{0\}/g, this.httprequest.desktop.kvm.rusers.join(', ')).replace(/\{1\}/g, this.httprequest.desktop.kvm.users.join(', ')).replace(/'/g, "\\'\\"), require('MeshAgent')._tsid, color_options);
                this.httprequest.desktop.kvm.connectionBar.httprequest = this.httprequest;
                this.httprequest.desktop.kvm.connectionBar.on('close', function ()
                {
                    MeshServerLogEx(29, null, "Remote Desktop Connection forcefully closed by local user (" + this.httprequest.remoteaddr + ")", this.httprequest);
                    for (var i in this.httprequest.desktop.kvm._pipedStreams)
                    {
                        this.httprequest.desktop.kvm._pipedStreams[i].end();
                    }
                    this.httprequest.desktop.kvm.end();
                });
                break;
            }
        }
    }

    if(this.httprequest.desktop.kvm.connectionBar)
    {
        console.info1('Setting ConnectionBar request to NULL');
        this.httprequest.desktop.kvm.connectionBar.httprequest = null;
    }

    this.httprequest = null;
    this.desktop.tunnel = null;
}

function kvm_tunnel_consentpromise_closehandler()
{
    if (this._consentpromise && this._consentpromise.close) { this._consentpromise.close(); }
}

function kvm_consent_ok(ws) {
    // User Consent Prompt is not required because no user is present
    if (ws.httprequest.consent && (ws.httprequest.consent & 1)){
        // User Notifications is required
        MeshServerLogEx(35, null, "Started remote desktop with toast notification (" + ws.httprequest.remoteaddr + ")", ws.httprequest);
        var notifyMessage = currentTranslation['desktopNotify'].replace(/\{0\}/g, ws.httprequest.realname);
        var notifyTitle = "MeshCentral";
        if (ws.httprequest.soptions != null) {
            if (ws.httprequest.soptions.notifyTitle != null) { notifyTitle = ws.httprequest.soptions.notifyTitle; }
            if (ws.httprequest.soptions.notifyMsgDesktop != null) { notifyMessage = ws.httprequest.soptions.notifyMsgDesktop.replace(/\{0\}/g, ws.httprequest.realname).replace(/\{1\}/g, ws.httprequest.username); }
        }
        try { require('toaster').Toast(notifyTitle, notifyMessage, ws.tsid); } catch (ex) { }
    } else {
        MeshServerLogEx(36, null, "Started remote desktop without notification (" + ws.httprequest.remoteaddr + ")", ws.httprequest);
    }
    if (ws.httprequest.consent && (ws.httprequest.consent & 0x40)) {
        // Connection Bar is required
        if (ws.httprequest.desktop.kvm.connectionBar) {
            ws.httprequest.desktop.kvm.connectionBar.removeAllListeners('close');
            ws.httprequest.desktop.kvm.connectionBar.close();
        }
        try {
            ws.httprequest.desktop.kvm.connectionBar = require('notifybar-desktop')(ws.httprequest.privacybartext.replace(/\{0\}/g, ws.httprequest.desktop.kvm.rusers.join(', ')).replace(/\{1\}/g, ws.httprequest.desktop.kvm.users.join(', ')).replace(/'/g, "\\'\\"), require('MeshAgent')._tsid, color_options);
            MeshServerLogEx(31, null, "Remote Desktop Connection Bar Activated/Updated (" + ws.httprequest.remoteaddr + ")", ws.httprequest);
        } catch (ex) {
            MeshServerLogEx(32, null, "Remote Desktop Connection Bar Failed or not Supported (" + ws.httprequest.remoteaddr + ")", ws.httprequest);
        }
        if (ws.httprequest.desktop.kvm.connectionBar) {
            ws.httprequest.desktop.kvm.connectionBar.state = {
                userid: ws.httprequest.userid,
                xuserid: ws.httprequest.xuserid,
                username: ws.httprequest.username,
                sessionid: ws.httprequest.sessionid,
                remoteaddr: ws.httprequest.remoteaddr,
                guestname: ws.httprequest.guestname,
                desktop: ws.httprequest.desktop
            };
            ws.httprequest.desktop.kvm.connectionBar.on('close', function () {
                console.info1('Connection Bar Forcefully closed');
                MeshServerLogEx(29, null, "Remote Desktop Connection forcefully closed by local user (" + this.state.remoteaddr + ")", this.state);
                for (var i in this.state.desktop.kvm._pipedStreams) {
                    this.state.desktop.kvm._pipedStreams[i].end();
                }
                this.state.desktop.kvm.end();
            });
        }
    }
    ws.httprequest.desktop.kvm.pipe(ws, { dataTypeSkip: 1 });
    if (ws.httprequest.autolock) {
        destopLockHelper_pipe(ws.httprequest);
    }
}

function kvm_consent_ask(ws){
    // Send a console message back using the console channel, "\n" is supported.
    ws.write(JSON.stringify({ ctrlChannel: '102938', type: 'console', msg: "Waiting for user to grant access...", msgid: 1 }));
    var consentMessage = currentTranslation['desktopConsent'].replace(/\{0\}/g, ws.httprequest.realname).replace(/\{1\}/g, ws.httprequest.username);
    var consentTitle = 'MeshCentral';
    if (ws.httprequest.soptions != null) {
        if (ws.httprequest.soptions.consentTitle != null) { consentTitle = ws.httprequest.soptions.consentTitle; }
        if (ws.httprequest.soptions.consentMsgDesktop != null) { consentMessage = ws.httprequest.soptions.consentMsgDesktop.replace(/\{0\}/g, ws.httprequest.realname).replace(/\{1\}/g, ws.httprequest.username); }
    }
    var pr;
    if (process.platform == 'win32') {
        var enhanced = false;
        if (ws.httprequest.oldStyle === false) {
            try { require('win-userconsent'); enhanced = true; } catch (ex) { }
        }
        if (enhanced) {
            var ipr = server_getUserImage(ws.httprequest.userid);
            ipr.consentTitle = consentTitle;
            ipr.consentMessage = consentMessage;
            ipr.consentTimeout = ws.httprequest.consentTimeout;
            ipr.consentAutoAccept = ws.httprequest.consentAutoAccept;
            ipr.tsid = ws.tsid;
            ipr.username = ws.httprequest.realname;
            ipr.translation = { Allow: currentTranslation['allow'], Deny: currentTranslation['deny'], Auto: currentTranslation['autoAllowForFive'], Caption: consentMessage };
            pr = ipr.then(function (img) {
                this.consent = require('win-userconsent').create(this.consentTitle, this.consentMessage, this.username, { b64Image: img.split(',').pop(), uid: this.tsid, timeout: this.consentTimeout * 1000, timeoutAutoAccept: this.consentAutoAccept, translations: this.translation, background: color_options.background, foreground: color_options.foreground });
                this.__childPromise.close = this.consent.close.bind(this.consent);
                return (this.consent);
            });
        } else {
            pr = require('message-box').create(consentTitle, consentMessage, ws.httprequest.consentTimeout, null, ws.tsid);
        }
    } else {
        pr = require('message-box').create(consentTitle, consentMessage, ws.httprequest.consentTimeout, null, ws.tsid);
    }
    pr.ws = ws;
    ws.pause();
    ws._consentpromise = pr;
    ws.prependOnceListener('end', kvm_tunnel_consentpromise_closehandler);
    pr.then(kvm_consentpromise_resolved, kvm_consentpromise_rejected);
}

function kvm_consentpromise_rejected(e)
{
    if (this.ws) {
        if(this.ws.httprequest){ // User Consent Denied
            if ((this.ws.httprequest.oldStyle === true) && (this.ws.httprequest.consentAutoAccept === true) && (e.toString() != "7")) {
                kvm_consentpromise_resolved.call(this); // oldStyle prompt timed out and User Consent is not required so connect anyway
                return;
            }
            MeshServerLogEx(34, null, "Failed to start remote desktop after local user rejected (" + this.ws.httprequest.remoteaddr + ")", this.ws.httprequest);
        } else { } // Connection was closed server side, maybe log some messages somewhere?
        this.ws._consentpromise = null;
        this.ws.end(JSON.stringify({ ctrlChannel: '102938', type: 'console', msg: e.toString(), msgid: 2 }));
        this.ws = null;
    } else { } // no websocket, maybe log some messages somewhere?
}
function kvm_consentpromise_resolved(always)
{
    if (always && process.platform=='win32') { server_set_consentTimer(this.ws.httprequest.userid); }

    // Success
    this.ws._consentpromise = null;
    MeshServerLogEx(30, null, "Starting remote desktop after local user accepted (" + this.ws.httprequest.remoteaddr + ")", this.ws.httprequest);
    this.ws.write(JSON.stringify({ ctrlChannel: '102938', type: 'console', msg: null, msgid: 0 }));
    if (this.ws.httprequest.consent && (this.ws.httprequest.consent & 1))
    {
        // User Notifications is required
        var notifyMessage = currentTranslation['desktopNotify'].replace(/\{0\}/g, this.ws.httprequest.realname);
        var notifyTitle = "MeshCentral";
        if (this.ws.httprequest.soptions != null)
        {
            if (this.ws.httprequest.soptions.notifyTitle != null) { notifyTitle = this.ws.httprequest.soptions.notifyTitle; }
            if (this.ws.httprequest.soptions.notifyMsgDesktop != null) { notifyMessage = this.ws.httprequest.soptions.notifyMsgDesktop.replace(/\{0\}/g, this.ws.httprequest.realname).replace(/\{1\}/g, this.ws.httprequest.username); }
        }
        try { require('toaster').Toast(notifyTitle, notifyMessage, tsid); } catch (ex) { }
    }
    if (this.ws.httprequest.consent && (this.ws.httprequest.consent & 0x40))
    {
        // Connection Bar is required
        if (this.ws.httprequest.desktop.kvm.connectionBar)
        {
            this.ws.httprequest.desktop.kvm.connectionBar.removeAllListeners('close');
            this.ws.httprequest.desktop.kvm.connectionBar.close();
        }
        try
        {
            this.ws.httprequest.desktop.kvm.connectionBar = require('notifybar-desktop')(this.ws.httprequest.privacybartext.replace(/\{0\}/g, this.ws.httprequest.desktop.kvm.rusers.join(', ')).replace(/\{1\}/g, this.ws.httprequest.desktop.kvm.users.join(', ')).replace(/'/g, "\\'\\"), require('MeshAgent')._tsid, color_options);
            MeshServerLogEx(31, null, "Remote Desktop Connection Bar Activated/Updated (" + this.ws.httprequest.remoteaddr + ")", this.ws.httprequest);
        } catch (ex)
        {
            if (process.platform != 'darwin')
            {
                MeshServerLogEx(32, null, "Remote Desktop Connection Bar Failed or Not Supported (" + this.ws.httprequest.remoteaddr + ")", this.ws.httprequest);
            }
        }
        try {
			if (this.ws.httprequest.desktop.kvm.connectionBar) {
				this.ws.httprequest.desktop.kvm.connectionBar.httprequest = this.ws.httprequest;
				this.ws.httprequest.desktop.kvm.connectionBar.on('close', function () {
					MeshServerLogEx(29, null, "Remote Desktop Connection forcefully closed by local user (" + this.httprequest.remoteaddr + ")", this.httprequest);
					for (var i in this.httprequest.desktop.kvm._pipedStreams) {
						this.httprequest.desktop.kvm._pipedStreams[i].end();
					}
					this.httprequest.desktop.kvm.end();
				});
			}
		}
		catch (ex)
        {
            if (process.platform != 'darwin')
            {
                MeshServerLogEx(32, null, "Failed2(" + this.ws.httprequest.remoteaddr + ")", this.ws.httprequest);
            }
        }
    }
    this.ws.httprequest.desktop.kvm.pipe(this.ws, { dataTypeSkip: 1 });
    if (this.ws.httprequest.autolock)
    {
        destopLockHelper_pipe(this.ws.httprequest);
    }
    this.ws.resume();
    this.ws = null;
}

function files_consent_ok(ws){
    // User Consent Prompt is not required
    if (ws.httprequest.consent && (ws.httprequest.consent & 4)) {
        // User Notifications is required
        MeshServerLogEx(42, null, "Started remote files with toast notification (" + ws.httprequest.remoteaddr + ")", ws.httprequest);
        var notifyMessage = currentTranslation['fileNotify'].replace(/\{0\}/g, ws.httprequest.realname);
        var notifyTitle = "MeshCentral";
        if (ws.httprequest.soptions != null) {
            if (ws.httprequest.soptions.notifyTitle != null) { notifyTitle = ws.httprequest.soptions.notifyTitle; }
            if (ws.httprequest.soptions.notifyMsgFiles != null) { notifyMessage = ws.httprequest.soptions.notifyMsgFiles.replace(/\{0\}/g, ws.httprequest.realname).replace(/\{1\}/g, ws.httprequest.username); }
        }
        try { require('toaster').Toast(notifyTitle, notifyMessage); } catch (ex) { }
    } else {
        MeshServerLogEx(43, null, "Started remote files without notification (" + ws.httprequest.remoteaddr + ")", ws.httprequest);
    }
    ws.resume();
}

function files_consent_ask(ws){
    // Send a console message back using the console channel, "\n" is supported.
    ws.write(JSON.stringify({ ctrlChannel: '102938', type: 'console', msg: "Waiting for user to grant access...", msgid: 1 }));
    var consentMessage = currentTranslation['fileConsent'].replace(/\{0\}/g, ws.httprequest.realname).replace(/\{1\}/g, ws.httprequest.username);
    var consentTitle = 'MeshCentral';

    if (ws.httprequest.soptions != null) {
        if (ws.httprequest.soptions.consentTitle != null) { consentTitle = ws.httprequest.soptions.consentTitle; }
        if (ws.httprequest.soptions.consentMsgFiles != null) { consentMessage = ws.httprequest.soptions.consentMsgFiles.replace(/\{0\}/g, ws.httprequest.realname).replace(/\{1\}/g, ws.httprequest.username); }
    }
    var pr;
    if (process.platform == 'win32') {
        var enhanced = false;
        if (ws.httprequest.oldStyle === false) {
            try { require('win-userconsent'); enhanced = true; } catch (ex) { }
        }
        if (enhanced) {
            var ipr = server_getUserImage(ws.httprequest.userid);
            ipr.consentTitle = consentTitle;
            ipr.consentMessage = consentMessage;
            ipr.consentTimeout = ws.httprequest.consentTimeout;
            ipr.consentAutoAccept = ws.httprequest.consentAutoAccept;
            ipr.username = ws.httprequest.realname;
            ipr.tsid = ws.tsid;
            ipr.translations = { Allow: currentTranslation['allow'], Deny: currentTranslation['deny'], Auto: currentTranslation['autoAllowForFive'], Caption: consentMessage };
            pr = ipr.then(function (img) {
                this.consent = require('win-userconsent').create(this.consentTitle, this.consentMessage, this.username, { b64Image: img.split(',').pop(), uid: this.tsid, timeout: this.consentTimeout * 1000, timeoutAutoAccept: this.consentAutoAccept, translations: this.translations, background: color_options.background, foreground: color_options.foreground });
                this.__childPromise.close = this.consent.close.bind(this.consent);
                return (this.consent);
            });
        } else {
            pr = require('message-box').create(consentTitle, consentMessage, ws.httprequest.consentTimeout, null);
        }
    } else {
        pr = require('message-box').create(consentTitle, consentMessage, ws.httprequest.consentTimeout, null);
    }
    pr.ws = ws;
    ws.pause();
    ws._consentpromise = pr;
    ws.prependOnceListener('end', files_tunnel_endhandler);
    pr.then(files_consentpromise_resolved, files_consentpromise_rejected);
}

function files_consentpromise_resolved(always)
{
    if (always && process.platform == 'win32') { server_set_consentTimer(this.ws.httprequest.userid); }

    // Success
    this.ws._consentpromise = null;
    MeshServerLogEx(40, null, "Starting remote files after local user accepted (" + this.ws.httprequest.remoteaddr + ")", this.ws.httprequest);
    this.ws.write(JSON.stringify({ ctrlChannel: '102938', type: 'console', msg: null }));
    if (this.ws.httprequest.consent && (this.ws.httprequest.consent & 4))
    {
        // User Notifications is required
        var notifyMessage = currentTranslation['fileNotify'].replace(/\{0\}/g, this.ws.httprequest.realname);
        var notifyTitle = "MeshCentral";
        if (this.ws.httprequest.soptions != null)
        {
            if (this.ws.httprequest.soptions.notifyTitle != null) { notifyTitle = this.ws.httprequest.soptions.notifyTitle; }
            if (this.ws.httprequest.soptions.notifyMsgFiles != null) { notifyMessage = this.ws.httprequest.soptions.notifyMsgFiles.replace(/\{0\}/g, this.ws.httprequest.realname).replace(/\{1\}/g, this.ws.httprequest.username); }
        }
        try { require('toaster').Toast(notifyTitle, notifyMessage); } catch (ex) { }
    }
    this.ws.resume();
    this.ws = null;
}
function files_consentpromise_rejected(e)
{
    if (this.ws) {
        if(this.ws.httprequest){ // User Consent Denied
            if ((this.ws.httprequest.oldStyle === true) && (this.ws.httprequest.consentAutoAccept === true) && (e.toString() != "7")) {
                files_consentpromise_resolved.call(this); // oldStyle prompt timed out and User Consent is not required so connect anyway
                return;
            }
            MeshServerLogEx(41, null, "Failed to start remote files after local user rejected (" + this.ws.httprequest.remoteaddr + ")", this.ws.httprequest);
        } else { } // Connection was closed server side, maybe log some messages somewhere?
        this.ws._consentpromise = null;
        this.ws.end(JSON.stringify({ ctrlChannel: '102938', type: 'console', msg: e.toString(), msgid: 2 }));
        this.ws = null;
    } else { } // no websocket, maybe log some messages somewhere?
}
function files_tunnel_endhandler()
{
    if (this._consentpromise && this._consentpromise.close) { this._consentpromise.close(); }
}

function registry_consent_ok(ws){
    if (ws.httprequest.consent && (ws.httprequest.consent & 0x0080)) {
        MeshServerLogEx(165, null, "Started remote registry with toast notification (" + ws.httprequest.remoteaddr + ")", ws.httprequest);
        var notifyMessage = currentTranslation['registryNotify'].replace(/\{0\}/g, ws.httprequest.realname);
        var notifyTitle = "MeshCentral";
        if (ws.httprequest.soptions != null) {
            if (ws.httprequest.soptions.notifyTitle != null) { notifyTitle = ws.httprequest.soptions.notifyTitle; }
            if (ws.httprequest.soptions.notifyMsgRegistry != null) { notifyMessage = ws.httprequest.soptions.notifyMsgRegistry.replace(/\{0\}/g, ws.httprequest.realname).replace(/\{1\}/g, ws.httprequest.username); }
        }
        try { require('toaster').Toast(notifyTitle, notifyMessage); } catch (ex) { }
    } else {
        MeshServerLogEx(166, null, "Started remote registry without notification (" + ws.httprequest.remoteaddr + ")", ws.httprequest);
    }
    ws.resume();
}

function registry_consent_ask(ws){
    ws.write(JSON.stringify({ ctrlChannel: '102938', type: 'console', msg: "Waiting for user to grant access...", msgid: 1 }));
    var consentMessage = currentTranslation['registryConsent'].replace(/\{0\}/g, ws.httprequest.realname).replace(/\{1\}/g, ws.httprequest.username);
    var consentTitle = 'MeshCentral';
    if (ws.httprequest.soptions != null) {
        if (ws.httprequest.soptions.consentTitle != null) { consentTitle = ws.httprequest.soptions.consentTitle; }
        if (ws.httprequest.soptions.consentMsgRegistry != null) { consentMessage = ws.httprequest.soptions.consentMsgRegistry.replace(/\{0\}/g, ws.httprequest.realname).replace(/\{1\}/g, ws.httprequest.username); }
    }
    var pr;
    if (process.platform == 'win32') {
        var enhanced = false;
        if (ws.httprequest.oldStyle === false) { try { require('win-userconsent'); enhanced = true; } catch (ex) { } }
        if (enhanced) {
            var ipr = server_getUserImage(ws.httprequest.userid);
            ipr.consentTitle = consentTitle;
            ipr.consentMessage = consentMessage;
            ipr.consentTimeout = ws.httprequest.consentTimeout;
            ipr.consentAutoAccept = ws.httprequest.consentAutoAccept;
            ipr.username = ws.httprequest.realname;
            ipr.tsid = ws.tsid;
            ipr.translations = { Allow: currentTranslation['allow'], Deny: currentTranslation['deny'], Auto: currentTranslation['autoAllowForFive'], Caption: consentMessage };
            pr = ipr.then(function (img) {
                this.consent = require('win-userconsent').create(this.consentTitle, this.consentMessage, this.username, { b64Image: img.split(',').pop(), uid: this.tsid, timeout: this.consentTimeout * 1000, timeoutAutoAccept: this.consentAutoAccept, translations: this.translations, background: color_options.background, foreground: color_options.foreground });
                this.__childPromise.close = this.consent.close.bind(this.consent);
                return (this.consent);
            });
        } else {
            pr = require('message-box').create(consentTitle, consentMessage, ws.httprequest.consentTimeout, null);
        }
    } else {
        pr = require('message-box').create(consentTitle, consentMessage, ws.httprequest.consentTimeout, null);
    }
    pr.ws = ws;
    ws.pause();
    ws._consentpromise = pr;
    ws.prependOnceListener('end', files_tunnel_endhandler);
    pr.then(registry_consentpromise_resolved, registry_consentpromise_rejected);
}

function registry_consentpromise_resolved(always)
{
    if (always && process.platform == 'win32') { server_set_consentTimer(this.ws.httprequest.userid); }
    this.ws._consentpromise = null;
    MeshServerLogEx(163, null, "Starting remote registry after local user accepted (" + this.ws.httprequest.remoteaddr + ")", this.ws.httprequest);
    this.ws.write(JSON.stringify({ ctrlChannel: '102938', type: 'console', msg: null }));
    if (this.ws.httprequest.consent && (this.ws.httprequest.consent & 0x0080)) {
        var notifyMessage = currentTranslation['registryNotify'].replace(/\{0\}/g, this.ws.httprequest.realname);
        var notifyTitle = "MeshCentral";
        if (this.ws.httprequest.soptions != null) {
            if (this.ws.httprequest.soptions.notifyTitle != null) { notifyTitle = this.ws.httprequest.soptions.notifyTitle; }
            if (this.ws.httprequest.soptions.notifyMsgRegistry != null) { notifyMessage = this.ws.httprequest.soptions.notifyMsgRegistry.replace(/\{0\}/g, this.ws.httprequest.realname).replace(/\{1\}/g, this.ws.httprequest.username); }
        }
        try { require('toaster').Toast(notifyTitle, notifyMessage); } catch (ex) { }
    }
    this.ws.resume();
    this.ws = null;
}

function registry_consentpromise_rejected(e)
{
    if (this.ws) {
        if (this.ws.httprequest) {
            if ((this.ws.httprequest.oldStyle === true) && (this.ws.httprequest.consentAutoAccept === true) && (e.toString() != "7")) {
                registry_consentpromise_resolved.call(this);
                return;
            }
            MeshServerLogEx(164, null, "Failed to start remote registry after local user rejected (" + this.ws.httprequest.remoteaddr + ")", this.ws.httprequest);
        }
        this.ws._consentpromise = null;
        this.ws.end(JSON.stringify({ ctrlChannel: '102938', type: 'console', msg: e.toString(), msgid: 2 }));
        this.ws = null;
    }
}

function onTunnelData(data)
{
    //sendConsoleText('OnTunnelData, ' + data.length + ', ' + typeof data + ', ' + data);

    // If this is upload data, save it to file
    if ((this.httprequest.uploadFile) && (typeof data == 'object') && (data[0] != 123)) {
        // Save the data to file being uploaded.
        if (data[0] == 0) {
            // If data starts with zero, skip the first byte. This is used to escape binary file data from JSON.
            this.httprequest.uploadFileSize += (data.length - 1);
            try { fs.writeSync(this.httprequest.uploadFile, data, 1, data.length - 1); } catch (ex) { sendConsoleText('FileUpload Error'); this.write(Buffer.from(JSON.stringify({ action: 'uploaderror' }))); return; } // Write to the file, if there is a problem, error out.
        } else {
            // If data does not start with zero, save as-is.
            this.httprequest.uploadFileSize += data.length;
            try { fs.writeSync(this.httprequest.uploadFile, data); } catch (ex) { sendConsoleText('FileUpload Error'); this.write(Buffer.from(JSON.stringify({ action: 'uploaderror' }))); return; } // Write to the file, if there is a problem, error out.
        }
        this.write(Buffer.from(JSON.stringify({ action: 'uploadack', reqid: this.httprequest.uploadFileid }))); // Ask for more data.
        return;
    }

    if (this.httprequest.state == 0) {
        // Check if this is a relay connection
        if ((data == 'c') || (data == 'cr')) {
            this.httprequest.state = 1;
            //sendConsoleText("Tunnel #" + this.httprequest.index + " now active", this.httprequest.sessionid);
        }
    }
    else {
        // Handle tunnel data
        if (this.httprequest.protocol == 0) { // 1 = Terminal (admin), 2 = Desktop, 4 = Registry, 5 = Files, 6 = PowerShell (admin), 7 = Plugin Data Exchange, 8 = Terminal (user), 9 = PowerShell (user), 10 = FileTransfer
            // Take a look at the protocol
            if ((data.length > 3) && (data[0] == '{')) { onTunnelControlData(data, this); return; }
            this.httprequest.protocol = parseInt(data);
            if (typeof this.httprequest.protocol != 'number') { this.httprequest.protocol = 0; }

            // See if this protocol request is allowed.
            if ((this.httprequest.soptions != null) && (this.httprequest.soptions.usages != null) && (this.httprequest.soptions.usages.indexOf(this.httprequest.protocol) == -1)) { this.httprequest.protocol = 0; }

            if (this.httprequest.protocol == 10) {
                //
                // Basic file transfer
                //
                var stats = null;
                if ((process.platform != 'win32') && (this.httprequest.xoptions.file.startsWith('/') == false)) { this.httprequest.xoptions.file = '/' + this.httprequest.xoptions.file; }
                try { stats = require('fs').statSync(this.httprequest.xoptions.file) } catch (ex) { }
                try { if (stats) { this.httprequest.downloadFile = fs.createReadStream(this.httprequest.xoptions.file, { flags: 'rbN' }); } } catch (ex) { }
                if (this.httprequest.downloadFile) {
                    MeshServerLogEx(106, [this.httprequest.xoptions.file, stats.size], 'Download: \"' + this.httprequest.xoptions.file + '\", Size: ' + stats.size, this.httprequest);
                    //sendConsoleText('BasicFileTransfer, ok, ' + this.httprequest.xoptions.file + ', ' + JSON.stringify(stats));
                    this.write(JSON.stringify({ op: 'ok', size: stats.size }));
                    this.httprequest.downloadFile.pipe(this);
                    this.httprequest.downloadFile.end = function () { }
                } else {
                    //sendConsoleText('BasicFileTransfer, cancel, ' + this.httprequest.xoptions.file);
                    this.write(JSON.stringify({ op: 'cancel' }));
                }
            }
            else if ((this.httprequest.protocol == 1) || (this.httprequest.protocol == 6) || (this.httprequest.protocol == 8) || (this.httprequest.protocol == 9)) {
                //
                // Remote Terminal
                //

                // Check user access rights for terminal
                if (((this.httprequest.rights & MESHRIGHT_REMOTECONTROL) == 0) || ((this.httprequest.rights != 0xFFFFFFFF) && ((this.httprequest.rights & MESHRIGHT_NOTERMINAL) != 0)))
                {
                    // Disengage this tunnel, user does not have the rights to do this!!
                    this.httprequest.protocol = 999999;
                    this.httprequest.s.end();
                    sendConsoleText("Error: No Terminal Control Rights.");
                    return;
                }

                this.descriptorMetadata = "Remote Terminal";

                // Look for a TSID
                var tsid = null;
                if ((this.httprequest.xoptions != null) && (typeof this.httprequest.xoptions.tsid == 'number')) { tsid = this.httprequest.xoptions.tsid; }
                require('MeshAgent')._tsid = tsid;
                this.tsid = tsid;

                if (process.platform == 'win32')
                {
                    if (!require('win-terminal').PowerShellCapable() && (this.httprequest.protocol == 6 || this.httprequest.protocol == 9)) {
                        this.httprequest.write(JSON.stringify({ ctrlChannel: '102938', type: 'console', msg: 'PowerShell is not supported on this version of windows', msgid: 1 }));
                        this.httprequest.s.end();
                        return;
                    }
                }

                var prom = require('promise');
                this.httprequest.tpromise = new prom(promise_init);
                this.httprequest.tpromise.that = this;
                this.httprequest.tpromise.httprequest = this.httprequest;
                this.end = terminal_end;

                // Perform User-Consent if needed. 
                if (this.httprequest.consent && (this.httprequest.consent & 16)) {
                    // User asked for consent so now we check if we can auto accept if no user is present/loggedin
                    if (this.httprequest.consentAutoAcceptIfNoUser || this.httprequest.consentAutoAcceptIfTerminalNoUser || this.httprequest.consentAutoAcceptIfLocked || this.httprequest.consentAutoAcceptIfTerminalLocked) {
                        var p = require('user-sessions').enumerateUsers();
                        p.sessionid = this.httprequest.sessionid;
                        p.ws = this;
                        p.then(function (u) {
                            var v = [];
                            for (var i in u) {
                                if (u[i].State == 'Active') { v.push({ tsid: i, type: u[i].StationName, user: u[i].Username, domain: u[i].Domain }); }
                            }
                            var autoAccept = false;
                            
                            // Check if we should auto-accept because no user is present
                            if ((this.ws.httprequest.consentAutoAcceptIfNoUser || this.ws.httprequest.consentAutoAcceptIfTerminalNoUser) && (v.length == 0)) {
                                autoAccept = true;
                            }
                            
                            // Check if we should auto-accept because all users are locked
                            if ((this.ws.httprequest.consentAutoAcceptIfLocked || this.ws.httprequest.consentAutoAcceptIfTerminalLocked) && (v.length > 0)) {
                                var allUsersLocked = true;
                                if (!meshCoreObj.lusers || meshCoreObj.lusers.length == 0) {
                                    // No locked users list available, assume users are not locked
                                    allUsersLocked = false;
                                } else {
                                    for (var i in v) {
                                        var username = v[i].domain ? (v[i].domain + '\\' + v[i].user) : v[i].user;
                                        if (meshCoreObj.lusers.indexOf(username) == -1) {
                                            allUsersLocked = false;
                                            break;
                                        }
                                    }
                                }
                                if (allUsersLocked) { autoAccept = true; }
                            }
                            
                            if (autoAccept) {
                                this.ws.httprequest.tpromise._res();
                            } else { 
                                // User is present and not all locked, so we still need consent
                                terminal_consent_ask(this.ws);
                            }
                        });
                    } else {
                        terminal_consent_ask(this);
                    }
                } else {
                    // User-Consent is not required, so just resolve this promise
                    this.httprequest.tpromise._res();
                }
                this.httprequest.tpromise.then(terminal_promise_consent_resolved, terminal_promise_consent_rejected);
            }
            else if (this.httprequest.protocol == 2)
            {
                //
                // Remote Desktop
                //

                // Check user access rights for desktop
                if ((((this.httprequest.rights & MESHRIGHT_REMOTECONTROL) == 0) && ((this.httprequest.rights & MESHRIGHT_REMOTEVIEW) == 0)) || ((this.httprequest.rights != 0xFFFFFFFF) && ((this.httprequest.rights & MESHRIGHT_NODESKTOP) != 0))) {
                    // Disengage this tunnel, user does not have the rights to do this!!
                    this.httprequest.protocol = 999999;
                    this.httprequest.s.end();
                    sendConsoleText("Error: No Desktop Control Rights.");
                    return;
                }

                this.descriptorMetadata = "Remote KVM";

                // Look for a TSID
                var tsid = null;
                if ((this.httprequest.xoptions != null) && (typeof this.httprequest.xoptions.tsid == 'number')) { tsid = this.httprequest.xoptions.tsid; }
                require('MeshAgent')._tsid = tsid;
                this.tsid = tsid;

                // If MacOS, Wake up device with caffeinate
                if(process.platform == 'darwin'){
                    try {
                        var options = {};
                        try { options.uid = require('user-sessions').consoleUid(); } catch (ex) { }
                        options.type = require('child_process').SpawnTypes.TERM;
                        var replydata = "";
                        var cmdchild = require('child_process').execFile('/usr/bin/caffeinate', ['caffeinate', '-u', '-t', '10'], options);
                        cmdchild.descriptorMetadata = 'UserCommandsShell';
                        cmdchild.stdout.on('data', function (c) { replydata += c.toString(); });
                        cmdchild.stderr.on('data', function (c) { replydata + c.toString(); });
                        cmdchild.on('exit', function () { delete cmdchild; });
                    } catch(err) { }
                }
                // Remote desktop using native pipes
                this.httprequest.desktop = { state: 0, kvm: mesh.getRemoteDesktopStream(tsid), tunnel: this };
                this.httprequest.desktop.kvm.parent = this.httprequest.desktop;
                this.desktop = this.httprequest.desktop;

                // Add ourself to the list of remote desktop sessions
                if (this.httprequest.desktop.kvm.tunnels == null) { this.httprequest.desktop.kvm.tunnels = []; }
                this.httprequest.desktop.kvm.tunnels.push(this);

                // Send a metadata update to all desktop sessions
                var users = {};
                if (this.httprequest.desktop.kvm.tunnels != null)
                {
                    for (var i in this.httprequest.desktop.kvm.tunnels)
                    {
                        try {
                            var userid = getUserIdAndGuestNameFromHttpRequest(this.httprequest.desktop.kvm.tunnels[i].httprequest);
                            if (users[userid] == null) { users[userid] = 1; } else { users[userid]++; }
                        } catch (ex) { sendConsoleText(ex); }
                    }
                    for (var i in this.httprequest.desktop.kvm.tunnels)
                    {
                        try { this.httprequest.desktop.kvm.tunnels[i].write(JSON.stringify({ ctrlChannel: '102938', type: 'metadata', users: users })); } catch (ex) { }
                    }
                    tunnelUserCount.desktop = users;
                    try { mesh.SendCommand({ action: 'sessions', type: 'kvm', value: users }); } catch (ex) { }
                    broadcastSessionsToRegisteredApps();
                }

                this.end = tunnel_kvm_end;

                if (this.httprequest.desktop.kvm.hasOwnProperty('connectionCount')) {
                    this.httprequest.desktop.kvm.connectionCount++;
                    this.httprequest.desktop.kvm.rusers.push(this.httprequest.realname);
                    this.httprequest.desktop.kvm.users.push(this.httprequest.username);
                    this.httprequest.desktop.kvm.rusers.sort();
                    this.httprequest.desktop.kvm.users.sort();
                } else {
                    this.httprequest.desktop.kvm.connectionCount = 1;
                    this.httprequest.desktop.kvm.rusers = [this.httprequest.realname];
                    this.httprequest.desktop.kvm.users = [this.httprequest.username];
                }

                if ((this.httprequest.desktopviewonly != true) && ((this.httprequest.rights == 0xFFFFFFFF) || (((this.httprequest.rights & MESHRIGHT_REMOTECONTROL) != 0) && ((this.httprequest.rights & MESHRIGHT_REMOTEVIEW) == 0))))
                {
                    // If we have remote control rights, pipe the KVM input
                    this.pipe(this.httprequest.desktop.kvm, { dataTypeSkip: 1, end: false }); // 0 = Binary, 1 = Text. Pipe the Browser --> KVM input.
                }
                else
                {
                    // We need to only pipe non-mouse & non-keyboard inputs.
                    // sendConsoleText('Warning: No Remote Desktop Input Rights.');
                    // TODO!!!
                }

                // Perform notification if needed. Toast messages may not be supported on all platforms.
                if (this.httprequest.consent && (this.httprequest.consent & 8)) {

                    // User asked for consent but now we check if can auto accept if no user is present
                    if (this.httprequest.consentAutoAcceptIfNoUser || this.httprequest.consentAutoAcceptIfDesktopNoUser || this.httprequest.consentAutoAcceptIfLocked || this.httprequest.consentAutoAcceptIfDesktopLocked) {
                        // Get list of users to check if we any actual users logged in, and if users logged in, we still need consent
                        var p = require('user-sessions').enumerateUsers();
                        p.sessionid = this.httprequest.sessionid;
                        p.ws = this;
                        p.then(function (u) {
                            var v = [];
                            for (var i in u) {
                                if (u[i].State == 'Active') { v.push({ tsid: i, type: u[i].StationName, user: u[i].Username, domain: u[i].Domain }); }
                            }
                            var autoAccept = false;
                            
                            // Check if we can auto-accept because no user is present
                            if ((this.ws.httprequest.consentAutoAcceptIfNoUser || this.ws.httprequest.consentAutoAcceptIfDesktopNoUser) && (v.length == 0)) {
                                // No user is present, auto accept
                                autoAccept = true;
                            }
                            
                            // Check if we can auto-accept because all users are locked
                            if ((this.ws.httprequest.consentAutoAcceptIfLocked || this.ws.httprequest.consentAutoAcceptIfDesktopLocked) && (v.length > 0)) {
                                var allUsersLocked = true;
                                if (!meshCoreObj.lusers || meshCoreObj.lusers.length == 0) {
                                    // No locked users list available, assume users are not locked
                                    allUsersLocked = false;
                                } else {
                                    for (var i in v) {
                                        var username = v[i].domain ? (v[i].domain + '\\' + v[i].user) : v[i].user;
                                        if (meshCoreObj.lusers.indexOf(username) == -1) {
                                            allUsersLocked = false;
                                            break;
                                        }
                                    }
                                }
                                if (allUsersLocked) { autoAccept = true; }
                            }
                            
                            if (autoAccept) {
                                kvm_consent_ok(this.ws);
                            } else { 
                                // User is present and not all locked, so we still need consent
                                kvm_consent_ask(this.ws);
                            }
                        });
                    } else {
                        // User Consent Prompt is required
                        kvm_consent_ask(this);
                    }
                } else {
                    // User Consent Prompt is not required
                    kvm_consent_ok(this);
                }

                this.removeAllListeners('data');
                this.on('data', onTunnelControlData);
                //this.write('MeshCore KVM Hello!1');
            } else if (this.httprequest.protocol == 4) {
                //
                // Remote Registry
                //

                // Check user access rights for registry
                if ((this.httprequest.rights & MESHRIGHT_REMOTECONTROL) == 0) {
                    // Disengage this tunnel, user does not have the rights to do this!!
                    this.httprequest.protocol = 999999;
                    this.httprequest.s.end();
                    sendConsoleText("Error: No registry control rights.");
                    return;
                }

                this.descriptorMetadata = "Remote Registry";

                // Add the registry session to the count to update the server
                if (this.httprequest.userid != null) {
                    var userid = getUserIdAndGuestNameFromHttpRequest(this.httprequest);
                    if (tunnelUserCount.registry[userid] == null) { tunnelUserCount.registry[userid] = 1; } else { tunnelUserCount.registry[userid]++; }
                    try { mesh.SendCommand({ action: 'sessions', type: 'registry', value: tunnelUserCount.registry }); } catch (ex) { }
                    broadcastSessionsToRegisteredApps();
                }

                this.end = function ()
                {
                    // Remove the registry session from the count to update the server
                    if (this.httprequest.userid != null) {
                        var userid = getUserIdAndGuestNameFromHttpRequest(this.httprequest);
                        if (tunnelUserCount.registry[userid] != null) { tunnelUserCount.registry[userid]--; if (tunnelUserCount.registry[userid] <= 0) { delete tunnelUserCount.registry[userid]; } }
                        try { mesh.SendCommand({ action: 'sessions', type: 'registry', value: tunnelUserCount.registry }); } catch (ex) { }
                        broadcastSessionsToRegisteredApps();
                    }
                };

                if (this.httprequest.consent && (this.httprequest.consent & 0x0100)) {
                    registry_consent_ask(this);
                } else {
                    registry_consent_ok(this);
                }
            } else if (this.httprequest.protocol == 5) {
                //
                // Remote Files
                //

                // Check user access rights for files
                if (((this.httprequest.rights & MESHRIGHT_REMOTECONTROL) == 0) || ((this.httprequest.rights != 0xFFFFFFFF) && ((this.httprequest.rights & MESHRIGHT_NOFILES) != 0))) {
                    // Disengage this tunnel, user does not have the rights to do this!!
                    this.httprequest.protocol = 999999;
                    this.httprequest.s.end();
                    sendConsoleText("Error: No files control rights.");
                    return;
                }

                this.descriptorMetadata = "Remote Files";

                // Look for a TSID
                var tsid = null;
                if ((this.httprequest.xoptions != null) && (typeof this.httprequest.xoptions.tsid == 'number')) { tsid = this.httprequest.xoptions.tsid; }
                require('MeshAgent')._tsid = tsid;
                this.tsid = tsid;

                // Add the files session to the count to update the server
                if (this.httprequest.userid != null) {
                    var userid = getUserIdAndGuestNameFromHttpRequest(this.httprequest);
                    if (tunnelUserCount.files[userid] == null) { tunnelUserCount.files[userid] = 1; } else { tunnelUserCount.files[userid]++; }
                    try { mesh.SendCommand({ action: 'sessions', type: 'files', value: tunnelUserCount.files }); } catch (ex) { }
                    broadcastSessionsToRegisteredApps();
                }

                this.end = function ()
                {
                    // Remove the files session from the count to update the server
                    if (this.httprequest.userid != null) {
                        var userid = getUserIdAndGuestNameFromHttpRequest(this.httprequest);
                        if (tunnelUserCount.files[userid] != null) { tunnelUserCount.files[userid]--; if (tunnelUserCount.files[userid] <= 0) { delete tunnelUserCount.files[userid]; } }
                        try { mesh.SendCommand({ action: 'sessions', type: 'files', value: tunnelUserCount.files }); } catch (ex) { }
                        broadcastSessionsToRegisteredApps();
                    }
                };

                // Perform notification if needed. Toast messages may not be supported on all platforms.
                if (this.httprequest.consent && (this.httprequest.consent & 32)) {
                    // User asked for consent so now we check if we can auto accept if no user is present/loggedin
                    if (this.httprequest.consentAutoAcceptIfNoUser || this.httprequest.consentAutoAcceptIfFileNoUser || this.httprequest.consentAutoAcceptIfLocked || this.httprequest.consentAutoAcceptIfFileLocked) {
                            var p = require('user-sessions').enumerateUsers();
                            p.sessionid = this.httprequest.sessionid;
                            p.ws = this;
                            p.then(function (u) {
                                var v = [];
                                for (var i in u) {
                                    if (u[i].State == 'Active') { v.push({ tsid: i, type: u[i].StationName, user: u[i].Username, domain: u[i].Domain }); }
                                }
                                var autoAccept = false;
                                
                                // Check if we should auto-accept because no user is present
                                if ((this.ws.httprequest.consentAutoAcceptIfNoUser || this.ws.httprequest.consentAutoAcceptIfFileNoUser) && (v.length == 0)) {
                                    autoAccept = true;
                                }
                                
                                // Check if we should auto-accept because all users are locked
                                if ((this.ws.httprequest.consentAutoAcceptIfLocked || this.ws.httprequest.consentAutoAcceptIfFileLocked) && (v.length > 0)) {
                                    var allUsersLocked = true;
                                    if (!meshCoreObj.lusers || meshCoreObj.lusers.length == 0) {
                                        // No locked users list available, assume users are not locked
                                        allUsersLocked = false;
                                    } else {
                                        for (var i in v) {
                                            var username = v[i].domain ? (v[i].domain + '\\' + v[i].user) : v[i].user;
                                            if (meshCoreObj.lusers.indexOf(username) == -1) {
                                                allUsersLocked = false;
                                                break;
                                            }
                                        }
                                    }
                                    if (allUsersLocked) { autoAccept = true; }
                                }
                                
                                if (autoAccept) {
                                    // User Consent Prompt is not required
                                    files_consent_ok(this.ws);
                                } else { 
                                    // User is present and not all locked, so we still need consent
                                    files_consent_ask(this.ws);
                                }
                            });
                    } else {
                         // User Consent Prompt is required
                        files_consent_ask(this);
                    }
                }  else {
                    // User Consent Prompt is not required
                    files_consent_ok(this);
                }

                // Setup files
                // NOP
            }
        } else if (this.httprequest.protocol == 1) {
            // Send data into terminal stdin
            //this.write(data); // Echo back the keys (Does not seem to be a good idea)
        } else if (this.httprequest.protocol == 2) {
            // Send data into remote desktop
            if (this.httprequest.desktop.state == 0) {
                this.write(Buffer.from(String.fromCharCode(0x11, 0xFE, 0x00, 0x00, 0x4D, 0x45, 0x53, 0x48, 0x00, 0x00, 0x00, 0x00, 0x02)));
                this.httprequest.desktop.state = 1;
            } else {
                this.httprequest.desktop.write(data);
            }
        } else if (this.httprequest.protocol == 4) {
            // Process registry commands
            var cmd = null;
            try { cmd = JSON.parse(data); } catch (ex) { };
            if (cmd == null) { return; }
            if ((cmd.ctrlChannel == '102938') || ((cmd.type == 'offer') && (cmd.sdp != null))) { onTunnelControlData(cmd, this); return; } // If this is control data, handle it now.
            if (cmd.action == undefined) { return; }
            var remoteRegistry = null;
            if (process.platform == 'win32') {
                try { remoteRegistry = require('win-registry-remote'); }
                catch (ex) { }
            }

            switch (cmd.action) {
                case 'listroots': {
                    var response = { action: 'listroots', reqid: cmd.reqid, roots: [] };
                    if (process.platform != 'win32') {
                        response.error = 'Registry is currently supported on Windows agents only.';
                    } else {
                        response.roots = remoteRegistry.getRoots();
                    }
                    this.write(JSON.stringify(response));
                    break;
                }
                case 'list': {
                    var response = { action: 'list', reqid: cmd.reqid, hive: cmd.hive, path: cmd.path, subkeys: [], values: [] };
                    if (process.platform != 'win32') {
                        response.error = 'Registry is currently supported on Windows agents only.';
                    } else {
                        try {
                            var listResponse = remoteRegistry.listKey(cmd.hive, cmd.path || '');
                            response.hive = listResponse.hive;
                            response.path = listResponse.path;
                            response.subkeys = listResponse.subkeys;
                            response.values = listResponse.values;
                        } catch (ex) {
                            response.error = (ex && ex.message) ? ex.message : String(ex);
                        }
                    }
                    this.write(JSON.stringify(response));
                    break;
                }
                case 'createkey': {
                    var response = { action: 'createkey', reqid: cmd.reqid, hive: cmd.hive, path: cmd.path, name: cmd.name };
                    if (process.platform != 'win32') {
                        response.error = 'Registry is currently supported on Windows agents only.';
                    } else {
                        try { remoteRegistry.createSubKey(cmd.hive, cmd.path || '', cmd.name); response.success = true; }
                        catch (ex) { response.error = (ex && ex.message) ? ex.message : String(ex); }
                    }
                    this.write(JSON.stringify(response));
                    break;
                }
                case 'delete': {
                    var response = { action: 'delete', reqid: cmd.reqid };
                    if (process.platform != 'win32') {
                        response.error = 'Registry is currently supported on Windows agents only.';
                    } else {
                        try { remoteRegistry.deleteEntries(cmd.items || []); response.success = true; }
                        catch (ex) { response.error = (ex && ex.message) ? ex.message : String(ex); }
                    }
                    this.write(JSON.stringify(response));
                    break;
                }
                case 'setvalue': {
                    var response = { action: 'setvalue', reqid: cmd.reqid, hive: cmd.hive, path: cmd.path, name: cmd.name, type: cmd.type };
                    if (process.platform != 'win32') {
                        response.error = 'Registry is currently supported on Windows agents only.';
                    } else {
                        try { remoteRegistry.setValue(cmd.hive, cmd.path || '', cmd.name, cmd.type, cmd.value); response.success = true; }
                        catch (ex) { response.error = (ex && ex.message) ? ex.message : String(ex); }
                    }
                    this.write(JSON.stringify(response));
                    break;
                }
                case 'rename': {
                    var response = { action: 'rename', reqid: cmd.reqid };
                    if (process.platform != 'win32') {
                        response.error = 'Registry is currently supported on Windows agents only.';
                    } else {
                        try { remoteRegistry.renameEntry(cmd.item, cmd.newName); response.success = true; }
                        catch (ex) { response.error = (ex && ex.message) ? ex.message : String(ex); }
                    }
                    this.write(JSON.stringify(response));
                    break;
                }
                case 'export': {
                    var response = { action: 'export', reqid: cmd.reqid, hive: cmd.hive, path: cmd.path };
                    if (process.platform != 'win32') {
                        response.error = 'Registry is currently supported on Windows agents only.';
                    } else {
                        try { response.success = true; response.content = remoteRegistry.exportKey(cmd.hive, cmd.path || ''); }
                        catch (ex) { response.error = (ex && ex.message) ? ex.message : String(ex); }
                    }
                    this.write(JSON.stringify(response));
                    break;
                }
                default: {
                    this.write(JSON.stringify({ action: cmd.action, reqid: cmd.reqid, error: 'Unknown registry action.' }));
                    break;
                }
            }
        } else if (this.httprequest.protocol == 5) {
            // Process files commands
            var cmd = null;
            try { cmd = JSON.parse(data); } catch (ex) { };
            if (cmd == null) { return; }
            if ((cmd.ctrlChannel == '102938') || ((cmd.type == 'offer') && (cmd.sdp != null))) { onTunnelControlData(cmd, this); return; } // If this is control data, handle it now.
            if (cmd.action == undefined) { return; }
            //sendConsoleText('CMD: ' + JSON.stringify(cmd));

            if ((cmd.path != null) && (process.platform != 'win32') && (cmd.path[0] != '/')) { cmd.path = '/' + cmd.path; } // Add '/' to paths on non-windows
            //console.log(objToString(cmd, 0, ' '));
            switch (cmd.action) {
                case 'ls': {
                    /*
                    // Close the watcher if required
                    var samepath = ((this.httprequest.watcher != undefined) && (cmd.path == this.httprequest.watcher.path));
                    if ((this.httprequest.watcher != undefined) && (samepath == false)) {
                        //console.log('Closing watcher: ' + this.httprequest.watcher.path);
                        //this.httprequest.watcher.close(); // TODO: This line causes the agent to crash!!!!
                        delete this.httprequest.watcher;
                    }
                    */

                    // Send the folder content to the browser
                    var response = getDirectoryInfo(cmd.path);
                    response.reqid = cmd.reqid;
                    this.write(Buffer.from(JSON.stringify(response)));

                    /*
                    // Start the directory watcher
                    if ((cmd.path != '') && (samepath == false)) {
                        var watcher = fs.watch(cmd.path, onFileWatcher);
                        watcher.tunnel = this.httprequest;
                        watcher.path = cmd.path;
                        this.httprequest.watcher = watcher;
                        //console.log('Starting watcher: ' + this.httprequest.watcher.path);
                    }
                    */
                    break;
                }
                case 'mkdir': {
                    // Create a new empty folder
                    fs.mkdirSync(cmd.path);
                    MeshServerLogEx(44, [cmd.path], "Create folder: \"" + cmd.path + "\"", this.httprequest);
                    break;
                }
                case 'mkfile': {
                    // Create a new empty file
                    fs.closeSync(fs.openSync(cmd.path, 'w'));
                    MeshServerLogEx(164, [cmd.path], "Create file: \"" + cmd.path + "\"", this.httprequest);
                    break;
                }
                case 'rm': {
                    // Delete, possibly recursive delete
                    for (var i in cmd.delfiles) {
                        var p = obj.path.join(cmd.path, cmd.delfiles[i]), delcount = 0;
                        try { delcount = deleteFolderRecursive(p, cmd.rec); } catch (ex) { }
                        if ((delcount == 1) && !cmd.rec) {
                            MeshServerLogEx(45, [p], "Delete: \"" + p + "\"", this.httprequest);
                        } else {
                            if (cmd.rec) {
                                MeshServerLogEx(46, [p, delcount], "Delete recursive: \"" + p + "\", " + delcount + " element(s) removed", this.httprequest);
                            } else {
                                MeshServerLogEx(47, [p, delcount], "Delete: \"" + p + "\", " + delcount + " element(s) removed", this.httprequest);
                            }
                        }
                    }
                    break;
                }
                case 'open': {
                    // Open the local file/folder on the users desktop
                    if (cmd.path) {
                        MeshServerLogEx(20, [cmd.path], "Opening: " + cmd.path, cmd);
                        openFileOnDesktop(cmd.path);
                    }
                }
                case 'markcoredump': {
                    // If we are asking for the coredump file, set the right path.
                    var coreDumpPath = null;
                    if (process.platform == 'win32') {
                        if (fs.existsSync(process.coreDumpLocation)) { coreDumpPath = process.coreDumpLocation; }
                    } else {
                        if ((process.cwd() != '//') && fs.existsSync(process.cwd() + 'core')) { coreDumpPath = process.cwd() + 'core'; }
                    }
                    if (coreDumpPath != null) { db.Put('CoreDumpTime', require('fs').statSync(coreDumpPath).mtime); }
                    break;
                }
                case 'rename':
                    {
                        // Rename a file or folder
                        var oldfullpath = obj.path.join(cmd.path, cmd.oldname);
                        var newfullpath = obj.path.join(cmd.path, cmd.newname);
                        MeshServerLogEx(48, [oldfullpath, cmd.newname], 'Rename: \"' + oldfullpath + '\" to \"' + cmd.newname + '\"', this.httprequest);
                        try { fs.renameSync(oldfullpath, newfullpath); } catch (ex) { console.log(ex); }
                        break;
                    }
                case 'findfile':
                    {
                        // Search for files
                        var r = require('file-search').find('"' + cmd.path + '"', cmd.filter);
                        if (!r.cancel) { r.cancel = function cancel() { this.child.kill(); }; }
                        this._search = r;
                        r.socket = this;
                        r.socket.reqid = cmd.reqid; // Search request id. This is used to send responses and cancel the request.
                        r.socket.path = cmd.path;   // Search path
                        r.on('result', function (str) { try { this.socket.write(Buffer.from(JSON.stringify({ action: 'findfile', r: str.substring(this.socket.path.length), reqid: this.socket.reqid }))); } catch (ex) { } });
                        r.then(function () { try { this.socket.write(Buffer.from(JSON.stringify({ action: 'findfile', r: null, reqid: this.socket.reqid }))); } catch (ex) { } });
                        break;
                    }
                case 'cancelfindfile':
                    {
                        if (this._search) { this._search.cancel(); this._search = null; }
                        break;
                    }
                case 'download':
                    {
                        // Download a file
                        var sendNextBlock = 0;
                        if (cmd.sub == 'start') { // Setup the download
                            if ((cmd.path == null) && (cmd.ask == 'coredump')) { // If we are asking for the coredump file, set the right path.
                                if (process.platform == 'win32') {
                                    if (fs.existsSync(process.coreDumpLocation)) { cmd.path = process.coreDumpLocation; }
                                } else {
                                    if ((process.cwd() != '//') && fs.existsSync(process.cwd() + 'core')) { cmd.path = process.cwd() + 'core'; }
                                }
                            }
                            MeshServerLogEx((cmd.ask == 'coredump') ? 104 : 49, [cmd.path], 'Download: \"' + cmd.path + '\"', this.httprequest);
                            if ((cmd.path == null) || (this.filedownload != null)) { this.write({ action: 'download', sub: 'cancel', id: this.filedownload.id }); delete this.filedownload; }
                            this.filedownload = { id: cmd.id, path: cmd.path, ptr: 0 }
                            try { this.filedownload.f = fs.openSync(this.filedownload.path, 'rbN'); } catch (ex) { this.write({ action: 'download', sub: 'cancel', id: this.filedownload.id }); delete this.filedownload; }
                            if (this.filedownload) { this.write({ action: 'download', sub: 'start', id: cmd.id }); }
                        } else if ((this.filedownload != null) && (cmd.id == this.filedownload.id)) { // Download commands
                            if (cmd.sub == 'startack') { sendNextBlock = ((typeof cmd.ack == 'number') ? cmd.ack : 8); } else if (cmd.sub == 'stop') { delete this.filedownload; } else if (cmd.sub == 'ack') { sendNextBlock = 1; }
                        }
                        // Send the next download block(s)
                        if (sendNextBlock > 0) {
                            sendNextBlock--;
                            var buf = Buffer.alloc(16384);
                            var len = fs.readSync(this.filedownload.f, buf, 4, 16380, null);
                            this.filedownload.ptr += len;
                            if (len < 16380) { buf.writeInt32BE(0x01000001, 0); fs.closeSync(this.filedownload.f); delete this.filedownload; sendNextBlock = 0; } else { buf.writeInt32BE(0x01000000, 0); }
                            this.write(buf.slice(0, len + 4)); // Write as binary
                        }
                        break;
                    }
                case 'upload':
                    {
                        // Upload a file, browser to agent
                        if (this.httprequest.uploadFile != null) { fs.closeSync(this.httprequest.uploadFile); delete this.httprequest.uploadFile; }
                        if (cmd.path == undefined) break;
                        var filepath = cmd.name ? obj.path.join(cmd.path, cmd.name) : cmd.path;
                        this.httprequest.uploadFilePath = filepath;
                        this.httprequest.uploadFileSize = 0;
                        try { this.httprequest.uploadFile = fs.openSync(filepath, cmd.append ? 'abN' : 'wbN'); } catch (ex) { this.write(Buffer.from(JSON.stringify({ action: 'uploaderror', reqid: cmd.reqid }))); break; }
                        this.httprequest.uploadFileid = cmd.reqid;
                        if (this.httprequest.uploadFile) { this.write(Buffer.from(JSON.stringify({ action: 'uploadstart', reqid: this.httprequest.uploadFileid }))); }
                        break;
                    }
                case 'uploaddone':
                    {
                        // Indicates that an upload is done
                        if (this.httprequest.uploadFile) {
                            MeshServerLogEx(105, [this.httprequest.uploadFilePath, this.httprequest.uploadFileSize], 'Upload: \"' + this.httprequest.uploadFilePath + '\", Size: ' + this.httprequest.uploadFileSize, this.httprequest);
                            fs.closeSync(this.httprequest.uploadFile);
                            this.write(Buffer.from(JSON.stringify({ action: 'uploaddone', reqid: this.httprequest.uploadFileid }))); // Indicate that we closed the file.
                            delete this.httprequest.uploadFile;
                            delete this.httprequest.uploadFileid;
                            delete this.httprequest.uploadFilePath;
                            delete this.httprequest.uploadFileSize;
                        }
                        break;
                    }
                case 'uploadcancel':
                    {
                        // Indicates that an upload is canceled
                        if (this.httprequest.uploadFile) {
                            fs.closeSync(this.httprequest.uploadFile);
                            fs.unlinkSync(this.httprequest.uploadFilePath);
                            this.write(Buffer.from(JSON.stringify({ action: 'uploadcancel', reqid: this.httprequest.uploadFileid }))); // Indicate that we closed the file.
                            delete this.httprequest.uploadFile;
                            delete this.httprequest.uploadFileid;
                            delete this.httprequest.uploadFilePath;
                            delete this.httprequest.uploadFileSize;
                        }
                        break;
                    }
                case 'uploadhash':
                    {
                        // Hash a file
                        var filepath = cmd.name ? obj.path.join(cmd.path, cmd.name) : cmd.path;
                        var h = null;
                        try { h = getSHA384FileHash(filepath); } catch (ex) { sendConsoleText(ex); }
                        this.write(Buffer.from(JSON.stringify({ action: 'uploadhash', reqid: cmd.reqid, path: cmd.path, name: cmd.name, tag: cmd.tag, hash: (h ? h.toString('hex') : null) })));
                        break
                    }
                case 'copy':
                    {
                        // Copy a bunch of files from scpath to dspath
                        for (var i in cmd.names) {
                            var sc = obj.path.join(cmd.scpath, cmd.names[i]), ds = obj.path.join(cmd.dspath, cmd.names[i]);
                            MeshServerLogEx(51, [sc, ds], 'Copy: \"' + sc + '\" to \"' + ds + '\"', this.httprequest);
                            if (sc != ds) { try { fs.copyFileSync(sc, ds); } catch (ex) { } }
                        }
                        break;
                    }
                case 'move':
                    {
                        // Move a bunch of files from scpath to dspath
                        for (var i in cmd.names) {
                            var sc = obj.path.join(cmd.scpath, cmd.names[i]), ds = obj.path.join(cmd.dspath, cmd.names[i]);
                            MeshServerLogEx(52, [sc, ds], 'Move: \"' + sc + '\" to \"' + ds + '\"', this.httprequest);
                            if (sc != ds) { try { fs.copyFileSync(sc, ds); fs.unlinkSync(sc); } catch (ex) { } }
                        }
                        break;
                    }
                case 'zip':
                    // Zip a bunch of files
                    if (this.zip != null) return; // Zip operating is currently running, exit now.

                    // Check that the specified files exist & build full paths
                    var fp, stat, p = [];
                    for (var i in cmd.files) { fp = cmd.path + '/' + cmd.files[i]; stat = null; try { stat = fs.statSync(fp); } catch (ex) { } if (stat != null) { p.push(fp); } }
                    if (p.length == 0) return; // No files, quit now.

                    // Setup file compression
                    var ofile = cmd.path + '/' + cmd.output;
                    this.write(Buffer.from(JSON.stringify({ action: 'dialogmessage', msg: 'zipping' })));
                    this.zipfile = ofile;
                    delete this.zipcancel;
                    var out = require('fs').createWriteStream(ofile, { flags: 'wb' });
                    out.xws = this;
                    out.on('close', function () {
                        this.xws.write(Buffer.from(JSON.stringify({ action: 'dialogmessage', msg: null })));
                        this.xws.write(Buffer.from(JSON.stringify({ action: 'refresh' })));
                        if (this.xws.zipcancel === true) { fs.unlinkSync(this.xws.zipfile); } // Delete the complete file.
                        delete this.xws.zipcancel;
                        delete this.xws.zipfile;
                        delete this.xws.zip;
                    });
                    this.zip = require('zip-writer').write({ files: p, basePath: cmd.path });
                    this.zip.xws = this;
                    this.zip.on('progress', require('events').moderated(function (name, p) { this.xws.write(Buffer.from(JSON.stringify({ action: 'dialogmessage', msg: 'zippingFile', file: ((process.platform == 'win32') ? (name.split('/').join('\\')) : name), progress: p }))); }, 1000));
                    this.zip.pipe(out);
                    break;
                case 'unzip':
                    if (this.unzip != null) return; // Unzip operating is currently running, exit now.
                    this.unzip = require('zip-reader').read(cmd.input);
                    this.unzip._dest = cmd.dest;
                    this.unzip.xws = this;
                    this.unzip.then(function (zipped) {
                        this.xws.write(Buffer.from(JSON.stringify({ action: 'dialogmessage', msg: 'unzipping' })));
                        zipped.xws = this.xws;
                        zipped.extractAll(this._dest).then(function () { // finished extracting
                            zipped.xws.write(Buffer.from(JSON.stringify({ action: 'dialogmessage', msg: null })));
                            zipped.xws.write(Buffer.from(JSON.stringify({ action: 'refresh' })));
                            delete zipped.xws.unzip;
                        }, function (e) { // error extracting
                            zipped.xws.write(Buffer.from(JSON.stringify({ action: 'dialogmessage', msg: 'unziperror', error: e })));
                            delete zipped.xws.unzip;
                        });
                    }, function (e) { this.xws.write(Buffer.from(JSON.stringify({ action: 'dialogmessage', msg: 'unziperror', error: e }))); delete this.xws.unzip });
                    break;
                case 'cancel':
                    // Cancel zip operation if present
                    try { this.zipcancel = true; this.zip.cancel(function () { }); } catch (ex) { }
                    this.zip = null;
                    break;
                default:
                    // Unknown action, ignore it.
                    break;
            }
        } else if (this.httprequest.protocol == 7) { // Plugin data exchange
            var cmd = null;
            try { cmd = JSON.parse(data); } catch (ex) { };
            if (cmd == null) { return; }
            if ((cmd.ctrlChannel == '102938') || ((cmd.type == 'offer') && (cmd.sdp != null))) { onTunnelControlData(cmd, this); return; } // If this is control data, handle it now.
            if (cmd.action == undefined) return;

            switch (cmd.action) {
                case 'plugin': {
                    try { require(cmd.plugin).consoleaction(cmd, null, null, this); } catch (ex) { throw ex; }
                    break;
                }
                default: {
                    // probably shouldn't happen, but just in case this feature is expanded
                }
            }

        }
        //sendConsoleText("Got tunnel #" + this.httprequest.index + " data: " + data, this.httprequest.sessionid);
    }
}

// Delete a directory with a files and directories within it
function deleteFolderRecursive(path, rec) {
    var count = 0;
    if (fs.existsSync(path)) {
        if (rec == true) {
            fs.readdirSync(obj.path.join(path, '*')).forEach(function (file, index) {
                var curPath = obj.path.join(path, file);
                if (fs.statSync(curPath).isDirectory()) { // recurse
                    count += deleteFolderRecursive(curPath, true);
                } else { // delete file
                    fs.unlinkSync(curPath);
                    count++;
                }
            });
        }
        fs.unlinkSync(path);
        count++;
    }
    return count;
}

// Called when receiving control data on WebRTC
function onTunnelWebRTCControlData(data) {
    if (typeof data != 'string') return;
    var obj;
    try { obj = JSON.parse(data); } catch (ex) { sendConsoleText('Invalid control JSON on WebRTC: ' + data); return; }
    if (obj.type == 'close') {
        //sendConsoleText('Tunnel #' + this.xrtc.websocket.tunnel.index + ' WebRTC control close');
        try { this.close(); } catch (ex) { }
        try { this.xrtc.close(); } catch (ex) { }
    }
}

function tunnel_webrtc_onEnd()
{
    // The WebRTC channel closed, unpipe the KVM now. This is also done when the web socket closes.
    //sendConsoleText('Tunnel #' + this.websocket.tunnel.index + ' WebRTC data channel closed');
    if (this.websocket.desktop && this.websocket.desktop.kvm)
    {
        try
        {
            this.unpipe(this.websocket.desktop.kvm);
            this.websocket.httprequest.desktop.kvm.unpipe(this);
        } catch (ex) { }
    }
    this.httprequest = null;
    this.websocket = null;
}
function tunnel_webrtc_DataChannel_OnFinalized()
{
    console.info1('WebRTC DataChannel Finalized');
}
function tunnel_webrtc_OnDataChannel(rtcchannel)
{
    //sendConsoleText('WebRTC Datachannel open, protocol: ' + this.websocket.httprequest.protocol);
    //rtcchannel.maxFragmentSize = 32768;
    rtcchannel.xrtc = this;
    rtcchannel.websocket = this.websocket;
    this.rtcchannel = rtcchannel;
    this.rtcchannel.once('~', tunnel_webrtc_DataChannel_OnFinalized);
    this.websocket.rtcchannel = rtcchannel;
    this.websocket.rtcchannel.on('data', onTunnelWebRTCControlData);
    this.websocket.rtcchannel.on('end', tunnel_webrtc_onEnd);
    this.websocket.write('{\"ctrlChannel\":\"102938\",\"type\":\"webrtc0\"}'); // Indicate we are ready for WebRTC switch-over.
}

function tunnel_webrtc_OnFinalized()
{
    console.info1('WebRTC Connection Finalized');
}

// Called when receiving control data on websocket
function onTunnelControlData(data, ws) {
    var obj;
    if (ws == null) { ws = this; }
    if (typeof data == 'string') { try { obj = JSON.parse(data); } catch (ex) { sendConsoleText('Invalid control JSON: ' + data); return; } }
    else if (typeof data == 'object') { obj = data; } else { return; }
    //sendConsoleText('onTunnelControlData(' + ws.httprequest.protocol + '): ' + JSON.stringify(data));
    //console.log('onTunnelControlData: ' + JSON.stringify(data));

    switch (obj.type) {
        case 'lock': {
            // Look for a TSID
            var tsid = null;
            if ((ws.httprequest.xoptions != null) && (typeof ws.httprequest.xoptions.tsid == 'number')) { tsid = ws.httprequest.xoptions.tsid; }

            // Lock the current user out of the desktop
            MeshServerLogEx(53, null, "Locking remote user out of desktop", ws.httprequest);
            lockDesktop(tsid);
            break;
        }
        case 'autolock': {
            // Set the session to auto lock on disconnect
            if (obj.value === true) {
                ws.httprequest.autolock = true;
                if (ws.httprequest.unlockerHelper == null) {
                    destopLockHelper_pipe(ws.httprequest);
                }
            }
            else {
                delete ws.httprequest.autolock;
            }
            break;
        }
        case 'options': {
            // These are additional connection options passed in the control channel.
            //sendConsoleText('options: ' + JSON.stringify(obj));
            delete obj.type;
            ws.httprequest.xoptions = obj;

            // Set additional user consent options if present
            if ((obj != null) && (typeof obj.consent == 'number')) { ws.httprequest.consent |= obj.consent; }

            // Set autolock
            if ((obj != null) && (obj.autolock === true)) {
                ws.httprequest.autolock = true;
                if (ws.httprequest.unlockerHelper == null) {
                    destopLockHelper_pipe(ws.httprequest);
                }
            }

            break;
        }
        case 'close': {
            // We received the close on the websocket
            //sendConsoleText('Tunnel #' + ws.tunnel.index + ' WebSocket control close');
            // Attempt to send EOF (Ctrl-D) multiple times to exit nested shells (screen, su, etc.) cleanly,
            // This allows the shell to write its history before the process is killed
            if (process.platform != 'win32' && ws.httprequest && ws.httprequest.process && ws.httprequest.process.stdin) {
                try { ws.httprequest.process.stdin.write('\x04\x04\x04'); } catch (ex) { }
            }
            try { ws.close(); } catch (ex) { }
            break;
        }
        case 'termsize': {
            // Indicates a change in terminal size
            if (process.platform == 'win32') {
                if (ws.httprequest._dispatcher == null) return;
                //sendConsoleText('Win32-TermSize: ' + obj.cols + 'x' + obj.rows);
                if (ws.httprequest._dispatcher.invoke) { ws.httprequest._dispatcher.invoke('resizeTerminal', [obj.cols, obj.rows]); }
            } else {
                if (ws.httprequest.process == null || ws.httprequest.process.pty == 0) return;
                //sendConsoleText('Linux Resize: ' + obj.cols + 'x' + obj.rows);

                if (ws.httprequest.process.tcsetsize) { ws.httprequest.process.tcsetsize(obj.rows, obj.cols); }
            }
            break;
        }
        case 'webrtc0': { // Browser indicates we can start WebRTC switch-over.
            if (ws.httprequest.protocol == 1)
            { // Terminal
                // This is a terminal data stream, unpipe the terminal now and indicate to the other side that terminal data will no longer be received over WebSocket
                if (process.platform == 'win32') {
                    ws.httprequest._term.unpipe(ws);
                } else {
                    ws.httprequest.process.stdout.unpipe(ws);
                    ws.httprequest.process.stderr.unpipe(ws);
                }
            } else if (ws.httprequest.protocol == 2) { // Desktop
                // This is a KVM data stream, unpipe the KVM now and indicate to the other side that KVM data will no longer be received over WebSocket
                ws.httprequest.desktop.kvm.unpipe(ws);
            } else
            {
                // Switch things around so all WebRTC data goes to onTunnelData().
                ws.rtcchannel.httprequest = ws.httprequest;
                ws.rtcchannel.removeAllListeners('data');
                ws.rtcchannel.on('data', onTunnelData);
            }
            ws.write("{\"ctrlChannel\":\"102938\",\"type\":\"webrtc1\"}"); // End of data marker
            break;
        }
        case 'webrtc1':
            {
            if ((ws.httprequest.protocol == 1) || (ws.httprequest.protocol == 6))
            { // Terminal
                // Switch the user input from websocket to webrtc at this point.
                if (process.platform == 'win32') {
                    ws.unpipe(ws.httprequest._term);
                    ws.rtcchannel.pipe(ws.httprequest._term, { dataTypeSkip: 1 }); // 0 = Binary, 1 = Text.
                } else {
                    ws.unpipe(ws.httprequest.process.stdin);
                    ws.rtcchannel.pipe(ws.httprequest.process.stdin, { dataTypeSkip: 1 }); // 0 = Binary, 1 = Text.
                }
                ws.resume(); // Resume the websocket to keep receiving control data
            }
            else if (ws.httprequest.protocol == 2)
            { // Desktop
                // Switch the user input from websocket to webrtc at this point.
                ws.unpipe(ws.httprequest.desktop.kvm);
                if ((ws.httprequest.desktopviewonly != true) && ((ws.httprequest.rights == 0xFFFFFFFF) || (((ws.httprequest.rights & MESHRIGHT_REMOTECONTROL) != 0) && ((ws.httprequest.rights & MESHRIGHT_REMOTEVIEW) == 0)))) {
                    // If we have remote control rights, pipe the KVM input
                    try { ws.webrtc.rtcchannel.pipe(ws.httprequest.desktop.kvm, { dataTypeSkip: 1, end: false }); } catch (ex) { sendConsoleText('EX2'); } // 0 = Binary, 1 = Text.
                } else {
                    // We need to only pipe non-mouse & non-keyboard inputs.
                    // sendConsoleText('Warning: No Remote Desktop Input Rights.');
                    // TODO!!!
                }
                ws.resume(); // Resume the websocket to keep receiving control data
            }
            ws.write('{\"ctrlChannel\":\"102938\",\"type\":\"webrtc2\"}'); // Indicates we will no longer get any data on websocket, switching to WebRTC at this point.
            break;
        }
        case 'webrtc2': {
            // Other side received websocket end of data marker, start sending data on WebRTC channel
            if ((ws.httprequest.protocol == 1) || (ws.httprequest.protocol == 6)) { // Terminal
                if (process.platform == 'win32') {
                    ws.httprequest._term.pipe(ws.webrtc.rtcchannel, { dataTypeSkip: 1, end: false }); // 0 = Binary, 1 = Text.
                } else {
                    ws.httprequest.process.stdout.pipe(ws.webrtc.rtcchannel, { dataTypeSkip: 1, end: false }); // 0 = Binary, 1 = Text.
                    ws.httprequest.process.stderr.pipe(ws.webrtc.rtcchannel, { dataTypeSkip: 1, end: false }); // 0 = Binary, 1 = Text.
                }
            } else if (ws.httprequest.protocol == 2) { // Desktop
                ws.httprequest.desktop.kvm.pipe(ws.webrtc.rtcchannel, { dataTypeSkip: 1 }); // 0 = Binary, 1 = Text.
            }
            break;
        }
        case 'offer': {
            // This is a WebRTC offer.
            if ((ws.httprequest.protocol == 1) || (ws.httprequest.protocol == 6)) return; // TODO: Terminal is currently broken with WebRTC. Reject WebRTC upgrade for now.
            ws.webrtc = rtc.createConnection();
            ws.webrtc.once('~', tunnel_webrtc_OnFinalized);
            ws.webrtc.websocket = ws;
            //ws.webrtc.on('connected', function () { /*sendConsoleText('Tunnel #' + this.websocket.tunnel.index + ' WebRTC connected');*/ });
            //ws.webrtc.on('disconnected', function () { /*sendConsoleText('Tunnel #' + this.websocket.tunnel.index + ' WebRTC disconnected');*/ });
            ws.webrtc.on('dataChannel', tunnel_webrtc_OnDataChannel);

            var sdp = null;
            try { sdp = ws.webrtc.setOffer(obj.sdp); } catch (ex) { }
            if (sdp != null) { ws.write({ type: 'answer', ctrlChannel: '102938', sdp: sdp }); }
            break;
        }
        case 'ping': {
            ws.write("{\"ctrlChannel\":\"102938\",\"type\":\"pong\"}"); // Send pong response
            break;
        }
        case 'pong': { // NOP
            break;
        }
        case 'rtt': {
            ws.write({ type: 'rtt', ctrlChannel: '102938', time: obj.time });
            break;
        }
    }
}

// Console state
var consoleWebSockets = {};
var consoleHttpRequest = null;

// Console HTTP response
function consoleHttpResponse(response) {
    response.data = function (data) { sendConsoleText(rstr2hex(buf2rstr(data)), this.sessionid); consoleHttpRequest = null; }
    response.close = function () { sendConsoleText('httprequest.response.close', this.sessionid); consoleHttpRequest = null; }
}

// Open a local file on current user's desktop
function openFileOnDesktop(file) {
    var child = null;
    try {
        switch (process.platform) {
            case 'win32':
                var uid = require('user-sessions').consoleUid();
                var user = require('user-sessions').getUsername(uid);
                var domain = require('user-sessions').getDomain(uid);
                var task = { name: 'MeshChatTask', user: user, domain: domain, execPath: (require('fs').statSync(file).isDirectory() ? process.env['windir'] + '\\explorer.exe' : file) };
                if (require('fs').statSync(file).isDirectory()) task.arguments = [file];
                try {
                    require('win-tasks').addTask(task);
                    require('win-tasks').getTask({ name: 'MeshChatTask' }).run();
                    require('win-tasks').deleteTask('MeshChatTask');
                    return (true);
                }
                catch (ex) {
                    var taskoptions = { env: { _target: (require('fs').statSync(file).isDirectory() ? process.env['windir'] + '\\explorer.exe' : file), _user: '"' + domain + '\\' + user + '"' }, _args: "" };
                    if (require('fs').statSync(file).isDirectory()) taskoptions.env._args = file;
                    for (var c1e in process.env) {
                        taskoptions.env[c1e] = process.env[c1e];
                    }
                    var child = require('child_process').execFile(process.env['windir'] + '\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', ['powershell', '-noprofile', '-nologo', '-command', '-'], taskoptions);
                    child.stderr.on('data', function (c) { });
                    child.stdout.on('data', function (c) { });
                    child.stdin.write('SCHTASKS /CREATE /F /TN MeshChatTask /SC ONCE /ST 00:00 ');
                    if (user) { child.stdin.write('/RU $env:_user '); }
                    child.stdin.write('/TR "$env:_target $env:_args"\r\n');
                    child.stdin.write('$ts = New-Object -ComObject Schedule.service\r\n');
                    child.stdin.write('$ts.connect()\r\n');
                    child.stdin.write('$tsfolder = $ts.getfolder("\\")\r\n');
                    child.stdin.write('$task = $tsfolder.GetTask("MeshChatTask")\r\n');
                    child.stdin.write('$taskdef = $task.Definition\r\n');
                    child.stdin.write('$taskdef.Settings.StopIfGoingOnBatteries = $false\r\n');
                    child.stdin.write('$taskdef.Settings.DisallowStartIfOnBatteries = $false\r\n');
                    child.stdin.write('$taskdef.Actions.Item(1).Path = $env:_target\r\n');
                    child.stdin.write('$taskdef.Actions.Item(1).Arguments = $env:_args\r\n');
                    child.stdin.write('$tsfolder.RegisterTaskDefinition($task.Name, $taskdef, 4, $null, $null, $null)\r\n');
                    child.stdin.write('SCHTASKS /RUN /TN MeshChatTask\r\n');
                    child.stdin.write('SCHTASKS /DELETE /F /TN MeshChatTask\r\nexit\r\n');
                    child.waitExit();
                }
                break;
            case 'linux':
                child = require('child_process').execFile('/usr/bin/xdg-open', ['xdg-open', file], { uid: require('user-sessions').consoleUid() });
                break;
            case 'darwin':
                child = require('child_process').execFile('/usr/bin/open', ['open', file]);
                break;
            default:
                // Unknown platform, ignore this command.
                break;
        }
    } catch (ex) { }
    return child;
}

// Open a web browser to a specified URL on current user's desktop
function openUserDesktopUrl(url) {
    if ((url.toLowerCase().startsWith('http://') == false) && (url.toLowerCase().startsWith('https://') == false)) { return null; }
    var child = null;
    try {
        switch (process.platform) {
            case 'win32':
                var uid = require('user-sessions').consoleUid();
                var user = require('user-sessions').getUsername(uid);
                var domain = require('user-sessions').getDomain(uid);
                var task = { name: 'MeshChatTask', user: user, domain: domain, execPath: process.env['windir'] + '\\system32\\cmd.exe', arguments: ['/C START ' + url.split('&').join('^&')] };

                try {
                    require('win-tasks').addTask(task);
                    require('win-tasks').getTask({ name: 'MeshChatTask' }).run();
                    require('win-tasks').deleteTask('MeshChatTask');
                    return (true);
                }
                catch (ex) {
                    var taskoptions = { env: { _target: process.env['windir'] + '\\system32\\cmd.exe', _args: '/C START ' + url.split('&').join('^&'), _user: '"' + domain + '\\' + user + '"' } };
                    for (var c1e in process.env) {
                        taskoptions.env[c1e] = process.env[c1e];
                    }
                    var child = require('child_process').execFile(process.env['windir'] + '\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', ['powershell', '-noprofile', '-nologo', '-command', '-'], taskoptions);
                    child.stderr.on('data', function (c) { });
                    child.stdout.on('data', function (c) { });
                    child.stdin.write('SCHTASKS /CREATE /F /TN MeshChatTask /SC ONCE /ST 00:00 ');
                    if (user) { child.stdin.write('/RU $env:_user '); }
                    child.stdin.write('/TR "$env:_target $env:_args"\r\n');
                    child.stdin.write('$ts = New-Object -ComObject Schedule.service\r\n');
                    child.stdin.write('$ts.connect()\r\n');
                    child.stdin.write('$tsfolder = $ts.getfolder("\\")\r\n');
                    child.stdin.write('$task = $tsfolder.GetTask("MeshChatTask")\r\n');
                    child.stdin.write('$taskdef = $task.Definition\r\n');
                    child.stdin.write('$taskdef.Settings.StopIfGoingOnBatteries = $false\r\n');
                    child.stdin.write('$taskdef.Settings.DisallowStartIfOnBatteries = $false\r\n');
                    child.stdin.write('$taskdef.Actions.Item(1).Path = $env:_target\r\n');
                    child.stdin.write('$taskdef.Actions.Item(1).Arguments = $env:_args\r\n');
                    child.stdin.write('$tsfolder.RegisterTaskDefinition($task.Name, $taskdef, 4, $null, $null, $null)\r\n');

                    child.stdin.write('SCHTASKS /RUN /TN MeshChatTask\r\n');
                    child.stdin.write('SCHTASKS /DELETE /F /TN MeshChatTask\r\nexit\r\n');
                    child.waitExit();
                }
                break;
            case 'linux':
                child = require('child_process').execFile('/usr/bin/xdg-open', ['xdg-open', url], { uid: require('user-sessions').consoleUid() });
                break;
            case 'darwin':
                child = require('child_process').execFile('/usr/bin/open', ['open', url], { uid: require('user-sessions').consoleUid() });
                break;
            default:
                // Unknown platform, ignore this command.
                break;
        }
    } catch (ex) { }
    return child;
}

// Process a mesh agent console command
function processConsoleCommand(cmd, args, rights, sessionid) {
    try {
        var response = null;
        switch (cmd) {
            case 'help': { // Displays available commands
                var fin = '', f = '', availcommands = 'domain,translations,agentupdate,errorlog,msh,timerinfo,coreinfo,coreinfoupdate,coredump,service,fdsnapshot,fdcount,startupoptions,';
                availcommands += 'alert,agentsize,versions,help,info,osinfo,args,print,type,dbkeys,dbget,dbset,dbdelete,dbcompact,eval,parseuri,httpget,wslist,plugin,wsconnect,wssend,wsclose,notify,';
                availcommands += 'ls,ps,kill,netinfo,location,power,wakeonlan,setdebug,smbios,rawsmbios,toast,lock,users,openurl,getclip,setclip,log,cpuinfo,sysinfo,';
                availcommands += 'apf,scanwifi,wallpaper,agentmsg,task,uninstallagent,display,openfile,installedapps';
                if (require('os').dns != null) { availcommands += ',dnsinfo'; }
                try { require('linux-dhcp'); availcommands += ',dhcp'; } catch (ex) { }
                if (process.platform == 'win32') {
                    availcommands += ',bitlocker,cs,wpfhwacceleration,uac,volumes,rdpport,domaininfo,printers,wmi';
                    if (bcdOK()) { availcommands += ',safemode'; }
                    if (require('notifybar-desktop').DefaultPinned != null) { availcommands += ',privacybar'; }
                    try { require('win-utils'); availcommands += ',taskbar'; } catch (ex) { }
                    try { require('win-info'); availcommands += ',qfe,defender,av,installedstoreapps'; } catch (ex) { }
                    try { require('win-updates'); availcommands += ',winupdates,winupdatesinstalled,winupdateshistory,winupdatesdedup'; } catch (ex) { }
                    try { require('win-deskutils'); availcommands += ',mousetrails,idletime,deskbackground'; } catch (ex) { }
                }
                if (amt != null) { availcommands += ',amt,amtconfig,amtevents'; }
                if (process.platform != 'freebsd') { availcommands += ',vm'; }
                if (require('MeshAgent').maxKvmTileSize != null) { availcommands += ',kvmmode'; }
                try { require('zip-reader'); availcommands += ',zip,unzip'; } catch (ex) { }

                availcommands = availcommands.split(',').sort();
                while (availcommands.length > 0) {
                    if (f.length > 90) { fin += (f + ',\r\n'); f = ''; }
                    f += (((f != '') ? ', ' : ' ') + availcommands.shift());
                }
                if (f != '') { fin += f; }
                response = "Available commands: \r\n" + fin + ".";
                break;
            }
            case 'mousetrails':
                try { require('win-deskutils'); } catch (ex) { response = 'Unknown command "mousetrails", type "help" for list of available commands.'; break; }
                var id = require('user-sessions').getProcessOwnerName(process.pid).tsid == 0 ? 1 : null;
                switch (args['_'].length) 
                {
                    case 0:                    
                        var trails = require('win-deskutils').mouse.getTrails(id);
                        response = trails == 0 ? 'MouseTrails Disabled' : ('MouseTrails enabled (' + trails + ')');
                        response += '\nTo change setting, specify a positive integer, where 0 is disable: mousetrails [n]';
                        break;
                    case 1:
                        var trails = parseInt(args['_'][0]);
                        require('win-deskutils').mouse.setTrails(trails, id);
                        trails = require('win-deskutils').mouse.getTrails(id);
                        response = trails == 0 ? 'MouseTrails Disabled' : ('MouseTrails enabled (' + trails + ')');
                        break;
                    default:
                        response = 'Proper usage: mousetrails [n]';
                        break;
                }
                break;
            case 'deskbackground':
                try { require('win-deskutils'); } catch (ex) { response = 'Unknown command "deskbackground", type "help" for list of available commands.'; break; }
                var id = require('user-sessions').getProcessOwnerName(process.pid).tsid == 0 ? 1 : null;
                switch (args['_'].length)
                {
                    case 0:
                        response = 'Desktop Background: ' + require('win-deskutils').background.get(id);
                        break;
                    case 1:
                        require('win-deskutils').background.set(args['_'][0], id);
                        response = 'Desktop Background: ' + require('win-deskutils').background.get(id);
                        break;
                    default:
                        response = 'Proper usage: deskbackground [path]';
                        break;
                }
                break;
            case 'idletime':
                try { require('win-deskutils'); } catch (ex) { response = 'Unknown command "idletime", type "help" for list of available commands.'; break; }
                require('win-deskutils').idle.getSecondsAllSessions().then(function (seconds) { sendConsoleText((seconds === -1 ? 'No active users' : 'Idle time for all sessions: ' + seconds + ' seconds'), sessionid); });
                break;
            case 'taskbar':
                try { require('win-utils'); } catch (ex) { response = 'Unknown command "taskbar", type "help" for list of available commands.'; break; }
                switch (args['_'].length) {
                    case 1:
                    case 2:
                        {
                            var tsid = parseInt(args['_'][1]);
                            if (isNaN(tsid)) { tsid = require('user-sessions').consoleUid(); }
                            sendConsoleText('Changing TaskBar AutoHide status. Please wait...', sessionid);
                            try {
                                var result = require('win-utils').taskBar.autoHide(tsid, args['_'][0].toLowerCase() == 'hide');
                                response = 'Current Status of TaskBar AutoHide: ' + result;
                            } catch (ex) { response = 'Unable to change TaskBar settings'; }
                        }
                        break;
                    default:
                        {
                            response = 'Proper usage: taskbar HIDE|SHOW [TSID]';
                            break;
                        }
                }
                break;
            case 'printers':
                if (process.platform != 'win32') {
                    response = 'Unknown command "printers", type "help" for list of available commands.';
                } else {
                    var winInfo = require('win-info');
                    var printers = winInfo.printers();
                    for (var i = 0; i < printers.length; ++i) {
                        var p = printers[i];
                        if (p.type === 'system') {
                            var line = p.name + ' - ' + p.port;
                            if (p.portDesc) { line += ' (' + p.portDesc + ')'; }
                            line += ' [' + p.status + ']';
                            if (p.errors.length > 0) { line += ' [' + p.errors.join(', ') + ']'; }
                            if (p.jobCount > 0) { line += ' [' + p.jobCount + ' job' + (p.jobCount > 1 ? 's' : '') + ' queued]'; }
                            sendConsoleText(line, sessionid);
                        } else if (p.type === 'adgpo') {
                            var line = p.name + ' [User/AD-GPO]';
                            if (p.portDesc) { line += ' - ' + p.portDesc; }
                            line += ' (source: ' + p.label + ')';
                            sendConsoleText(line, sessionid);
                        }
                    }
                }
                break;
            case 'privacybar':
                if (process.platform != 'win32' || require('notifybar-desktop').DefaultPinned == null) {
                    response = 'Unknown command "privacybar", type "help" for list of available commands.';
                }
                else {
                    switch (args['_'].length) {
                        default:
                            // Show Help
                            response = "Current Default Pinned State: " + (require('notifybar-desktop').DefaultPinned ? "PINNED" : "UNPINNED") + '\r\n';
                            response += "To set default pinned state:\r\n  privacybar [PINNED|UNPINNED]\r\n";
                            break;
                        case 1:
                            switch (args['_'][0].toUpperCase()) {
                                case 'PINNED':
                                    require('notifybar-desktop').DefaultPinned = true;
                                    response = "privacybar default pinned state is: PINNED";
                                    break;
                                case 'UNPINNED':
                                    require('notifybar-desktop').DefaultPinned = false;
                                    response = "privacybar default pinned state is: UNPINNED";
                                    break;
                                default:
                                    response = "INVALID parameter: " + args['_'][0].toUpperCase();
                                    break;
                            }
                            break;
                    }
                }
                break;
            case 'domain':
                response = getDomainInfo();
                break;
            case 'domaininfo':
                {
                    if (process.platform != 'win32') {
                        response = 'Unknown command "domaininfo", type "help" for list of available commands.';
                        break;
                    }
                    if (global._domainQuery != null) {
                        response = "There is already an outstanding Domain Controller Query... Please try again later...";
                        break;
                    }

                    sendConsoleText('Querying Domain Controller... This can take up to 60 seconds. Please wait...', sessionid);
                    global._domainQuery = require('win-wmi-fixed').queryAsync('ROOT\\CIMV2', 'SELECT * FROM Win32_NTDomain');
                    global._domainQuery.session = sessionid;
                    global._domainQuery.then(function (v) {
                        var results = [];
                        if (Array.isArray(v)) {
                            var i;
                            var r;
                            for (i = 0; i < v.length; ++i) {
                                r = {};
                                if (v[i].DomainControllerAddress != null) { r.DomainControllerAddress = v[i].DomainControllerAddress.split('\\').pop(); }
                                if (r.DomainControllerName != null) { r.DomainControllerName = v[i].DomainControllerName.split('\\').pop(); }
                                r.DomainGuid = v[i].DomainGuid;
                                r.DomainName = v[i].DomainName;
                                if (r.DomainGuid != null) {
                                    results.push(r);
                                }
                            }
                        }
                        if (results.length > 0) {
                            sendConsoleText('Domain Controller Results:', this.session);
                            sendConsoleText(JSON.stringify(results, null, 1), this.session);
                            sendConsoleText('End of results...', this.session);
                        }
                        else {
                            sendConsoleText('Domain Controller: No results returned. Is the domain controller reachable?', this.session);
                        }
                        global._domainQuery = null;
                    });
                    break;
                }
            case 'wmi':
                if (process.platform != 'win32') {
                    response = 'Unknown command "wmi", type "help" for list of available commands.';
                    break;
                }
                if (args['_'].length < 2 || args['_'].length > 3) {
                    response = 'Execute a WMI query.\r\nUsage: wmi namespace "query" [(n)sync][(u)npretty][(s)ilence][(i)ncludesystemproperties]\r\n' +
                            'Default: async, pretty and shows progress\r\n' +
                            'Note: Sync queries block the agent for the duration of the query\r\n' +
                            'Example: wmi CIMV2 "SELECT Name,ProcessId FROM Win32_Process WHERE Name=\'meshagent.exe\'" in\r\n';
                    break;
                }
                var opt = (args['_'][2]|| '').toLowerCase();
                var ns = args['_'][0].trim();
                if (!/^root\\\w/i.test(ns)) { ns = 'ROOT\\' + ns; }
                var q = (args['_'][1]).trim();
                var indent = (opt.indexOf('u') === -1); // unpretty, so default true
                var showProgress = (opt.indexOf('s') === -1);   //s is now silence
                var includeSysProp = (opt.indexOf('i') !== -1);
                var async = opt.indexOf('n') === -1;
                var wmi = require('win-wmi-fixed');
                var output = function (res) { sendConsoleText((res && res.length > 0) ? (JSON.stringify(res, null, (indent ? 2 : 0))) : 'No results', sessionid); };
                var error = function (e) {
                    e = e || {};
                    sendConsoleText(((e.results && e.results.length) ? 'Partial result:\r\n' + JSON.stringify(e.results, null, (indent ? 2 : 0)) + '\r\nPartial resultcount: ' + e.results.length + '\r\n' : '') +
                        'Error: ' + (e.message || JSON.stringify(e)), sessionid); };
                if (showProgress) { sendConsoleText('Performing ' + (async ? 'asynchronous ': '') + 'query ' + (async ? '': 'synchronously (be careful with large queries as it blocks the agent for the duration)'), sessionid); }
                if (async) {
                    wmi.queryAsync(ns, q, null, includeSysProp, null, (showProgress ? sessionid : null))
                    .then( output )
                    .catch( error );
                } else {
                    try { output(wmi.query(ns, q, null, includeSysProp, null, (showProgress ? sessionid : null) )); } catch (e) { error(e); }
                }
                break;
            case 'translations': {
                response = JSON.stringify(coretranslations, null, 2);
                break;
            }
            case 'volumes':
                response = JSON.stringify(require('win-volumes').getVolumes(), null, 1);
                break;
            case 'bitlocker':
                if (process.platform == 'win32') {
                    if (require('user-sessions').isRoot()) {
                        if (require('win-volumes').volumes_promise != null) {
                            var p = require('win-volumes').volumes_promise();
                            p.sessionid = sessionid;
                            p.then(function (res) {
                                if (res && res.error) { sendConsoleText('Bitlocker error: ' + (res.error.message ? res.error.message : res.error), this.sessionid); }
                                var drives = (res && res.drives && (Object.keys(res.drives).length !== 0)) ? res.drives : null;     // win-volumes returns 'drives' as at least {}, so also check on empty object
                                if (drives) {
                                    var conversionStatuses = { 0: 'FullyDecrypted', 1: 'FullyEncrypted', 2: 'EncryptionInProgress', 3: 'DecryptionInProgress', 4: 'EncryptionPaused', 5: 'DecryptionPaused' };
                                    var encryptionMethods = { 0: 'None', 1: 'AES_128_WITH_DIFFUSER', 2: 'AES_256_WITH_DIFFUSER', 3: 'AES_128', 4: 'AES_256', 5: 'HARDWARE_ENCRYPTION', 6: 'XTS_AES_128', 7: 'XTS_AES_256' };
                                    var protectionStatuses = { 0: 'Off', 1: 'On', 2: 'Locked'};
                                    var driveType = { 0: "Unknown", 1: "No Root Directory", 2: "Removable Disk", 3: "Local Disk", 4: "Network Drive", 5: "Compact Disc", 6: "RAM Disk" };
                                    for (var i in drives) {
                                        const v = drives[i];
                                        if (conversionStatuses[v.volumeStatus]) { v.volumeStatus = conversionStatuses[v.volumeStatus]; } else { v.volumeStatus = 'Unknown'; }
                                        if (encryptionMethods[v.encryptionMethod]) { v.encryptionMethod = encryptionMethods[v.encryptionMethod]; } else { v.encryptionMethod = 'Unknown'; }
                                        if (protectionStatuses[v.protectionStatus]) { v.protectionStatus = protectionStatuses[v.protectionStatus]; } else { v.protectionStatus = 'Unknown'; }
                                        if (driveType[v.dType]) {v.dType = driveType[v.dType]; } else { v.dType = 'Unknown'; }
                                        if (v.recoveryPassword && (rights != MESHRIGHT_ADMIN)) { v.recoveryPassword = '(Only admins)'; }
                                    }
                                }
                                sendConsoleText(JSON.stringify((drives ? drives : 'No volume/bitlocker info'), null, 1), this.sessionid);
                            });
                        } else {
                            sendConsoleText('BitLocker info not available.', sessionid);
                        }
                    } else {
                        sendConsoleText('Bitlocker info requires an elevated agent', sessionid);
                    }
                } else {
                    sendConsoleText('BitLocker is only supported on Windows.', sessionid);
                }
                break;
            case 'dhcp': // This command is only supported on Linux, this is because Linux does not give us the DNS suffix for each network adapter independently so we have to ask the DHCP server.
                {
                    try { require('linux-dhcp'); } catch (ex) { response = 'Unknown command "dhcp", type "help" for list of available commands.'; break; }
                    if (args['_'].length == 0) {
                        var j = require('os').networkInterfaces();
                        var ifcs = [];
                        for (var i in j) {
                            for (var z in j[i]) {
                                if (j[i][z].status == 'up' && j[i][z].type != 'loopback' && j[i][z].address != null) {
                                    ifcs.push('"' + i + '"');
                                    break;
                                }
                            }
                        }
                        response = 'Proper usage: dhcp [' + ifcs.join(' | ') + ']';
                    }
                    else {
                        require('linux-dhcp').client.info(args['_'][0]).
                            then(function (d) {
                                sendConsoleText(JSON.stringify(d, null, 1), sessionid);
                            },
                            function (e) {
                                sendConsoleText(e, sessionid);
                            });
                    }
                    break;
                }
            case 'cs':
                if (process.platform != 'win32') {
                    response = 'Unknown command "cs", type "help" for list of available commands.';
                    break;
                }
                switch (args['_'].length) {
                    case 0:
                        try {
                            var cs = require('win-registry').QueryKey(require('win-registry').HKEY.LocalMachine, 'System\\CurrentControlSet\\Control\\Power', 'CsEnabled');
                            response = "Connected Standby: " + (cs == 1 ? "ENABLED" : "DISABLED");
                        } catch (ex) {
                            response = "This machine does not support Connected Standby";
                        }
                        break;
                    case 1:
                        if ((args['_'][0].toUpperCase() != 'ENABLE' && args['_'][0].toUpperCase() != 'DISABLE')) {
                            response = "Proper usage:\r\n  cs [ENABLE|DISABLE]";
                        }
                        else {
                            try {
                                var cs = require('win-registry').QueryKey(require('win-registry').HKEY.LocalMachine, 'System\\CurrentControlSet\\Control\\Power', 'CsEnabled');
                                require('win-registry').WriteKey(require('win-registry').HKEY.LocalMachine, 'System\\CurrentControlSet\\Control\\Power', 'CsEnabled', args['_'][0].toUpperCase() == 'ENABLE' ? 1 : 0);

                                cs = require('win-registry').QueryKey(require('win-registry').HKEY.LocalMachine, 'System\\CurrentControlSet\\Control\\Power', 'CsEnabled');
                                response = "Connected Standby: " + (cs == 1 ? "ENABLED" : "DISABLED");
                            } catch (ex) {
                                response = "This machine does not support Connected Standby";
                            }
                        }
                        break;
                    default:
                        response = "Proper usage:\r\n  cs [ENABLE|DISABLE]";
                        break;
                }
                break;
            case 'assistant':
                if (process.platform == 'win32') {
                    // Install MeshCentral Assistant on this device
                    response = "Usage: Assistant [info|install|uninstall]";
                    if (args['_'].length == 1) {
                        if ((args['_'][0] == 'install') || (args['_'][0] == 'info')) { response = ''; require('MeshAgent').SendCommand({ action: 'meshToolInfo', sessionid: sessionid, name: 'MeshCentralAssistant', cookie: true, tag: args['_'][0] }); }
                        // TODO: Uninstall
                    }
                } else {
                    response = "MeshCentral Assistant is not supported on this platform.";
                }
                break;
            case 'userimage':
                require('MeshAgent').SendCommand({ action: 'getUserImage', sessionid: sessionid, userid: args['_'][0], tag: 'info' });
                response = 'ok';
                break;
            case 'agentupdate':
                require('MeshAgent').SendCommand({ action: 'agentupdate', sessionid: sessionid });
                break;
            case 'agentupdateex':
                // Perform an direct agent update without requesting any information from the server, this should not typically be used.
                if (args['_'].length == 1) {
                    if (args['_'][0].startsWith('https://')) { agentUpdate_Start(args['_'][0], { sessionid: sessionid }); } else { response = "Usage: agentupdateex https://server/path"; }
                } else {
                    agentUpdate_Start(null, { sessionid: sessionid });
                }
                break;
            case 'errorlog':
                switch (args['_'].length) {
                    case 0:
                        // All Error Logs
                        response = JSON.stringify(require('util-agentlog').read(), null, 1);
                        break;
                    case 1:
                        // Error Logs, by either count or timestamp
                        response = JSON.stringify(require('util-agentlog').read(parseInt(args['_'][0])), null, 1);
                        break;
                    default:
                        response = "Proper usage:\r\n  errorlog [lastCount|linuxEpoch]";
                        break;
                }
                break;
            case 'msh':
                if (args['_'].length == 0) {
                    response = JSON.stringify(_MSH(), null, 2);
                } else if (args['_'].length > 3) {
                    response = 'Proper usage: msh [get|set|delete]\r\nmsh get MeshServer\r\nmsh set abc "xyz"\r\nmsh delete abc';
                } else {
                    var mshFileName = process.execPath.replace('.exe','') + '.msh';
                    switch (args['_'][0].toLocaleLowerCase()) {
                        case 'get':
                            if (typeof args['_'][1] != 'string' || args['_'].length > 2) {
                                response = 'Proper usage: msh get MeshServer';
                            } else if(_MSH()[args['_'][1]]) {
                                response = _MSH()[args['_'][1]];
                            } else {
                                response = "Unknown Value: " + args['_'][1];
                            }
                            break;
                        case 'set': 
                            if (typeof args['_'][1] != 'string' || typeof args['_'][2] != 'string') {
                                response = 'Proper usage: msh set abc "xyz"';
                            } else {
                                var jsonToSave = _MSH();
                                jsonToSave[args['_'][1]] = args['_'][2];
                                var updatedContent = '';
                                for (var key in jsonToSave) {
                                    if (jsonToSave.hasOwnProperty(key)) {
                                        updatedContent += key + '=' + jsonToSave[key] + '\n';
                                    }
                                }
                                try {
                                    require('fs').writeFileSync(mshFileName, updatedContent);
                                    response = "msh set " + args['_'][1] + " successful"
                                } catch (ex) {
                                    response = "msh set " + args['_'][1] + " unsuccessful";
                                }
                            }
                            break;
                        case 'delete':
                            if (typeof args['_'][1] != 'string') {
                                response = 'Proper usage: msh delete abc';
                            } else {
                                var jsonToSave = _MSH();
                                delete jsonToSave[args['_'][1]];
                                var updatedContent = '';
                                for (var key in jsonToSave) {
                                    if (jsonToSave.hasOwnProperty(key)) {
                                        updatedContent += key + '=' + jsonToSave[key] + '\n';
                                    }
                                }
                                try {
                                    require('fs').writeFileSync(mshFileName, updatedContent);
                                    response = "msh delete " + args['_'][1] + " successful"
                                } catch (ex) {
                                    response = "msh delete " + args['_'][1] + " unsuccessful";
                                }
                            }
                            break;
                        default:
                            response = 'Proper usage: msh [get|set|delete]\r\nmsh get MeshServer\r\nmsh set abc "xyz"\r\nmsh delete abc';
                            break;
                    }
                }
                break;
            case 'dnsinfo':
                if (require('os').dns == null) {
                    response = "Unknown command \"" + cmd + "\", type \"help\" for list of available commands.";
                }
                else {
                    response = 'DNS Servers: ';
                    var dns = require('os').dns();
                    for (var i = 0; i < dns.length; ++i) {
                        if (i > 0) { response += ', '; }
                        response += dns[i];
                    }
                }
                break;
            case 'timerinfo':
                response = require('ChainViewer').getTimerInfo();
                break;
            case 'rdpport':
                if (process.platform != 'win32') {
                    response = 'Unknown command "rdpport", type "help" for list of available commands.';
                    return;
                }
                if (args['_'].length == 0) {
                    response = 'Proper usage: rdpport [get|default|PORTNUMBER]';
                } else {
                    switch (args['_'][0].toLocaleLowerCase()) {
                        case 'get':
                            var rdpport = require('win-registry').QueryKey(require('win-registry').HKEY.LocalMachine, 'System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp', 'PortNumber');
                            response = "Current RDP Port Set To: " + rdpport + '\r\n';
                            break;
                        case 'default':
                            try {
                                require('win-registry').WriteKey(require('win-registry').HKEY.LocalMachine, 'System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp', 'PortNumber', 3389);
                                response = 'RDP Port Set To 3389, Please Dont Forget To Restart Your Computer To Fully Apply';
                            } catch (ex) {
                                response = 'Unable to Set RDP Port To: 3389';
                            }
                            break;
                        default:
                            if (isNaN(parseFloat(args['_'][0]))){
                                response = 'Proper usage: rdpport [get|default|PORTNUMBER]';
                            } else if(parseFloat(args['_'][0]) < 0 || args['_'][0] > 65535) {
                                response = 'RDP Port Must Be More Than 0 And Less Than 65535';
                            } else {
                                try {
                                    require('win-registry').WriteKey(require('win-registry').HKEY.LocalMachine, 'System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp', 'PortNumber', parseFloat(args['_'][0]));
                                    response = 'RDP Port Set To ' + args['_'][0] + ', Please Dont Forget To Restart Your Computer To Fully Apply';
                                } catch (ex) {
                                    response = 'Unable to Set RDP Port To: '+args['_'][0];
                                }
                            }
                            break;
                    }
                }
                break;
            case 'find':
                if (args['_'].length <= 1) {
                    response = "Proper usage:\r\n  find root criteria [criteria2] [criteria n...]";
                }
                else {
                    var root = args['_'][0];
                    var p = args['_'].slice(1);
                    var r = require('file-search').find(root, p);
                    r.sid = sessionid;
                    r.on('result', function (str) { sendConsoleText(str, this.sid); });
                    r.then(function () { sendConsoleText('*** End Results ***', this.sid); });
                    response = "Find: [" + root + "] " + JSON.stringify(p);
                }
                break;
            case 'coreinfo': {
                response = JSON.stringify(meshCoreObj, null, 2);
                break;
            }
            case 'coreinfoupdate': {
                sendPeriodicServerUpdate(null, true);
                response = "Core Info Update Requested"
                break;
            }
            case 'agentmsg': {
                if (args['_'].length == 0) {
                    response = "Proper usage:\r\n  agentmsg add \"[message]\" [iconIndex]\r\n  agentmsg remove [id]\r\n  agentmsg list"; // Display usage
                } else {
                    if ((args['_'][0] == 'add') && (args['_'].length > 1)) {
                        var msgID, iconIndex = 0;
                        if (args['_'].length >= 3) { try { iconIndex = parseInt(args['_'][2]); } catch (ex) { } }
                        if (typeof iconIndex != 'number') { iconIndex = 0; }
                        msgID = sendAgentMessage(args['_'][1], iconIndex);
                        response = 'Agent message: ' + msgID + ' added.';
                    } else if ((args['_'][0] == 'remove') && (args['_'].length > 1)) {
                        var r = removeAgentMessage(args['_'][1]);
                        response = 'Message ' + (r ? 'removed' : 'NOT FOUND');
                    } else if (args['_'][0] == 'list') {
                        response = JSON.stringify(sendAgentMessage(), null, 2);
                    }
                    broadcastSessionsToRegisteredApps();
                }
                break;
            }
            case 'clearagentmsg': {
                removeAgentMessage();
                broadcastSessionsToRegisteredApps();
                break;
            }
            case 'coredump':
                if (args['_'].length != 1) {
                    response = "Proper usage: coredump on|off|status|clear"; // Display usage
                } else {
                    switch (args['_'][0].toLowerCase()) {
                        case 'on':
                            process.coreDumpLocation = (process.platform == 'win32') ? (process.execPath.replace('.exe', '.dmp')) : (process.execPath + '.dmp');
                            response = 'coredump is now on';
                            break;
                        case 'off':
                            process.coreDumpLocation = null;
                            response = 'coredump is now off';
                            break;
                        case 'status':
                            response = 'coredump is: ' + ((process.coreDumpLocation == null) ? 'off' : 'on');
                            if (process.coreDumpLocation != null) {
                                if (process.platform == 'win32') {
                                    if (fs.existsSync(process.coreDumpLocation)) {
                                        response += '\r\n  CoreDump present at: ' + process.coreDumpLocation;
                                        response += '\r\n  CoreDump Time: ' + new Date(fs.statSync(process.coreDumpLocation).mtime).getTime();
                                        response += '\r\n  Agent Time   : ' + new Date(fs.statSync(process.execPath).mtime).getTime();
                                    }
                                } else {
                                    if ((process.cwd() != '//') && fs.existsSync(process.cwd() + 'core')) {
                                        response += '\r\n  CoreDump present at: ' + process.cwd() + 'core';
                                        response += '\r\n  CoreDump Time: ' + new Date(fs.statSync(process.cwd() + 'core').mtime).getTime();
                                        response += '\r\n  Agent Time   : ' + new Date(fs.statSync(process.execPath).mtime).getTime();
                                    }
                                }
                            }
                            break;
                        case 'clear':
                            db.Put('CoreDumpTime', null);
                            response = 'coredump db cleared';
                            break;
                        default:
                            response = "Proper usage: coredump on|off|status"; // Display usage
                            break;
                    }
                }
                break;
            case 'service':
                if (args['_'].length != 1) {
                    response = "Proper usage: service status|restart"; // Display usage
                } else {
                    var svcname = process.platform == 'win32' ? 'Mesh Agent' : 'meshagent';
                    try {
                        svcname = require('MeshAgent').serviceName;
                    } catch (ex) { }
                    var s = require('service-manager').manager.getService(svcname);
                    switch (args['_'][0].toLowerCase()) {
                        case 'status':
                            response = 'Service ' + (s.isRunning() ? (s.isMe() ? '[SELF]' : '[RUNNING]') : ('[NOT RUNNING]'));
                            break;
                        case 'restart':
                            if (s.isMe()) {
                                s.restart();
                            } else {
                                response = 'Restarting another agent instance is not allowed';
                            }
                            break;
                        default:
                            response = "Proper usage: service status|restart"; // Display usage
                            break;
                    }
                    if (process.platform == 'win32') { s.close(); }
                }
                break;
            case 'zip':
                if (args['_'].length == 0) {
                    response = "Proper usage: zip (output file name), input1 [, input n]"; // Display usage
                } else {
                    var p = args['_'].join(' ').split(',');
                    var ofile = p.shift();
                    sendConsoleText('Writing ' + ofile + '...');
                    var out = require('fs').createWriteStream(ofile, { flags: 'wb' });
                    out.fname = ofile;
                    out.sessionid = sessionid;
                    out.on('close', function () { sendConsoleText('DONE writing ' + this.fname, this.sessionid); });
                    var zip = require('zip-writer').write({ files: p });
                    zip.pipe(out);
                }
                break;
            case 'unzip':
                if (args['_'].length == 0) {
                    response = "Proper usage: unzip input,destination"; // Display usage
                } else {
                    var p = args['_'].join(' ').split(',');
                    if (p.length != 2) { response = "Proper usage: unzip input,destination"; break; } // Display usage
                    var prom = require('zip-reader').read(p[0].trim());
                    prom._dest = p[1].trim();
                    prom.self = this;
                    prom.sessionid = sessionid;
                    prom.then(function (zipped) {
                        sendConsoleText('Extracting to ' + this._dest + '...', this.sessionid);
                        zipped.extractAll(this._dest).then(function () { sendConsoleText('finished unzipping', this.sessionid); }, function (e) { sendConsoleText('Error unzipping: ' + e, this.sessionid); }).parentPromise.sessionid = this.sessionid;
                    }, function (e) { sendConsoleText('Error unzipping: ' + e, this.sessionid); });
                }
                break;
            case 'setbattery':
                // require('MeshAgent').SendCommand({ action: 'battery', state: 'dc', level: 55 });
                if ((args['_'].length > 0) && ((args['_'][0] == 'ac') || (args['_'][0] == 'dc'))) {
                    var b = { action: 'battery', state: args['_'][0] };
                    if (args['_'].length == 2) { b.level = parseInt(args['_'][1]); }
                    require('MeshAgent').SendCommand(b);
                } else {
                    require('MeshAgent').SendCommand({ action: 'battery' });
                }
                break;
            case 'fdsnapshot':
                require('ChainViewer').getSnapshot().then(function (c) { sendConsoleText(c, this.sessionid); }).parentPromise.sessionid = sessionid;
                break;
            case 'fdcount':
                require('DescriptorEvents').getDescriptorCount().then(
                    function (c) {
                        sendConsoleText('Descriptor Count: ' + c, this.sessionid);
                    }, function (e) {
                        sendConsoleText('Error fetching descriptor count: ' + e, this.sessionid);
                    }).parentPromise.sessionid = sessionid;
                break;
            case 'uac':
                if (process.platform != 'win32') {
                    response = 'Unknown command "uac", type "help" for list of available commands.';
                    break;
                }
                if (args['_'].length != 1) {
                    response = 'Proper usage: uac [get|interactive|secure]';
                }
                else {
                    switch (args['_'][0].toUpperCase()) {
                        case 'GET':
                            var secd = require('win-registry').QueryKey(require('win-registry').HKEY.LocalMachine, 'Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System', 'PromptOnSecureDesktop');
                            response = "UAC mode: " + (secd == 0 ? "Interactive Desktop" : "Secure Desktop");
                            break;
                        case 'INTERACTIVE':
                            try {
                                require('win-registry').WriteKey(require('win-registry').HKEY.LocalMachine, 'Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System', 'PromptOnSecureDesktop', 0);
                                response = 'UAC mode changed to: Interactive Desktop';
                            } catch (ex) {
                                response = "Unable to change UAC Mode";
                            }
                            break;
                        case 'SECURE':
                            try {
                                require('win-registry').WriteKey(require('win-registry').HKEY.LocalMachine, 'Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System', 'PromptOnSecureDesktop', 1);
                                response = 'UAC mode changed to: Secure Desktop';
                            } catch (ex) {
                                response = "Unable to change UAC Mode";
                            }
                            break;
                        default:
                            response = 'Proper usage: uac [get|interactive|secure]';
                            break;
                    }
                }
                break;
            case 'vm':
                response = 'Virtual Machine = ' + require('computer-identifiers').isVM();
                break;
            case 'startupoptions':
                response = JSON.stringify(require('MeshAgent').getStartupOptions());
                break;
            case 'kvmmode':
                if (require('MeshAgent').maxKvmTileSize == null) {
                    response = "Unknown command \"kvmmode\", type \"help\" for list of available commands.";
                }
                else {
                    if (require('MeshAgent').maxKvmTileSize == 0) {
                        response = 'KVM Mode: Full JUMBO';
                    }
                    else {
                        response = 'KVM Mode: ' + (require('MeshAgent').maxKvmTileSize <= 65500 ? 'NO JUMBO' : 'Partial JUMBO');
                        response += (', TileLimit: ' + (require('MeshAgent').maxKvmTileSize < 1024 ? (require('MeshAgent').maxKvmTileSize + ' bytes') : (Math.round(require('MeshAgent').maxKvmTileSize / 1024) + ' Kbytes')));
                    }
                }
                break;
            case 'alert':
                if (args['_'].length == 0) {
                    response = "Proper usage: alert TITLE, CAPTION [, TIMEOUT]"; // Display usage
                }
                else {
                    var p = args['_'].join(' ').split(',');
                    if (p.length < 2) {
                        response = "Proper usage: alert TITLE, CAPTION [, TIMEOUT]"; // Display usage
                    }
                    else {
                        this._alert = require('message-box').create(p[0], p[1], p.length == 3 ? parseInt(p[2]) : 9999, 1);
                    }
                }
                break;
            case 'agentsize':
                var actualSize = Math.floor(require('fs').statSync(process.execPath).size / 1024);
                if (process.platform == 'win32') {
                    // Check the Agent Uninstall MetaData for correctness, as the installer may have written an incorrect value
                    var writtenSize = 0;
                    var serviceName =  (_MSH().serviceName ?  _MSH().serviceName : (require('_agentNodeId').serviceName() ? require('_agentNodeId').serviceName() : 'Mesh Agent'));
                    try { writtenSize = require('win-registry').QueryKey(require('win-registry').HKEY.LocalMachine, 'Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\' + serviceName, 'EstimatedSize'); } catch (ex) { response = ex; }
                    if (writtenSize != actualSize) {
                        response = "Size updated from: " + writtenSize + " to: " + actualSize;
                        try { require('win-registry').WriteKey(require('win-registry').HKEY.LocalMachine, 'Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\' + serviceName, 'EstimatedSize', actualSize); } catch (ex) { response = ex; }
                    } else
                    { response = "Agent Size: " + actualSize + " kb"; }
                } else
                { response = "Agent Size: " + actualSize + " kb"; }
                break;
            case 'versions':
                response = JSON.stringify(process.versions, null, '  ');
                break;
            case 'wpfhwacceleration':
                if (process.platform != 'win32') { throw ("wpfhwacceleration setting is only supported on Windows"); }
                if (args['_'].length != 1) {
                    response = "Proper usage: wpfhwacceleration (ON|OFF|STATUS)"; // Display usage
                }
                else {
                    var reg = require('win-registry');
                    var uname = require('user-sessions').getUsername(require('user-sessions').consoleUid());
                    var key = reg.usernameToUserKey(uname);

                    switch (args['_'][0].toUpperCase()) {
                        default:
                            response = "Proper usage: wpfhwacceleration (ON|OFF|STATUS|DEFAULT)"; // Display usage
                            break;
                        case 'ON':
                            try {
                                reg.WriteKey(reg.HKEY.Users, key + '\\SOFTWARE\\Microsoft\\Avalon.Graphics', 'DisableHWAcceleration', 0);
                                response = "OK";
                            } catch (ex) { response = "FAILED"; }
                            break;
                        case 'OFF':
                            try {
                                reg.WriteKey(reg.HKEY.Users, key + '\\SOFTWARE\\Microsoft\\Avalon.Graphics', 'DisableHWAcceleration', 1);
                                response = 'OK';
                            } catch (ex) { response = 'FAILED'; }
                            break;
                        case 'STATUS':
                            var s;
                            try { s = reg.QueryKey(reg.HKEY.Users, key + '\\SOFTWARE\\Microsoft\\Avalon.Graphics', 'DisableHWAcceleration') == 1 ? 'DISABLED' : 'ENABLED'; } catch (ex) { s = 'DEFAULT'; }
                            response = "WPF Hardware Acceleration: " + s;
                            break;
                        case 'DEFAULT':
                            try { reg.DeleteKey(reg.HKEY.Users, key + '\\SOFTWARE\\Microsoft\\Avalon.Graphics', 'DisableHWAcceleration'); } catch (ex) { }
                            response = 'OK';
                            break;
                    }
                }
                break;
            case 'tsid':
                if (process.platform == 'win32') {
                    if (args['_'].length != 1) {
                        response = "TSID: " + (require('MeshAgent')._tsid == null ? "console" : require('MeshAgent')._tsid);
                    } else {
                        var i = parseInt(args['_'][0]);
                        require('MeshAgent')._tsid = (isNaN(i) ? null : i);
                        response = "TSID set to: " + (require('MeshAgent')._tsid == null ? "console" : require('MeshAgent')._tsid);
                    }
                } else
                { response = "TSID command only supported on Windows"; }
                break;
            case 'activeusers':
                if (process.platform == 'win32') {
                    var p = require('user-sessions').enumerateUsers();
                    p.sessionid = sessionid;
                    p.then(function (u) {
                        var v = [];
                        var ret = getDomainInfo();
                        for (var i in u) {
                            if (u[i].State == 'Active') {
                                if ((u[i].Domain != null && u[i].Domain == 'AzureAD') || getJoinState() == 1){
                                    var userobj = getLogonCacheKeys();
                                    if(userobj && userobj.length > 0){
                                        for (var j = 0; j < userobj.length; j++) {
                                            if (userobj[j] && userobj[j].SAM && userobj[j].SAM[0].trim() === u[i].Username) {
                                                u[i].UPN = userobj[j].UPN
                                                break;
                                            }
                                        }
                                    }  
                                } else if (u[i].Domain != null) {
                                    if (ret != null && ret.PartOfDomain === true) {
                                        u[i].UPN = u[i].Username + '@' + ret.Domain;
                                    } else if (getJoinState() == 4) { // One account with Microsoft Account
                                        var userobj = getLogonCacheKeys();
                                        if(userobj && userobj.length > 0){
                                            for (var j = 0; j < userobj.length; j++) {
                                                if (userobj[j] && userobj[j].SAM && userobj[j].SAM.length == 0 && userobj[j].UPN && userobj[j].UPN != '') {
                                                    u[i].UPN = userobj[j].UPN;
                                                    break;
                                                }
                                            }
                                        }  
                                    }
                                }
                                if (u[i].UPN == null) { u[i].UPN = ''; }
                                v.push({ tsid: i, type: u[i].StationName, user: u[i].Username, domain: u[i].Domain, upn: u[i].UPN });
                            }
                        }
                        sendConsoleText(JSON.stringify(v, null, 1), this.sessionid);
                    });
                } else
                { response = "activeusers command only supported on Windows"; }
                break;
            case 'wallpaper':
                if (process.platform != 'win32' && !(process.platform == 'linux' && require('linux-gnome-helpers').available)) {
                    response = "wallpaper command not supported on this platform";
                }
                else {
                    if (args['_'].length != 1) {
                        response = 'Proper usage: wallpaper (GET|TOGGLE)'; // Display usage
                    }
                    else {
                        switch (args['_'][0].toUpperCase()) {
                            default:
                                response = 'Proper usage: wallpaper (GET|TOGGLE)'; // Display usage
                                break;
                            case 'GET':
                            case 'TOGGLE':
                                if (process.platform == 'win32') {
                                    var id = require('user-sessions').getProcessOwnerName(process.pid).tsid == 0 ? 1 : 0;
                                    var child = require('child_process').execFile(process.execPath, [process.execPath.split('\\').pop(), '-b64exec', 'dmFyIFNQSV9HRVRERVNLV0FMTFBBUEVSID0gMHgwMDczOwp2YXIgU1BJX1NFVERFU0tXQUxMUEFQRVIgPSAweDAwMTQ7CnZhciBHTSA9IHJlcXVpcmUoJ19HZW5lcmljTWFyc2hhbCcpOwp2YXIgdXNlcjMyID0gR00uQ3JlYXRlTmF0aXZlUHJveHkoJ3VzZXIzMi5kbGwnKTsKdXNlcjMyLkNyZWF0ZU1ldGhvZCgnU3lzdGVtUGFyYW1ldGVyc0luZm9BJyk7CgppZiAocHJvY2Vzcy5hcmd2Lmxlbmd0aCA9PSAzKQp7CiAgICB2YXIgdiA9IEdNLkNyZWF0ZVZhcmlhYmxlKDEwMjQpOwogICAgdXNlcjMyLlN5c3RlbVBhcmFtZXRlcnNJbmZvQShTUElfR0VUREVTS1dBTExQQVBFUiwgdi5fc2l6ZSwgdiwgMCk7CiAgICBjb25zb2xlLmxvZyh2LlN0cmluZyk7CiAgICBwcm9jZXNzLmV4aXQoKTsKfQplbHNlCnsKICAgIHZhciBuYiA9IEdNLkNyZWF0ZVZhcmlhYmxlKHByb2Nlc3MuYXJndlszXSk7CiAgICB1c2VyMzIuU3lzdGVtUGFyYW1ldGVyc0luZm9BKFNQSV9TRVRERVNLV0FMTFBBUEVSLCBuYi5fc2l6ZSwgbmIsIDApOwogICAgcHJvY2Vzcy5leGl0KCk7Cn0='], { type: id });
                                    child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
                                    child.stderr.on('data', function () { });
                                    child.waitExit();
                                    var current = child.stdout.str.trim();
                                    if (args['_'][0].toUpperCase() == 'GET') {
                                        response = current;
                                        break;
                                    }
                                    if (current != '') {
                                        require('MeshAgent')._wallpaper = current;
                                        response = 'Wallpaper cleared';
                                    } else {
                                        response = 'Wallpaper restored';
                                    }
                                    child = require('child_process').execFile(process.execPath, [process.execPath.split('\\').pop(), '-b64exec', 'dmFyIFNQSV9HRVRERVNLV0FMTFBBUEVSID0gMHgwMDczOwp2YXIgU1BJX1NFVERFU0tXQUxMUEFQRVIgPSAweDAwMTQ7CnZhciBHTSA9IHJlcXVpcmUoJ19HZW5lcmljTWFyc2hhbCcpOwp2YXIgdXNlcjMyID0gR00uQ3JlYXRlTmF0aXZlUHJveHkoJ3VzZXIzMi5kbGwnKTsKdXNlcjMyLkNyZWF0ZU1ldGhvZCgnU3lzdGVtUGFyYW1ldGVyc0luZm9BJyk7CgppZiAocHJvY2Vzcy5hcmd2Lmxlbmd0aCA9PSAzKQp7CiAgICB2YXIgdiA9IEdNLkNyZWF0ZVZhcmlhYmxlKDEwMjQpOwogICAgdXNlcjMyLlN5c3RlbVBhcmFtZXRlcnNJbmZvQShTUElfR0VUREVTS1dBTExQQVBFUiwgdi5fc2l6ZSwgdiwgMCk7CiAgICBjb25zb2xlLmxvZyh2LlN0cmluZyk7CiAgICBwcm9jZXNzLmV4aXQoKTsKfQplbHNlCnsKICAgIHZhciBuYiA9IEdNLkNyZWF0ZVZhcmlhYmxlKHByb2Nlc3MuYXJndlszXSk7CiAgICB1c2VyMzIuU3lzdGVtUGFyYW1ldGVyc0luZm9BKFNQSV9TRVRERVNLV0FMTFBBUEVSLCBuYi5fc2l6ZSwgbmIsIDApOwogICAgcHJvY2Vzcy5leGl0KCk7Cn0=', current != '' ? '""' : require('MeshAgent')._wallpaper], { type: id });
                                    child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
                                    child.stderr.on('data', function () { });
                                    child.waitExit();
                                }
                                else {
                                    var id = require('user-sessions').consoleUid();
                                    var current = require('linux-gnome-helpers').getDesktopWallpaper(id);
                                    if (args['_'][0].toUpperCase() == 'GET') {
                                        response = current;
                                        break;
                                    }
                                    if (current != '/dev/null') {
                                        require('MeshAgent')._wallpaper = current;
                                        response = 'Wallpaper cleared';
                                    } else {
                                        response = 'Wallpaper restored';
                                    }
                                    require('linux-gnome-helpers').setDesktopWallpaper(id, current != '/dev/null' ? undefined : require('MeshAgent')._wallpaper);
                                }
                                break;
                        }
                    }
                }
                break;
            case 'safemode':
                if (process.platform != 'win32') {
                    response = 'safemode only supported on Windows Platforms'
                }
                else {
                    if (!bcdOK()) {
                        response = 'safemode not supported on 64 bit Windows from a 32 bit process'
                        break;
                    }
                    if (args['_'].length != 1) {
                        response = 'Proper usage: safemode (ON|OFF|STATUS)'; // Display usage
                    }
                    else {
                        var svcname = process.platform == 'win32' ? 'Mesh Agent' : 'meshagent';
                        try {
                            svcname = require('MeshAgent').serviceName;
                        } catch (ex) { }

                        switch (args['_'][0].toUpperCase()) {
                            default:
                                response = 'Proper usage: safemode (ON|OFF|STATUS)'; // Display usage
                                break;
                            case 'ON':
                                require('win-bcd').setKey('safeboot', 'Network');
                                require('win-bcd').enableSafeModeService(svcname);
                                break;
                            case 'OFF':
                                require('win-bcd').deleteKey('safeboot');
                                break;
                            case 'STATUS':
                                var nextboot = require('win-bcd').getKey('safeboot');
                                if (nextboot) {
                                    switch (nextboot) {
                                        case 'Network':
                                        case 'network':
                                            nextboot = 'SAFE_MODE_NETWORK';
                                            break;
                                        default:
                                            nextboot = 'SAFE_MODE';
                                            break;
                                    }
                                }
                                response = 'Current: ' + require('win-bcd').bootMode + ', NextBoot: ' + (nextboot ? nextboot : 'NORMAL');
                                break;
                        }
                    }
                }
                break;
            /*
            case 'border':
                {
                    if ((args['_'].length == 1) && (args['_'][0] == 'on')) {
                        if (meshCoreObj.users.length > 0) {
                            obj.borderManager.Start(meshCoreObj.users[0]);
                            response = 'Border blinking is on.';
                        } else {
                            response = 'Cannot turn on border blinking, no logged in users.';
                        }
                    } else if ((args['_'].length == 1) && (args['_'][0] == 'off')) {
                        obj.borderManager.Stop();
                        response = 'Border blinking is off.';
                    } else {
                        response = 'Proper usage: border "on|off"'; // Display correct command usage
                    }
                }
                break;
            */
            case 'av':
                if (process.platform == 'win32') {
                    // Windows Command: "wmic /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct get /FORMAT:CSV"
                    response = JSON.stringify(require('win-info').av(), null, 1);
                } else if (process.platform == 'linux') {
                    require('linux-info').av(function (r) { sendConsoleText(JSON.stringify(r, null, 1), sessionid); });
                    response = null;
                } else {
                    response = 'Not supported on the platform';
                }
                break;
            case 'defender':
                 if (process.platform == 'win32') {
                    // Windows Command: "wmic /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct get /FORMAT:CSV"
                    response = JSON.stringify(require('win-info').defender(), null, 1);
                } else {
                    response = 'Not supported on the platform';
                }
                break;
            case 'log':
                if (args['_'].length != 1) { response = 'Proper usage: log "sample text"'; } else { MeshServerLog(args['_'][0]); response = 'ok'; }
                break;
            case 'getclip':
                if (require('MeshAgent').isService) {
                    require('clipboard').dispatchRead().then(function (str) { sendConsoleText(str, sessionid); });
                } else {
                    require('clipboard').read().then(function (str) { sendConsoleText(str, sessionid); });
                }
                break;
            case 'setclip': {
                if (pendingSetClip) {
                    response = 'Busy';
                } else if (args['_'].length != 1) {
                    response = 'Proper usage: setclip "sample text"';
                } else {
                    if (require('MeshAgent').isService) {
                        if (process.platform != 'win32') {
                            require('clipboard').dispatchWrite(args['_'][0]);
                        }
                        else {
                            var clipargs = args['_'][0];
                            var uid = require('user-sessions').consoleUid();
                            var user = require('user-sessions').getUsername(uid);
                            var domain = require('user-sessions').getDomain(uid);
                            user = (domain + '\\' + user);

                            if (this._dispatcher) { this._dispatcher.close(); }
                            this._dispatcher = require('win-dispatcher').dispatch({ user: user, modules: [{ name: 'clip-dispatch', script: "module.exports = { dispatch: function dispatch(val) { require('clipboard')(val); process.exit(); } };" }], launch: { module: 'clip-dispatch', method: 'dispatch', args: [clipargs] } });
                            this._dispatcher.parent = this;
                            //require('events').setFinalizerMetadata.call(this._dispatcher, 'clip-dispatch');
                            pendingSetClip = true;
                            this._dispatcher.on('connection', function (c) {
                                this._c = c;
                                this._c.root = this.parent;
                                this._c.on('end', function ()
                                {
                                    pendingSetClip = false;
                                    try { this.root._dispatcher.close(); } catch (ex) { }
                                    this.root._dispatcher = null;
                                    this.root = null;
                                });
                            });
                        }
                        response = 'Setting clipboard to: "' + args['_'][0] + '"';
                    }
                    else {
                        require('clipboard')(args['_'][0]); response = 'Setting clipboard to: "' + args['_'][0] + '"';
                    }
                }
                break;
            }
            case 'openurl': {
                if (args['_'].length != 1) { response = 'Proper usage: openurl (url)'; } // Display usage
                else { if (openUserDesktopUrl(args['_'][0]) == null) { response = 'Failed.'; } else { response = 'Success.'; } }
                break;
            }
            case 'openfile': {
                if (args['_'].length != 1) { response = 'Proper usage: openfile (filepath)'; } // Display usage
                else { if (openFileOnDesktop(args['_'][0]) == null) { response = 'Failed.'; } else { response = 'Success.'; } }
                break;
            }
            case 'users': {
                if (meshCoreObj.users == null) { response = 'Active users are unknown.'; } else { response = 'Active Users: ' + meshCoreObj.users.join(', ') + '.'; }
                require('user-sessions').enumerateUsers().then(function (u) { 
                    var ret = getDomainInfo();
                    for (var i in u) { 
                       if ((u[i].Domain != null && u[i].Domain == 'AzureAD') || getJoinState() == 1){
                            var userobj = getLogonCacheKeys();
                            if(userobj && userobj.length > 0){
                                for (var j = 0; j < userobj.length; j++) {
                                    var a = userobj[j];
                                    if (a && a.SAM && a.SAM[0].trim() === u[i].Username) {
                                        u[i].UPN = a.UPN
                                        break;
                                    }
                                }
                            }  
                        } else if (u[i].Domain != null) {
                            if (ret != null && ret.PartOfDomain === true) {
                                u[i].UPN = u[i].Username + '@' + ret.Domain;
                            } else if (getJoinState() == 4) { // One account with Microsoft Account
                                var userobj = getLogonCacheKeys();
                                if(userobj && userobj.length > 0){
                                    for (var j = 0; j < userobj.length; j++) {
                                        var a = userobj[j];
                                        if (a && a.SAM && a.SAM.length == 0 && a.UPN && a.UPN != '') {
                                            u[i].UPN = a.UPN;
                                            break;
                                        }
                                    }
                                }  
                            }
                        }
                        if (u[i].UPN == null) { u[i].UPN = ''; }
                        sendConsoleText(u[i]);
                    }
                });
                break;
            }
            case 'kvmusers':
                response = JSON.stringify(require('kvm-helper').users(), null, 1);
                break;
            case 'toast': {
                if (args['_'].length < 1) { response = 'Proper usage: toast "message"'; } else {
                    if (require('MeshAgent')._tsid == null) {
                        require('toaster').Toast('MeshCentral', args['_'][0]).then(sendConsoleText, sendConsoleText);
                    }
                    else {
                        require('toaster').Toast('MeshCentral', args['_'][0], require('MeshAgent')._tsid).then(sendConsoleText, sendConsoleText);
                    }
                }
                break;
            }
            case 'setdebug': {
                if (args['_'].length < 1) { response = 'Proper usage: setdebug (target), 0 = Disabled, 1 = StdOut, 2 = This Console, * = All Consoles, 4 = WebLog, 8 = Logfile'; } // Display usage
                else { if (args['_'][0] == '*') { console.setDestination(2); } else { console.setDestination(parseInt(args['_'][0]), sessionid); } }
                break;
            }
            case 'ps': {
                processManager.getProcesses(function (plist) {
                    var x = '';
                    for (var i in plist) { x += i + ((plist[i].user) ? (', ' + plist[i].user) : '') + ', ' + plist[i].cmd + '\r\n'; }
                    sendConsoleText(x, sessionid);
                });
                break;
            }
            case 'kill': {
                if ((args['_'].length < 1)) {
                    response = 'Proper usage: kill [pid]'; // Display correct command usage
                } else {
                    process.kill(parseInt(args['_'][0]));
                    response = 'Killed process ' + args['_'][0] + '.';
                }
                break;
            }
            case 'smbios': {
                if (SMBiosTables == null) { response = 'SMBios tables not available.'; } else { response = objToString(SMBiosTables, 0, ' ', true); }
                break;
            }
            case 'rawsmbios': {
                if (SMBiosTablesRaw == null) { response = 'SMBios tables not available.'; } else {
                    response = '';
                    for (var i in SMBiosTablesRaw) {
                        var header = false;
                        for (var j in SMBiosTablesRaw[i]) {
                            if (SMBiosTablesRaw[i][j].length > 0) {
                                if (header == false) { response += ('Table type #' + i + ((require('smbios').smTableTypes[i] == null) ? '' : (', ' + require('smbios').smTableTypes[i]))) + '\r\n'; header = true; }
                                response += ('  ' + SMBiosTablesRaw[i][j].toString('hex')) + '\r\n';
                            }
                        }
                    }
                }
                break;
            }
            case 'eval': { // Eval JavaScript
                if (args['_'].length < 1) {
                    response = 'Proper usage: eval "JavaScript code"'; // Display correct command usage
                } else {
                    var evalResult = mesh.eval(args['_'][0]); try { response = JSON.stringify(evalResult); } catch (ex) { response = null; } // This can only be run by trusted administrator.
                }
                break;
            }
            case 'uninstallagent': // Uninstall this agent
                var agentName = process.platform == 'win32' ? 'Mesh Agent' : 'meshagent';
                try {
                    agentName = require('MeshAgent').serviceName;
                } catch (ex) { }

                if (!require('service-manager').manager.getService(agentName).isMe()) {
                    response = 'Uininstall failed, this instance is not the service instance';
                } else {
                    try { diagnosticAgent_uninstall(); } catch (ex) { }
                    var js = "require('service-manager').manager.getService('" + agentName + "').stop(); require('service-manager').manager.uninstallService('" + agentName + "'); process.exit();";
                    this.child = require('child_process').execFile(process.execPath, [process.platform == 'win32' ? (process.execPath.split('\\').pop()) : (process.execPath.split('/').pop()), '-b64exec', Buffer.from(js).toString('base64')], { type: 4, detached: true });
                }
                break;
            case 'notify': { // Send a notification message to the mesh
                if (args['_'].length != 1) {
                    response = 'Proper usage: notify "message" [--session]'; // Display correct command usage
                } else {
                    var notification = { action: 'msg', type: 'notify', value: args['_'][0], tag: 'console' };
                    if (args.session) { notification.sessionid = sessionid; } // If "--session" is specified, notify only this session, if not, the server will notify the mesh
                    mesh.SendCommand(notification); // no sessionid or userid specified, notification will go to the entire mesh
                    response = "ok";
                }
                break;
            }
            case 'cpuinfo': { // Return system information
                // CPU & memory utilization
                pr = require('sysinfo').cpuUtilization();
                pr.sessionid = sessionid;
                pr.then(function (data) {
                    sendConsoleText(JSON.stringify(
                        {
                            cpu: data,
                            memory: require('sysinfo').memUtilization(),
                            thermals: require('sysinfo').thermals == null ? [] : require('sysinfo').thermals()
                        }, null, 1), this.sessionid);
                }, function (e) {
                    sendConsoleText(e);
                });
                break;
            }
            case 'sysinfo': { // Return system information
                getSystemInformation(function (results, err) {
                    if (results == null) {
                        sendConsoleText(err, this.sessionid);
                    } else {
                        // Send the full data to the server first
                        mesh.SendCommand({ action: 'sysinfo', sessionid: this.sessionid, data: results });
                        // Mask BitLocker recovery keys for non-admins in the console output only and optionally replace codes with strings
                        pretty = !(args['_'].length > 0 && args['_'][0] == 'raw');
                        const encMethod = { 0: '', 1: "AES-128 with diffuser", 2: "AES-256 with diffuser", 3: 'AES-128', 4: 'AES-256', 5: "Hardware encryption", 6: 'XTS-AES-128', 7: 'XTS-AES-256' };
                        const driveType = { 0: "Unknown", 1: "No Root Directory", 2: "Removable Disk", 3: "Local Disk", 4: "Network Drive", 5: "Compact Disc", 6: "RAM Disk" };
                        const conversionStatus = { "-1": "Unknown", 1: "Fully Encrypted", 2: "Encryption In Progress", 3: "Decryption In Progress", 4: "Encryption Paused", 5: "Decryption Paused" };
                        const protectionStatus = { 0: "Off", 1: "On", 2: "Locked"};
                        var replacer = function (k, val) {
                            if ( k === 'recoveryPassword' && rights != MESHRIGHT_ADMIN) { return '(Only admins)'; }
                            else if (pretty && typeof val === 'number') {
                                switch (k) {
                                    case 'encryptionMethod':
                                        return (val >= 1 && val <= 7)  ? encMethod[val] : val;
                                    case 'protectionStatus':
                                        return (val >= 0 && val <= 2) ? protectionStatus[val] : val;
                                    case 'volumeStatus':
                                        return (val >= -1 && val <= 5) ? conversionStatus[val] : val;
                                    case 'dType':
                                        return (val >= 1 && val <= 6) ? driveType[val]: val;
                                }
                            }
                            return val;
                        };
                        sendConsoleText(JSON.stringify(results, replacer, 1), this.sessionid);
                    }
                });
                break;
            }
            case 'info': { // Return information about the agent and agent core module
                response = 'Current Core: ' + meshCoreObj.value + '\r\nAgent Time: ' + Date() + '.\r\nUser Rights: 0x' + rights.toString(16) + '.\r\nPlatform: ' + process.platform + '.\r\nCapabilities: ' + meshCoreObj.caps + '.\r\nServer URL: ' + mesh.ServerUrl + '.';
                if (amt != null) { response += '\r\nBuilt-in LMS: ' + ['Disabled', 'Connecting..', 'Connected'][amt.lmsstate] + '.'; }
                if (meshCoreObj.osdesc) { response += '\r\nOS: ' + meshCoreObj.osdesc + '.'; }
                response += '\r\nModules: ' + addedModules.join(', ') + '.';
                response += '\r\nServer Connection: ' + mesh.isControlChannelConnected + ', State: ' + meshServerConnectionState + '.';
                var oldNodeId = db.Get('OldNodeId');
                if (oldNodeId != null) { response += '\r\nOldNodeID: ' + oldNodeId + '.'; }
                response += '\r\nNode ID: ' + Buffer.from(require('_agentNodeId')(), 'hex').toString('base64').replace(/\+/g, '@').replace(/\//g, '$');
                if (process.platform == 'linux' || process.platform == 'freebsd') { response += '\r\nX11 support: ' + require('monitor-info').kvm_x11_support + '.'; }
                response += '\r\nApplication Location: ' + process.cwd();
                //response += '\r\Debug Console: ' + debugConsole + '.';
                break;
            }
            case 'osinfo': { // Return the operating system information
                var i = 1;
                if (args['_'].length > 0) { i = parseInt(args['_'][0]); if (i > 8) { i = 8; } response = 'Calling ' + i + ' times.'; }
                for (var j = 0; j < i; j++) {
                    var pr = require('os').name();
                    pr.sessionid = sessionid;
                    pr.then(function (v) {
                        sendConsoleText("OS: " + v + (process.platform == 'win32' ? (require('win-virtual-terminal').supported ? ' [ConPTY: YES]' : ' [ConPTY: NO]') : ''), this.sessionid);
                    });
                }
                break;
            }
            case 'args': { // Displays parsed command arguments
                response = 'args ' + objToString(args, 0, ' ', true);
                break;
            }
            case 'print': { // Print a message on the mesh agent console, does nothing when running in the background
                var r = [];
                for (var i in args['_']) { r.push(args['_'][i]); }
                console.log(r.join(' '));
                response = 'Message printed on agent console.';
                break;
            }
            case 'type': { // Returns the content of a file
                if (args['_'].length == 0) {
                    response = 'Proper usage: type (filepath) [maxlength]'; // Display correct command usage
                } else {
                    var max = 4096;
                    if ((args['_'].length > 1) && (typeof args['_'][1] == 'number')) { max = args['_'][1]; }
                    if (max > 4096) max = 4096;
                    var buf = Buffer.alloc(max), fd = fs.openSync(args['_'][0], "r"), r = fs.readSync(fd, buf, 0, max); // Read the file content
                    response = buf.toString();
                    var i = response.indexOf('\n');
                    if ((i > 0) && (response[i - 1] != '\r')) { response = response.split('\n').join('\r\n'); }
                    if (r == max) response += '...';
                    fs.closeSync(fd);
                }
                break;
            }
            case 'dbkeys': { // Return all data store keys
                if (db == null) { response = 'Database not accessible.'; break; }
                response = JSON.stringify(db.Keys);
                break;
            }
            case 'dbget': { // Return the data store value for a given key
                if (db == null) { response = 'Database not accessible.'; break; }
                if (args['_'].length != 1) {
                    response = 'Proper usage: dbget (key)';
                } else {
                    response = (db.Get(args['_'][0]) != null ? db.Get(args['_'][0]) : 'Key not found');
                }
                break;
            }
            case 'dbset': { // Set a data store key and value pair
                if (db == null) { response = 'Database not accessible.'; break; }
                if (args['_'].length != 2) {
                    response = 'Proper usage: dbset (key) (value)'; // Set a database key
                } else {
                    var r = db.Put(args['_'][0], args['_'][1]);
                    response = r == 0 ? 'Key set' : 'Failed to set key';
                }
                break;
            }
            case 'dbdelete': { // Delete a data store key
                if (db == null) { response = 'Database not accessible.'; break; }
                if (args['_'].length != 1) {
                    response = 'Proper usage: dbdelete (key)'; // Delete a database key
                } else {
                    var existed = db.Get(args['_'][0]) != null;
                    db.Delete(args['_'][0]); // new agent with Delete fix
                    db.Delete('0/' + args['_'][0]); // old agent without Delete fix
                    response = existed ? 'Key deleted' : 'Key not found';
                }
                break;
            }
            case 'dbcompact': { // Compact the data store
                if (db == null) { response = 'Database not accessible.'; break; }
                var r = db.Compact();
                response = r == 0 ? 'Database compacted' : 'Compact failed';
                break;
            }
            case 'httpget': {
                if (consoleHttpRequest != null) {
                    response = 'HTTP operation already in progress.';
                } else {
                    if (args['_'].length != 1) {
                        response = 'Proper usage: httpget (url)';
                    } else {
                        var options = http.parseUri(args['_'][0]);
                        options.method = 'GET';
                        if (options == null) {
                            response = 'Invalid url.';
                        } else {
                            try { consoleHttpRequest = http.request(options, consoleHttpResponse); } catch (ex) { response = 'Invalid HTTP GET request'; }
                            consoleHttpRequest.sessionid = sessionid;
                            if (consoleHttpRequest != null) {
                                consoleHttpRequest.end();
                                response = 'HTTPGET ' + options.protocol + '//' + options.host + ':' + options.port + options.path;
                            }
                        }
                    }
                }
                break;
            }
            case 'wslist': { // List all web sockets
                response = '';
                for (var i in consoleWebSockets) {
                    var httprequest = consoleWebSockets[i];
                    response += 'Websocket #' + i + ', ' + httprequest.url + '\r\n';
                }
                if (response == '') { response = 'no websocket sessions.'; }
                break;
            }
            case 'wsconnect': { // Setup a web socket
                if (args['_'].length == 0) {
                    response = 'Proper usage: wsconnect (url)\r\nFor example: wsconnect wss://localhost:443/meshrelay.ashx?id=abc'; // Display correct command usage
                } else {
                    var httprequest = null;
                    try {
                        var options = http.parseUri(args['_'][0].split('$').join('%24').split('@').join('%40')); // Escape the $ and @ characters in the URL
                        options.rejectUnauthorized = 0;
                        httprequest = http.request(options);
                    } catch (ex) { response = 'Invalid HTTP websocket request'; }
                    if (httprequest != null) {
                        httprequest.upgrade = onWebSocketUpgrade;
                        httprequest.on('error', function (e) { sendConsoleText("ERROR: Unable to connect to: " + this.url + ", " + JSON.stringify(e)); });

                        var index = 1;
                        while (consoleWebSockets[index]) { index++; }
                        httprequest.sessionid = sessionid;
                        httprequest.index = index;
                        httprequest.url = args['_'][0];
                        consoleWebSockets[index] = httprequest;
                        response = 'New websocket session #' + index;
                    }
                }
                break;
            }
            case 'wssend': { // Send data on a web socket
                if (args['_'].length == 0) {
                    response = 'Proper usage: wssend (socketnumber)\r\n'; // Display correct command usage
                    for (var i in consoleWebSockets) {
                        var httprequest = consoleWebSockets[i];
                        response += 'Websocket #' + i + ', ' + httprequest.url + '\r\n';
                    }
                } else {
                    var i = parseInt(args['_'][0]);
                    var httprequest = consoleWebSockets[i];
                    if (httprequest != undefined) {
                        httprequest.s.write(args['_'][1]);
                        response = 'ok';
                    } else {
                        response = 'Invalid web socket number';
                    }
                }
                break;
            }
            case 'wsclose': { // Close a websocket
                if (args['_'].length == 0) {
                    response = 'Proper usage: wsclose (socketnumber)'; // Display correct command usage
                } else {
                    var i = parseInt(args['_'][0]);
                    var httprequest = consoleWebSockets[i];
                    if (httprequest != undefined) {
                        if (httprequest.s != null) { httprequest.s.end(); } else { httprequest.end(); }
                        response = 'ok';
                    } else {
                        response = 'Invalid web socket number';
                    }
                }
                break;
            }
            case 'tunnels': { // Show the list of current tunnels
                response = '';
                for (var i in tunnels) {
                    response += 'Tunnel #' + i + ', ' + tunnels[i].protocol; //tunnels[i].url
                    if (tunnels[i].userid) { response += ', ' + tunnels[i].userid; }
                    if (tunnels[i].guestname) { response += '/' + tunnels[i].guestname; }
                    response += '\r\n'
                }
                if (response == '') { response = 'No websocket sessions.'; }
                break;
            }
            case 'ls': { // Show list of files and folders
                response = '';
                var xpath = '*';
                if (args['_'].length > 0) { xpath = obj.path.join(args['_'][0], '*'); }
                response = 'List of ' + xpath + '\r\n';
                var results = fs.readdirSync(xpath);
                for (var i = 0; i < results.length; ++i) {
                    var stat = null, p = obj.path.join(args['_'][0], results[i]);
                    try { stat = fs.statSync(p); } catch (ex) { }
                    if ((stat == null) || (stat == undefined)) {
                        response += (results[i] + "\r\n");
                    } else {
                        response += (results[i] + " " + ((stat.isDirectory()) ? "(Folder)" : "(File)") + "\r\n");
                    }
                }
                break;
            }
            case 'lsx': { // Show list of files and folders
                response = objToString(getDirectoryInfo(args['_'][0]), 0, ' ', true);
                break;
            }
            case 'lock': { // Lock the current user out of the desktop
                lockDesktop();
                break;
            }
            case 'amt': { // Show Intel AMT status
                if (amt != null) {
                    amt.getMeiState(9, function (state) {
                        var resp = "Intel AMT not detected.";
                        if (state != null) { resp = objToString(state, 0, ' ', true); }
                        sendConsoleText(resp, sessionid);
                    });
                } else {
                    response = "Intel AMT not detected.";
                }
                break;
            }
            case 'netinfo': { // Show network interface information
                var interfaces = require('os').networkInterfaces();
                if (process.platform == 'win32') {
                    try {
                        var ret = require('win-wmi-fixed').query('ROOT\\CIMV2', 'SELECT InterfaceIndex,NetConnectionID,Speed FROM Win32_NetworkAdapter', ['InterfaceIndex','NetConnectionID','Speed']);
                        if (ret[0]) {
                            var speedMap = {};
                            for (var i = 0; i < ret.length; i++) speedMap[ret[i].InterfaceIndex] = ret[i].Speed;
                            var adapterNames = Object.keys(interfaces);
                            for (var j = 0; j < adapterNames.length; j++) {
                                var theinterfaces = interfaces[adapterNames[j]];
                                for (var k = 0; k < theinterfaces.length; k++) {
                                    var iface = theinterfaces[k], speed = speedMap[iface.index] || 0;
                                    iface.speed = parseInt(speed); // bits per seconds
                                }
                            }
                        }
                    } catch(ex) { }
                } else if (process.platform == 'linux') {
                    var adapterNames = Object.keys(interfaces);
                    for (var i = 0; i < adapterNames.length; i++) {
                        var ifaceName = adapterNames[i];
                        try {
                            var speedStr = require('fs').readFileSync('/sys/class/net/' + ifaceName + '/speed').toString();
                            if ((speedStr.trim() != "") && (speedStr.trim() != "-1")) {
                                var theinterfaces = interfaces[ifaceName];
                                for (var k = 0; k < theinterfaces.length; k++) {
                                    var iface = theinterfaces[k];
                                    iface.speed = parseInt(speedStr) * 1000000; // bits per seconds
                                }
                            }
                        } catch(ex) { }
                    }
                }
                response = objToString(interfaces, 0, ' ', true);
                break;
            }
            case 'wakeonlan': { // Send wake-on-lan
                if ((args['_'].length != 1) || (args['_'][0].length != 12)) {
                    response = 'Proper usage: wakeonlan [mac], for example "wakeonlan 010203040506".';
                } else {
                    var count = sendWakeOnLanEx([args['_'][0]]);
                    sendWakeOnLanEx([args['_'][0]]);
                    sendWakeOnLanEx([args['_'][0]]);
                    response = 'Sending wake-on-lan on ' + count + ' interface(s).';
                }
                break;
            }
            case 'display': {
                 if (args['_'].length != 1) {
                    response = 'Proper usage: display (sleep | awake)';
                } else {
                    var sleepawake = [args['_'][0]];
                    if(sleepawake=='sleep'){
                        require('power-monitor').sleepDisplay()
                    }else if(sleepawake=='awake'){
                        require('power-monitor').wakeDisplay()

                    }
                    response = 'Setting Display To ' + sleepawake;
                }
                break;
            }
            case 'sendall': { // Send a message to all consoles on this mesh
                sendConsoleText(args['_'].join(' '));
                break;
            }
            case 'power': { // Execute a power action on this computer
                if (mesh.ExecPowerState == undefined) {
                    response = 'Power command not supported on this agent.';
                } else {
                    if ((args['_'].length == 0) || isNaN(Number(args['_'][0]))) {
                        response = 'Proper usage: power (actionNumber), where actionNumber is:\r\n  LOGOFF = 1\r\n  SHUTDOWN = 2\r\n  REBOOT = 3\r\n  SLEEP = 4\r\n  HIBERNATE = 5\r\n  DISPLAYON = 6\r\n  KEEPAWAKE = 7\r\n  BEEP = 8\r\n  CTRLALTDEL = 9\r\n  VIBRATE = 13\r\n  FLASH = 14'; // Display correct command usage
                    } else {
                        var r = mesh.ExecPowerState(Number(args['_'][0]), Number(args['_'][1]));
                        response = 'Power action executed with return code: ' + r + '.';
                    }
                }
                break;
            }
            case 'location': {
                getIpLocationData(function (location) {
                    sendConsoleText(objToString({ action: 'iplocation', type: 'publicip', value: location }, 0, ' '));
                });
                break;
            }
            case 'parseuri': {
                response = JSON.stringify(http.parseUri(args['_'][0]));
                break;
            }
            case 'scanwifi': {
                if (wifiScanner != null) {
                    var wifiPresent = wifiScanner.hasWireless;
                    if (wifiPresent) { response = "Perfoming Wifi scan..."; wifiScanner.Scan(); } else { response = "Wifi absent."; }
                } else
                { response = "Wifi module not present."; }
                break;
            }
            case 'modules': {
                response = JSON.stringify(addedModules);
                break;
            }
            case 'listservices': {
                var services = require('service-manager').manager.enumerateService();
                response = JSON.stringify(services, null, 1);
                break;
            }
            case 'diagnostic':
                {
                    if (!mesh.DAIPC.listening) {
                        response = 'Unable to bind to Diagnostic IPC, most likely because the path (' + process.cwd() + ') is not on a local file system';
                        break;
                    }
                    var diag = diagnosticAgent_installCheck();
                    if (diag) {
                        if (args['_'].length == 1 && args['_'][0] == 'uninstall') {
                            diagnosticAgent_uninstall();
                            response = 'Diagnostic Agent uninstalled';
                        }
                        else {
                            response = 'Diagnostic Agent installed at: ' + diag.appLocation();
                        }
                    }
                    else {
                        if (args['_'].length == 1 && args['_'][0] == 'install') {
                            diag = diagnosticAgent_installCheck(true);
                            if (diag) {
                                response = 'Diagnostic agent was installed at: ' + diag.appLocation();
                            }
                            else {
                                response = 'Diagnostic agent installation failed';
                            }
                        }
                        else {
                            response = 'Diagnostic Agent Not installed. To install: diagnostic install';
                        }
                    }
                    if (diag) { diag.close(); diag = null; }
                    break;
                }
            case 'amtevents': {
                if ((args['_'].length == 1) && (args['_'][0] == 'on')) { obj.showamtevent = true; response = 'Intel AMT configuration events live view enabled.'; }
                else if ((args['_'].length == 1) && (args['_'][0] == 'off')) { delete obj.showamtevent; response = 'Intel AMT configuration events live view disabled.'; }
                else if (obj.amtevents == null) { response = 'No events.'; } else { response = obj.amtevents.join('\r\n'); }
                break;
            }
            case 'amtconfig': {
                if (amt == null) { response = 'Intel AMT not detected.'; break; }
                if (!obj.showamtevent) { obj.showamtevent = true; require('MeshAgent').SendCommand({ action: 'msg', type: 'console', value: 'Enabled live view of Intel AMT configuration events, \"amtevents off\" to disable.' }); }
                if (apftunnel != null) { response = 'Intel AMT server tunnel already active'; break; }
                require('MeshAgent').SendCommand({ action: 'amtconfig' }); // Request that the server give us a server authentication cookie to start the APF session.
                break;
            }
            case 'apf': {
                if (meshCoreObj.intelamt !== null) {
                    if (args['_'].length == 1) {
                        var connType = -1, connTypeStr = args['_'][0].toLowerCase();
                        if (connTypeStr == 'lms') { connType = 2; }
                        if (connTypeStr == 'relay') { connType = 1; }
                        if (connTypeStr == 'cira') { connType = 0; }
                        if (connTypeStr == 'off') { connType = -2; }
                        if (connType >= 0) { // Connect
                            var apfarg = {
                                mpsurl: mesh.ServerUrl.replace('agent.ashx', 'apf.ashx'),
                                mpsuser: Buffer.from(mesh.ServerInfo.MeshID, 'hex').toString('base64').substring(0, 16).replace(/\+/g, '@').replace(/\//g, '$'),
                                mpspass: Buffer.from(mesh.ServerInfo.MeshID, 'hex').toString('base64').substring(0, 16).replace(/\+/g, '@').replace(/\//g, '$'),
                                mpskeepalive: 60000,
                                clientname: require('os').hostname(),
                                clientaddress: '127.0.0.1',
                                clientuuid: meshCoreObj.intelamt.UUID,
                                conntype: connType // 0 = CIRA, 1 = Relay, 2 = LMS. The correct value is 2 since we are performing an LMS relay, other values for testing.
                            };
                            if ((apfarg.clientuuid == null) || (apfarg.clientuuid.length != 36)) {
                                response = "Unable to get Intel AMT UUID: " + apfarg.clientuuid;
                            } else {
                                apftunnel = require('amt-apfclient')({ debug: false }, apfarg);
                                apftunnel.onJsonControl = handleApfJsonControl;
                                apftunnel.onChannelClosed = function () { apftunnel = null; }
                                try {
                                    apftunnel.connect();
                                    response = "Started APF tunnel";
                                } catch (ex) {
                                    response = JSON.stringify(ex);
                                }
                            }
                        } else if (connType == -2) { // Disconnect
                            try {
                                apftunnel.disconnect();
                                response = "Stopped APF tunnel";
                            } catch (ex) {
                                response = JSON.stringify(ex);
                            }
                            apftunnel = null;
                        } else {
                            response = "Invalid command.\r\nUse: apf lms|relay|cira|off";
                        }
                    } else {
                        response = "APF tunnel is " + (apftunnel == null ? "off" : "on") + "\r\nUse: apf lms|relay|cira|off";
                    }
                } else {
                    response = "APF tunnel requires Intel AMT";
                }
                break;
            }
            case 'plugin': {
                if (typeof args['_'][0] == 'string') {
                    try {
                        // Pass off the action to the plugin
                        // for plugin creators, you'll want to have a plugindir/modules_meshcore/plugin.js
                        // to control the output / actions here.
                        response = require(args['_'][0]).consoleaction(args, rights, sessionid, mesh);
                    } catch (ex) {
                        response = "There was an error in the plugin (" + ex + ")";
                    }
                } else {
                    response = "Proper usage: plugin [pluginName] [args].";
                }
                break;
            }
            case 'installedapps': {
                if (process.platform == 'win32') {
                    try {
                        sendConsoleText('Fetching installed apps, please wait...', sessionid);
                        var iaPr = require('win-info').installedApps();
                        iaPr.sessionid = sessionid;
                        iaPr.then(function (apps) {
                            if (apps.length === 0) { sendConsoleText('No installed apps found.', this.sessionid); return; }
                            var lines = ['Installed Apps (' + apps.length + '):'];
                            for (var i = 0; i < apps.length; i++) {
                                var a = apps[i];
                                var line = '  [' + (i + 1) + '] ' + a.name;
                                if (a.version) line += ' (v' + a.version + ')';
                                if (a.publisher) line += ' - ' + a.publisher;
                                if (a.date) line += ' [Installed: ' + a.date + ']';
                                if (a.location) line += '\n       Location: ' + a.location;
                                lines.push(line);
                            }
                            sendConsoleText(lines.join('\n'), this.sessionid);
                        }, function (e) { sendConsoleText('Error: ' + e, this.sessionid); });
                    } catch (ex) {
                        sendConsoleText('Module win-info error: ' + ex, sessionid);
                    }
                } else if (process.platform == 'linux') {
                    try {
                        sendConsoleText('Fetching installed apps, please wait...', sessionid);
                        var iaLPr = require('linux-info').packages();
                        iaLPr.sessionid = sessionid;
                        iaLPr.then(function (apps) {
                            if (apps.length === 0) { sendConsoleText('No installed apps found.', this.sessionid); return; }
                            var lines = ['Installed Apps (' + apps.length + '):'];
                            for (var i = 0; i < apps.length; i++) {
                                var a = apps[i];
                                var line = '  [' + (i + 1) + '] ' + a.name;
                                if (a.version) line += ' (v' + a.version + ')';
                                if (a.arch) line += ' [' + a.arch + ']';
                                if (a.publisher) line += ' - ' + a.publisher;
                                if (a.date) line += ' [Installed: ' + a.date + ']';
                                if (a.location) line += ' (' + a.location + ')';
                                lines.push(line);
                            }
                            sendConsoleText(lines.join('\n'), this.sessionid);
                        }, function (e) { sendConsoleText('Error: ' + e, this.sessionid); });
                    } catch (ex) {
                        sendConsoleText('Module linux-info error: ' + ex, sessionid);
                    }
                } else if (process.platform == 'darwin') {
                    try {
                        sendConsoleText('Fetching installed apps, please wait...', sessionid);
                        var iaMPr = require('mac-info').apps();
                        iaMPr.sessionid = sessionid;
                        iaMPr.then(function (apps) {
                            if (apps.length === 0) { sendConsoleText('No installed apps found.', this.sessionid); return; }
                            var lines = ['Installed Apps (' + apps.length + '):'];
                            for (var i = 0; i < apps.length; i++) {
                                var a = apps[i];
                                var line = '  [' + (i + 1) + '] ' + a.name;
                                if (a.version) line += ' (v' + a.version + ')';
                                if (a.arch) line += ' [' + a.arch + ']';
                                if (a.publisher) line += ' - ' + a.publisher;
                                if (a.date) line += ' [Installed: ' + a.date + ']';
                                if (a.location) line += ' (' + a.location + ')';
                                lines.push(line);
                            }
                            sendConsoleText(lines.join('\n'), this.sessionid);
                        }, function (e) { sendConsoleText('Error: ' + e, this.sessionid); });
                    } catch (ex) {
                        sendConsoleText('Module mac-info error: ' + ex, sessionid);
                    }
                } else {
                    sendConsoleText('Installed apps not supported on this platform.', sessionid);
                }
                break;
            }
            case 'installedstoreapps': {
                if (process.platform == 'win32') {
                    try {
                        sendConsoleText('Fetching installed Store apps, please wait...', sessionid);
                        var isaPr = require('win-info').installedStoreApps();
                        isaPr.sessionid = sessionid;
                        isaPr.then(function (apps) {
                            if (!apps || apps.length === 0) { sendConsoleText('No Store apps found.', this.sessionid); return; }
                            var lines = ['Installed Store Apps (' + apps.length + '):'];
                            for (var i = 0; i < apps.length; i++) {
                                var a = apps[i];
                                var line = '  [' + (i + 1) + '] ' + a.name;
                                if (a.version) line += ' (v' + a.version + ')';
                                if (a.publisher) line += ' - ' + a.publisher;
                                if (a.scope) line += ' [' + a.scope + ']';
                                if (a.packageFullName) line += '\n       Package: ' + a.packageFullName;
                                lines.push(line);
                            }
                            sendConsoleText(lines.join('\n'), this.sessionid);
                        }, function (e) { sendConsoleText('Error: ' + e, this.sessionid); });
                    } catch (ex) {
                        sendConsoleText('Module win-info error: ' + ex, sessionid);
                    }
                } else {
                    sendConsoleText('Installed Store Apps not supported on this platform.', sessionid);
                }
                break;
            }
            case 'winupdates': {
                if (process.platform == 'win32') {
                    try {
                        sendConsoleText('Checking for pending updates, this may take up to 60 seconds...', sessionid);
                        var wuPr = require('win-updates').getAvailableUpdates();
                        wuPr.sessionid = sessionid;
                        wuPr.then(function (updates) {
                            if (updates.length === 0) { sendConsoleText('No pending updates.', this.sessionid); return; }
                            var lines = ['Pending Updates (' + updates.length + '):'];
                            for (var i = 0; i < updates.length; i++) {
                                lines.push('  [' + (i + 1) + '] ' + updates[i].title + (updates[i].kbArticleIDs.length ? ' (' + updates[i].kbArticleIDs.join(', ') + ')' : '') + (updates[i].severity ? ' [' + updates[i].severity + ']' : ''));
                            }
                            sendConsoleText(lines.join('\n'), this.sessionid);
                        }, function (e) { sendConsoleText('Error: ' + e, this.sessionid); });
                    } catch (ex) { sendConsoleText('win-updates error: ' + ex, sessionid); }
                } else { sendConsoleText('Windows updates not supported on this platform.', sessionid); }
                break;
            }
            case 'winupdatesinstalled': {
                if (process.platform == 'win32') {
                    try {
                        sendConsoleText('Checking installed updates, this may take up to 60 seconds...', sessionid);
                        var wuiPr = require('win-updates').getInstalledUpdates();
                        wuiPr.sessionid = sessionid;
                        wuiPr.then(function (updates) {
                            if (updates.length === 0) { sendConsoleText('No installed updates found.', this.sessionid); return; }
                            var lines = ['Installed Updates (' + updates.length + '):'];
                            for (var i = 0; i < updates.length; i++) {
                                lines.push('  [' + (i + 1) + '] ' + updates[i].title + (updates[i].kbArticleIDs.length ? ' (' + updates[i].kbArticleIDs.join(', ') + ')' : ''));
                            }
                            sendConsoleText(lines.join('\n'), this.sessionid);
                        }, function (e) { sendConsoleText('Error: ' + e, this.sessionid); });
                    } catch (ex) { sendConsoleText('win-updates error: ' + ex, sessionid); }
                } else { sendConsoleText('Windows updates not supported on this platform.', sessionid); }
                break;
            }
            case 'winupdateshistory': {
                if (process.platform == 'win32') {
                    try {
                        sendConsoleText('Fetching update history, this may take up to 60 seconds...', sessionid);
                        var wuhPr = require('win-updates').getInstalledUpdateHistory();
                        wuhPr.sessionid = sessionid;
                        wuhPr.then(function (updates) {
                            if (updates.length === 0) { sendConsoleText('No update history found.', this.sessionid); return; }
                            var lines = ['Update History (' + updates.length + '):'];
                            for (var i = 0; i < updates.length; i++) {
                                lines.push('  [' + (i + 1) + '] ' + updates[i].title + (updates[i].kbArticleIDs.length ? ' (' + updates[i].kbArticleIDs.join(', ') + ')' : ''));
                            }
                            sendConsoleText(lines.join('\n'), this.sessionid);
                        }, function (e) { sendConsoleText('Error: ' + e, this.sessionid); });
                    } catch (ex) { sendConsoleText('win-updates error: ' + ex, sessionid); }
                } else { sendConsoleText('Windows updates not supported on this platform.', sessionid); }
                break;
            }
            case 'winupdatesdedup': {
                if (process.platform == 'win32') {
                    try {
                        sendConsoleText('Fetching de-duplicated update history, this may take up to 60 seconds...', sessionid);
                        var wudPr = require('win-updates').getInstalledUpdatesDeDuplicated();
                        wudPr.sessionid = sessionid;
                        wudPr.then(function (updates) {
                            if (updates.length === 0) { sendConsoleText('No update history found.', this.sessionid); return; }
                            var lines = ['Installed Updates De-duplicated (' + updates.length + '):'];
                            for (var i = 0; i < updates.length; i++) {
                                lines.push('  [' + (i + 1) + '] ' + updates[i].title + (updates[i].kbArticleIDs.length ? ' (' + updates[i].kbArticleIDs.join(', ') + ')' : ''));
                            }
                            sendConsoleText(lines.join('\n'), this.sessionid);
                        }, function (e) { sendConsoleText('Error: ' + e, this.sessionid); });
                    } catch (ex) { sendConsoleText('win-updates error: ' + ex, sessionid); }
                } else { sendConsoleText('Windows updates not supported on this platform.', sessionid); }
                break;
            }
            case 'uninstallapp': {
                if (args['_'].length < 1) {
                    response = "Usage: uninstallapp <base64-encoded-command>";
                } else {
                    var base64Cmd = args['_'][0];
                    var uninstallCmd = '';
                    try {
                        var b = Buffer.from(base64Cmd, 'base64');
                        var decoded = b.toString();
                        var lc = decoded ? decoded.toLowerCase() : '';
                        if (decoded && decoded.length > 0 && (lc.indexOf('msiexec') >= 0 || lc.indexOf('.exe') >= 0)) {
                            uninstallCmd = decoded;
                        } else {
                            uninstallCmd = base64Cmd;
                        }
                    } catch (e) {
                        uninstallCmd = base64Cmd;
                    }
                    if (!uninstallCmd || uninstallCmd.trim() === '' || uninstallCmd.trim() === '\\') {
                        response = JSON.stringify({ success: false, error: 'No valid uninstall command available' });
                        break;
                    }
                    var logDir = (process.env['ProgramData'] || 'C:\\ProgramData') + '\\MeshAgent';
                    try { if (!require('fs').existsSync(logDir)) { require('fs').mkdirSync(logDir); } } catch (e) { }
                    var logFile = logDir + '\\MeshAgent_Uninstall.log';
                    var child_process = require('child_process');
                    var cmdPath = process.env['windir'] + '\\system32\\cmd.exe';
                    function writeLog(message, callback) {
                        try {
                            var timestamp = new Date().toISOString();
                            var logLine = timestamp + ' | ' + message;
                            logLine = logLine.replace(/"/g, '""').replace(/&/g, '^&').replace(/</g, '^<').replace(/>/g, '^>').replace(/\|/g, '^|');
                            var logChild = child_process.execFile(cmdPath, ['cmd', '/c', 'echo ' + logLine + ' >> "' + logFile + '"'], { timeout: 5000 });
                            logChild.on('exit', function() {
                                if (callback) callback();
                            });
                        } catch (e) {
                            if (callback) callback();
                        }
                    }
                    try {
                        writeLog('UNINSTALL START - Command: ' + uninstallCmd.replace(/\\/g, '/'));
                        var originalCmd = uninstallCmd;
                        if (uninstallCmd.toLowerCase().indexOf('msiexec') >= 0) {
                            uninstallCmd = uninstallCmd.replace(/\/I\s*(\{[^}]+\})/gi, '/X $1');
                            uninstallCmd = uninstallCmd.replace(/\/q[nbrf]?/gi, '');
                            if (uninstallCmd.indexOf('/QN') < 0) {
                                uninstallCmd = uninstallCmd + ' /QN /norestart';
                            }
                        } else {
                            if (uninstallCmd.toLowerCase().indexOf('/s') < 0) {
                                uninstallCmd = uninstallCmd + ' /S /silent /SILENT /VERYSILENT /quiet /norestart';
                            }
                        }
                        uninstallCmd = uninstallCmd.replace(/\s+/g, ' ').trim();
                        writeLog('UNINSTALL EXEC - Modified: ' + uninstallCmd.replace(/\\/g, '/'));
                        var child = child_process.execFile(cmdPath, ['cmd', '/c', uninstallCmd], { timeout: 300000 });
                        child.stdout.str = '';
                        child.stderr.str = '';
                        child._sessionid = sessionid;
                        child._cmd = uninstallCmd;
                        child._originalCmd = originalCmd;
                        child._writeLog = writeLog;
                        child.stdout.on('data', function(c) { this.str += c.toString(); });
                        child.stderr.on('data', function(c) { this.str += c.toString(); });
                        child.on('exit', function(code) {
                            var success = (code === 0 || code === null || code === 3010);
                            var status = success ? 'SUCCESS' : 'FAILED';
                            child._writeLog('UNINSTALL ' + status + ' - ExitCode: ' + code);
                            var result = { 
                                success: success, 
                                exitCode: code,
                                command: child._cmd
                            };
                            if (child.stdout.str) result.stdout = child.stdout.str.trim().substring(0, 500);
                            if (child.stderr.str) result.stderr = child.stderr.str.trim().substring(0, 500);
                            sendConsoleText(JSON.stringify(result), child._sessionid);
                        });
                        response = JSON.stringify({ status: 'Silent uninstall started', command: uninstallCmd });
                    } catch (ex) {
                        writeLog('UNINSTALL ERROR - ' + ex.toString());
                        response = JSON.stringify({ error: ex.toString() });
                    }
                }
                break;
            }
            case 'uninstallstoreapp': {
                if (args['_'].length < 1) {
                    response = "Usage: uninstallstoreapp <PackageName>";
                } else {
                    var packageName = args['_'][0];
                    var logDir = (process.env['ProgramData'] || 'C:\\ProgramData') + '\\MeshAgent';
                    try { if (!require('fs').existsSync(logDir)) { require('fs').mkdirSync(logDir); } } catch (e) { }
                    var logFile = logDir + '\\MeshAgent_StoreUninstall.log';
                    try {
                        var psPath = (process.env['SystemRoot'] || 'C:\\Windows') + '\\System32\\WindowsPowerShell\\v1.0\\powershell.exe';
                        var child_process = require('child_process');
                        var safePackageName = packageName.replace(/'/g, "''");
                        var completionMarker = '###DONE###' + Date.now();
                        var child = child_process.execFile(psPath, ['powershell', '-NoProfile', '-NoLogo', '-Command', '-'], {});
                        child.stdout.str = '';
                        child.stderr.str = '';
                        child._sessionid = sessionid;
                        child._packageName = packageName;
                        child._marker = completionMarker;
                        child._completed = false;
                        child._logFile = logFile;
                        child.stdout.on('data', function(c) { 
                            this.str += c.toString();
                            if (!child._completed && this.str.indexOf(child._marker) >= 0) {
                                child._completed = true;
                                var result = this.str.split(child._marker)[0].trim();
                                if (result === 'NO_MATCH' || result === '') {
                                    sendConsoleText(JSON.stringify({ 
                                        success: false, 
                                        error: 'No matching packages found',
                                        package: child._packageName
                                    }), child._sessionid);
                                } else if (result.indexOf('REMOVED') >= 0 || result.indexOf('DEPROVISIONED') >= 0) {
                                    var items = result.split('|').filter(function(x) { return x.length > 0; });
                                    sendConsoleText(JSON.stringify({ 
                                        success: true, 
                                        message: 'Store app removed',
                                        results: items
                                    }), child._sessionid);
                                } else if (result.indexOf('FAILED') >= 0) {
                                    sendConsoleText(JSON.stringify({ 
                                        success: false, 
                                        error: 'Removal failed',
                                        details: result.split('|')
                                    }), child._sessionid);
                                } else {
                                    sendConsoleText(JSON.stringify({ output: result }), child._sessionid);
                                }
                            }
                        });
                        child.stderr.on('data', function(c) { this.str += c.toString(); });
                        var script = [
                            "$LogFile = '" + logFile + "'",
                            "function Write-Log { param([string]$Message); $LogLine = \"$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - $Message\"; Add-Content -Path $LogFile -Value $LogLine -ErrorAction SilentlyContinue }",
                            "",
                            "Write-Log 'STORE UNINSTALL START: " + safePackageName + "'",
                            "Write-Log \"Running as: $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)\"",
                            "",
                            "$ErrorActionPreference = 'SilentlyContinue'",
                            "$results = @()",
                            "",
                            "# Packages suchen",
                            "$pkgs = Get-AppxPackage -AllUsers -Name '*" + safePackageName + "*'",
                            "Write-Log \"Found (AllUsers): $($pkgs.Count) packages\"",
                            "",
                            "if (-not $pkgs) {",
                            "    $pkgs = Get-AppxPackage -Name '*" + safePackageName + "*'",
                            "    Write-Log \"Found (CurrentUser): $($pkgs.Count) packages\"",
                            "}",
                            "",
                            "foreach ($p in $pkgs) {",
                            "    Write-Log \"Removing: $($p.PackageFullName)\"",
                            "    try {",
                            "        Remove-AppxPackage -Package $p.PackageFullName -AllUsers -ErrorAction Stop",
                            "        Write-Log 'SUCCESS: Removed with -AllUsers'",
                            "        $results += 'REMOVED_ALLUSERS:' + $p.PackageFullName",
                            "    } catch {",
                            "        Write-Log \"FAILED -AllUsers: $($_.Exception.Message)\"",
                            "        try {",
                            "            Remove-AppxPackage -Package $p.PackageFullName -ErrorAction Stop",
                            "            Write-Log 'SUCCESS: Removed'",
                            "            $results += 'REMOVED:' + $p.PackageFullName",
                            "        } catch {",
                            "            Write-Log \"FAILED: $($_.Exception.Message)\"",
                            "            $results += 'FAILED:' + $p.PackageFullName + ':' + $_.Exception.Message",
                            "        }",
                            "    }",
                            "}",
                            "",
                            "# Provisioned Packages entfernen",
                            "$prov = Get-AppxProvisionedPackage -Online 2>$null | Where-Object { $_.PackageName -like '*" + safePackageName + "*' }",
                            "Write-Log \"Found provisioned: $($prov.Count) packages\"",
                            "",
                            "foreach ($pr in $prov) {",
                            "    Write-Log \"Deprovisioning: $($pr.DisplayName)\"",
                            "    try {",
                            "        Remove-AppxProvisionedPackage -Online -PackageName $pr.PackageName -ErrorAction Stop | Out-Null",
                            "        Write-Log 'SUCCESS: Deprovisioned'",
                            "        $results += 'DEPROVISIONED:' + $pr.DisplayName",
                            "    } catch {",
                            "        Write-Log \"FAILED: $($_.Exception.Message)\"",
                            "        $results += 'DEPROV_FAILED:' + $pr.DisplayName",
                            "    }",
                            "}",
                            "",
                            "if ($results.Count -eq 0) {",
                            "    Write-Log 'NO_MATCH'",
                            "    'NO_MATCH'",
                            "} else {",
                            "    $output = $results -join '|'",
                            "    Write-Log \"RESULT: $output\"",
                            "    $output",
                            "}",
                            "'" + completionMarker + "'",
                            "exit"
                        ].join("\r\n");
                        child.stdin.write(script + "\r\n");
                        setTimeout(function() {
                            if (!child._completed) {
                                sendConsoleText(JSON.stringify({ error: 'Timeout after 2 minutes' }), child._sessionid);
                            }
                        }, 120000);
                        response = JSON.stringify({ status: 'Store app removal started', package: packageName });
                    } catch (ex) {
                        var logErr = new Date().toISOString() + ' - STORE UNINSTALL ERROR: ' + ex.toString() + '\r\n';
                        try { require('fs').appendFileSync(logFile, logErr); } catch (e) { }
                        response = JSON.stringify({ error: ex.toString() });
                    }
                }
                break;
            }
            case 'qfe': {
                if(process.platform == 'win32'){
                    var qfe = require('win-info').qfe();
                    sendConsoleText(JSON.stringify(qfe,null,1));
                }
                break;
            }
            default: { // This is an unknown command, return an error message
                response = "Unknown command \"" + cmd + "\", type \"help\" for list of available commands.";
                break;
            }
        }
    } catch (ex) { response = "Command returned an exception error: " + ex; console.log(ex); }
    if (response != null) { sendConsoleText(response, sessionid); }
}

// Send a mesh agent console command
function sendConsoleText(text, sessionid) {
    if (typeof text == 'object') { text = JSON.stringify(text); }
    if (debugConsole && ((sessionid == null) || (sessionid == 'pipe'))) { broadcastToRegisteredApps({ cmd: 'console', value: text }); }
    if (sessionid != 'pipe') { require('MeshAgent').SendCommand({ action: 'msg', type: 'console', value: text, sessionid: sessionid }); }
}

function removeAgentMessage(msgid) {
    var ret = false;
    if (msgid == null) {
        // Delete all messages
        sendAgentMessage.messages = [];
        ret = true;
    }
    else {
        var i = sendAgentMessage.messages.findIndex(function (v) { return (v.id == msgid); });
        if (i >= 0) {
            sendAgentMessage.messages.splice(i, 1);
            ret = true;
        }
    }
    if (ret) { sendAgentMessage(); }
    return (ret);
}

// Send a mesh agent message to server, placing a bubble/badge on the agent device
function sendAgentMessage(msg, icon, serverid, first) {
    if (sendAgentMessage.messages == null) {
        sendAgentMessage.messages = [];
    }

    if (arguments.length > 0) {
        if (first == null || (serverid && first && sendAgentMessage.messages.findIndex(function (v) { return (v.msgid == serverid); }) < 0)) {
            sendAgentMessage.messages.push({ msg: msg, icon: icon, msgid: serverid });
            sendAgentMessage.messages.peek().id = sendAgentMessage.messages.peek()._hashCode();
        }
    }

    var p = {}, i;
    for (i = 0; i < sendAgentMessage.messages.length; ++i) {
        p[i] = sendAgentMessage.messages[i];
    }
    try {
        require('MeshAgent').SendCommand({ action: 'sessions', type: 'msg', value: p });
    } catch (ex) { }
    return (arguments.length > 0 ? sendAgentMessage.messages.peek().id : sendAgentMessage.messages);
}
function getOpenDescriptors() {
    var r = [];
    switch (process.platform) {
        case "freebsd": {
            var child = require('child_process').execFile('/bin/sh', ['sh']);
            child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
            child.stderr.on('data', function (c) { });

            child.stdin.write("procstat -f " + process.pid + " | tr '\\n' '`' | awk -F'`' '");
            child.stdin.write('{');
            child.stdin.write('   DEL="";');
            child.stdin.write('   printf "[";');
            child.stdin.write('   for(i=1;i<NF;++i)');
            child.stdin.write('   {');
            child.stdin.write('      A=split($i,B," ");');
            child.stdin.write('      if(B[3] ~ /^[0-9]/)');
            child.stdin.write('      {');
            child.stdin.write('         printf "%s%s", DEL, B[3];');
            child.stdin.write('         DEL=",";');
            child.stdin.write('      }');
            child.stdin.write('   }');
            child.stdin.write('   printf "]";');
            child.stdin.write("}'");

            child.stdin.write('\nexit\n');
            child.waitExit();

            try { r = JSON.parse(child.stdout.str.trim()); } catch (ex) { }
            break;
        }
        case "linux": {
            var child = require('child_process').execFile('/bin/sh', ['sh']);
            child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
            child.stderr.on('data', function (c) { });

            child.stdin.write("ls /proc/" + process.pid + "/fd | tr '\\n' '`' | awk -F'`' '");
            child.stdin.write('{');
            child.stdin.write('   printf "[";');
            child.stdin.write('   DEL="";');
            child.stdin.write('   for(i=1;i<NF;++i)');
            child.stdin.write('   {');
            child.stdin.write('      printf "%s%s",DEL,$i;');
            child.stdin.write('      DEL=",";');
            child.stdin.write('   }');
            child.stdin.write('   printf "]";');
            child.stdin.write("}'");
            child.stdin.write('\nexit\n');
            child.waitExit();

            try { r = JSON.parse(child.stdout.str.trim()); } catch (ex) { }
            break;
        }
    }
    return r;
}
function closeDescriptors(libc, descriptors) {
    var fd = null;
    while (descriptors.length > 0) {
        fd = descriptors.pop();
        if (fd > 2) {
            libc.close(fd);
        }
    }
}
function linux_execv(name, agentfilename, sessionid) {
    var libs = require('monitor-info').getLibInfo('libc');
    var libc = null;

    if ((libs.length == 0 || libs.length == null) && require('MeshAgent').ARCHID == 33) {
        var child = require('child_process').execFile('/bin/sh', ['sh']);
        child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
        child.stderr.str = ''; child.stderr.on('data', function (c) { this.str += c.toString(); });
        child.stdin.write("ls /lib/libc.* | tr '\\n' '`' | awk -F'`' '{ " + ' printf "["; DEL=""; for(i=1;i<NF;++i) { printf "%s{\\"path\\":\\"%s\\"}",DEL,$i; DEL=""; } printf "]"; }\'\nexit\n');
        child.waitExit();

        try {
            libs = JSON.parse(child.stdout.str.trim());
        } catch (ex) { }
    }

    while (libs.length > 0) {
        try {
            libc = require('_GenericMarshal').CreateNativeProxy(libs.pop().path);
            break;
        } catch (ex) {
            libc = null;
            continue;
        }
    }
    if (libc != null) {
        try {
            libc.CreateMethod('execv');
            libc.CreateMethod('close');
        } catch (ex) {
            libc = null;
        }
    }

    if (libc == null) {
        // Couldn't find libc.so, fallback to using service manager to restart agent
        if (sessionid != null) { sendConsoleText('Restarting service via service-manager...', sessionid) }
        try {
            // restart service
            var s = require('service-manager').manager.getService(name);
            s.restart();
        } catch (ex) {
            sendConsoleText('Self Update encountered an error trying to restart service', sessionid);
            sendAgentMessage('Self Update encountered an error trying to restart service', 3);
        }
        return;
    }

    if (sessionid != null) { sendConsoleText('Restarting service via execv()...', sessionid) }

    var i;
    var args;
    var argarr = [process.execPath];
    var argtmp = [];
    var path = require('_GenericMarshal').CreateVariable(process.execPath);

    if (require('MeshAgent').getStartupOptions != null) {
        var options = require('MeshAgent').getStartupOptions();
        for (i in options) {
            argarr.push('--' + i + '="' + options[i] + '"');
        }
    }

    args = require('_GenericMarshal').CreateVariable((1 + argarr.length) * require('_GenericMarshal').PointerSize);
    for (i = 0; i < argarr.length; ++i) {
        var arg = require('_GenericMarshal').CreateVariable(argarr[i]);
        argtmp.push(arg);
        arg.pointerBuffer().copy(args.toBuffer(), i * require('_GenericMarshal').PointerSize);
    }

    var descriptors = getOpenDescriptors();
    closeDescriptors(libc, descriptors);

    libc.execv(path, args);
    if (sessionid != null) { sendConsoleText('Self Update failed because execv() failed', sessionid) }
    sendAgentMessage('Self Update failed because execv() failed', 3);
}

function bsd_execv(name, agentfilename, sessionid) {
    var child = require('child_process').execFile('/bin/sh', ['sh']);
    child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
    child.stderr.str = ''; child.stderr.on('data', function (c) { this.str += c.toString(); });
    child.stdin.write("cat /usr/lib/libc.so | awk '");
    child.stdin.write('{');
    child.stdin.write(' a=split($0, tok, "(");');
    child.stdin.write(' if(a>1)');
    child.stdin.write(' {');
    child.stdin.write('     split(tok[2], b, ")");');
    child.stdin.write('     split(b[1], c, " ");');
    child.stdin.write('     print c[1];');
    child.stdin.write(' }');
    child.stdin.write("}'\nexit\n");
    child.waitExit();
    if (child.stdout.str.trim() == '') {
        if (sessionid != null) { sendConsoleText('Self Update failed because cannot find libc.so', sessionid) }
        sendAgentMessage('Self Update failed because cannot find libc.so', 3);
        return;
    }

    var libc = null;
    try {
        libc = require('_GenericMarshal').CreateNativeProxy(child.stdout.str.trim());
        libc.CreateMethod('execv');
        libc.CreateMethod('close');
    } catch (ex) {
        if (sessionid != null) { sendConsoleText('Self Update failed: ' + ex.toString(), sessionid) }
        sendAgentMessage('Self Update failed: ' + ex.toString(), 3);
        return;
    }

    var path = require('_GenericMarshal').CreateVariable(process.execPath);
    var argarr = [process.execPath];
    var args, i, argtmp = [];
    var options = require('MeshAgent').getStartupOptions();
    for (i in options) {
        argarr.push('--' + i + '="' + options[i] + '"');
    }
    args = require('_GenericMarshal').CreateVariable((1 + argarr.length) * require('_GenericMarshal').PointerSize);
    for (i = 0; i < argarr.length; ++i) {
        var arg = require('_GenericMarshal').CreateVariable(argarr[i]);
        argtmp.push(arg);
        arg.pointerBuffer().copy(args.toBuffer(), i * require('_GenericMarshal').PointerSize);
    }

    if (sessionid != null) { sendConsoleText('Restarting service via execv()', sessionid) }

    var descriptors = getOpenDescriptors();
    closeDescriptors(libc, descriptors);

    libc.execv(path, args);
    if (sessionid != null) { sendConsoleText('Self Update failed because execv() failed', sessionid) }
    sendAgentMessage('Self Update failed because execv() failed', 3);
}

function windows_execve(name, agentfilename, sessionid) {
    var libc;
    try {
        libc = require('_GenericMarshal').CreateNativeProxy('msvcrt.dll');
        libc.CreateMethod('_wexecve');
    } catch (ex) {
        sendConsoleText('Self Update failed because msvcrt.dll is missing', sessionid);
        sendAgentMessage('Self Update failed because msvcrt.dll is missing', 3);
        return;
    }
    
    var cmd = require('_GenericMarshal').CreateVariable(process.env['windir'] + '\\system32\\cmd.exe', { wide: true });
    var args = require('_GenericMarshal').CreateVariable(3 * require('_GenericMarshal').PointerSize);
    var arg1 = require('_GenericMarshal').CreateVariable('cmd.exe', { wide: true });
    var arg2 = require('_GenericMarshal').CreateVariable('/C net stop "' + name + '" & "' + process.cwd() + agentfilename + '.update.exe" -b64exec ' + 'dHJ5CnsKICAgIHZhciBzZXJ2aWNlTG9jYXRpb24gPSBwcm9jZXNzLmFyZ3YucG9wKCkudG9Mb3dlckNhc2UoKTsKICAgIHJlcXVpcmUoJ3Byb2Nlc3MtbWFuYWdlcicpLmVudW1lcmF0ZVByb2Nlc3NlcygpLnRoZW4oZnVuY3Rpb24gKHByb2MpCiAgICB7CiAgICAgICAgZm9yICh2YXIgcCBpbiBwcm9jKQogICAgICAgIHsKICAgICAgICAgICAgaWYgKHByb2NbcF0ucGF0aCAmJiAocHJvY1twXS5wYXRoLnRvTG93ZXJDYXNlKCkgPT0gc2VydmljZUxvY2F0aW9uKSkKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgcHJvY2Vzcy5raWxsKHByb2NbcF0ucGlkKTsKICAgICAgICAgICAgfQogICAgICAgIH0KICAgICAgICBwcm9jZXNzLmV4aXQoKTsKICAgIH0pOwp9CmNhdGNoIChlKQp7CiAgICBwcm9jZXNzLmV4aXQoKTsKfQ==' +
        ' "' + process.execPath + '" & copy "' + process.cwd() + agentfilename + '.update.exe" "' + process.execPath + '" & net start "' + name + '" & erase "' + process.cwd() + agentfilename + '.update.exe"', { wide: true });

    arg1.pointerBuffer().copy(args.toBuffer());
    arg2.pointerBuffer().copy(args.toBuffer(), require('_GenericMarshal').PointerSize);

    libc._wexecve(cmd, args, 0);
}

// Start a JavaScript based Agent Self-Update
function agentUpdate_Start(updateurl, updateoptions) {
    // If this value is null
    var sessionid = (updateoptions != null) ? updateoptions.sessionid : null; // If this is null, messages will be broadcast. Otherwise they will be unicasted

    // If the url starts with *, switch it to use the same protoco, host and port as the control channel.
    if (updateurl != null) {
        updateurl = getServerTargetUrlEx(updateurl);
        if (updateurl.startsWith("wss://")) { updateurl = "https://" + updateurl.substring(6); }
    }

    if (agentUpdate_Start._selfupdate != null) {
        // We were already called, so we will ignore this duplicate request
        if (sessionid != null) { sendConsoleText('Self update already in progress...', sessionid); }
    }
    else {
        if (agentUpdate_Start._retryCount == null) { agentUpdate_Start._retryCount = 0; }
        if (require('MeshAgent').ARCHID == null && updateurl == null) {
            // This agent doesn't have the ability to tell us which ARCHID it is, so we don't know which agent to pull
            sendConsoleText('Unable to initiate update, agent ARCHID is not defined', sessionid);
        }
        else {
            var agentfilename = process.execPath.split(process.platform == 'win32' ? '\\' : '/').pop(); // Local File Name, ie: MeshAgent.exe
            var name = require('MeshAgent').serviceName;
            if (name == null) { name = (process.platform == 'win32' ? 'Mesh Agent' : 'meshagent'); } // This is an older agent that doesn't expose the service name, so use the default
            try {
                var s = require('service-manager').manager.getService(name);
                if (!s.isMe()) {
                    if (process.platform == 'win32') { s.close(); }
                    sendConsoleText('Self Update cannot continue, this agent is not an instance of (' + name + ')', sessionid);
                    return;
                }
                if (process.platform == 'win32') { s.close(); }
            }
            catch (ex) {
                sendConsoleText('Self Update Failed because this agent is not an instance of (' + name + ')', sessionid);
                sendAgentMessage('Self Update Failed because this agent is not an instance of (' + name + ')', 3);
                return;
            }

            if ((sessionid != null) && (updateurl != null)) { sendConsoleText('Downloading update from: ' + updateurl, sessionid); }
            var options = require('http').parseUri(updateurl != null ? updateurl : require('MeshAgent').ServerUrl);
            options.protocol = 'https:';
            if (updateurl == null) { options.path = ('/meshagents?id=' + require('MeshAgent').ARCHID); sendConsoleText('Downloading update from: ' + options.path, sessionid); }
            options.rejectUnauthorized = false;
            options.checkServerIdentity = function checkServerIdentity(certs) {
                // If the tunnel certificate matches the control channel certificate, accept the connection
                try { if (require('MeshAgent').ServerInfo.ControlChannelCertificate.digest == certs[0].digest) return; } catch (ex) { }
                try { if (require('MeshAgent').ServerInfo.ControlChannelCertificate.fingerprint == certs[0].fingerprint) return; } catch (ex) { }

                // Check that the certificate is the one expected by the server, fail if not.
                if (checkServerIdentity.servertlshash == null) {
                    if (require('MeshAgent').ServerInfo == null || require('MeshAgent').ServerInfo.ControlChannelCertificate == null) { return; }
                    sendConsoleText('Self Update failed, because the url cannot be verified: ' + updateurl, sessionid);
                    sendAgentMessage('Self Update failed, because the url cannot be verified: ' + updateurl, 3);
                    throw new Error('BadCert');
                }
                if (certs[0].digest == null) { return; }
                if ((checkServerIdentity.servertlshash != null) && (checkServerIdentity.servertlshash.toLowerCase() != certs[0].digest.split(':').join('').toLowerCase())) {
                    sendConsoleText('Self Update failed, because the supplied certificate does not match', sessionid);
                    sendAgentMessage('Self Update failed, because the supplied certificate does not match', 3);
                    throw new Error('BadCert')
                }
            }
            options.checkServerIdentity.servertlshash = (updateoptions != null ? updateoptions.tlshash : null);
            agentUpdate_Start._selfupdate = require('https').get(options);
            agentUpdate_Start._selfupdate.on('error', function (e) {
                sendConsoleText('Self Update failed, because there was a problem trying to download the update from ' + updateurl, sessionid);
                sendAgentMessage('Self Update failed, because there was a problem trying to download the update from ' + updateurl, 3);
                agentUpdate_Start._selfupdate = null;
            });
            agentUpdate_Start._selfupdate.on('response', function (img) {
                this._file = require('fs').createWriteStream(agentfilename + (process.platform == 'win32' ? '.update.exe' : '.update'), { flags: 'wb' });
                this._filehash = require('SHA384Stream').create();
                this._filehash.on('hash', function (h) {
                    if (updateoptions != null && updateoptions.hash != null) {
                        if (updateoptions.hash.toLowerCase() == h.toString('hex').toLowerCase()) {
                            if (sessionid != null) { sendConsoleText('Download complete. HASH verified.', sessionid); }
                        } else {
                            agentUpdate_Start._retryCount++;
                            sendConsoleText('Self Update FAILED because the downloaded agent FAILED hash check (' + agentUpdate_Start._retryCount + '), URL: ' + updateurl, sessionid);
                            sendConsoleText(updateoptions.hash + " != " + h.toString('hex'));
                            sendAgentMessage('Self Update FAILED because the downloaded agent FAILED hash check (' + agentUpdate_Start._retryCount + '), URL: ' + updateurl, 3);
                            agentUpdate_Start._selfupdate = null;

                            if (agentUpdate_Start._retryCount < 4) {
                                // Retry the download again
                                sendConsoleText('Self Update will try again in 60 seconds...', sessionid);
                                agentUpdate_Start._timeout = setTimeout(agentUpdate_Start, 60000, updateurl, updateoptions);
                            }
                            else {
                                sendConsoleText('Self Update giving up, too many failures...', sessionid);
                                sendAgentMessage('Self Update giving up, too many failures...', 3);
                            }
                            return;
                        }
                    }
                    else {
                        sendConsoleText('Download complete. HASH=' + h.toString('hex'), sessionid);
                    }

                    // Send an indication to the server that we got the update download correctly.
                    try { require('MeshAgent').SendCommand({ action: 'agentupdatedownloaded' }); } catch (ex) { }

                    if (sessionid != null) { sendConsoleText('Updating and restarting agent...', sessionid); }
                    if (process.platform == 'win32') {
                        // Use _wexecve() equivalent to perform the update
                        windows_execve(name, agentfilename, sessionid);
                    }
                    else {
                        var m = require('fs').statSync(process.execPath).mode;
                        require('fs').chmodSync(process.cwd() + agentfilename + '.update', m);

                        // remove binary
                        require('fs').unlinkSync(process.execPath);

                        // copy update
                        require('fs').copyFileSync(process.cwd() + agentfilename + '.update', process.execPath);
                        require('fs').chmodSync(process.execPath, m);

                        // erase update
                        require('fs').unlinkSync(process.cwd() + agentfilename + '.update');

                        switch (process.platform) {
                            case 'freebsd':
                                bsd_execv(name, agentfilename, sessionid);
                                break;
                            case 'linux':
                                linux_execv(name, agentfilename, sessionid);
                                break;
                            default:
                                try {
                                    // restart service
                                    var s = require('service-manager').manager.getService(name);
                                    s.restart();
                                }
                                catch (ex) {
                                    sendConsoleText('Self Update encountered an error trying to restart service', sessionid);
                                    sendAgentMessage('Self Update encountered an error trying to restart service', 3);
                                }
                                break;
                        }
                    }
                });
                img.pipe(this._file);
                img.pipe(this._filehash);
            });
        }
    }
}




// Called before the process exits
//process.exit = function (code) { console.log("Exit with code: " + code.toString()); }

// Called when the server connection state changes
function handleServerConnection(state) {
    meshServerConnectionState = state;
    if (meshServerConnectionState == 0) {
        // Server disconnected
        if (selfInfoUpdateTimer != null) { clearInterval(selfInfoUpdateTimer); selfInfoUpdateTimer = null; }
        lastSelfInfo = null;
    } else {
        // Server connected, send mesh core information
        if (require('MeshAgent').ServerInfo == null || require('MeshAgent').ServerInfo.ControlChannelCertificate == null) {
            // Outdated Agent, will have insecure tunnels
            sendAgentMessage("This agent has an outdated certificate validation mechanism, consider updating.", 3, 118);
        }
        else if (global._MSH == null) {
            sendAgentMessage("This is an old agent version, consider updating.", 3, 117);
        }

        // Send SMBios tables if present
        if (SMBiosTablesRaw != null) { mesh.SendCommand({ action: 'smbios', value: SMBiosTablesRaw }); }

        // Update the server on with basic info, logged in users and more advanced stuff, like Intel ME and Network Settings
        meInfoStr = null;
        LastPeriodicServerUpdate = null;
        sendPeriodicServerUpdate(null, true);
        if (selfInfoUpdateTimer == null) {
            selfInfoUpdateTimer = setInterval(sendPeriodicServerUpdate, 300000); // 5 minutes
            selfInfoUpdateTimer.metadata = 'meshcore (InfoUpdate Timer)';
        }

        // Send any state messages
        if (Object.keys(tunnelUserCount.msg).length > 0) {
            sendAgentMessage();
            broadcastSessionsToRegisteredApps();
        }

        // Send update of registered applications to the server
        updateRegisteredAppsToServer();
    }

    // Send server state update to registered applications
    broadcastToRegisteredApps({ cmd: 'serverstate', value: meshServerConnectionState, url: require('MeshAgent').ConnectedServer });
}

function getProbableMainLanIp() {
    if (process.platform != 'win32') return null;

    function str(v) {
        if (v == null) return '';
        try { return String(v); } catch (ex) { return ''; }
    }

    function intVal(v, d) {
        var x;
        try { x = parseInt(str(v)); } catch (ex) { x = NaN; }
        if (isNaN(x)) return d;
        return x;
    }

    function isIPv4(ip) {
        var p, i, n;

        ip = str(ip);
        if (ip == '') return false;
        if (ip == '0.0.0.0') return false;
        if (ip.indexOf(':') >= 0) return false;
        if (ip.indexOf('169.254.') == 0) return false;
        if (ip.indexOf('127.') == 0) return false;

        p = ip.split('.');
        if (p.length != 4) return false;

        for (i = 0; i < 4; i++) {
            if (p[i] == '') return false;
            n = parseInt(p[i]);
            if (isNaN(n)) return false;
            if ((n < 0) || (n > 255)) return false;
        }

        return true;
    }

    function hasAnyValue(v) {
        var i;

        if (v == null) return false;

        if (typeof v == 'string') {
            return (v != '');
        }

        if (typeof v == 'number') {
            return true;
        }

        // Duktape/WMI may expose arrays or array-like objects.
        try {
            if (v.length != null) {
                for (i = 0; i < v.length; i++) {
                    if (str(v[i]) != '') return true;
                }
                return false;
            }
        } catch (ex) { }

        return (str(v) != '');
    }

    function firstIPv4(v) {
        var i, s;

        if (v == null) return null;

        if (typeof v == 'string') {
            return isIPv4(v) ? v : null;
        }

        try {
            if (v.length != null) {
                for (i = 0; i < v.length; i++) {
                    s = str(v[i]);
                    if (isIPv4(s)) return s;
                }
            }
        } catch (ex) { }

        s = str(v);
        if (isIPv4(s)) return s;

        return null;
    }

    function isUpAdapter(a) {
        var op, media;

        if (a == null) return true;

        // InterfaceOperationalStatus commonly has 1 = Up.
        // But do not hard-fail unknown values; WMI support varies.
        op = intVal(a.InterfaceOperationalStatus, -1);
        if ((op != -1) && (op != 1)) return false;

        // MediaConnectState commonly has 1 = Connected.
        media = intVal(a.MediaConnectState, -1);
        if ((media != -1) && (media != 1)) return false;

        return true;
    }

    function adapterPriority(a) {
        var pm, medium, link, hardware, connector;

        if (a == null) return 20;

        pm = intVal(a.NdisPhysicalMedium, -1);
        medium = intVal(a.NdisMedium, -1);
        link = intVal(a.LinkTechnology, -1);

        hardware = (str(a.HardwareInterface).toLowerCase() == 'true');
        connector = (str(a.ConnectorPresent).toLowerCase() == 'true');

        /*
            MSFT_NetAdapter is documented in ROOT\StandardCimv2.
            Useful physical media values include:
              14 = 802.3 / Ethernet
               1 = Wireless LAN
               9 = Native 802.11

            These numeric values avoid matching adapter names such as
            "Wi-Fi", "WLAN", or "Wireless".
        */

        if (pm == 14) return 0;                         // wired Ethernet
        if ((medium == 0) && connector) return 1;       // 802.3-style fallback
        if ((link == 2) && hardware) return 2;          // Ethernet-ish fallback

        if ((pm == 1) || (pm == 9)) return 10;          // Wi-Fi / WLAN
        if (link == 11) return 11;                      // wireless fallback

        return 20;                                      // VPN, virtual, tunnel, unknown
    }

    try {
        var wmi = require('win-wmi-fixed');
        var configs;
        var adapters;
        var adapterByIndex = {};
        var candidates = [];
        var i, cfg, a, ip, gw, idx, metric;

        configs = wmi.query(
            'ROOT\\CIMV2',
            'SELECT InterfaceIndex,IPAddress,DefaultIPGateway,IPConnectionMetric FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled = True',
            ['InterfaceIndex', 'IPAddress', 'DefaultIPGateway', 'IPConnectionMetric']
        );

        if ((configs == null) || (configs.length == null) || (configs.length == 0)) {
            return null;
        }

        try {
            adapters = wmi.query(
                'ROOT\\StandardCimv2',
                'SELECT InterfaceIndex,NdisPhysicalMedium,NdisMedium,LinkTechnology,HardwareInterface,ConnectorPresent,InterfaceOperationalStatus,MediaConnectState FROM MSFT_NetAdapter',
                ['InterfaceIndex', 'NdisPhysicalMedium', 'NdisMedium', 'LinkTechnology', 'HardwareInterface', 'ConnectorPresent', 'InterfaceOperationalStatus', 'MediaConnectState']
            );

            if ((adapters != null) && (adapters.length != null)) {
                for (i = 0; i < adapters.length; i++) {
                    idx = intVal(adapters[i].InterfaceIndex, -1);
                    if (idx >= 0) adapterByIndex['i' + idx] = adapters[i];
                }
            }
        } catch (ex2) {
            adapters = null;
        }

        for (i = 0; i < configs.length; i++) {
            cfg = configs[i];

            gw = cfg.DefaultIPGateway;
            if (!hasAnyValue(gw)) continue;

            ip = firstIPv4(cfg.IPAddress);
            if (ip == null) continue;

            idx = intVal(cfg.InterfaceIndex, -1);
            a = adapterByIndex['i' + idx];

            if (!isUpAdapter(a)) continue;

            metric = intVal(cfg.IPConnectionMetric, 999999);

            candidates[candidates.length] = {
                ip: ip,
                idx: idx,
                pri: adapterPriority(a),
                metric: metric
            };
        }

        if (candidates.length == 0) return null;

        candidates.sort(function (x, y) {
            if (x.pri != y.pri) return x.pri - y.pri;
            if (x.metric != y.metric) return x.metric - y.metric;
            return x.idx - y.idx;
        });

        return candidates[0].ip;
    } catch (ex) {
        return null;
    }
}

// Update the server with the latest network interface information
var sendNetworkUpdateNagleTimer = null;
function sendNetworkUpdateNagle() { if (sendNetworkUpdateNagleTimer != null) { clearTimeout(sendNetworkUpdateNagleTimer); sendNetworkUpdateNagleTimer = null; } sendNetworkUpdateNagleTimer = setTimeout(sendNetworkUpdate, 5000); }
function sendNetworkUpdate(force) {
    sendNetworkUpdateNagleTimer = null;

    try {
        // Update the network interfaces information data
        var netInfo = { netif2: require('os').networkInterfaces() };
        if (process.platform == 'win32') {
            try {
                var ret = require('win-wmi-fixed').query('ROOT\\CIMV2', 'SELECT InterfaceIndex,NetConnectionID,Speed FROM Win32_NetworkAdapter', ['InterfaceIndex','NetConnectionID','Speed']);
                if (ret[0]) {
                    var speedMap = {};
                    for (var i = 0; i < ret.length; i++) speedMap[ret[i].InterfaceIndex] = ret[i].Speed;
                    var adapterNames = Object.keys(netInfo.netif2);
                    for (var j = 0; j < adapterNames.length; j++) {
                        var interfaces = netInfo.netif2[adapterNames[j]];
                        for (var k = 0; k < interfaces.length; k++) {
                            var iface = interfaces[k], speed = speedMap[iface.index] || 0;
                            iface.speed = parseInt(speed); // bits per seconds
                        }
                    }
                }
            } catch(ex) { }
            
			try {
                var probableMainLanIp = getProbableMainLanIp();
                if (probableMainLanIp != null) {
                    netInfo.probable_main_lan_ip = probableMainLanIp;
                }
            } catch (ex) { }
        } else if (process.platform == 'linux') {
            var adapterNames = Object.keys(netInfo.netif2);
            for (var i = 0; i < adapterNames.length; i++) {
                var ifaceName = adapterNames[i];
                try {
                    var speedStr = require('fs').readFileSync('/sys/class/net/' + ifaceName + '/speed').toString();
                    if ((speedStr.trim() != "") && (speedStr.trim() != "-1")) {
                        var theinterfaces = netInfo.netif2[ifaceName];
                        for (var k = 0; k < theinterfaces.length; k++) {
                            var iface = theinterfaces[k];
                            iface.speed = parseInt(speedStr) * 1000000; // bits per seconds
                        }
                    }
                } catch(ex) { }
            }
        }
        if (netInfo.netif2) {
            netInfo.action = 'netinfo';
            var netInfoStr = JSON.stringify(netInfo);
            if ((force == true) || (clearGatewayMac(netInfoStr) != clearGatewayMac(lastNetworkInfo))) { mesh.SendCommand(netInfo); lastNetworkInfo = netInfoStr; }
        }
    } catch (ex) { }
}

// Called periodically to check if we need to send updates to the server
var sendPeriodicServerUpdateInProgress = false;
function sendPeriodicServerUpdate(flags, force) {
    if (meshServerConnectionState == 0) return; // Not connected to server, do nothing.

    // Defensive guard against re-entrancy. The info collectors below are currently
    // non-blocking (Linux av()/firewall() are async; Windows uses native WMI), so
    // nothing here pumps the event loop and this guard never actually fires. It's
    // kept as a safety net: if a future collector re-introduces a blocking
    // child.waitExit() (which runs a nested event loop), a timer firing inside it
    // could re-enter and throw 'waitExit() already in progress'. Skipping the
    // overlapping run avoids that.
    if (sendPeriodicServerUpdateInProgress) return;
    sendPeriodicServerUpdateInProgress = true;
    try {
        if (!flags) { flags = 0xFFFFFFFF; }
        if (!force) { force = false; }

        // If we have a connected MEI, get Intel ME information
        if ((flags & 1) && (amt != null) && (amt.state == 2)) {
            delete meshCoreObj.intelamt;
            amt.getMeiState(9, function (meinfo) {
                meshCoreObj.intelamt = meinfo;
                meshCoreObj.intelamt.microlms = amt.lmsstate;
                meshCoreObjChanged();
            });
        }

        // Update network information
        if (flags & 2) { sendNetworkUpdateNagle(false); }

        // Update anti-virus information
        if ((flags & 4) && (process.platform == 'win32')) {
            // Windows Command: "wmic /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct get /FORMAT:CSV"
            try { meshCoreObj.av = require('win-info').av(); meshCoreObjChanged(); } catch (ex) { av = null; } // Antivirus
        }
        // Update Linux AV/Firewall information. av()/firewall() are asynchronous (they
        // spawn child processes), so they don't block this periodic update with a nested
        // waitExit() loop. Results are applied in the callbacks and flushed via
        // meshCoreObjChanged().
        if ((flags & 4) && (process.platform == 'linux')) {
            try {
                require('linux-info').av(function (avResult) {
                    try {
                        var lsc = {};
                        if (avResult && avResult.length > 0) { meshCoreObj.av = avResult; lsc.antiVirus = 'OK'; }
                        require('linux-info').firewall(function (fwResult) {
                            try {
                                if (fwResult && fwResult.installed) { lsc.firewall = fwResult.enabled ? 'OK' : 'BAD'; }
                                if (Object.keys(lsc).length > 0) { meshCoreObj.lsc = lsc; meshCoreObjChanged(); }
                            } catch (ex) { }
                        });
                    } catch (ex) { }
                });
            } catch (ex) { }
        }

        if (process.platform == 'win32') {
            if (require('MeshAgent')._securitycenter == null) {
                try {
                    require('MeshAgent')._securitycenter = require('win-securitycenter').status();
                    meshCoreObj['wsc'] = require('MeshAgent')._securitycenter; // Windows Security Central (WSC)
                    require('win-securitycenter').on('changed', function () {
                        require('MeshAgent')._securitycenter = require('win-securitycenter').status();
                        meshCoreObj['wsc'] = require('MeshAgent')._securitycenter; // Windows Security Central (WSC)
                        require('MeshAgent').SendCommand({ action: 'coreinfo', wsc: require('MeshAgent')._securitycenter });
                    });
                } catch (ex) { }
            }

            // Pending reboot
            try {
                meshCoreObj.pr = require('win-info').pendingReboot();
                meshCoreObjChanged();
            } catch (ex) { }


            // Get Defender Information
            try {
                meshCoreObj.defender = require('win-info').defender();
                meshCoreObjChanged();
            } catch (ex) { }

            // Calculate Windows Idle Time
            try {
                require('win-deskutils').idle.getSecondsAllSessions().then(function (seconds) {
                    meshCoreObj.idletime = seconds;
                    meshCoreObjChanged();
                });
            } catch (ex) { sendConsoleText('Error getting idle time: ' + ex.toString());}
        }

        // Send available data right now
        if (force) {
            meshCoreObj = sortObjRec(meshCoreObj);
            var x = JSON.stringify(meshCoreObj);
            if (x != LastPeriodicServerUpdate) {
                LastPeriodicServerUpdate = x;
                mesh.SendCommand(meshCoreObj);
            }
        }
    } finally { sendPeriodicServerUpdateInProgress = false; }
}

// Sort the names in an object
function sortObject(obj) { return Object.keys(obj).sort().reduce(function(a, v) { a[v] = obj[v]; return a; }, {}); }

// Fix the incoming data and cut down how much data we use
function cleanGetBitLockerVolumeInfo(volumes) {
    // Keep the raw codes info and let the view convert to strings
    for (var i in volumes) {
        const v = volumes[i];
        if (typeof v.size == 'string') { v.size = parseInt(v.size); }
        if (typeof v.sizeremaining == 'string') { v.sizeremaining = parseInt(v.sizeremaining); }
        if (v.identifier == '') { delete v.identifier; }
        if (v.name == '') { delete v.name; }
        if (v.recoveryPassword == '') { delete v.recoveryPassword; }
        if (v.volumeStatus === 0) { delete v.volumeStatus; }
        if (v.encryptionMethod === 0) { delete v.encryptionMethod; }
        if (v.protectionStatus === 0) { delete v.protectionStatus; }
    }
    return sortObject(volumes);
}

// Once we are done collecting all the data, send to server if needed
var LastPeriodicServerUpdate = null;
var PeriodicServerUpdateNagleTimer = null;
function meshCoreObjChanged() {
    if (PeriodicServerUpdateNagleTimer == null) {
        PeriodicServerUpdateNagleTimer = setTimeout(meshCoreObjChangedEx, 500);
    }
}
function meshCoreObjChangedEx() {
    PeriodicServerUpdateNagleTimer = null;
    meshCoreObj = sortObjRec(meshCoreObj);
    var x = JSON.stringify(meshCoreObj);
    if (x != LastPeriodicServerUpdate) {
        try { LastPeriodicServerUpdate = x; mesh.SendCommand(meshCoreObj); } catch (ex) { }
    }
}

function sortObjRec(o) { if ((typeof o != 'object') || (Array.isArray(o))) return o; for (var i in o) { if (typeof o[i] == 'object') { o[i] = sortObjRec(o[i]); } } return sortObj(o); }
function sortObj(o) { return Object.keys(o).sort().reduce(function (result, key) { result[key] = o[key]; return result; }, {}); }

function onWebSocketClosed() { sendConsoleText("WebSocket #" + this.httprequest.index + " closed.", this.httprequest.sessionid); delete consoleWebSockets[this.httprequest.index]; }
function onWebSocketData(data) { sendConsoleText("Got WebSocket #" + this.httprequest.index + " data: " + data, this.httprequest.sessionid); }
function onWebSocketSendOk() { sendConsoleText("WebSocket #" + this.index + " SendOK.", this.sessionid); }

function onWebSocketUpgrade(response, s, head) {
    sendConsoleText("WebSocket #" + this.index + " connected.", this.sessionid);
    this.s = s;
    s.httprequest = this;
    s.end = onWebSocketClosed;
    s.data = onWebSocketData;
}

mesh.AddCommandHandler(handleServerCommand);
mesh.AddConnectHandler(handleServerConnection);
