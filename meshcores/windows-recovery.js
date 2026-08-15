var addedModules = [];
try { addModule("win-console", "/*\r\nCopyright 2018-2021 Intel Corporation\r\n\r\nLicensed under the Apache License, Version 2.0 (the \"License\");\r\nyou may not use this file except in compliance with the License.\r\nYou may obtain a copy of the License at\r\n\r\n    http://www.apache.org/licenses/LICENSE-2.0\r\n\r\nUnless required by applicable law or agreed to in writing, software\r\ndistributed under the License is distributed on an \"AS IS\" BASIS,\r\nWITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.\r\nSee the License for the specific language governing permissions and\r\nlimitations under the License.\r\n*/\r\n\r\nvar TrayIconFlags =\r\n    {\r\n        NIF_MESSAGE: 0x00000001,\r\n        NIF_ICON: 0x00000002,\r\n        NIF_TIP: 0x00000004,\r\n        NIF_STATE: 0x00000008,\r\n        NIF_INFO: 0x00000010,\r\n        NIF_GUID: 0x00000020,\r\n        NIF_REALTIME: 0x00000040,\r\n        NIF_SHOWTIP: 0x00000080,\r\n\r\n        NIM_ADD: 0x00000000,\r\n        NIM_MODIFY: 0x00000001,\r\n        NIM_DELETE: 0x00000002,\r\n        NIM_SETFOCUS: 0x00000003,\r\n        NIM_SETVERSION: 0x00000004\r\n    };\r\nvar NOTIFYICON_VERSION_4 = 4;\r\nvar MessageTypes = { WM_APP: 0x8000, WM_USER: 0x0400 };\r\nfunction WindowsConsole()\r\n{\r\n    if (process.platform == \'win32\')\r\n    {\r\n        this._ObjectID = \'win-console\';\r\n        this._Marshal = require(\'_GenericMarshal\');\r\n        this._kernel32 = this._Marshal.CreateNativeProxy(\"kernel32.dll\");\r\n        this._user32 = this._Marshal.CreateNativeProxy(\"user32.dll\");\r\n        this._kernel32.CreateMethod(\"GetConsoleWindow\");\r\n        this._kernel32.CreateMethod(\'GetCurrentThread\');\r\n        this._user32.CreateMethod(\"ShowWindow\");\r\n        this._user32.CreateMethod(\"LoadImageA\");\r\n        this._user32.CreateMethod({ method: \'GetMessageA\', threadDispatch: 1 });\r\n        this._shell32 = this._Marshal.CreateNativeProxy(\'Shell32.dll\');\r\n        this._shell32.CreateMethod(\'Shell_NotifyIconA\');\r\n\r\n        this._handle = this._kernel32.GetConsoleWindow();\r\n        this.minimize = function () {\r\n            this._user32.ShowWindow(this._handle, 6);\r\n        };\r\n        this.restore = function () {\r\n            this._user32.ShowWindow(this._handle, 9);\r\n        };\r\n        this.hide = function () {\r\n            this._user32.ShowWindow(this._handle, 0);\r\n        };\r\n        this.show = function () {\r\n            this._user32.ShowWindow(this._handle, 5);\r\n        };\r\n\r\n\r\n        this._loadicon = function (imagePath) {\r\n            var h = this._user32.LoadImageA(0, this._Marshal.CreateVariable(imagePath), 1, 0, 0, 0x00000010 | 0x00008000 | 0x00000040); // LR_LOADFROMFILE | LR_SHARED | LR_DEFAULTSIZE\r\n            return (h);\r\n        };\r\n\r\n        this.SetTrayIcon = function SetTrayIcon(options)\r\n        {\r\n            var data = this._Marshal.CreateVariable(this._Marshal.PointerSize == 4 ? 508 : 528);\r\n            //console.log(\'struct size = \' + data._size);\r\n            //console.log(\'TryIcon, WM_MESSAGE filter = \' + options.filter);\r\n            data.toBuffer().writeUInt32LE(data._size, 0);\r\n\r\n            var trayType = TrayIconFlags.NIF_TIP | TrayIconFlags.NIF_MESSAGE\r\n            options.filter = MessageTypes.WM_APP + 1;\r\n            data.Deref(this._Marshal.PointerSize == 4 ? 16 : 24, 4).toBuffer().writeUInt32LE(options.filter);\r\n\r\n            if (!options.noBalloon) { trayType |= TrayIconFlags.NIF_INFO; }\r\n\r\n            if (options.icon)\r\n            {                \r\n                trayType |= TrayIconFlags.NIF_ICON;\r\n                var hIcon = data.Deref(this._Marshal.PointerSize == 4 ? 20 : 32, this._Marshal.PointerSize);\r\n                options.icon.pointerBuffer().copy(hIcon.toBuffer());\r\n            }\r\n\r\n            data.Deref(this._Marshal.PointerSize * 2, 4).toBuffer().writeUInt32LE(1);\r\n            data.Deref(this._Marshal.PointerSize == 4 ? 12 : 20, 4).toBuffer().writeUInt32LE(trayType);\r\n            data.Deref(this._Marshal.PointerSize == 4 ? 416 : 432, 4).toBuffer().writeUInt32LE(NOTIFYICON_VERSION_4);\r\n\r\n            var szTip = data.Deref(this._Marshal.PointerSize == 4 ? 24 : 40, 128);\r\n            var szInfo = data.Deref(this._Marshal.PointerSize == 4 ? 160 : 176, 256);\r\n            var szInfoTitle = data.Deref(this._Marshal.PointerSize == 4 ? 420 : 436, 64);\r\n\r\n            if (options.szTip) { Buffer.from(options.szTip).copy(szTip.toBuffer()); }\r\n            if (options.szInfo) { Buffer.from(options.szInfo).copy(szInfo.toBuffer()); }\r\n            if (options.szInfoTitle) { Buffer.from(options.szInfoTitle).copy(szInfoTitle.toBuffer()); }\r\n\r\n\r\n            var MessagePump = require(\'win-message-pump\');\r\n            retVal = { _ObjectID: \'WindowsConsole.TrayIcon\', MessagePump: new MessagePump(options) };\r\n            var retValEvents = require(\'events\').inherits(retVal);\r\n            retValEvents.createEvent(\'ToastClicked\');\r\n            retValEvents.createEvent(\'IconHover\');\r\n            retValEvents.createEvent(\'ToastDismissed\');\r\n            retVal.Options = options;\r\n            retVal.MessagePump.TrayIcon = retVal;\r\n            retVal.MessagePump.NotifyData = data;\r\n            retVal.MessagePump.WindowsConsole = this;\r\n            retVal.MessagePump.on(\'exit\', function onExit(code) { console.log(\'Pump Exited\'); if (this.TrayIcon) { this.TrayIcon.remove(); } });\r\n            retVal.MessagePump.on(\'hwnd\', function onHwnd(h)\r\n            {\r\n                //console.log(\'Got HWND\');\r\n                options.hwnd = h;\r\n                h.pointerBuffer().copy(this.NotifyData.Deref(this.WindowsConsole._Marshal.PointerSize, this.WindowsConsole._Marshal.PointerSize).toBuffer());\r\n\r\n                if(this.WindowsConsole._shell32.Shell_NotifyIconA(TrayIconFlags.NIM_ADD, this.NotifyData).Val == 0)\r\n                {\r\n                    // Something went wrong\r\n                }\r\n            });\r\n            retVal.MessagePump.on(\'message\', function onWindowsMessage(msg)\r\n            {\r\n                if(msg.message == this.TrayIcon.Options.filter)\r\n                {\r\n                    var handled = false;\r\n                    if (msg.wparam == 1 && msg.lparam == 1029)\r\n                    {\r\n                        this.TrayIcon.emit(\'ToastClicked\');\r\n                        handled = true;\r\n                    }\r\n                    if (msg.wparam == 1 && msg.lparam == 512)\r\n                    {\r\n                        this.TrayIcon.emit(\'IconHover\');\r\n                        handled = true;\r\n                    }\r\n                    if (this.TrayIcon.Options.balloonOnly && msg.wparam == 1 && (msg.lparam == 1028 || msg.lparam == 1029))\r\n                    {\r\n                        this.TrayIcon.emit(\'ToastDismissed\');\r\n                        this.TrayIcon.remove();\r\n                        handled = true;\r\n                    }\r\n                }\r\n            });\r\n            retVal.remove = function remove()\r\n            {\r\n                this.MessagePump.WindowsConsole._shell32.Shell_NotifyIconA(TrayIconFlags.NIM_DELETE, this.MessagePump.NotifyData);\r\n                this.MessagePump.stop();\r\n                delete this.MessagePump.TrayIcon;\r\n                delete this.MessagePump;\r\n            };\r\n            return (retVal);\r\n            \r\n        };\r\n    }\r\n}\r\n\r\nmodule.exports = new WindowsConsole();"); addedModules.push("win-console"); } catch (ex) { }
try { addModule("win-terminal", "/*\r\nCopyright 2018-2022 Intel Corporation\r\n\r\nLicensed under the Apache License, Version 2.0 (the \"License\");\r\nyou may not use this file except in compliance with the License.\r\nYou may obtain a copy of the License at\r\n\r\n    http://www.apache.org/licenses/LICENSE-2.0\r\n\r\nUnless required by applicable law or agreed to in writing, software\r\ndistributed under the License is distributed on an \"AS IS\" BASIS,\r\nWITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.\r\nSee the License for the specific language governing permissions and\r\nlimitations under the License.\r\n*/\r\n\r\nvar promise = require(\'promise\');\r\nvar duplex = require(\'stream\').Duplex;\r\n\r\nvar SW_HIDE = 0;\r\nvar SW_MINIMIZE = 6;\r\nvar STARTF_USESHOWWINDOW = 0x1;\r\nvar STD_INPUT_HANDLE = -10;\r\nvar STD_OUTPUT_HANDLE = -11;\r\nvar EVENT_CONSOLE_CARET = 0x4001;\r\nvar EVENT_CONSOLE_END_APPLICATION = 0x4007;\r\nvar WINEVENT_OUTOFCONTEXT = 0x000;\r\nvar WINEVENT_SKIPOWNPROCESS = 0x0002;\r\nvar CREATE_NEW_PROCESS_GROUP = 0x200;\r\nvar EVENT_CONSOLE_UPDATE_REGION = 0x4002;\r\nvar EVENT_CONSOLE_UPDATE_SIMPLE = 0x4003;\r\nvar EVENT_CONSOLE_UPDATE_SCROLL = 0x4004;\r\nvar EVENT_CONSOLE_LAYOUT = 0x4005;\r\nvar EVENT_CONSOLE_START_APPLICATION = 0x4006;\r\nvar KEY_EVENT = 0x1;\r\nvar MAPVK_VK_TO_VSC = 0;\r\nvar WM_QUIT = 0x12;\r\n\r\nvar GM = require(\'_GenericMarshal\');\r\nvar si = GM.CreateVariable(GM.PointerSize == 4 ? 68 : 104);\r\nvar pi = GM.CreateVariable(GM.PointerSize == 4 ? 16 : 24);\r\n\r\nsi.Deref(0, 4).toBuffer().writeUInt32LE(GM.PointerSize == 4 ? 68 : 104);                    // si.cb\r\nsi.Deref(GM.PointerSize == 4 ? 48 : 64, 2).toBuffer().writeUInt16LE(SW_HIDE | SW_MINIMIZE); // si.wShowWindow\r\nsi.Deref(GM.PointerSize == 4 ? 44 : 60, 4).toBuffer().writeUInt32LE(STARTF_USESHOWWINDOW);  // si.dwFlags;\r\n\r\nvar MSG = GM.CreateVariable(GM.PointerSize == 4 ? 28 : 48);\r\n\r\nfunction windows_terminal() {\r\n    this._ObjectID = \'windows_terminal\';\r\n    this._user32 = GM.CreateNativeProxy(\'User32.dll\');\r\n    this._user32.CreateMethod(\'DispatchMessageA\');\r\n    this._user32.CreateMethod(\'GetMessageA\');\r\n    this._user32.CreateMethod(\'MapVirtualKeyA\');\r\n    this._user32.CreateMethod(\'PostThreadMessageA\');\r\n    this._user32.CreateMethod(\'SetWinEventHook\');\r\n    this._user32.CreateMethod(\'ShowWindow\');\r\n    this._user32.CreateMethod(\'TranslateMessage\');\r\n    this._user32.CreateMethod(\'UnhookWinEvent\');\r\n    this._user32.CreateMethod(\'VkKeyScanA\');\r\n    this._user32.terminal = this;\r\n    \r\n    this._kernel32 = GM.CreateNativeProxy(\'Kernel32.dll\');\r\n    this._kernel32.CreateMethod(\'AllocConsole\');\r\n    this._kernel32.CreateMethod(\'CreateProcessA\');\r\n    this._kernel32.CreateMethod(\'CloseHandle\');\r\n    this._kernel32.CreateMethod(\'FillConsoleOutputAttribute\');\r\n    this._kernel32.CreateMethod(\'FillConsoleOutputCharacterA\');\r\n    this._kernel32.CreateMethod(\'GetConsoleScreenBufferInfo\');\r\n    this._kernel32.CreateMethod(\'GetConsoleWindow\');\r\n    this._kernel32.CreateMethod(\'GetLastError\');\r\n    this._kernel32.CreateMethod(\'GetStdHandle\');\r\n    this._kernel32.CreateMethod(\'GetThreadId\');\r\n    this._kernel32.CreateMethod(\'ReadConsoleOutputA\');\r\n    this._kernel32.CreateMethod(\'SetConsoleCursorPosition\');\r\n    this._kernel32.CreateMethod(\'SetConsoleScreenBufferSize\');\r\n    this._kernel32.CreateMethod(\'SetConsoleWindowInfo\');\r\n    this._kernel32.CreateMethod(\'TerminateProcess\');\r\n    this._kernel32.CreateMethod(\'WaitForSingleObject\');\r\n    this._kernel32.CreateMethod(\'WriteConsoleInputA\');\r\n    \r\n    var currentX = 0;\r\n    var currentY = 0;\r\n    \r\n    this._scrx = 0;\r\n    this._scry = 0;\r\n    \r\n    this.SendCursorUpdate = function () {\r\n        var newCsbi = GM.CreateVariable(22);\r\n        \r\n        if (this._kernel32.GetConsoleScreenBufferInfo(this._stdoutput, newCsbi).Val == 0) { return; }\r\n        if (newCsbi.Deref(4, 2).toBuffer().readUInt16LE() != this.currentX || newCsbi.Deref(6, 2).toBuffer().readUInt16LE() != this.currentY)\r\n        {\r\n            //\r\n            // Reference for CONSOLE_SCREEN_BUFFER_INFO can be found at:\r\n            // https://learn.microsoft.com/en-us/windows/console/console-screen-buffer-info-str\r\n            //\r\n\r\n            this.currentX = newCsbi.Deref(4, 2).toBuffer().readUInt16LE();\r\n            this.currentY = newCsbi.Deref(6, 2).toBuffer().readUInt16LE();\r\n        }\r\n    }\r\n\r\n    this.ClearScreen = function ()\r\n    {\r\n        //\r\n        // Reference for CONSOLE_SCREEN_BUFFER_INFO can be found at:\r\n        // https://learn.microsoft.com/en-us/windows/console/console-screen-buffer-info-str\r\n        //\r\n\r\n        // \r\n        // Reference for GetConsoleScreenBufferInfo can be found at:\r\n        // https://learn.microsoft.com/en-us/windows/console/getconsolescreenbufferinfo\r\n        //\r\n\r\n        //\r\n        // Reference for FillConsoleOutputCharacter can be found at:\r\n        // https://learn.microsoft.com/en-us/windows/console/fillconsoleoutputcharacter\r\n        //\r\n\r\n        // \r\n        // Reference for FillConsoleOutputAttribute can be found at:\r\n        // https://learn.microsoft.com/en-us/windows/console/fillconsoleoutputattribute\r\n        //\r\n\r\n        //\r\n        // Reference for SetConsoleCursorPosition can be found at:\r\n        // https://learn.microsoft.com/en-us/windows/console/setconsolecursorposition\r\n        //\r\n\r\n        // \r\n        // Reference for SetConsoleWindowInfo can be fount at:\r\n        // https://learn.microsoft.com/en-us/windows/console/setconsolewindowinfo\r\n        //\r\n\r\n        var CONSOLE_SCREEN_BUFFER_INFO = GM.CreateVariable(22);\r\n        if (this._kernel32.GetConsoleScreenBufferInfo(this._stdoutput, CONSOLE_SCREEN_BUFFER_INFO).Val == 0) { return; }\r\n        \r\n        var coordScreen = GM.CreateVariable(4);\r\n        var dwConSize = CONSOLE_SCREEN_BUFFER_INFO.Deref(0, 2).toBuffer().readUInt16LE(0) * CONSOLE_SCREEN_BUFFER_INFO.Deref(2, 2).toBuffer().readUInt16LE(0);\r\n        var cCharsWritten = GM.CreateVariable(4);\r\n        \r\n        // Fill the entire screen with blanks.\r\n        if (this._kernel32.FillConsoleOutputCharacterA(this._stdoutput, 32, dwConSize, coordScreen.Deref(0, 4).toBuffer().readUInt32LE(), cCharsWritten).Val == 0) { return; }\r\n        \r\n        // Get the current text attribute.\r\n        if (this._kernel32.GetConsoleScreenBufferInfo(this._stdoutput, CONSOLE_SCREEN_BUFFER_INFO).Val == 0) { return; }\r\n        \r\n        // Set the buffer\'s attributes accordingly.\r\n        if (this._kernel32.FillConsoleOutputAttribute(this._stdoutput, CONSOLE_SCREEN_BUFFER_INFO.Deref(8, 2).toBuffer().readUInt16LE(0), dwConSize, coordScreen.Deref(0, 4).toBuffer().readUInt32LE(), cCharsWritten).Val == 0) { return; }\r\n        \r\n        // Put the cursor at its home coordinates.\r\n        this._kernel32.SetConsoleCursorPosition(this._stdoutput, coordScreen.Deref(0, 4).toBuffer().readUInt32LE());\r\n        \r\n        // Put the window to top-left.\r\n        var rect = GM.CreateVariable(8);\r\n        var srWindow = CONSOLE_SCREEN_BUFFER_INFO.Deref(10, 8).toBuffer();\r\n        rect.Deref(4, 2).toBuffer().writeUInt16LE(srWindow.readUInt16LE(4) - srWindow.readUInt16LE(0));\r\n        rect.Deref(6, 2).toBuffer().writeUInt16LE(srWindow.readUInt16LE(6) - srWindow.readUInt16LE(2));\r\n        \r\n        this._kernel32.SetConsoleWindowInfo(this._stdoutput, 1, rect);\r\n    }\r\n    \r\n    // This does a rudimentary check if the platform is capable of PowerShell\r\n    this.PowerShellCapable = function()\r\n    {\r\n        if (require(\'os\').arch() == \'x64\')\r\n        {\r\n            return (require(\'fs\').existsSync(process.env[\'windir\'] + \'\\\\SysWow64\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe\'));\r\n        }\r\n        else\r\n        {\r\n            return (require(\'fs\').existsSync(process.env[\'windir\'] + \'\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe\'));\r\n        }\r\n    }\r\n\r\n    // Starts a Legacy Windows Terminal Session\r\n    this.StartEx = function Start(CONSOLE_SCREEN_WIDTH, CONSOLE_SCREEN_HEIGHT, terminalTarget)\r\n    {\r\n        // The older windows terminal does not support \r\n        CONSOLE_SCREEN_WIDTH = 80;\r\n        CONSOLE_SCREEN_HEIGHT = 25;\r\n\r\n        if (this._stream != null)\r\n        {\r\n            throw (\'Concurrent terminal sessions are not supported on Windows.\');\r\n        }\r\n        this.stopping = null;\r\n        if (this._kernel32.GetConsoleWindow().Val == 0) {\r\n            if (this._kernel32.AllocConsole().Val == 0) {\r\n                throw (\'AllocConsole failed with: \' + this._kernel32.GetLastError().Val);\r\n            }\r\n        }\r\n        \r\n        this._stdinput = this._kernel32.GetStdHandle(STD_INPUT_HANDLE);\r\n        this._stdoutput = this._kernel32.GetStdHandle(STD_OUTPUT_HANDLE);\r\n        this._connected = false;\r\n\r\n        // Coord structure can be found at: https://learn.microsoft.com/en-us/windows/console/coord-str\r\n        var coordScreen = GM.CreateVariable(4); \r\n        coordScreen.Deref(0, 2).toBuffer().writeUInt16LE(CONSOLE_SCREEN_WIDTH);\r\n        coordScreen.Deref(2, 2).toBuffer().writeUInt16LE(CONSOLE_SCREEN_HEIGHT);\r\n        \r\n        var rect = GM.CreateVariable(8);\r\n        rect.Deref(4, 2).toBuffer().writeUInt16LE(CONSOLE_SCREEN_WIDTH - 1);\r\n        rect.Deref(6, 2).toBuffer().writeUInt16LE(CONSOLE_SCREEN_HEIGHT - 1);\r\n        \r\n        // \r\n        // Reference for SetConsoleWindowInfo can be found at:\r\n        // https://learn.microsoft.com/en-us/windows/console/setconsolewindowinfo\r\n        //\r\n        if (this._kernel32.SetConsoleWindowInfo(this._stdoutput, 1, rect).Val == 0)\r\n        {\r\n            throw (\'Failed to set Console Screen Size\');\r\n        }\r\n\r\n        //\r\n        // Reference for SetConsoleScreenBufferSize can be found at:\r\n        // https://learn.microsoft.com/en-us/windows/console/setconsolescreenbuffersize\r\n        //\r\n        if (this._kernel32.SetConsoleScreenBufferSize(this._stdoutput, coordScreen.Deref(0, 4).toBuffer().readUInt32LE()).Val == 0)\r\n        {\r\n            throw (\'Failed to set Console Buffer Size\');\r\n        }\r\n\r\n        // Hide the console window\r\n        this._user32.ShowWindow(this._kernel32.GetConsoleWindow().Val, SW_HIDE);\r\n\r\n        this.ClearScreen();\r\n        this._hookThread(terminalTarget).then(function ()\r\n        {\r\n            // Hook Ready\r\n            this.terminal.StartCommand(this.userArgs[0]);\r\n        }, console.log);\r\n        this._stream = new duplex(\r\n            {\r\n                \'write\': function (chunk, flush)\r\n                {\r\n                    if (!this.terminal.connected)\r\n                    {\r\n                        //console.log(\'_write: \' + chunk);\r\n                        if (!this._promise.chunk)\r\n                        {\r\n                            this._promise.chunk = [];\r\n                        }\r\n                        if (typeof (chunk) == \'string\')\r\n                        {\r\n                            this._promise.chunk.push(chunk);\r\n                        } else\r\n                        {\r\n                            this._promise.chunk.push(Buffer.alloc(chunk.length));\r\n                            chunk.copy(this._promise.chunk.peek());\r\n                        }\r\n                        this._promise.chunk.peek().flush = flush;\r\n                        this._promise.then(function ()\r\n                        {\r\n                            var buf;\r\n                            while (this.chunk.length > 0)\r\n                            {\r\n                                buf = this.chunk.shift();\r\n                                this.terminal._WriteBuffer(buf);\r\n                                buf.flush();\r\n                            }\r\n                        });\r\n                    }\r\n                    else\r\n                    {\r\n                        //console.log(\'writeNOW: \' + chunk);\r\n                        this.terminal._WriteBuffer(chunk);\r\n                        flush();\r\n                    }\r\n                    return (true);\r\n                },\r\n                \'final\': function (flush)\r\n                {\r\n                    var p = this.terminal._stop();\r\n                    p.__flush = flush;\r\n                    p.then(function () { this.__flush(); });\r\n                }\r\n            });\r\n        this._stream.terminal = this;\r\n        this._stream._promise = new promise(function (res, rej) { this._res = res; this._rej = rej; });\r\n        this._stream._promise.terminal = this;\r\n        this._stream.prependOnceListener(\'end\', function ()\r\n        {\r\n            this.terminal._stream = null;\r\n        });\r\n        return (this._stream);\r\n    };\r\n    this.Start = function Start(CONSOLE_SCREEN_WIDTH, CONSOLE_SCREEN_HEIGHT)\r\n    {\r\n        return (this.StartEx(CONSOLE_SCREEN_WIDTH, CONSOLE_SCREEN_HEIGHT, process.env[\'windir\'] + \'\\\\System32\\\\cmd.exe\'));\r\n    }\r\n    this.StartPowerShell = function StartPowerShell(CONSOLE_SCREEN_WIDTH, CONSOLE_SCREEN_HEIGHT)\r\n    {\r\n        if (require(\'os\').arch() == \'x64\')\r\n        {\r\n            if (require(\'fs\').existsSync(process.env[\'windir\'] + \'\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe\'))\r\n            {\r\n                return (this.StartEx(CONSOLE_SCREEN_WIDTH, CONSOLE_SCREEN_HEIGHT, process.env[\'windir\'] + \'\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe\'));\r\n            }\r\n            else\r\n            {\r\n                return (this.StartEx(CONSOLE_SCREEN_WIDTH, CONSOLE_SCREEN_HEIGHT, process.env[\'windir\'] + \'\\\\SysWow64\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe\'));\r\n            }\r\n        }\r\n        else\r\n        {\r\n            return (this.StartEx(CONSOLE_SCREEN_WIDTH, CONSOLE_SCREEN_HEIGHT, process.env[\'windir\'] + \'\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe\'));\r\n        }\r\n    }\r\n\r\n    this._stop = function () {\r\n        if (this.stopping) { return (this.stopping); }\r\n        //console.log(\'Stopping Terminal...\');\r\n        this._ConsoleWinEventProc.removeAllListeners(\'GlobalCallback\');\r\n        this.stopping = new promise(function (res, rej) { this._res = res; this._rej = rej; });\r\n        \r\n        var threadID = this._kernel32.GetThreadId(this._user32.SetWinEventHook.async.thread()).Val;\r\n        this._user32.PostThreadMessageA(threadID, WM_QUIT, 0, 0);\r\n        this._stream.emit(\'end\');\r\n        return (this.stopping);\r\n    }\r\n    \r\n    //\r\n    // This function uses the SetWinEventHook() method, so we can hook \r\n    // All events between EVENT_CONSOLE_CARET and EVENT_CONSOLE_END_APPLICATION\r\n    //\r\n    this._hookThread = function ()\r\n    {\r\n        // \r\n        // Reference for SetWinEventHook() can be found at:\r\n        // https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-setwineventhook\r\n        //\r\n        var ret = new promise(function (res, rej) { this._res = res; this._rej = rej; });\r\n        ret.userArgs = [];\r\n        for (var a in arguments)\r\n        {\r\n            ret.userArgs.push(arguments[a]);\r\n        }\r\n        ret.terminal = this;\r\n        this._ConsoleWinEventProc = GM.GetGenericGlobalCallback(7);\r\n        this._ConsoleWinEventProc.terminal = this;\r\n        var p = this._user32.SetWinEventHook.async(EVENT_CONSOLE_CARET, EVENT_CONSOLE_END_APPLICATION, 0, this._ConsoleWinEventProc, 0, 0, WINEVENT_OUTOFCONTEXT | WINEVENT_SKIPOWNPROCESS);\r\n        p.ready = ret;\r\n        p.terminal = this;\r\n        p.then(function (hwinEventHook)\r\n        {\r\n            if (hwinEventHook.Val == 0)\r\n            {\r\n                this.ready._rej(\'Error calling SetWinEventHook\');\r\n            } else\r\n            {\r\n                this.terminal.hwinEventHook = hwinEventHook;\r\n                this.ready._res();\r\n                this.terminal._GetMessage();\r\n            }\r\n        });\r\n\r\n        //\r\n        // This is the WINEVENTPROC callback for the WinEventHook we set\r\n        //\r\n        this._ConsoleWinEventProc.on(\'GlobalCallback\', function (hhook, dwEvent, hwnd, idObject, idChild, idEventThread, swmsEventTime)\r\n        {\r\n            //\r\n            // Reference for WINEVENTPROC can be found at:\r\n            // https://learn.microsoft.com/en-us/windows/win32/api/winuser/nc-winuser-wineventproc\r\n            //\r\n            if (!this.terminal.hwinEventHook || this.terminal.hwinEventHook.Val != hhook.Val) { return; }\r\n            var buffer = null;\r\n            \r\n            //\r\n            // Reference for Console WinEvents can be found at:\r\n            // https://learn.microsoft.com/en-us/windows/console/console-winevents\r\n            //\r\n\r\n            switch (dwEvent.Val)\r\n            {          \r\n                case EVENT_CONSOLE_CARET:\r\n                    // The console caret has moved\r\n                    break;\r\n                case EVENT_CONSOLE_UPDATE_REGION:\r\n                    // More than one character has changed\r\n                    if (!this.terminal.connected) {\r\n                        this.terminal.connected = true;\r\n                        this.terminal._stream._promise._res();\r\n                    }\r\n                    if (this.terminal._scrollTimer == null) {\r\n                        buffer = this.terminal._GetScreenBuffer(LOWORD(idObject.Val), HIWORD(idObject.Val), LOWORD(idChild.Val), HIWORD(idChild.Val));\r\n                        //console.log(\'UPDATE REGION: [Left: \' + LOWORD(idObject.Val) + \' Top: \' +  HIWORD(idObject.Val) + \' Right: \' + LOWORD(idChild.Val) + \' Bottom: \' + HIWORD(idChild.Val) + \']\');\r\n                        this.terminal._SendDataBuffer(buffer);\r\n                    }\r\n                    break;\r\n                case EVENT_CONSOLE_UPDATE_SIMPLE:\r\n                    // A single character has changed\r\n                    //console.log(\'UPDATE SIMPLE: [X: \' + LOWORD(idObject.Val) + \' Y: \' + HIWORD(idObject.Val) + \' Char: \' + LOWORD(idChild.Val) + \' Attr: \' + HIWORD(idChild.Val) + \']\');\r\n                    var simplebuffer = { data: [ Buffer.alloc(1, LOWORD(idChild.Val)) ], attributes: [ HIWORD(idChild.Val) ], width: 1, height: 1, x: LOWORD(idObject.Val), y: HIWORD(idObject.Val) };\r\n                    this.terminal._SendDataBuffer(simplebuffer);\r\n                    break;\r\n                case EVENT_CONSOLE_UPDATE_SCROLL:\r\n                    // The console has scrolled\r\n                    //console.log(\'UPDATE SCROLL: [dx: \' + idObject.Val + \' dy: \' + idChild.Val + \']\');\r\n                    this.terminal._SendScroll(idObject.Val, idChild.Val);\r\n                    break;\r\n                case EVENT_CONSOLE_LAYOUT:\r\n                    // The console layout has changed.\r\n                    //console.log(\'CONSOLE_LAYOUT\');\r\n                    //snprintf( Buf, 512, \"Event Console LAYOUT!\\r\\n\");\r\n                    //SendLayout();\r\n                    break;\r\n                case EVENT_CONSOLE_START_APPLICATION:\r\n                    // A new console process has started\r\n                    //console.log(\'START APPLICATION: [PID: \' + idObject.Val + \' CID: \' + idChild.Val + \']\');\r\n                    //snprintf( Buf, 512, \"Event Console START APPLICATION!\\r\\nProcess ID: %d  -  Child ID: %d\\r\\n\\r\\n\", (int)idObject, (int)idChild);\r\n                    //SendConsoleEvent(dwEvent, idObject, idChild);\r\n                    break;\r\n                case EVENT_CONSOLE_END_APPLICATION:\r\n                    // A console process has exited\r\n                    if (idObject.Val == this.terminal._hProcessID)\r\n                    {\r\n                        //console.log(\'END APPLICATION: [PID: \' + idObject.Val + \' CID: \' + idChild.Val + \']\');\r\n                        this.terminal._hProcess = null;\r\n                        this.terminal._stop().then(function () { console.log(\'STOPPED\'); });\r\n                    }\r\n                    break;\r\n                default:\r\n                    //snprintf(Buf, 512, \"unknown console event.\\r\\n\");\r\n                    console.log(\'Unknown event: \' + dwEvent.Val);\r\n                    break;\r\n            }\r\n\r\n            //mbstowcs_s(&l, wBuf, Buf, 512);\r\n            //OutputDebugString(wBuf);\r\n\r\n        });\r\n        return (ret);\r\n    }\r\n    \r\n    // Retrieves a message from the calling thread\'s message queue\r\n    this._GetMessage = function ()\r\n    {\r\n        //\r\n        // Reference for GetMessage() can be found at:\r\n        // https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getmessage\r\n        //\r\n\r\n        //\r\n        // Reference for TranslateMessage() can be found at:\r\n        // https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-translatemessage\r\n        //\r\n\r\n        //\r\n        // Reference for DispatchMessage() can be found at:\r\n        // https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-dispatchmessage\r\n        //\r\n\r\n        if (this._user32.abort) { console.log(\'aborting loop\'); return; }\r\n        this._user32.GetMessageA.async(this._user32.SetWinEventHook.async, MSG, 0, 0, 0).then(function (ret)\r\n        {\r\n            //console.log(\'GetMessage Response\');\r\n            if (ret.Val != 0)\r\n            {\r\n                if (ret.Val == -1)\r\n                {\r\n                    // handle the error and possibly exit\r\n                }\r\n                else\r\n                {\r\n                    // Translates virtual-key messages into character messages\r\n                    //console.log(\'TranslateMessage\');\r\n                    this.nativeProxy._user32.TranslateMessage.async(this.nativeProxy.user32.SetWinEventHook.async, MSG).then(function ()\r\n                    {\r\n                        // Dispatches a message to a window procedure\r\n                        //console.log(\'DispatchMessage\');\r\n                        this.nativeProxy._user32.DispatchMessageA.async(this.nativeProxy.user32.SetWinEventHook.async, MSG).then(function ()\r\n                        {\r\n                            this.nativeProxy.terminal._GetMessage();\r\n                        }, console.log);\r\n                    }, console.log);\r\n                }\r\n            } else\r\n            {\r\n                this.nativeProxy.UnhookWinEvent.async(this.nativeProxy.terminal._user32.SetWinEventHook.async, this.nativeProxy.terminal.hwinEventHook)\r\n                    .then(function ()\r\n                    {\r\n                        if (this.nativeProxy.terminal._hProcess == null) { return; }\r\n\r\n                        this.nativeProxy.terminal.stopping._res();\r\n                        if (this.nativeProxy.terminal._kernel32.TerminateProcess(this.nativeProxy.terminal._hProcess, 1067).Val == 0)\r\n                        {\r\n                            var e = this.nativeProxy.terminal._kernel32.GetLastError().Val;\r\n                            console.log(\'Unable to kill Terminal Process, error: \' + e);\r\n                        }\r\n                        this.nativeProxy.terminal.stopping = null;\r\n                    }, function (err)\r\n                    {\r\n                        console.log(\'REJECTED_UnhookWinEvent: \' + err);\r\n                    });\r\n            }\r\n        }, function (err)\r\n        {\r\n            // Get Message Failed\r\n            console.log(\'REJECTED_GETMessage: \' + err);\r\n        });\r\n    }\r\n\r\n    this._WriteBuffer = function (buf)\r\n    {\r\n        for (var i = 0; i < buf.length; ++i)\r\n        {\r\n            if (typeof (buf) == \'string\')\r\n            {\r\n                this._WriteCharacter(buf.charCodeAt(i), false);\r\n            } else\r\n            {\r\n                this._WriteCharacter(buf[i], false);\r\n            }\r\n        }\r\n    }\r\n    this._WriteCharacter = function (key, bControlKey)\r\n    {\r\n        //\r\n        // Reference for WriteConsoleInput() can be found at:\r\n        // https://learn.microsoft.com/en-us/windows/console/writeconsoleinput\r\n        //\r\n\r\n        //\r\n        // Reference for INPUT_RECORD can be found at:\r\n        // https://learn.microsoft.com/en-us/windows/console/input-record-str\r\n        //\r\n\r\n        var rec = GM.CreateVariable(20);\r\n        rec.Deref(0, 2).toBuffer().writeUInt16LE(KEY_EVENT);                                // rec.EventType \r\n        rec.Deref(4, 4).toBuffer().writeUInt16LE(1);                                        // rec.Event.KeyEvent.bKeyDown\r\n        rec.Deref(16, 4).toBuffer().writeUInt32LE(bControlKey);                             // rec.Event.KeyEvent.dwControlKeyState\r\n        rec.Deref(14, 1).toBuffer()[0] = key;                                               // rec.Event.KeyEvent.uChar.AsciiChar\r\n        rec.Deref(8, 2).toBuffer().writeUInt16LE(1);                                        // rec.Event.KeyEvent.wRepeatCount\r\n        rec.Deref(10, 2).toBuffer().writeUInt16LE(this._user32.VkKeyScanA(key).Val);        // rec.Event.KeyEvent.wVirtualKeyCode\r\n        rec.Deref(12, 2).toBuffer().writeUInt16LE(this._user32.MapVirtualKeyA(this._user32.VkKeyScanA(key).Val, MAPVK_VK_TO_VSC).Val);\r\n\r\n        var dwWritten = GM.CreateVariable(4);\r\n        if (this._kernel32.WriteConsoleInputA(this._stdinput, rec, 1, dwWritten).Val == 0) { return (false); }\r\n\r\n        rec.Deref(4, 4).toBuffer().writeUInt16LE(0);                                         // rec.Event.KeyEvent.bKeyDown\r\n        return (this._kernel32.WriteConsoleInputA(this._stdinput, rec, 1, dwWritten).Val != 0);\r\n    }\r\n    \r\n    // Get the current visible screen buffer\r\n    this._GetScreenBuffer = function (sx, sy, ex, ey)\r\n    {\r\n        //\r\n        // Reference for GetConsoleScreenBufferInfo() can be found at:\r\n        // https://learn.microsoft.com/en-us/windows/console/getconsolescreenbufferinfo\r\n        //\r\n\r\n        //\r\n        // Reference for ReadConsoleOutput() can be found at:\r\n        // https://learn.microsoft.com/en-us/windows/console/readconsoleoutput\r\n        //\r\n\r\n        var info = GM.CreateVariable(22);\r\n        if (this._kernel32.GetConsoleScreenBufferInfo(this._stdoutput, info).Val == 0) { throw (\'Error getting screen buffer info\'); }\r\n\r\n        var nWidth = info.Deref(14, 2).toBuffer().readUInt16LE() - info.Deref(10, 2).toBuffer().readUInt16LE() + 1;\r\n        var nHeight = info.Deref(16, 2).toBuffer().readUInt16LE() - info.Deref(12, 2).toBuffer().readUInt16LE() + 1;\r\n\r\n        if (arguments[3] == null)\r\n        {\r\n            // Use Default Parameters\r\n            sx = 0;\r\n            sy = 0;\r\n            ex = nWidth - 1;\r\n            ey = nHeight - 1;\r\n        } else\r\n        {\r\n            if (this._scrx != 0) { sx += this._scrx; ex += this._scrx; }\r\n            if (this._scry != 0) { sy += this._scry; ey += this._scry; }\r\n            this._scrx = this._scry = 0;\r\n        }\r\n\r\n        var nBuffer = GM.CreateVariable((ex - sx + 1) * (ey - sy + 1) * 4);\r\n        var size = GM.CreateVariable(4);\r\n        size.Deref(0, 2).toBuffer().writeUInt16LE(ex - sx + 1, 0);\r\n        size.Deref(2, 2).toBuffer().writeUInt16LE(ey - sy + 1, 0);\r\n\r\n        var startCoord = GM.CreateVariable(4);\r\n        startCoord.Deref(0, 2).toBuffer().writeUInt16LE(0, 0);\r\n        startCoord.Deref(2, 2).toBuffer().writeUInt16LE(0, 0);\r\n\r\n        var region = GM.CreateVariable(8);\r\n        region.buffer = region.toBuffer();\r\n        region.buffer.writeUInt16LE(sx, 0);\r\n        region.buffer.writeUInt16LE(sy, 2);\r\n        region.buffer.writeUInt16LE(ex, 4);\r\n        region.buffer.writeUInt16LE(ey, 6);\r\n\r\n        if (this._kernel32.ReadConsoleOutputA(this._stdoutput, nBuffer, size.Deref(0, 4).toBuffer().readUInt32LE(), startCoord.Deref(0, 4).toBuffer().readUInt32LE(), region).Val == 0)\r\n        {\r\n            throw (\'Unable to read Console Output\');\r\n        }\r\n\r\n        // Lets convert the buffer into something simpler\r\n        //var retVal = { data: Buffer.alloc((dw - dx + 1) * (dh - dy + 1)), attributes: Buffer.alloc((dw - dx + 1) * (dh - dy + 1)), width: dw - dx + 1, height: dh - dy + 1, x: dx, y: dy };\r\n\r\n        var retVal = { data: [], attributes: [], width: ex - sx + 1, height: ey - sy + 1, x: sx, y: sy };\r\n        var x, y, line, ifo, tmp, lineWidth = ex - sx + 1;\r\n\r\n        for (y = 0; y <= (ey - sy) ; ++y)\r\n        {\r\n            retVal.data.push(Buffer.alloc(lineWidth));\r\n            retVal.attributes.push(Buffer.alloc(lineWidth));\r\n\r\n            line = nBuffer.Deref(y * lineWidth * 4, lineWidth * 4).toBuffer();\r\n            for (x = 0; x < lineWidth; ++x)\r\n            {\r\n                retVal.data.peek()[x] = line[x * 4];\r\n                retVal.attributes.peek()[x] = line[2 + (x * 4)];\r\n            }\r\n        }\r\n\r\n        return (retVal);\r\n    }\r\n    \r\n    this._SendDataBuffer = function (data)\r\n    {\r\n        // { data, attributes, width, height, x, y }\r\n        if (this._stream != null)\r\n        {\r\n            var dy, line, attr;\r\n            for (dy = 0; dy < data.height; ++dy)\r\n            {\r\n                line = data.data[dy];\r\n                attr = data.attributes[dy];\r\n                line.s = line.toString();\r\n\r\n                //line = data.data.slice(data.width * dy, (data.width * dy) + data.width);\r\n                //attr = data.attributes.slice(data.width * dy, (data.width * dy) + data.width);\r\n                this._stream.push(TranslateLine(data.x + 1, data.y + dy + 1, line, attr));\r\n            }\r\n        }\r\n    }\r\n\r\n    this._SendScroll = function _SendScroll(dx, dy)\r\n    {\r\n        //\r\n        // Reference for GetConsoleScreenBufferInfo() can be found at:\r\n        // https://learn.microsoft.com/en-us/windows/console/getconsolescreenbufferinfo\r\n        //\r\n\r\n        if (this._scrollTimer || this._stream == null) { return; }\r\n        \r\n        var info = GM.CreateVariable(22);\r\n        if (this._kernel32.GetConsoleScreenBufferInfo(this._stdoutput, info).Val == 0) { throw (\'Error getting screen buffer info\'); }\r\n        \r\n        var nWidth = info.Deref(14, 2).toBuffer().readUInt16LE() - info.Deref(10, 2).toBuffer().readUInt16LE() + 1;\r\n        var nHeight = info.Deref(16, 2).toBuffer().readUInt16LE() - info.Deref(12, 2).toBuffer().readUInt16LE() + 1;\r\n        \r\n        this._stream.push(GetEsc(\'H\', [nHeight - 1, 0]));\r\n        for (var i = 0; i > nHeight; ++i) { this._stream.push(Buffer.from(\'\\r\\n\')); }\r\n        \r\n        var buffer = this._GetScreenBuffer(0, 0, nWidth - 1, nHeight - 1);\r\n        this._SendDataBuffer(buffer);\r\n        \r\n        this._scrollTimer = setTimeout(function (self, nw, nh) {\r\n            var buffer = self._GetScreenBuffer(0, 0, nw - 1, nh - 1);\r\n            self._SendDataBuffer(buffer);\r\n            self._scrollTimer = null;\r\n        }, 250, this, nWidth, nHeight);\r\n    }\r\n    \r\n    this.StartCommand = function StartCommand(target) {\r\n        if (this._kernel32.CreateProcessA(GM.CreateVariable(target), 0, 0, 0, 1, CREATE_NEW_PROCESS_GROUP, 0, 0, si, pi).Val == 0)\r\n        {\r\n            console.log(\'Error Spawning CMD\');\r\n            return;\r\n        }\r\n        \r\n        this._kernel32.CloseHandle(pi.Deref(GM.PointerSize, GM.PointerSize).Deref());           // pi.hThread\r\n        this._hProcess = pi.Deref(0, GM.PointerSize).Deref();                                   // pi.hProcess\r\n        this._hProcessID = pi.Deref(GM.PointerSize == 4 ? 8 : 16, 4).toBuffer().readUInt32LE(); // pi.dwProcessId\r\n        //console.log(\'Ready => hProcess: \' + this._hProcess._ptr + \' PID: \' + this._hProcessID);\r\n    }\r\n}\r\n\r\nfunction LOWORD(val) { return (val & 0xFFFF); }\r\nfunction HIWORD(val) { return ((val >> 16) & 0xFFFF); }\r\nfunction GetEsc(op, args) { return (Buffer.from(\'\\x1B[\' + args.join(\';\') + op)); }\r\nfunction MeshConsole(msg) { require(\'MeshAgent\').SendCommand({ \"action\": \"msg\", \"type\": \"console\", \"value\": JSON.stringify(msg) }); }\r\nfunction TranslateLine(x, y, data, attributes)\r\n{\r\n    var i, fcolor, bcolor, rcolor, fbright, bbright, lastAttr, fc, bc, rc, fb, bb, esc = [], output = [GetEsc(\'H\', [y, x])];\r\n    if (typeof attributes == \'number\') { attributes = [attributes]; } // If we get a single attribute, turn it into an array.\r\n\r\n    for (i = 0; i < data.length; i++)\r\n    {\r\n        if (lastAttr != attributes[i])\r\n        { // To boost performance, if the attribute is the same as the last one, skip this entire part.\r\n            fc = (attributes[i] & 0x0007);\r\n            fc = ((fc & 0x0001) << 2) + (fc & 0x0002) + ((fc & 0x0004) >> 2); // Foreground color\r\n            bc = (attributes[i] & 0x0070) >> 4;\r\n            bc = ((bc & 0x0001) << 2) + (bc & 0x0002) + ((bc & 0x0004) >> 2); // Background color\r\n            rc = (attributes[i] & 0x4000); // Reverse color set\r\n            fb = (attributes[i] & 0x0008) >> 3; // Bright foreground set\r\n            bb = (attributes[i] & 0x0080); // Bright background set\r\n\r\n            if (rc != rcolor) { if (rc != 0) { esc.push(7); } else { esc.push(0); fcolor = 7; bcolor = 0; fbright = 0; bbright = 0; } rcolor = rc; } // Reverse Color\r\n            if (fc != fcolor) { esc.push(fc + 30); fcolor = fc; } // Set the foreground color if needed\r\n            if (bc != bcolor) { esc.push(bc + 40); bcolor = bc; } // Set the background color if needed\r\n            if (fb != fbright) { esc.push(2 - fb); fbright = fb; } // Set the bright foreground color if needed\r\n            if (bb != bbright) { if (bb == 0) { esc.push(bcolor + 40); } else { esc.push(bcolor + 100); bbright = bb; } } // Set bright Background color if needed\r\n\r\n            if (esc.length > 0) { output.push(GetEsc(\'m\', esc)); esc = []; }\r\n            lastAttr = attributes[i];\r\n        }\r\n        output.push(Buffer.from(String.fromCharCode(data[i])));\r\n    }\r\n\r\n    return Buffer.concat(output);\r\n}\r\n\r\nmodule.exports = new windows_terminal();"); addedModules.push("win-terminal"); } catch (ex) { }
try { addModule("win-virtual-terminal", "/*\r\nCopyright 2019 Intel Corporation\r\n\r\nLicensed under the Apache License, Version 2.0 (the \"License\");\r\nyou may not use this file except in compliance with the License.\r\nYou may obtain a copy of the License at\r\n\r\n    http://www.apache.org/licenses/LICENSE-2.0\r\n\r\nUnless required by applicable law or agreed to in writing, software\r\ndistributed under the License is distributed on an \"AS IS\" BASIS,\r\nWITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.\r\nSee the License for the specific language governing permissions and\r\nlimitations under the License.\r\n*/\r\n\r\nvar PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE = 0x00020016;\r\nvar EXTENDED_STARTUPINFO_PRESENT = 0x00080000;\r\nvar HEAP_ZERO_MEMORY = 0x00000008;\r\n\r\nvar duplex = require(\'stream\').Duplex;\r\n\r\nfunction vt()\r\n{\r\n    this._ObjectID = \'win-virtual-terminal\';\r\n    Object.defineProperty(this, \'supported\', {\r\n        value: (function ()\r\n        {\r\n            var gm = require(\'_GenericMarshal\');\r\n            var k32 = gm.CreateNativeProxy(\'kernel32.dll\');\r\n            try\r\n            {\r\n                k32.CreateMethod(\'CreatePseudoConsole\');\r\n            }\r\n            catch(e)\r\n            {\r\n                return (false);\r\n            }\r\n            return (true);\r\n        })()\r\n    });\r\n    this.Create = function Create(path, width, height)\r\n    {\r\n        if (!this.supported) { throw (\'This build of Windows does not have support for PseudoConsoles\'); }\r\n        if (!width) { width = 80; }\r\n        if (!height) { height = 25; }\r\n\r\n        var GM = require(\'_GenericMarshal\');\r\n        var k32 = GM.CreateNativeProxy(\'kernel32.dll\');\r\n        k32.CreateMethod(\'CancelIoEx\');                         // https://learn.microsoft.com/en-us/windows/win32/fileio/cancelioex-func\r\n        k32.CreateMethod(\'CreatePipe\');                         // https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createpipe\r\n        k32.CreateMethod(\'CreateProcessW\');                     // https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw\r\n        k32.CreateMethod(\'CreatePseudoConsole\');                // https://learn.microsoft.com/en-us/windows/console/createpseudoconsole\r\n        k32.CreateMethod(\'CloseHandle\');                        // https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-closehandle\r\n        k32.CreateMethod(\'ClosePseudoConsole\');                 // https://learn.microsoft.com/en-us/windows/console/closepseudoconsole\r\n        k32.CreateMethod(\'GetProcessHeap\');                     // https://learn.microsoft.com/en-us/windows/win32/api/heapapi/nf-heapapi-getprocessheap\r\n        k32.CreateMethod(\'HeapAlloc\');                          // https://learn.microsoft.com/en-us/windows/win32/api/heapapi/nf-heapapi-heapalloc\r\n        k32.CreateMethod(\'InitializeProcThreadAttributeList\');  // https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-initializeprocthreadattributelist\r\n        k32.CreateMethod(\'ResizePseudoConsole\');                // https://learn.microsoft.com/en-us/windows/console/resizepseudoconsole\r\n        k32.CreateMethod(\'UpdateProcThreadAttribute\');          // https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute\r\n        k32.CreateMethod(\'WriteFile\');                          // https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-writefile\r\n        k32.CreateMethod(\'ReadFile\');                           // https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-readfile\r\n        k32.CreateMethod(\'TerminateProcess\');                   // https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-terminateprocess\r\n\r\n        var ret = { _h: GM.CreatePointer(), _consoleInput: GM.CreatePointer(), _consoleOutput: GM.CreatePointer(), _input: GM.CreatePointer(), _output: GM.CreatePointer(), k32: k32 };\r\n        var attrSize = GM.CreateVariable(8);\r\n        var attrList;\r\n        var pi = GM.CreateVariable(GM.PointerSize == 4 ? 16 : 24);\r\n\r\n        // Create the necessary pipes\r\n        if (k32.CreatePipe(ret._consoleInput, ret._input, 0, 0).Val == 0) { console.log(\'PIPE/FAIL\'); }\r\n        if (k32.CreatePipe(ret._output, ret._consoleOutput, 0, 0).Val == 0) { console.log(\'PIPE/FAIL\'); }\r\n\r\n\r\n        if (k32.CreatePseudoConsole((height << 16) | width, ret._consoleInput.Deref(), ret._consoleOutput.Deref(), 0, ret._h).Val != 0)\r\n        {\r\n            throw (\'Error calling CreatePseudoConsole()\');\r\n        }\r\n\r\n        //\r\n        // Reference for STARTUPINFOEXW\r\n        // https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-startupinfoexw\r\n        //\r\n\r\n        //\r\n        // Reference for STARTUPINFOW\r\n        // https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/ns-processthreadsapi-startupinfow\r\n        //\r\n\r\n        k32.InitializeProcThreadAttributeList(0, 1, 0, attrSize);\r\n        attrList = GM.CreateVariable(attrSize.toBuffer().readUInt32LE());\r\n        var startupinfoex = GM.CreateVariable(GM.PointerSize == 8 ? 112 : 72);                                          // Create Structure, 64 bits is 112 bytes, 32 bits is 72 bytes\r\n        startupinfoex.toBuffer().writeUInt32LE(GM.PointerSize == 8 ? 112 : 72, 0);                                      // Write buffer size\r\n        attrList.pointerBuffer().copy(startupinfoex.Deref(GM.PointerSize == 8 ? 104 : 68, GM.PointerSize).toBuffer());  // Write the reference to STARTUPINFOEX\r\n\r\n        if (k32.InitializeProcThreadAttributeList(attrList, 1, 0, attrSize).Val != 0)\r\n        {\r\n            if (k32.UpdateProcThreadAttribute(attrList, 0, PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, ret._h.Deref(), GM.PointerSize, 0, 0).Val != 0)\r\n            {\r\n                if (k32.CreateProcessW(0, GM.CreateVariable(path, { wide: true }), 0, 0, 1, EXTENDED_STARTUPINFO_PRESENT, 0, 0, startupinfoex, pi).Val != 0) // Create the process to run in the pseudoconsole\r\n                {\r\n                    //\r\n                    // Create a Stream Object, to be able to read/write data to the pseudoconsole\r\n                    //\r\n                    ret._startupinfoex = startupinfoex;\r\n                    ret._process = pi.Deref(0);\r\n                    ret._pid = pi.Deref(GM.PointerSize == 4 ? 8 : 16, 4).toBuffer().readUInt32LE();\r\n                    var ds = new duplex(\r\n                    {\r\n                        \'write\': function (chunk, flush)\r\n                        {\r\n                            var written = require(\'_GenericMarshal\').CreateVariable(4);\r\n                            this.terminal.k32.WriteFile(this.terminal._input.Deref(), require(\'_GenericMarshal\').CreateVariable(chunk), chunk.length, written, 0);\r\n                            flush();\r\n                            return (true);\r\n                        },\r\n                        \'final\': function (flush)\r\n                        {\r\n                            if (this.terminal._process)\r\n                            {\r\n                                this.terminal._process = null;\r\n                                k32.ClosePseudoConsole(this._obj._h.Deref());\r\n                            }\r\n                            flush();\r\n                        }\r\n                    });\r\n                    \r\n                    //\r\n                    // The ProcessInfo object is signaled when the process exits\r\n                    //\r\n                    ds._obj = ret;\r\n                    ret._waiter = require(\'DescriptorEvents\').addDescriptor(pi.Deref(0));\r\n                    ret._waiter.ds = ds;\r\n                    ret._waiter._obj = ret;\r\n                    ret._waiter.on(\'signaled\', function ()\r\n                    {\r\n                        k32.CancelIoEx(this._obj._output.Deref(), 0);\r\n\r\n                        // Child process has exited\r\n                        this.ds.push(null);\r\n\r\n                        if (this._obj._process)\r\n                        {\r\n                            this._obj._process = null;\r\n                            k32.ClosePseudoConsole(this._obj._h.Deref());\r\n                        }\r\n                       k32.CloseHandle(this._obj._input.Deref());\r\n                       k32.CloseHandle(this._obj._output.Deref());\r\n\r\n                       k32.CloseHandle(this._obj._consoleInput.Deref());\r\n                       k32.CloseHandle(this._obj._consoleOutput.Deref());\r\n                    });\r\n                    ds.resizeTerminal = function (w, h)\r\n                    {\r\n                        console.setDestination(console.Destinations.LOGFILE);\r\n                        console.log(\'resizeTerminal(\' + w + \', \' + h + \')\');\r\n                        var hr;\r\n                        if((hr=k32.ResizePseudoConsole(this._obj._h.Deref(),  (h << 16) | w).Val) != 0)\r\n                        {\r\n                            console.log(\'HResult=\' + hr);\r\n                            throw (\'Resize returned HRESULT: \' + hr);\r\n                        }\r\n                        console.log(\'SUCCESS\');\r\n                    };\r\n\r\n                    ds.terminal = ret;\r\n                    ds._rpbuf = GM.CreateVariable(4096);\r\n                    ds._rpbufRead = GM.CreateVariable(4);\r\n                    ds.__read = function __read()\r\n                    {\r\n                        // Asyncronously read data from the pseudoconsole\r\n                        this._rp = this.terminal.k32.ReadFile.async(this.terminal._output.Deref(), this._rpbuf, this._rpbuf._size, this._rpbufRead, 0);                      \r\n                        this._rp.then(function ()\r\n                        {\r\n                            var len = this.parent._rpbufRead.toBuffer().readUInt32LE();\r\n                            if (len <= 0) { return; }\r\n\r\n                            this.parent.push(this.parent._rpbuf.toBuffer().slice(0, len));\r\n                            this.parent.__read();\r\n                        });\r\n                        this._rp.parent = this;\r\n                    };\r\n                    ds.__read();\r\n                    return (ds);\r\n                }\r\n                else\r\n                {\r\n                }\r\n            }\r\n\r\n        }\r\n        throw (\'Internal Error\');\r\n    }\r\n\r\n    // This evaluates whether or not the powershell binary exists\r\n    this.PowerShellCapable = function ()\r\n    {\r\n        if (require(\'os\').arch() == \'x64\')\r\n        {\r\n            return (require(\'fs\').existsSync(process.env[\'windir\'] + \'\\\\SysWow64\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe\'));\r\n        }\r\n        else\r\n        {\r\n            return (require(\'fs\').existsSync(process.env[\'windir\'] + \'\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe\'));\r\n        }\r\n    }\r\n\r\n    // Start the PseudoConsole with the Command Prompt\r\n    this.Start = function Start(CONSOLE_SCREEN_WIDTH, CONSOLE_SCREEN_HEIGHT)\r\n    {\r\n        return (this.Create(process.env[\'windir\'] + \'\\\\System32\\\\cmd.exe\', CONSOLE_SCREEN_WIDTH, CONSOLE_SCREEN_HEIGHT));\r\n    }\r\n\r\n    // Start the PseduoConsole with PowerShell\r\n    this.StartPowerShell = function StartPowerShell(CONSOLE_SCREEN_WIDTH, CONSOLE_SCREEN_HEIGHT)\r\n    {\r\n        if (require(\'os\').arch() == \'x64\')\r\n        {\r\n            if (require(\'fs\').existsSync(process.env[\'windir\'] + \'\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe\'))\r\n            {\r\n                return (this.Create(process.env[\'windir\'] + \'\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe\', CONSOLE_SCREEN_WIDTH, CONSOLE_SCREEN_HEIGHT));\r\n            }\r\n            else\r\n            {\r\n                return (this.Create(process.env[\'windir\'] + \'\\\\SysWow64\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe\', CONSOLE_SCREEN_WIDTH, CONSOLE_SCREEN_HEIGHT));\r\n            }\r\n        }\r\n        else\r\n        {\r\n            return (this.Create(process.env[\'windir\'] + \'\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe\', CONSOLE_SCREEN_WIDTH, CONSOLE_SCREEN_HEIGHT));\r\n        }\r\n    }\r\n}\r\n\r\nif (process.platform == \'win32\')\r\n{\r\n    module.exports = new vt();\r\n}"); addedModules.push("win-virtual-terminal"); } catch (ex) { }

var http = require('http');
var childProcess = require('child_process');
var meshCoreObj = { action: 'coreinfo', value: "MeshCore Recovery", caps: 14 }; // Capability bitmask: 1 = Desktop, 2 = Terminal, 4 = Files, 8 = Console, 16 = JavaScript
var nextTunnelIndex = 1;
var tunnels = {};
var fs = require('fs');

var needStreamFix = (new Date(process.versions.meshAgent) < new Date('2020-01-21 13:27:45.000-08:00'));
try
{
    Object.defineProperty(Array.prototype, 'find', {
        value: function (func)
        {
            var i = 0;
            for(i=0;i<this.length;++i)
            {
                if(func(this[i]))
                {
                    return (this[i]);
                }
            }
            return (null);
        }
    });
}
catch(x)
{

}
try
{
    Object.defineProperty(Array.prototype, 'findIndex', {
        value: function (func)
        {
            var i = 0;
            for (i = 0; i < this.length; ++i)
            {
                if (func(this[i], i, this))
                {
                    return (i);
                }
            }
            return (-1);
        }
    });
}
catch (x)
{

}

if (process.platform != 'win32')
{
    var ch = require('child_process');
    ch._execFile = ch.execFile;
    ch.execFile = function execFile(path, args, options)
    {
        if (options && options.type && options.type == ch.SpawnTypes.TERM && options.env)
        {
            options.env['TERM'] = 'xterm-256color';
        }
        return (this._execFile(path, args, options));
    };
}

function _getPotentialServiceNames()
{
    var registry = require('win-registry');
    var ret = [];
    var K = registry.QueryKey(registry.HKEY.LocalMachine, 'SYSTEM\\CurrentControlSet\\Services');
    var service, s;
    while (K.subkeys.length > 0)
    {
        service = K.subkeys.shift();
        try
        {
            s = registry.QueryKey(registry.HKEY.LocalMachine, 'SYSTEM\\CurrentControlSet\\Services\\' + service, 'ImagePath');
            if (s.startsWith(process.execPath) || s.startsWith('"' + process.execPath + '"'))
            {
                ret.push(service);
            }
        }
        catch (x)
        {
        }
    }
    return (ret);
}
function _verifyServiceName(names)
{
    var i;
    var s;
    var ret = null;
    for (i = 0; i < names.length; ++i)
    {
        try
        {
            s = require('service-manager').manager.getService(names[i]);
            if (s.isMe())
            {
                ret = names[i];
                s.close();
                break;
            }
            s.close();
        }
        catch (z) { }
    }
    return (ret);
}

function windows_getCommandLine()
{
    var parms = [];
    var GM = require('_GenericMarshal');
    var k32 = GM.CreateNativeProxy('kernel32.dll');
    var s32 = GM.CreateNativeProxy('shell32.dll');
    k32.CreateMethod('GetCommandLineW');
    k32.CreateMethod('LocalFree');
    s32.CreateMethod('CommandLineToArgvW');
    var v = k32.GetCommandLineW();
    var i;
    var len = GM.CreateVariable(4);
    var val = s32.CommandLineToArgvW(v, len);
    len = len.toBuffer().readInt32LE(0);
    if (len > 0)
    {
        for (i = 0; i < len; ++i)
        {
            parms.push(val.Deref(i * GM.PointerSize, GM.PointerSize).Deref().Wide2UTF8);
        }
    }
    k32.LocalFree(val);
    return (parms);
}

if (require('MeshAgent').ARCHID == null)
{
    var id = null;
    switch (process.platform)
    {
        case 'win32':
            id = require('_GenericMarshal').PointerSize == 4 ? 3 : 4;
            break;
        case 'freebsd':
            id = require('_GenericMarshal').PointerSize == 4 ? 31 : 30;
            break;
        case 'darwin':
            try
            {
                id = require('os').arch() == 'x64' ? 16 : 29;
            }
            catch (xx)
            {
                id = 16;
            }
            break;
    }
    if (id != null) { Object.defineProperty(require('MeshAgent'), 'ARCHID', { value: id }); }
}

//attachDebugger({ webport: 9994, wait: 1 }).then(function (p) { console.log('Debug on port: ' + p); });

function sendConsoleText(msg, sessionid)
{
    if (sessionid != null)
    {
        require('MeshAgent').SendCommand({ action: 'msg', type: 'console', value: msg, sessionid: sessionid });
    }
    else
    {
        require('MeshAgent').SendCommand({ action: 'msg', type: 'console', value: msg });
    }
}

function sendAgentMessage(msg, icon)
{
    if (sendAgentMessage.messages == null)
    {
        sendAgentMessage.messages = {};
        sendAgentMessage.nextid = 1;
    }
    sendAgentMessage.messages[sendAgentMessage.nextid++] = { msg: msg, icon: icon };
    require('MeshAgent').SendCommand({ action: 'sessions', type: 'msg', value: sendAgentMessage.messages });
}

// Add to the server event log
function MeshServerLog(msg, state)
{
    if (typeof msg == 'string') { msg = { action: 'log', msg: msg }; } else { msg.action = 'log'; }
    if (state)
    {
        if (state.userid) { msg.userid = state.userid; }
        if (state.username) { msg.username = state.username; }
        if (state.sessionid) { msg.sessionid = state.sessionid; }
        if (state.remoteaddr) { msg.remoteaddr = state.remoteaddr; }
    }
    require('MeshAgent').SendCommand(msg);
}

// Add to the server event log, use internationalized events
function MeshServerLogEx(id, args, msg, state)
{
    var msg = { action: 'log', msgid: id, msgArgs: args, msg: msg };
    if (state)
    {
        if (state.userid) { msg.userid = state.userid; }
        if (state.username) { msg.username = state.username; }
        if (state.sessionid) { msg.sessionid = state.sessionid; }
        if (state.remoteaddr) { msg.remoteaddr = state.remoteaddr; }
    }
    require('MeshAgent').SendCommand(msg);
}

function getOpenDescriptors()
{
    switch(process.platform)
    {
        case "freebsd":
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

            try
            {
                return(JSON.parse(child.stdout.str.trim()));
            }
            catch(e)
            {
                return ([]);
            }
            break;
        case "linux":
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

            try
            {
                return (JSON.parse(child.stdout.str.trim()));
            }
            catch (e)
            {
                return ([]);
            }
            break;
        default:
            return ([]);
    }
}


function pathjoin() {
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
// Replace a string with a number if the string is an exact number
function toNumberIfNumber(x) { if ((typeof x == 'string') && (+parseInt(x) === x)) { x = parseInt(x); } return x; }


function closeDescriptors(libc, descriptors)
{
    var fd = null;
    while(descriptors.length>0)
    {
        fd = descriptors.pop();
        if(fd > 2)
        {
            libc.close(fd);
        }
    }
}

function linux_execv(name, agentfilename, sessionid)
{
    var libs = require('monitor-info').getLibInfo('libc');
    var libc = null;

    if ((libs.length == 0 || libs.length == null) && require('MeshAgent').ARCHID == 33)
    {
        var child = require('child_process').execFile('/bin/sh', ['sh']);
        child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
        child.stderr.str = ''; child.stderr.on('data', function (c) { this.str += c.toString(); });
        child.stdin.write("ls /lib/libc.* | tr '\\n' '`' | awk -F'`' '{ " + ' printf "["; DEL=""; for(i=1;i<NF;++i) { printf "%s{\\"path\\":\\"%s\\"}",DEL,$i; DEL=""; } printf "]"; }\'\nexit\n');
        child.waitExit();

        try
        {
            libs = JSON.parse(child.stdout.str.trim());
        }
        catch(e)
        {
        }
    }

    while (libs.length > 0)
    {
        try {
            libc = require('_GenericMarshal').CreateNativeProxy(libs.pop().path);
            break;
        }
        catch (e) {
            libc = null;
            continue;
        }
    }
    if (libc != null) {
        try
        {
            libc.CreateMethod('execv');
            libc.CreateMethod('close');
        }
        catch (e) {
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
        }
        catch (zz) {
            sendConsoleText('Self Update encountered an error trying to restart service', sessionid);
            sendAgentMessage('Self Update encountered an error trying to restart service', 3);
        }
        return;
    }

    if (sessionid != null) { sendConsoleText('Restarting service via execv()...', sessionid) }

    var i;
    var args;
    var argtmp = [];
    var argarr = [process.execPath];
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
    try
    {
        libc = require('_GenericMarshal').CreateNativeProxy(child.stdout.str.trim());
        libc.CreateMethod('execv');
        libc.CreateMethod('close');
    }
    catch (e) {
        if (sessionid != null) { sendConsoleText('Self Update failed: ' + e.toString(), sessionid) }
        sendAgentMessage('Self Update failed: ' + e.toString(), 3);
        return;
    }

    var i;
    var path = require('_GenericMarshal').CreateVariable(process.execPath);
    var argarr = [process.execPath];
    var argtmp = [];
    var args;
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
    }
    catch (xx) {
        sendConsoleText('Self Update failed because msvcrt.dll is missing', sessionid);
        sendAgentMessage('Self Update failed because msvcrt.dll is missing', 3);
        return;
    }

    var cwd = process.cwd();
    if (!cwd.endsWith('\\'))
    {
        cwd += '\\';
    }
    var cmd = require('_GenericMarshal').CreateVariable(process.env['windir'] + '\\system32\\cmd.exe', { wide: true });
    var args = require('_GenericMarshal').CreateVariable(3 * require('_GenericMarshal').PointerSize);
    var arg1 = require('_GenericMarshal').CreateVariable('cmd.exe', { wide: true });
    var arg2 = require('_GenericMarshal').CreateVariable('/C net stop "' + name + '" & "' + cwd + agentfilename + '.update.exe" -b64exec ' + 'dHJ5CnsKICAgIHZhciBzZXJ2aWNlTG9jYXRpb24gPSBwcm9jZXNzLmFyZ3YucG9wKCkudG9Mb3dlckNhc2UoKTsKICAgIHJlcXVpcmUoJ3Byb2Nlc3MtbWFuYWdlcicpLmVudW1lcmF0ZVByb2Nlc3NlcygpLnRoZW4oZnVuY3Rpb24gKHByb2MpCiAgICB7CiAgICAgICAgZm9yICh2YXIgcCBpbiBwcm9jKQogICAgICAgIHsKICAgICAgICAgICAgaWYgKHByb2NbcF0ucGF0aCAmJiAocHJvY1twXS5wYXRoLnRvTG93ZXJDYXNlKCkgPT0gc2VydmljZUxvY2F0aW9uKSkKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgcHJvY2Vzcy5raWxsKHByb2NbcF0ucGlkKTsKICAgICAgICAgICAgfQogICAgICAgIH0KICAgICAgICBwcm9jZXNzLmV4aXQoKTsKICAgIH0pOwp9CmNhdGNoIChlKQp7CiAgICBwcm9jZXNzLmV4aXQoKTsKfQ==' +
        ' "' + process.execPath + '" & copy "' + cwd + agentfilename + '.update.exe" "' + process.execPath + '" & net start "' + name + '" & erase "' + cwd + agentfilename + '.update.exe"', { wide: true });

    if (name == null)
    {
        // We can continue with self update for Temp/Console Mode on Windows
        var db = null;
        var update = cwd + agentfilename + '.update.exe';
        var updatedb = cwd + agentfilename + '.update.db';
        var parms = windows_getCommandLine(); parms.shift();
        
        var updatesource = parms.find(function (v) { return (v.startsWith('--updateSourcePath=')); });
        if (updatesource == null)
        {
            parms.push('--updateSourcePath="' + cwd + agentfilename + '"');
            updatesource = (cwd + agentfilename).split('.exe'); updatesource.pop(); updatesource = updatesource.join('.exe');
            db = updatesource + '.db';
            updatesource = (' & move "' + updatedb + '" "' + db + '"') + (' & erase "' + updatedb + '" & move "' + update + '" "' + updatesource + '.exe"');
        }
        else
        {
            updatesource = updatesource.substring(19).split('.exe');
            updatesource.pop(); updatesource = updatesource.join('.exe');
            db = updatesource + '.db';
            updatesource = (' & move "' + update + '" "' + updatesource + '.exe" & move "' + updatedb + '" "' + db + '" & erase "' + updatedb + '"') + (' & echo move "' + update + '" "' + updatesource + '.exe" & echo move "' + updatedb + '" "' + db + '"');
        }

        var tmp = '/C echo copy "' + db + '" "' + updatedb + '" & copy "' + db + '" "' + updatedb + '"' + ' & "' + update + '" ' + parms.join(' ') + updatesource + ' & erase "' + update + '" & echo ERASE "' + update + '"';
        arg2 = require('_GenericMarshal').CreateVariable(tmp, { wide: true });
    }

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

    if (agentUpdate_Start._selfupdate != null)
    {
        // We were already called, so we will ignore this duplicate request
        if (sessionid != null) { sendConsoleText('Self update already in progress...', sessionid); }
    }
    else {
        if (agentUpdate_Start._retryCount == null) { agentUpdate_Start._retryCount = 0; }
        if (require('MeshAgent').ARCHID == null && updateurl == null) {
            // This agent doesn't have the ability to tell us which ARCHID it is, so we don't know which agent to pull
            sendConsoleText('Unable to initiate update, agent ARCHID is not defined', sessionid);
        }
        else
        {
            var agentfilename = process.execPath.split(process.platform == 'win32' ? '\\' : '/').pop(); // Local File Name, ie: MeshAgent.exe
            var name = require('MeshAgent').serviceName;
            if (name == null) { name = process.platform == 'win32' ? 'Mesh Agent' : 'meshagent'; }
            if (process.platform == 'win32')
            {
                // Special Processing for Temporary/Console Mode Agents on Windows
                var parms = windows_getCommandLine(); // This uses FFI to fetch the command line parameters that the agent was started with
                if (parms.findIndex(function (val) { return (val != null && (val.toUpperCase() == 'RUN' || val.toUpperCase() == 'CONNECT')); }) >= 0)
                {
                    // This is a Temporary/Console Mode Agent
                    sendConsoleText('This is a temporary/console agent, checking for conflicts with background services...');

                    // Check to see if our binary conflicts with an installed agent
                    var agents = _getPotentialServiceNames();
                    if (_getPotentialServiceNames().length > 0)
                    {
                        sendConsoleText('Self update cannot continue because the installed agent (' + agents[0] + ') conflicts with the currently running Temp/Console agent...', sessionid);
                        return;
                    }


                    sendConsoleText('No conflicts detected...');
                    name = null;
                }
                else
                {
                    // Not running in Temp/Console Mode... No Op here....
                }
            }
            else
            {
                // Non Windows Self Update
                try
                {
                    var s = require('service-manager').manager.getService(name);
                    if (!s.isMe())
                    {
                        if (process.platform == 'win32') { s.close(); }
                        sendConsoleText('Self Update cannot continue, this agent is not an instance of background service (' + name + ')', sessionid);
                        return;
                    }
                    if (process.platform == 'win32') { s.close(); }
                }
                catch (zz)
                {
                    sendConsoleText('Self Update Failed because this agent is not an instance of (' + name + ')', sessionid);
                    sendAgentMessage('Self Update Failed because this agent is not an instance of (' + name + ')', 3);
                    return;
                }
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
            agentUpdate_Start._selfupdate.on('response', function (img)
            {
                var self = this;
                this._file = require('fs').createWriteStream(agentfilename + (process.platform=='win32'?'.update.exe':'.update'), { flags: 'wb' });
                this._filehash = require('SHA384Stream').create();
                this._filehash.on('hash', function (h)
                {
                    if (updateoptions != null && updateoptions.hash != null)
                    {
                        if (updateoptions.hash.toLowerCase() == h.toString('hex').toLowerCase())
                        {
                            if (sessionid != null) { sendConsoleText('Download complete. HASH verified.', sessionid); }
                        }
                        else
                        {
                            agentUpdate_Start._retryCount++;
                            sendConsoleText('Self Update FAILED because the downloaded agent FAILED hash check (' + agentUpdate_Start._retryCount + '), URL: ' + updateurl, sessionid);
                            sendAgentMessage('Self Update FAILED because the downloaded agent FAILED hash check (' + agentUpdate_Start._retryCount + '), URL: ' + updateurl, 3);
                            agentUpdate_Start._selfupdate = null;

                            try
                            {
                                // We are clearing these two properties, becuase some older agents may not cleanup correctly causing problems with the retry
                                require('https').globalAgent.sockets = {};  
                                require('https').globalAgent.requests = {};
                            }
                            catch(z)
                            {}
                            if (needStreamFix)
                            {
                                sendConsoleText('This is an older agent that may have an httpstream bug. On next retry will try to fetch the update differently...');
                                needStreamFix = false;
                            }

                            if (agentUpdate_Start._retryCount < 4)
                            {
                                // Retry the download again
                                sendConsoleText('Self Update will try again in 20 seconds...', sessionid);
                                agentUpdate_Start._timeout = setTimeout(agentUpdate_Start, 20000, updateurl, updateoptions);
                            }
                            else
                            {
                                sendConsoleText('Self Update giving up, too many failures...', sessionid);
                                sendAgentMessage('Self Update giving up, too many failures...', 3);
                            }
                            return;
                        }
                    }
                    else
                    {
                        sendConsoleText('Download complete. HASH=' + h.toString('hex'), sessionid);
                    }

                    // Send an indication to the server that we got the update download correctly.
                    try { require('MeshAgent').SendCommand({ action: 'agentupdatedownloaded' }); } catch (e) { }

                    if (sessionid != null) { sendConsoleText('Updating and restarting agent...', sessionid); }
                    if (process.platform == 'win32')
                    {
                        // Use _wexecve() equivalent to perform the update
                        windows_execve(name, agentfilename, sessionid);
                    }
                    else
                    {
                        var m = require('fs').statSync(process.execPath).mode;
                        require('fs').chmodSync(process.cwd() + agentfilename + '.update', m);

                        // remove binary
                        require('fs').unlinkSync(process.execPath);

                        // copy update
                        require('fs').copyFileSync(process.cwd() + agentfilename + '.update', process.execPath);
                        require('fs').chmodSync(process.execPath, m);

                        // erase update
                        require('fs').unlinkSync(process.cwd() + agentfilename + '.update');

                        switch (process.platform)
                        {
                            case 'freebsd':
                                bsd_execv(name, agentfilename, sessionid);
                                break;
                            case 'linux':
                                linux_execv(name, agentfilename, sessionid);
                                break;
                            default:
                                try
                                {
                                    // restart service
                                    var s = require('service-manager').manager.getService(name);
                                    s.restart();
                                }
                                catch (zz)
                                {
                                    if (zz.toString() != 'waitExit() aborted because thread is exiting')
                                    {
                                        sendConsoleText('Self Update encountered an error trying to restart service', sessionid);
                                        sendAgentMessage('Self Update encountered an error trying to restart service', 3);
                                    }
                                }
                                break;
                        }
                    }
                });

                if (!needStreamFix)
                {
                    img.pipe(this._file);
                    img.pipe(this._filehash);
                }
                else
                {
                    img.once('data', function (buffer)
                    {
                        if(this.immediate)
                        {
                            clearImmediate(this.immediate);
                            this.immediate = null;

                            // No need to apply fix
                            self._file.write(buffer);
                            self._filehash.write(buffer);

                            this.pipe(self._file);
                            this.pipe(self._filehash);
                        }
                        else
                        {
                            // Need to apply fix
                            this.pipe(self._file);
                            this.pipe(self._filehash);
                        }
                    });
                    this.immediate = setImmediate(function (self)
                    {
                        self.immediate = null;
                    },this);
                }
            });
        }
    }
}

// Return p number of spaces 
function addPad(p, ret) { var r = ''; for (var i = 0; i < p; i++) { r += ret; } return r; }

setInterval(function () { sendConsoleText('Timer!'); }, 2000);

var path =
    {
        join: function () {
            var x = [];
            for (var i in arguments) {
                var w = arguments[i];
                if (w != null) {
                    while (w.endsWith('/') || w.endsWith('\\')) { w = w.substring(0, w.length - 1); }
                    if (i != 0) { while (w.startsWith('/') || w.startsWith('\\')) { w = w.substring(1); } }
                    x.push(w);
                }
            }
            if (x.length == 0) return '/';
            return x.join('/');
        }
    };
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
    var x = require('MeshAgent').ServerUrl;
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

require('MeshAgent').on('Connected', function () {
    require('os').name().then(function (v) {
        //sendConsoleText("Mesh Agent Recovery Console, OS: " + v);
        require('MeshAgent').SendCommand(meshCoreObj);
    });
});

// Called when receiving control data on websocket
function onTunnelControlData(data, ws) {
    var obj;
    if (ws == null) { ws = this; }
    if (typeof data == 'string') { try { obj = JSON.parse(data); } catch (e) { sendConsoleText('Invalid control JSON: ' + data); return; } }
    else if (typeof data == 'object') { obj = data; } else { return; }
    //sendConsoleText('onTunnelControlData(' + ws.httprequest.protocol + '): ' + JSON.stringify(data));
    //console.log('onTunnelControlData: ' + JSON.stringify(data));

    if (obj.action) {
        switch (obj.action) {
            case 'lock': {
                // Lock the current user out of the desktop
                try {
                    if (process.platform == 'win32') {
                        MeshServerLog("Locking remote user out of desktop", ws.httprequest);
                        var child = require('child_process');
                        child.execFile(process.env['windir'] + '\\system32\\cmd.exe', ['/c', 'RunDll32.exe user32.dll,LockWorkStation'], { type: 1 });
                    }
                } catch (e) { }
                break;
            }
            default:
                // Unknown action, ignore it.
                break;
        }
        return;
    }

    switch (obj.type) {
        case 'options': {
            // These are additional connection options passed in the control channel.
            //sendConsoleText('options: ' + JSON.stringify(obj));
            delete obj.type;
            ws.httprequest.xoptions = obj;

            // Set additional user consent options if present
            if ((obj != null) && (typeof obj.consent == 'number')) { ws.httprequest.consent |= obj.consent; }

            break;
        }
        case 'close': {
            // We received the close on the websocket
            //sendConsoleText('Tunnel #' + ws.tunnel.index + ' WebSocket control close');
            try { ws.close(); } catch (e) { }
            break;
        }
        case 'termsize': {
            // Indicates a change in terminal size
            if (process.platform == 'win32') {
                if (ws.httprequest._dispatcher == null) return;
                if (ws.httprequest._dispatcher.invoke) { ws.httprequest._dispatcher.invoke('resizeTerminal', [obj.cols, obj.rows]); }
            }
            else {
                if (ws.httprequest.process == null || ws.httprequest.process.pty == 0) return;
                if (ws.httprequest.process.tcsetsize) { ws.httprequest.process.tcsetsize(obj.rows, obj.cols); }
            }
            break;
        }
    }
}


require('MeshAgent').AddCommandHandler(function (data)
{
    if (typeof data == 'object') {
        // If this is a console command, parse it and call the console handler
        switch (data.action) {
            case 'agentupdate':
                agentUpdate_Start(data.url, { hash: data.hash, tlshash: data.servertlshash, sessionid: data.sessionid });
                break;
            case 'msg':
                {
                    switch (data.type) {
                        case 'console': { // Process a console command
                            if ((typeof data.rights != 'number') || ((data.rights & 8) == 0) || ((data.rights & 16) == 0)) break; // Check console rights (Remote Control and Console)
                            if (data.value && data.sessionid) {
                                var args = splitArgs(data.value);
                                processConsoleCommand(args[0].toLowerCase(), parseArgs(args), data.rights, data.sessionid);
                            }
                            break;
                        }
                        case 'tunnel':
                            {
                                if (data.value != null) { // Process a new tunnel connection request
                                    // Create a new tunnel object
                                    if (data.rights != 4294967295) {
                                        MeshServerLog('Tunnel Error: RecoveryCore requires admin rights for tunnels');
                                        break;
                                    }

                                    var xurl = getServerTargetUrlEx(data.value);
                                    if (xurl != null)
                                    {
                                        xurl = xurl.split('$').join('%24').split('@').join('%40'); // Escape the $ and @ characters
                                        var woptions = http.parseUri(xurl);
                                        woptions.rejectUnauthorized = 0;
                                        woptions.perMessageDeflate = false;
                                        woptions.checkServerIdentity = function checkServerIdentity(certs) {
                                            // If the tunnel certificate matches the control channel certificate, accept the connection
                                            try { if (require('MeshAgent').ServerInfo.ControlChannelCertificate.digest == certs[0].digest) return; } catch (ex) { }
                                            try { if (require('MeshAgent').ServerInfo.ControlChannelCertificate.fingerprint == certs[0].fingerprint) return; } catch (ex) { }

                                            // Check that the certificate is the one expected by the server, fail if not.
                                            if ((checkServerIdentity.servertlshash != null) && (checkServerIdentity.servertlshash.toLowerCase() != certs[0].digest.split(':').join('').toLowerCase())) { throw new Error('BadCert') }
                                        }
                                        woptions.checkServerIdentity.servertlshash = data.servertlshash;


                                        //sendConsoleText(JSON.stringify(woptions));
                                        var tunnel = http.request(woptions);
                                        tunnel.on('upgrade', function (response, s, head) {
                                            if (require('MeshAgent').idleTimeout != null) {
                                                s.setTimeout(require('MeshAgent').idleTimeout * 1000);
                                                s.on('timeout', function () {
                                                    this.ping();
                                                    this.setTimeout(require('MeshAgent').idleTimeout * 1000);
                                                });
                                            }

                                            this.s = s;
                                            s.httprequest = this;
                                            s.tunnel = this;
                                            s.on('end', function () {
                                                if (tunnels[this.httprequest.index] == null) return; // Stop duplicate calls.

                                                // If there is a upload or download active on this connection, close the file
                                                if (this.httprequest.uploadFile) { fs.closeSync(this.httprequest.uploadFile); delete this.httprequest.uploadFile; delete this.httprequest.uploadFileid; delete this.httprequest.uploadFilePath; }
                                                if (this.httprequest.downloadFile) { delete this.httprequest.downloadFile; }

                                                //sendConsoleText("Tunnel #" + this.httprequest.index + " closed.", this.httprequest.sessionid);
                                                delete tunnels[this.httprequest.index];

                                                // Clean up WebSocket
                                                this.removeAllListeners('data');
                                            });
                                            s.on('data', function (data) {
                                                // If this is upload data, save it to file
                                                if ((this.httprequest.uploadFile) && (typeof data == 'object') && (data[0] != 123)) {
                                                    // Save the data to file being uploaded.
                                                    if (data[0] == 0) {
                                                        // If data starts with zero, skip the first byte. This is used to escape binary file data from JSON.
                                                        try { fs.writeSync(this.httprequest.uploadFile, data, 1, data.length - 1); } catch (e) { sendConsoleText('FileUpload Error'); this.write(Buffer.from(JSON.stringify({ action: 'uploaderror' }))); return; } // Write to the file, if there is a problem, error out.
                                                    } else {
                                                        // If data does not start with zero, save as-is.
                                                        try { fs.writeSync(this.httprequest.uploadFile, data); } catch (e) { sendConsoleText('FileUpload Error'); this.write(Buffer.from(JSON.stringify({ action: 'uploaderror' }))); return; } // Write to the file, if there is a problem, error out.
                                                    }
                                                    this.write(Buffer.from(JSON.stringify({ action: 'uploadack', reqid: this.httprequest.uploadFileid }))); // Ask for more data.
                                                    return;
                                                }

                                                if (this.httprequest.state == 0) {
                                                    // Check if this is a relay connection
                                                    if ((data == 'c') || (data == 'cr')) { this.httprequest.state = 1; /*sendConsoleText("Tunnel #" + this.httprequest.index + " now active", this.httprequest.sessionid);*/ }
                                                }
                                                else {
                                                    // Handle tunnel data
                                                    if (this.httprequest.protocol == 0) {   // 1 = Terminal (admin), 2 = Desktop, 5 = Files, 6 = PowerShell (admin), 7 = Plugin Data Exchange, 8 = Terminal (user), 9 = PowerShell (user), 10 = FileTransfer
                                                        // Take a look at the protocol
                                                        if ((data.length > 3) && (data[0] == '{')) { onTunnelControlData(data, this); return; }
                                                        this.httprequest.protocol = parseInt(data);
                                                        if (typeof this.httprequest.protocol != 'number') { this.httprequest.protocol = 0; }
                                                        if (this.httprequest.protocol == 10) {
                                                            //
                                                            // Basic file transfer
                                                            //
                                                            var stats = null;
                                                            if ((process.platform != 'win32') && (this.httprequest.xoptions.file.startsWith('/') == false)) { this.httprequest.xoptions.file = '/' + this.httprequest.xoptions.file; }
                                                            try { stats = require('fs').statSync(this.httprequest.xoptions.file) } catch (e) { }
                                                            try { if (stats) { this.httprequest.downloadFile = fs.createReadStream(this.httprequest.xoptions.file, { flags: 'rbN' }); } } catch (e) { }
                                                            if (this.httprequest.downloadFile) {
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
                                                            if (process.platform == "win32") {
                                                                var cols = 80, rows = 25;
                                                                if (this.httprequest.xoptions) {
                                                                    if (this.httprequest.xoptions.rows) { rows = this.httprequest.xoptions.rows; }
                                                                    if (this.httprequest.xoptions.cols) { cols = this.httprequest.xoptions.cols; }
                                                                }

                                                                // Admin Terminal
                                                                if (require('win-virtual-terminal').supported) {
                                                                    // ConPTY PseudoTerminal
                                                                    // this.httprequest._term = require('win-virtual-terminal')[this.httprequest.protocol == 6 ? 'StartPowerShell' : 'Start'](80, 25);

                                                                    // The above line is commented out, because there is a bug with ClosePseudoConsole() API, so this is the workaround
                                                                    this.httprequest._dispatcher = require('win-dispatcher').dispatch({ modules: [{ name: 'win-virtual-terminal', script: getJSModule('win-virtual-terminal') }], launch: { module: 'win-virtual-terminal', method: 'Start', args: [cols, rows] } });
                                                                    this.httprequest._dispatcher.ws = this;
                                                                    this.httprequest._dispatcher.on('connection', function (c) {
                                                                        this.ws._term = c;
                                                                        c.pipe(this.ws, { dataTypeSkip: 1 });
                                                                        this.ws.pipe(c, { dataTypeSkip: 1 });
                                                                    });
                                                                }
                                                                else {
                                                                    // Legacy Terminal
                                                                    this.httprequest._term = require('win-terminal').Start(80, 25);
                                                                    this.httprequest._term.pipe(this, { dataTypeSkip: 1 });
                                                                    this.pipe(this.httprequest._term, { dataTypeSkip: 1, end: false });
                                                                    this.prependListener('end', function () { this.httprequest._term.end(function () { sendConsoleText('Terminal was closed'); }); });
                                                                }
                                                            }
                                                            else {
                                                                var env = { HISTCONTROL: 'ignoreboth' };
                                                                if (process.env['LANG']) { env['LANG'] = process.env['LANG']; }
                                                                if (process.env['PATH']) { env['PATH'] = process.env['PATH']; }
                                                                if (this.httprequest.xoptions)
                                                                {
                                                                    if (this.httprequest.xoptions.rows) { env.LINES = ('' + this.httprequest.xoptions.rows); }
                                                                    if (this.httprequest.xoptions.cols) { env.COLUMNS = ('' + this.httprequest.xoptions.cols); }
                                                                }
                                                                var options = { type: childProcess.SpawnTypes.TERM, env: env };

                                                                if (require('fs').existsSync('/bin/bash')) {
                                                                    this.httprequest.process = childProcess.execFile('/bin/bash', ['bash'], options); // Start bash
                                                                }
                                                                else {
                                                                    this.httprequest.process = childProcess.execFile('/bin/sh', ['sh'], options); // Start sh
                                                                }

                                                                // Spaces at the beginning of lines are needed to hide commands from the command history
                                                                if (process.platform == 'linux') { this.httprequest.process.stdin.write(' alias ls=\'ls --color=auto\';clear\n'); }
                                                                this.httprequest.process.tunnel = this;
                                                                this.httprequest.process.on('exit', function (ecode, sig) { this.tunnel.end(); });
                                                                this.httprequest.process.stderr.on('data', function (chunk) { this.parent.tunnel.write(chunk); });
                                                                this.httprequest.process.stdout.pipe(this, { dataTypeSkip: 1 }); // 0 = Binary, 1 = Text.
                                                                this.pipe(this.httprequest.process.stdin, { dataTypeSkip: 1, end: false }); // 0 = Binary, 1 = Text.
                                                                this.prependListener('end', function () { this.httprequest.process.kill(); });
                                                            }
                                                        }
                                                    }
                                                    else if (this.httprequest.protocol == 5) {
                                                        // Process files commands
                                                        var cmd = null;
                                                        try { cmd = JSON.parse(data); } catch (e) { };
                                                        if (cmd == null) { return; }
                                                        if ((cmd.ctrlChannel == '102938') || ((cmd.type == 'offer') && (cmd.sdp != null))) { return; } // If this is control data, handle it now.
                                                        if (cmd.action == undefined) { return; }
                                                        console.log('action: ', cmd.action);

                                                        //sendConsoleText('CMD: ' + JSON.stringify(cmd));

                                                        if ((cmd.path != null) && (process.platform != 'win32') && (cmd.path[0] != '/')) { cmd.path = '/' + cmd.path; } // Add '/' to paths on non-windows
                                                        //console.log(objToString(cmd, 0, ' '));
                                                        switch (cmd.action) {
                                                            case 'ls':
                                                                // Send the folder content to the browser
                                                                var response = getDirectoryInfo(cmd.path);
                                                                if (cmd.reqid != undefined) { response.reqid = cmd.reqid; }
                                                                this.write(Buffer.from(JSON.stringify(response)));
                                                                break;
                                                            case 'mkdir':
                                                                {
                                                                    // Create a new empty folder
                                                                    fs.mkdirSync(cmd.path);
                                                                    break;
                                                                }
                                                            case 'rm':
                                                                {
                                                                    // Delete, possibly recursive delete
                                                                    for (var i in cmd.delfiles) {
                                                                        try { deleteFolderRecursive(path.join(cmd.path, cmd.delfiles[i]), cmd.rec); } catch (e) { }
                                                                    }
                                                                    break;
                                                                }
                                                            case 'rename':
                                                                {
                                                                    // Rename a file or folder
                                                                    var oldfullpath = path.join(cmd.path, cmd.oldname);
                                                                    var newfullpath = path.join(cmd.path, cmd.newname);
                                                                    try { fs.renameSync(oldfullpath, newfullpath); } catch (e) { console.log(e); }
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
                                                                        try { this.filedownload.f = fs.openSync(this.filedownload.path, 'rbN'); } catch (e) { this.write({ action: 'download', sub: 'cancel', id: this.filedownload.id }); delete this.filedownload; }
                                                                        if (this.filedownload) { this.write({ action: 'download', sub: 'start', id: cmd.id }); }
                                                                    } else if ((this.filedownload != null) && (cmd.id == this.filedownload.id)) { // Download commands
                                                                        if (cmd.sub == 'startack') { sendNextBlock = ((typeof cmd.ack == 'number') ? cmd.ack : 8); } else if (cmd.sub == 'stop') { delete this.filedownload; } else if (cmd.sub == 'ack') { sendNextBlock = 1; }
                                                                    }
                                                                    // Send the next download block(s)
                                                                    while (sendNextBlock > 0) {
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
                                                                    var filepath = cmd.name ? pathjoin(cmd.path, cmd.name) : cmd.path;
                                                                    this.httprequest.uploadFilePath = filepath;
                                                                    MeshServerLogEx(50, [filepath], 'Upload: \"' + filepath + '\"', this.httprequest);
                                                                    try { this.httprequest.uploadFile = fs.openSync(filepath, 'wbN'); } catch (e) { this.write(Buffer.from(JSON.stringify({ action: 'uploaderror', reqid: cmd.reqid }))); break; }
                                                                    this.httprequest.uploadFileid = cmd.reqid;
                                                                    if (this.httprequest.uploadFile) { this.write(Buffer.from(JSON.stringify({ action: 'uploadstart', reqid: this.httprequest.uploadFileid }))); }
                                                                    break;
                                                                }
                                                            case 'uploaddone':
                                                                {
                                                                    // Indicates that an upload is done
                                                                    if (this.httprequest.uploadFile) {
                                                                        fs.closeSync(this.httprequest.uploadFile);
                                                                        this.write(Buffer.from(JSON.stringify({ action: 'uploaddone', reqid: this.httprequest.uploadFileid }))); // Indicate that we closed the file.
                                                                        delete this.httprequest.uploadFile;
                                                                        delete this.httprequest.uploadFileid;
                                                                        delete this.httprequest.uploadFilePath;
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
                                                                    }
                                                                    break;
                                                                }
                                                            case 'copy': {
                                                                // Copy a bunch of files from scpath to dspath
                                                                for (var i in cmd.names) {
                                                                    var sc = path.join(cmd.scpath, cmd.names[i]), ds = path.join(cmd.dspath, cmd.names[i]);
                                                                    if (sc != ds) { try { fs.copyFileSync(sc, ds); } catch (e) { } }
                                                                }
                                                                break;
                                                            }
                                                            case 'move': {
                                                                // Move a bunch of files from scpath to dspath
                                                                for (var i in cmd.names) {
                                                                    var sc = path.join(cmd.scpath, cmd.names[i]), ds = path.join(cmd.dspath, cmd.names[i]);
                                                                    if (sc != ds) { try { fs.copyFileSync(sc, ds); fs.unlinkSync(sc); } catch (e) { } }
                                                                }
                                                                break;
                                                            }
                                                        }
                                                    }
                                                }
                                            });
                                        });
                                        tunnel.onerror = function (e) { sendConsoleText("ERROR: " + JSON.stringify(e)); }
                                        tunnel.sessionid = data.sessionid;
                                        tunnel.rights = data.rights;
                                        tunnel.state = 0;
                                        tunnel.url = xurl;
                                        tunnel.protocol = 0;
                                        tunnel.tcpaddr = data.tcpaddr;
                                        tunnel.tcpport = data.tcpport;
                                        tunnel.end();
                                        // Put the tunnel in the tunnels list
                                        var index = nextTunnelIndex++;
                                        tunnel.index = index;
                                        tunnels[index] = tunnel;

                                        //sendConsoleText('New tunnel connection #' + index + ': ' + tunnel.url + ', rights: ' + tunnel.rights, data.sessionid);
                                    }
                                }
                                break;
                            }

                        default:
                            // Unknown action, ignore it.
                            break;
                    }
                    break;
                }
            default:
                // Unknown action, ignore it.
                break;
        }
    }
});

function processConsoleCommand(cmd, args, rights, sessionid) {
    try {
        var response = null;
        switch (cmd)
        {
            default:
                { // This is an unknown command, return an error message
                    response = 'Unknown command \"' + cmd + '\", type \"help\" for list of available commands.';
                    break;
                }
            case 'commandline':
                {
                    if (process.platform == 'win32')
                    {
                        response = JSON.stringify(windows_getCommandLine(), null, 1);
                    }
                    else
                    {
                        response = 'Unknown command \"' + cmd + '\", type \"help\" for list of available commands.';
                    }
                }
                break;
            case 'help':
                response = "Available commands are: agentupdate, agentupdateex, dbkeys, dbget, dbset, dbcompact, eval, netinfo, osinfo, setdebug, versions.";
                break;
            case '_descriptors':
                response = 'Open Descriptors: ' + JSON.stringify(getOpenDescriptors());
                break;
            case 'versions':
                response = JSON.stringify(process.versions, null, '  ');
                break;
            case 'agentupdate':
                // Request that the server send a agent update command
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
            case 'eval':
                { // Eval JavaScript
                    if (args['_'].length < 1) {
                        response = 'Proper usage: eval "JavaScript code"'; // Display correct command usage
                    } else {
                        response = JSON.stringify(require('MeshAgent').eval(args['_'][0])); // This can only be run by trusted administrator.
                    }
                    break;
                }
            case 'setdebug':
                {
                    if (args['_'].length < 1) { response = 'Proper usage: setdebug (target), 0 = Disabled, 1 = StdOut, 2 = This Console, * = All Consoles, 4 = WebLog, 8 = Logfile'; } // Display usage
                    else { if (args['_'][0] == '*') { console.setDestination(2); } else { console.setDestination(parseInt(args['_'][0]), sessionid); } }
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
            case 'dbkeys': { // Return all data store keys
                response = JSON.stringify(db.Keys);
                break;
            }
            case 'dbget': { // Return the data store value for a given key
                if (db == null) { response = "Database not accessible."; break; }
                if (args['_'].length != 1) {
                    response = "Proper usage: dbget (key)"; // Display the value for a given database key
                } else {
                    response = db.Get(args['_'][0]);
                }
                break;
            }
            case 'dbset': { // Set a data store key and value pair
                if (db == null) { response = "Database not accessible."; break; }
                if (args['_'].length != 2) {
                    response = "Proper usage: dbset (key) (value)"; // Set a database key
                } else {
                    var r = db.Put(args['_'][0], args['_'][1]);
                    response = "Key set: " + r;
                }
                break;
            }
            case 'dbcompact': { // Compact the data store
                if (db == null) { response = "Database not accessible."; break; }
                var r = db.Compact();
                response = "Database compacted: " + r;
                break;
            }
            case 'tunnels': { // Show the list of current tunnels
                response = '';
                for (var i in tunnels) { response += "Tunnel #" + i + ", " + tunnels[i].url + '\r\n'; }
                if (response == '') { response = "No websocket sessions."; }
                break;
            }
            case 'netinfo': { // Show network interface information
                //response = objToString(mesh.NetInfo, 0, ' ');
                var interfaces = require('os').networkInterfaces();
                response = objToString(interfaces, 0, ' ', true);
                break;
            }
            case 'name':
                {
                    response = 'Service Name = ' + require('MeshAgent').serviceName;
                }
                break;
        }
    } catch (e) { response = "Command returned an exception error: " + e; console.log(e); }
    if (response != null) { sendConsoleText(response, sessionid); }
}

// Get a formatted response for a given directory path
function getDirectoryInfo(reqpath) {
    var response = { path: reqpath, dir: [] };
    if (((reqpath == undefined) || (reqpath == '')) && (process.platform == 'win32')) {
        // List all the drives in the root, or the root itself
        var results = null;
        try { results = fs.readDrivesSync(); } catch (e) { } // TODO: Anyway to get drive total size and free space? Could draw a progress bar.
        if (results != null) {
            for (var i = 0; i < results.length; ++i) {
                var drive = { n: results[i].name, t: 1 };
                if (results[i].type == 'REMOVABLE') { drive.dt = 'removable'; } // TODO: See if this is USB/CDROM or something else, we can draw icons.
                response.dir.push(drive);
            }
        }
    } else {
        // List all the files and folders in this path
        if (reqpath == '') { reqpath = '/'; }
        var results = null, xpath = path.join(reqpath, '*');
        //if (process.platform == "win32") { xpath = xpath.split('/').join('\\'); }
        try { results = fs.readdirSync(xpath); } catch (e) { }
        if (results != null) {
            for (var i = 0; i < results.length; ++i) {
                if ((results[i] != '.') && (results[i] != '..')) {
                    var stat = null, p = path.join(reqpath, results[i]);
                    //if (process.platform == "win32") { p = p.split('/').join('\\'); }
                    try { stat = fs.statSync(p); } catch (e) { } // TODO: Get file size/date
                    if ((stat != null) && (stat != undefined)) {
                        if (stat.isDirectory() == true) {
                            response.dir.push({ n: results[i], t: 2, d: stat.mtime });
                        } else {
                            response.dir.push({ n: results[i], t: 3, s: stat.size, d: stat.mtime });
                        }
                    }
                }
            }
        }
    }
    return response;
}
// Delete a directory with a files and directories within it
function deleteFolderRecursive(path, rec) {
    if (fs.existsSync(path)) {
        if (rec == true) {
            fs.readdirSync(path.join(path, '*')).forEach(function (file, index) {
                var curPath = path.join(path, file);
                if (fs.statSync(curPath).isDirectory()) { // recurse
                    deleteFolderRecursive(curPath, true);
                } else { // delete file
                    fs.unlinkSync(curPath);
                }
            });
        }
        fs.unlinkSync(path);
    }
};
