#NoTrayIcon
#include "_netcode Performancetest.au3"

;~ _netcode_SetOption("DebugLogToConsole", True)
_netcode_PerformanceTestClient('127.0.0.1', 1225)
;~ _netcode_PerformanceTestClient(_netcode_GetIP(), 1225)
