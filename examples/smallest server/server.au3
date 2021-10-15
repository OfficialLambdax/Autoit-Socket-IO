#NoTrayIcon
#include "..\..\_netcode.au3"

;~ _Io_DevDebug(True)
;~ _netcode_SetOption("DebugLogToConsole", True)
_netcode_SetMessageCallback("_Net_Message")

Global $___hServerSocket = _netcode_Listen('0.0.0.0', '1225')

While _Io_Loop($___hServerSocket)
WEnd

Func _Net_Message(Const $hSocket, $sMessage)
	Local Static $nCount = 0
	$nCount += 1
	ConsoleWrite($nCount & " Client: " & $hSocket & " message len " & StringLen($sMessage) & @CRLF)
	_netcode_Send($hSocket, 'netcode_message', '1111' & $sMessage)
EndFunc
