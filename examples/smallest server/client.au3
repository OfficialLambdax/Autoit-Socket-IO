#NoTrayIcon
#include "..\..\_netcode.au3"

;~ _Io_DevDebug(True)
;~ _netcode_SetOption("DebugLogToConsole", True)
_netcode_SetMessageCallback("_Net_Message")

Global $___hServerSocket = _netcode_Connect('127.0.0.1', '1225')
Global $___sLastMessageFromServer = ""

_netcode_Send($___hServerSocket, 'netcode_message', '1111')

While _Io_Loop($___hServerSocket)
	if $___sLastMessageFromServer <> "" Then
		_netcode_Send($___hServerSocket, 'netcode_message', '1111' & $___sLastMessageFromServer)
		$___sLastMessageFromServer = ""
	EndIf
WEnd

Func _Net_Message(Const $hSocket, $sMessage)
	Local Static $nCount = 0
	$nCount += 1
	ConsoleWrite($nCount & " Server: " & $hSocket & " message len " & StringLen($sMessage) & @CRLF)
	$___sLastMessageFromServer = $sMessage
EndFunc
