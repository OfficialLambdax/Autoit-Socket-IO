#Region ;**** Directives created by AutoIt3Wrapper_GUI ****
#AutoIt3Wrapper_Version=Beta
#AutoIt3Wrapper_Change2CUI=y
#EndRegion ;**** Directives created by AutoIt3Wrapper_GUI ****
#NoTrayIcon
#include-once
#include "_sharedfuncs.au3"

Global $__s_MyPrivateKey = @ScriptDir & "\RSA_Server_private.blob"
Global $__s_MyPublicKey = @ScriptDir & "\RSA_Server_public.blob"
Global $__h_MySocket = 0

;~ _Io_DevDebug(True)
;~ _netcode_SetOption("DebugLogToConsole", True)
_RSA_EnableConsole(True)

_RSA_CreatePrivateAndPublicKeys(2048, $__s_MyPublicKey, $__s_MyPrivateKey)
_RSA_MyPublicAndPrivateKey($__s_MyPublicKey, $__s_MyPrivateKey)
_RSA_EnableRSA(True)

_netcode_SetConnectionCallback("_Net_Connect")
_netcode_SetDisconnectCallback("_Net_Disconnect")
_netcode_SetMessageCallback("_Net_Message")
_netcode_SetNetworkCustomSync("ServerVersion", '!', 'RSA Example Server')
_netcode_SetNetworkCustomAllow("ServerVersion", True)

_StartServer()

ConsoleWrite("Press SHIFT + D to Broadcast a Messages to all Clients." & @CRLF)
HotKeySet('+d', "_RSA_Test") ; hotkey is slightly delayed


While True
	_Io_Loop($__h_MySocket)
WEnd


Func _RSA_TEST()
	$nSendBytes = _netcode_Broadcast($__h_MySocket, 'netcode_message', 'Hi from Server. Who am i to you?')
	ConsoleWrite("Send " & $nSendBytes & ' bytes' & @CRLF)
EndFunc



Func _Net_Message($hSocket, $sData)
	ConsoleWrite($hSocket & @TAB & "message: " & @TAB & $sData & @CRLF)
EndFunc

Func _Net_Connect($hSocket)
	ConsoleWrite("New Socket at: " & $hSocket & @CRLF)
	_netcode_Sync_Netcode($hSocket)
EndFunc

Func _Net_Disconnect($hSocket)
	ConsoleWrite($hSocket & @TAB & "left server" & @CRLF)
EndFunc

Func _StartServer()
	$__h_MySocket = _netcode_Listen('0.0.0.0', 1225)
	if @error Then
		ConsoleWrite("Port taken?" & @CRLF)
		Exit
	EndIf

	ConsoleWrite("RSA Example Server Online" & @CRLF)
EndFunc

