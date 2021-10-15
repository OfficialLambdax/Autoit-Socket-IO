#Region ;**** Directives created by AutoIt3Wrapper_GUI ****
#AutoIt3Wrapper_Version=Beta
#AutoIt3Wrapper_Change2CUI=y
#EndRegion ;**** Directives created by AutoIt3Wrapper_GUI ****
#NoTrayIcon
#include-once
#include <Inet.au3>
#include "_sharedfuncs.au3"

Global $__s_MyPrivateKey = @ScriptDir & "\RSA_Client_private.blob"
Global $__s_MyPublicKey = @ScriptDir & "\RSA_Client_public.blob"
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
_netcode_SetNetworkCustomSync("ServerVersion", '?', '_Sync_DevServer', '', '', '', True)

ConsoleWrite("Trying to Connect to Server" & @CRLF)

While Sleep(50)
	_netcode_Connect('127.0.0.1', 1225)
	if Not @error Then ExitLoop
WEnd

ConsoleWrite("Connected to RSA Server at " & $__h_MySocket & @CRLF)
ConsoleWrite("Syncing with Server" & @CRLF)

_netcode_Sync_Netcode($__h_MySocket)

While Sleep(10)
	if _netcode_Sync_Check($__h_MySocket) Then ExitLoop
	_Io_Loop($__h_MySocket)
WEnd

ConsoleWrite("Client ready for encrypted Messages" & @CRLF)
;~ HotKeySet('+d', "_RSA_Test")


While True
	_Io_Loop($__h_MySocket)
WEnd


Func _RSA_TEST()
	$nSendBytes = _netcode_Send($__h_MySocket, 'netcode_message', 'Hi from Client')
;~ 	ConsoleWrite("Send " & $nSendBytes & @CRLF)
EndFunc


Func _Net_Message($hSocket, $sData)
	ConsoleWrite($hSocket & @TAB & "message: " & @TAB & $sData & @CRLF)
	_netcode_Send($hSocket, 'netcode_message', 'Hi from Client. I registered you as ' & $__h_MySocket)
EndFunc

Func _Net_Connect($hSocket)
	$__h_MySocket = $hSocket
EndFunc

Func _Net_Disconnect($hSocket)
	Exit
EndFunc

Func _Sync_DevServer($hSocket, $sMode, $sData)
	Local $sServerVersion = 'RSA Example Server'

	Switch $sMode
		Case "GET"
			Return $sServerVersion

		Case "POST"
;~ 			MsgBox(0, "", $sData)
			if $sServerVersion <> $sData Then
				MsgBox(0, "", "We Dont Support this Server. Exiting")
				Exit
			EndIf
			Return

	EndSwitch
EndFunc