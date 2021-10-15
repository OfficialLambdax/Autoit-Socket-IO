#NoTrayIcon
#Region ;**** Directives created by AutoIt3Wrapper_GUI ****
#AutoIt3Wrapper_Version=Beta
#AutoIt3Wrapper_UseX64=n
#AutoIt3Wrapper_Change2CUI=y
#AutoIt3Wrapper_Run_Au3Stripper=n
#EndRegion ;**** Directives created by AutoIt3Wrapper_GUI ****
#AutoIt3Wrapper_Au3stripper_OnError=ForceUse
#Au3Stripper_Ignore_Funcs=_Net_*
#Au3Stripper_Ignore_Funcs=_Sync_*
#include "_netcode.au3"

;~ _Io_DevDebug(True)
_Io_SetBytesPerSecond(True)

Global $___nServerPort = 1225
Global $___sServerIP = "0.0.0.0"
Global $___hServerSocket
Global $___bServerListen = False


; Callback Options
_netcode_SetConnectionCallback("_Net_Connect")
_netcode_SetDisconnectCallback("_Net_Disconnect")
_netcode_SetMessageCallback("_Net_Message")
_netcode_SetFloodCallback("_Net_Flood")

;~ _netcode_SetOption("DebugLogToConsole", True)
_netcode_SetOption("SetMaxPackageSize", 1048576 * 5)
_netcode_SetOption("SetAutoSplitBigPackets", True)
;~ _netcode_SetOption("SetCryptionMode", "default")
_netcode_SetOption("EnableEncryption", "testpw")
;~ _netcode_SetOption("SetAcceptUnecryptedTraffic", True)
;~ _netcode_SetOption("SetPacketValidation", True)
;~ _netcode_SetOption("SetPacketSafety", True) ; Validation needs to be enabled
;~ _netcode_SetOption("SetFloodPrevention", False)
;~ _netcode_SetOption("SetFloodWaitForPreventionPacket", False)
_netcode_SetNetworkCustomSync("ServerVersion", '!', 'Development Server')
_netcode_SetNetworkCustomAllow("ServerVersion", True)
_netcode_SetNetworkCustomSync("ClientAuth", '?', '_Sync_ClientAuth', '', '', 'String', True)

;~ HotKeySet('+d', '_Net_Broadcast')

While True
	_CheckServer($___sServerIP, $___nServerPort)
	if $___bServerListen Then _Io_Loop($___hServerSocket)
WEnd

;~ Func _Net_Broadcast()
;~ 	ConsoleWrite("Broadcasting" & @CRLF)
;~ 	_netcode_Broadcast($___hServerSocket, 'netcode_message', "Hello from Server")
;~ EndFunc

Func _Sync_ClientAuth(Const $hSocket, $sMode, $sData)
	ConsoleWrite("Client: " & $hSocket & " authes as: " & $sData & @CRLF)
EndFunc

Func _CheckServer($sIP, $sPort)
	if $___bServerListen Then Return
	$try = _netcode_Listen($sIP, $sPort)
	if @error Then
		ConsoleWrite("Port already taken? Error: " & @error & @CRLF)
		Exit
	EndIf

	$___hServerSocket = $try
	$___bServerListen = True

	ConsoleWrite("Development Server Started" & @CRLF)
EndFunc

Func _Net_Connect(Const $hSocket)
	ConsoleWrite("Con SOCKET: " & $hSocket & @TAB & "IP: " & __Io_SocketToIp($hSocket) & @CRLF)
	_netcode_Sync_Netcode($hSocket)
EndFunc

Func _Net_Disconnect(Const $hSocket)
	ConsoleWrite("Dis SOCKET: " & $hSocket & @CRLF)
EndFunc

Func _Net_Flood(Const $hSocket)
	ConsoleWrite($hSocket & " flood" & @CRLF)
EndFunc

Func _Net_Message(Const $hSocket, $sData)
	ConsoleWrite("Message from: " & $hSocket & @TAB & " Message Len " & Round(StringLen($sData) / 1024, 2) & ' KB' & @CRLF)
;~ 	ConsoleWrite("Message from: " & $hSocket & @TAB & " Message Len " & Round(StringLen($sData) / 1024, 2) & ' KB Hash is ' & _Crypt_HashData($sData, $CALG_SHA1) & @CRLF)
;~ 	ConsoleWrite("Message from: " & $hSocket & @TAB & $sData & @CRLF)
	ConsoleWrite("Receiving: " & Round(_Io_GetBytesPerSecond($hSocket, True) / 1024, 2) & ' KB/s' & @CRLF)
	$arTmp = _Io_GetLastMeassurements()
	ConsoleWrite($hSocket & " from Recv to FireEvent Call() took: " & Round($arTmp[1][1], 2) & ' ms' & @CRLF)
	ConsoleWrite(@CRLF)
EndFunc