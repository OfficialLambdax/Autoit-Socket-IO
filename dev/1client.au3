#NoTrayIcon
#Region ;**** Directives created by AutoIt3Wrapper_GUI ****
#AutoIt3Wrapper_Version=Beta
#AutoIt3Wrapper_Change2CUI=y
#AutoIt3Wrapper_Run_Au3Stripper=n
#AutoIt3Wrapper_UseX64=n
#EndRegion ;**** Directives created by AutoIt3Wrapper_GUI ****
#AutoIt3Wrapper_Au3stripper_OnError=ForceUse
#Au3Stripper_Ignore_Funcs=_Net_*
#Au3Stripper_Ignore_Funcs=_Sync_*
#include "_netcode.au3"
;~ #include <Inet.au3>

;~ _Io_DevDebug(True)
_Io_SetBytesPerSecond(True)

Global $___nServerPort = 1225
;~ Global $___sServerIP = _netcode_GetIP()
Global $___sServerIP = '127.0.0.1'
;~ if @Compiled Then $___sServerIP = InputBox("", "", "127.0.0.1")
if @error Then Exit
Global $___hServerSocket
Global $___bServerConnected = False
Global $___bSendData = False


;~ _netcode_SetOption("DebugLogToConsole", True)
_netcode_SetConnectionCallback("_Net_Connect")
_netcode_SetDisconnectCallback("_Net_Disconnect")
_netcode_SetMessageCallback("_Net_Message")
;~ _netcode_SetEncryptionCallback("_Net_Encrypt")
;~ _netcode_SetDecryptionCallback("_Net_Decrypt")
;~ _netcode_SetOption("SetFloodWaitForPreventionPacket", False)
;~ _netcode_SetOption("SetCryptionMode", "default")
_netcode_SetOption("SetAutoSplitBigPackets", True)
;~ _netcode_SetOption("SetEncryptionPassword", "testpw")
_netcode_SetOption("EnableEncryption", "testpw")
;~ _netcode_SetOption("SetOnlySendInLoop", True)
_netcode_SetNetworkCustomSync("ServerVersion", '?', '_Sync_DevServer', '', '', '', True)
_netcode_SetNetworkCustomSync("ClientAuth", '!', 'My Name is Dev')
_netcode_SetNetworkCustomAllow("ClientAuth", True)

ConsoleWrite("Client trying to Connect to " & $___sServerIP & ':' & $___nServerPort & @CRLF)

While True
	if Not $___bServerConnected Then _netcode_Connect($___sServerIP, $___nServerPort)
;~ 	if Not $___bServerConnected Then _netcode_ConnectTor($___sServerIP, $___nServerPort, 'u2g7ymb532whqquy3xfdnfqe7vigwp5ofifiwis2h4mufarfnoer5uad.onion', 1225)
;~ 	if Not $___bServerConnected Then _netcode_ConnectTor($___sServerIP, $___nServerPort, _netcode_GetIP(), 1225)
	if $___bServerConnected Then _Io_Loop($___hServerSocket)
;~ 	if $___bServerConnected Then _SendData_MaxTest_Perma()
	if $___bServerConnected Then _SendData_2MBTest_Perma()
;~ 	if $___bServerConnected Then _SendData_20MBTest()
;~ 	if $___bServerConnected Then _SendData_100KBytesTest_Perma()
;~ 	if $___bServerConnected Then _SendData_SingleByteTest()
WEnd

Func _SendData_SingleByteTest()
	ConsoleWrite("Bytes Send: " & _netcode_Send($___hServerSocket, 'netcode_message', '1') & @CRLF)
	ConsoleWrite(Round(_Io_GetBytesPerSecond($___hServerSocket, False) / 1024, 2) & ' KB/s' & @CRLF)

	$arTmp = _Io_GetLastMeassurements()
	ConsoleWrite("From Emit to TCPSend() took: " & $arTmp[0][1] & @CRLF)

	ConsoleWrite(@CRLF)
EndFunc

Func _SendData_20MBTest()
	if $___bSendData Then Return
	ConsoleWrite("Testing _netcode_Send() with 20 MB" & @CRLF)

	Local $hTimer = TimerInit()
	Local $sData = ""
	For $i = 1 To (1048576 * 20)
		$sData &= '1'
	Next
	ConsoleWrite("Generating Data Took " & TimerDiff($hTimer) & ' Hash is ' & _Crypt_HashData($sData, $CALG_SHA1) & @CRLF)

	ConsoleWrite("Bytes Send: " & _netcode_Send($___hServerSocket, 'netcode_message', $sData) & @CRLF)
	ConsoleWrite(Round(_Io_GetBytesPerSecond($___hServerSocket, False) / 1024, 2) & ' KB/s' & @CRLF)

	$arTmp = _Io_GetLastMeassurements()
	ConsoleWrite("From Emit to TCPSend() took: " & $arTmp[0][1] & @CRLF)

	$___bSendData = True
	ConsoleWrite(@CRLF)
;~ 	Exit
	Return
EndFunc

Func _SendData_2MBTest_Perma()
	Local Static $sData = "", $sHash = ""
	if $sData = "" Then
		ConsoleWrite("Testing _netcode_Send() with 2 MB" & @CRLF)

		Local $hTimer = TimerInit()

		For $i = 1 To (1048576 * 2)
			$sData &= '1'
		Next
		ConsoleWrite("Generating Data Took " & TimerDiff($hTimer) & @CRLF)
		$sHash = _Crypt_HashData($sData, $CALG_SHA1)

	EndIf

	ConsoleWrite("Bytes Send: " & _netcode_Send($___hServerSocket, 'netcode_message', $sData) & ' Hash is ' & $sHash & @CRLF)
	ConsoleWrite("Sending: " & Round(_Io_GetBytesPerSecond($___hServerSocket, False) / 1024, 2) & ' KB/s' & @CRLF)

	$arTmp = _Io_GetLastMeassurements()
	ConsoleWrite("From Emit to TCPSend() took: " & $arTmp[0][1] & @CRLF)

	ConsoleWrite(@CRLF)

	Return
EndFunc

Func _SendData_MaxTest_Perma()
	Local Static $sData = "", $sHash = ""
	if $sData = "" Then
		ConsoleWrite("Testing _netcode_Send() with Maximum Size" & @CRLF)

		Local $hTimer = TimerInit()

		For $i = 1 To _netcode_GetMaxPacketContentSize('netcode_message')
			$sData &= '1'
		Next
		ConsoleWrite("Generating Data Took " & TimerDiff($hTimer) & @CRLF)
		$sHash = _Crypt_HashData($sData, $CALG_SHA1)

	EndIf

	ConsoleWrite("Bytes Send: " & _netcode_Send($___hServerSocket, 'netcode_message', $sData) & ' Hash is ' & $sHash & @CRLF)
	ConsoleWrite("Sending: " & Round(_Io_GetBytesPerSecond($___hServerSocket, False) / 1024, 2) & ' KB/s' & @CRLF)

	$arTmp = _Io_GetLastMeassurements()
	ConsoleWrite("From Emit to TCPSend() took: " & $arTmp[0][1] & @CRLF)

	ConsoleWrite(@CRLF)

	Return
EndFunc

Func _SendData_100KBytesTest_Perma()
	Local Static $sData = "", $sHash = ""
	if $sData = "" Then
		ConsoleWrite("Testing _netcode_Send() with 2 MB" & @CRLF)

		Local $hTimer = TimerInit()

		For $i = 1 To 1024 * 100
;~ 		For $i = 1 To 1000
			$sData &= '1'
		Next
		ConsoleWrite("Generating Data Took " & TimerDiff($hTimer) & @CRLF)
		$sHash = _Crypt_HashData($sData, $CALG_SHA1)

	EndIf

	ConsoleWrite("Bytes Send: " & _netcode_Send($___hServerSocket, 'netcode_message', $sData) & ' Hash is ' & $sHash & @CRLF)
	ConsoleWrite("Sending: " & Round(_Io_GetBytesPerSecond($___hServerSocket, False) / 1024, 2) & ' KB/s' & @CRLF)

	$arTmp = _Io_GetLastMeassurements()
	ConsoleWrite("From Emit to TCPSend() took: " & $arTmp[0][1] & @CRLF)

	ConsoleWrite(@CRLF)

	Return
EndFunc


;~ Func _CheckConnection($ServerIP, $ServerPort)
;~ 	$try = _netcode_Connect($___sServerIP, $___nServerPort)
;~ 	if @error Then Return
;~ EndFunc

Func _Net_Connect(Const $hSocket)
	ConsoleWrite("Connected. Socket is: " & $hSocket & @CRLF)
	Local $hTimer_SyncTime = TimerInit()

	$___hServerSocket = $hSocket
	$___bServerConnected = True

	ConsoleWrite("Syncing with Socket: " & $hSocket & @CRLF)
	_netcode_Sync_Netcode($___hServerSocket)

	While Sleep(1)
		if _netcode_Sync_Check($___hServerSocket) Then ExitLoop
		_Io_Loop($___hServerSocket)
		if Not $___bServerConnected Then Return False ; if disconnected
	WEnd
	ConsoleWrite("Synchronized in " & Round(TimerDiff($hTimer_SyncTime), 2) & " ms with Socket: " & $hSocket & @CRLF)
;~ 	__Io_BytesPerSecond($hSocket, "Reset")
EndFunc

Func _Net_Disconnect(Const $hSocket)
	ConsoleWrite("Disconnected from Socket: " & $hSocket & @CRLF)
	$___bServerConnected = False
	$___bSendData = False

	if @Compiled Then Exit ; for development purposes
EndFunc

Func _Net_Message(Const $hSocket, $sData)
;~ 	ConsoleWrite("Message from: " & $hSocket & @TAB & " Message Len " & Round(StringLen($sData) / 1024, 2) & ' KB' & @CRLF)
;~ 	ConsoleWrite("Message from: " & $hSocket & @TAB & " Message Len " & Round(StringLen($sData) / 1024, 2) & ' KB Hash is ' & _Crypt_HashData($sData, $CALG_SHA1) & @CRLF)
	ConsoleWrite("Message from: " & $hSocket & @TAB & $sData & @CRLF)
;~ 	$arTmp = _Io_GetLastMeassurements()
;~ 	ConsoleWrite($hSocket & " from Recv to FireEvent Call() took: " & Round($arTmp[1][1], 2) & ' ms' & @CRLF)
EndFunc

Func _Sync_DevServer($hSocket, $sMode, $sData)
	Local $sServerVersion = 'Development Server'

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