#NoTrayIcon
#Region ;**** Directives created by AutoIt3Wrapper_GUI ****
#AutoIt3Wrapper_Version=Beta
#AutoIt3Wrapper_Change2CUI=y
#EndRegion ;**** Directives created by AutoIt3Wrapper_GUI ****
#include-once
#include "..\..\_netcode.au3"

;~ _Io_DevDebug(True)
_Io_SetBytesPerSecond(True)

;~ Global $___nServerIP = _netcode_GetIP()
Global $___nServerIP = InputBox('', "What IP", "127.0.0.1")
Global $___nServerPort = "1225"
Global $___hServerSocket
Global $___bConnectedToServer = False
Global $___bFileToTransferSet = False
Global $___hFileHandle
Global $___sfFileToUpload = ""
Global $___nFileSize = 0

;~ _netcode_SetOption("DebugLogToConsole", True)
_netcode_SetOption("SetCryptionMode", "default")
;~ _netcode_SetOption("EnableEncryption", "testpw")
_netcode_SetConnectionCallback("_ConnectedToServer")
_netcode_SetDisconnectCallback("_DisconnectedFromServer")
_netcode_SetCustomSocketEvent("FileTransfer")
_netcode_SetNetworkCustomSync("ServerVersion", '?', '_Sync_DevServer', '', '', '', True)

ConsoleWrite("Client trying to Connect to " & $___nServerIP & ':' & $___nServerPort & @CRLF)

While Sleep(1)
	if Not $___bConnectedToServer Then _netcode_Connect($___nServerIP, $___nServerPort)
	if $___bConnectedToServer Then _Io_Loop($___hServerSocket)
	if $___bConnectedToServer Then _FileTransfer()
WEnd

Func _FileTransfer()
	if $___sfFileToUpload = "" Then
		$___sfFileToUpload = FileOpenDialog("Choose File to Upload", @ScriptDir, "(*.*)", 1)
		if @error Then Exit

		$sFileName = StringTrimLeft($___sfFileToUpload, StringInStr($___sfFileToUpload, '\', 0, -1))
		$___nFileSize = FileGetSize($___sfFileToUpload)
		_netcode_Send($___hServerSocket, 'FileTransfer', 'Register|' & $sFileName & '|' & $___nFileSize)
	EndIf

	if $___bFileToTransferSet Then
		$sRead = FileRead($___hFileHandle, _netcode_GetMaxPacketContentSize('FileTransfer'))
		if @error = -1 Then
			FileClose($___hFileHandle)
			$___bFileToTransferSet = False
			_netcode_Send($___hServerSocket, 'FileTransfer', "Done")
			ConsoleWrite("Upload Done" & @CRLF)
		Else
			$nBytesSend = _netcode_Send($___hServerSocket, 'FileTransfer', _Io_sParams('Stream', BinaryToString($sRead)))
;~ 			ConsoleWrite("Send " & Round($nBytesSend / 1024, 2) & ' KB' & @TAB & FileGetPos($___hFileHandle) & ' / ' & $___nFileSize & @TAB & @TAB & Round(_Io_GetBytesPerSecond($___hServerSocket, False) / 1024, 2) & ' KB/s' & @TAB & _Crypt_HashData($sRead, $CALG_MD5) & @CRLF)
			ConsoleWrite("Send " & Round($nBytesSend / 1024, 2) & ' KB' & @TAB & FileGetPos($___hFileHandle) & ' / ' & $___nFileSize & @TAB & @TAB & Round(_Io_GetBytesPerSecond($___hServerSocket, False) / 1024, 2) & ' KB/s' & @CRLF)
		EndIf
	EndIf
EndFunc

Func _On_FileTransfer(Const $hSocket, $sData)
	Local $arData = StringSplit($sData, '|', 1 + 2)

	Switch $arData[0]
		Case "OK"
			$___bFileToTransferSet = True
			$___hFileHandle = FileOpen($___sfFileToUpload, 16)
			ConsoleWrite("Server Send OK" & @CRLF)

		Case "Done"
;~ 			ConsoleWrite("Exiting" & @TAB & @TAB & _Crypt_HashFile($___sfFileToUpload, $CALG_MD5) & @CRLF)
			ConsoleWrite("Exiting" & @CRLF)
			$___sfFileToUpload = ""
	EndSwitch
EndFunc





Func _ConnectedToServer(Const $hSocket)
	ConsoleWrite("Connected to Server on Socket: " & $hSocket & @CRLF)
	$___hServerSocket = $hSocket
	$___bConnectedToServer = True

	ConsoleWrite("Trying to Syn with server" & @CRLF)
	_netcode_Sync_Netcode($___hServerSocket)

	While Sleep(1)
		if _netcode_Sync_Check($___hServerSocket) Then ExitLoop
		_Io_Loop($___hServerSocket)
		if Not $___bConnectedToServer Then Return
	WEnd

	ConsoleWrite("Syn Finished" & @CRLF)
EndFunc

Func _DisconnectedFromServer(Const $hSocket)
	ConsoleWrite("Disconnected From Server on Socket: " & $hSocket & @CRLF)
	$___bConnectedToServer = False
	$___bFileToTransferSet = False
	$___sfFileToUpload = ""
EndFunc

Func _Sync_DevServer($hSocket, $sMode, $sData)
	Local $sServerVersion = 'Example File Recv'

	Switch $sMode
		Case "GET"
			Return $sServerVersion

		Case "POST"
			if $sServerVersion <> $sData Then
				MsgBox(0, "", "We Dont Support this Server. Exiting")
				Exit
			EndIf
			Return

	EndSwitch
EndFunc