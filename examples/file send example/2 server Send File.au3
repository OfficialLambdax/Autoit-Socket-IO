#NoTrayIcon
#Region ;**** Directives created by AutoIt3Wrapper_GUI ****
#AutoIt3Wrapper_Change2CUI=y
#EndRegion ;**** Directives created by AutoIt3Wrapper_GUI ****
#include-once
#include "..\..\_netcode.au3"


;~ _Io_DevDebug(True)

Global $___nServerIP = "0.0.0.0"
Global $___nServerPort = "1225"
Global $___hServerSocket
;~ Global $___sfDownloadDir = @ScriptDir & "\Downloads"
;~ Global $___hMeassurementTimer

Global $___bFileToTransferSet = False
Global $___hFileHandle
Global $___sfFileToUpload = ""
Global $___nFileSize = 0
Global $___bConnectedToClient = False
Global $___hClientSocket

;~ _netcode_SetOption("DebugLogToConsole", True)
_netcode_SetOption("SetMaxPackageSize", 1048576 * 2)
_netcode_SetConnectionCallback("_NewClientConnection")
_netcode_SetDisconnectCallback("_ClientDisconnect")
;~ _netcode_SetMessageCallback("_StandardMessage")
_netcode_SetFloodCallback("_Flood")
_netcode_SetCustomSocketEvent("FileTransfer")
_netcode_SetNetworkCustomSync("ServerVersion", '!', 'Example File Send')
_netcode_SetNetworkCustomAllow("ServerVersion", True)


$___hServerSocket = _netcode_Listen($___nServerIP, $___nServerPort)
if @error Then Exit

ConsoleWrite("File Upload Server Up" & @CRLF)

While True
	_Io_Loop($___hServerSocket)
;~ 	_Io_Loop()
	if $___bConnectedToClient Then _FileTransfer()
WEnd

Func _FileTransfer()
	if $___sfFileToUpload = "" Then
		$___sfFileToUpload = FileOpenDialog("Choose File to Upload", @ScriptDir, "(*.*)", 1)
		if @error Then Exit

		$sFileName = StringTrimLeft($___sfFileToUpload, StringInStr($___sfFileToUpload, '\', 0, -1))
		$___nFileSize = FileGetSize($___sfFileToUpload)
		_netcode_Send($___hClientSocket, 'FileTransfer', 'Register|' & $sFileName & '|' & $___nFileSize)
	EndIf

	if $___bFileToTransferSet Then
		$sRead = FileRead($___hFileHandle, _netcode_GetMaxPacketContentSize('FileTransfer') / 2)
		if @error = -1 Then
			FileClose($___hFileHandle)
			$___bFileToTransferSet = False
			_netcode_Send($___hClientSocket, 'FileTransfer', "Done")
			ConsoleWrite("Upload Done" & @CRLF)
		Else
			$nBytesSend = _netcode_Send($___hClientSocket, 'FileTransfer', 'Stream|' & $sRead)
			ConsoleWrite("Send " & Round($nBytesSend / 1024, 2) & ' KB' & @TAB & @TAB & FileGetPos($___hFileHandle) & ' / ' & $___nFileSize & @CRLF)
		EndIf

	EndIf
EndFunc

Func _On_FileTransfer(Const $hSocket, $sData)
	Local $arData = StringSplit($sData, '|', 1 + 2)

	Switch $arData[0]
		Case "OK"
			$___bFileToTransferSet = True
			$___hFileHandle = FileOpen($___sfFileToUpload, 16)
			ConsoleWrite("Client Send OK" & @CRLF)

		Case "Done"
			ConsoleWrite("Exiting" & @CRLF)
			$___sfFileToUpload = ""

		Case "SynDone"
			ConsoleWrite("Client Synchronized" & @CRLF)
			$___bConnectedToClient = True
			$___hClientSocket = $hSocket

	EndSwitch
EndFunc



Func _NewClientConnection(Const $hSocket)
	ConsoleWrite("New Client at: " & $hSocket & @CRLF)
;~ 	$___bConnectedToClient = True
EndFunc

Func _ClientDisconnect(Const $hSocket)
	ConsoleWrite("Client Disconnected: " & $hSocket & @CRLF)
	$___bFileToTransferSet = False
	$___sfFileToUpload = ""
	$___bConnectedToClient = False
	$___hClientSocket = 0
EndFunc

Func _StandardMessage(Const $hSocket, $sData)
	ConsoleWrite("Socket: " & $hSocket & " says: " & $sData & @CRLF)
EndFunc

Func _Flood(Const $hSocket)
	ConsoleWrite($hSocket & " flood" & @CRLF)
EndFunc
