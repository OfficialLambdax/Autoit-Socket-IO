#NoTrayIcon
#Region ;**** Directives created by AutoIt3Wrapper_GUI ****
#AutoIt3Wrapper_Change2CUI=y
#EndRegion ;**** Directives created by AutoIt3Wrapper_GUI ****
#include-once
#include "..\..\_netcode.au3"

;~ _Io_DevDebug(True)

;~ Global $___nServerIP = "127.0.0.1"
Global $___nServerIP = InputBox('', "What IP", "127.0.0.1")
Global $___nServerPort = "1225"
Global $___hServerSocket
Global $___bConnectedToServer = False

Global $___sfDownloadDir = @ScriptDir & "\Downloads"
Global $___hMeassurementTimer


;~ _netcode_SetOption("DebugLogToConsole", True)
_netcode_SetConnectionCallback("_ConnectedToServer")
_netcode_SetDisconnectCallback("_DisconnectedFromServer")
;~ _netcode_SetMessageCallback("_StandardMessage")
_netcode_SetCustomSocketEvent("FileTransfer")
_netcode_SetNetworkCustomSync("ServerVersion", '?', '_Sync_DevServer', '', '', '', True)

ConsoleWrite("Client trying to Connect to " & $___nServerIP & ':' & $___nServerPort & @CRLF)

While Sleep(1)
	if Not $___bConnectedToServer Then _netcode_Connect($___nServerIP, $___nServerPort)
	if $___bConnectedToServer Then _Io_Loop($___hServerSocket)
WEnd

Func _On_FileTransfer(Const $hSocket, $sData)
	Local Static $sfFilePath = "", $hFileHandle, $bRegistered = False, $nFileSize = 0, $nAlreadyTransmitted = 0
	Local $arData = StringSplit($sData, '|', 1 + 2)

	Switch $arData[0]
		Case "Register" ; 1 = FileName | 2 = FileSize
			$___hMeassurementTimer = TimerInit()
			; check for \..\
			$sfFilePath = $___sfDownloadDir & "\" & $arData[1]
			$nFileSize = $arData[2]
			$hFileHandle = FileOpen($sfFilePath, 18)
			$bRegistered = True
			_netcode_Send($hSocket, 'FileTransfer', 'OK')
			ConsoleWrite("Download Registered " & $arData[1] & " with size " & Round($arData[2] / 1024, 2) & ' KB' & @CRLF)

		Case "Stream"
			FileWrite($hFileHandle, $arData[1])
			$nLen = StringLen($arData[1])
			$nAlreadyTransmitted += $nLen / 2 ; because binary
			ConsoleWrite("Received " & Round(StringLen($sData) / 1024, 2) & " KB" & @TAB & '~ ' & $nAlreadyTransmitted & ' / ' & $nFileSize & @CRLF)

		Case "Done"
			FileClose($hFileHandle)
			$bRegistered = False
			$nAlreadyTransmitted = 0
			_netcode_Send($hSocket, 'FileTransfer', "Done")
			ConsoleWrite("Download Finished" & @CRLF)
			ConsoleWrite("Took " & Round(TimerDiff($___hMeassurementTimer) / 1000, 2) & ' Seconds' & @CRLF)

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

	_netcode_Send($___hServerSocket, 'FileTransfer', 'SynDone')
	ConsoleWrite("Syn Finished" & @CRLF)
EndFunc

Func _DisconnectedFromServer(Const $hSocket)
	ConsoleWrite("Disconnected From Server on Socket: " & $hSocket & @CRLF)
	$___bConnectedToServer = False
EndFunc

Func _StandardMessage(Const $hSocket, $sData)
	ConsoleWrite("Server Message: " & $sData & @CRLF)
EndFunc

Func _Sync_DevServer($hSocket, $sMode, $sData)
	Local $sServerVersion = 'Example File Send'

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
