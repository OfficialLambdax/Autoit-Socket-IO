#Region ;**** Directives created by AutoIt3Wrapper_GUI ****
#AutoIt3Wrapper_Version=Beta
#AutoIt3Wrapper_Change2CUI=y
#EndRegion ;**** Directives created by AutoIt3Wrapper_GUI ****
;~ #NoTrayIcon
#AutoIt3Wrapper_Au3stripper_OnError=ForceUse
#Au3Stripper_Ignore_Funcs=_net_*
#Au3Stripper_Ignore_Funcs=_Sync_*
#include-once
#include "..\..\_netcode.au3"
#include "_screenshot.au3"
#include <ScreenCapture.au3>

_Io_SetBytesPerSecond(True)

Global $___nServerIP = InputBox("", "", "127.0.0.1")
if @error Then Exit
Global $___nServerPort = "1225"
Global $___hServerSocket = 0
Global $___bSendPictures = False
Global $___nPicturesPerSecondActual = 0
Global $___nPicturesPerSecondLast = 0
Global $___hPicturePerSecondTimer = TimerInit()

;~ _netcode_SetOption("DebugLogToConsole", True)
_netcode_SetOption("SetAutoSplitBigPackets", True)
_netcode_SetOption("EnableEncryption", "testpw")
_netcode_SetConnectionCallback("_net_ConnectedToServer")
_netcode_SetDisconnectCallback("_net_Disconnected")
_netcode_SetCustomSocketEvent("GetDesktopPicture")
_netcode_SetNetworkCustomSync("ServerVersion", '?', '_Sync_DevServer', '', '', '', True)

ConsoleWrite("Example Client: Send Desktop Picture Online" & @CRLF)

While Sleep(1)
	if Not $___hServerSocket Then _netcode_Connect($___nServerIP, $___nServerPort)
	if $___hServerSocket Then _Io_Loop($___hServerSocket)
	if $___bSendPictures Then _SendScreenShots()
WEnd

Func _On_GetDesktopPicture(Const $hSocket, $sData)
	Local $arData = StringSplit($sData, '|', 1 + 2)

	Switch $arData[0]
		Case "Start"
			ConsoleWrite(@CRLF & "Start Sending Pictures" & @CRLF)
			$___bSendPictures = True

		Case "Stop"
			ConsoleWrite(@CRLF & "Stop Sending Pictures" & @CRLF)
			$___bSendPictures = False

		Case "Exit"
			Exit

	EndSwitch
EndFunc

Func _SendScreenShots()
	if TimerDiff($___hPicturePerSecondTimer) > 1000 Then
		$___hPicturePerSecondTimer = TimerInit()
		$___nPicturesPerSecondLast = $___nPicturesPerSecondActual
		$___nPicturesPerSecondActual = 0
	EndIf

	$___nPicturesPerSecondActual += 1
	ConsoleWrite("Sending Picture " & @HOUR & ':' & @MIN & ':' & @SEC & @TAB & $___nPicturesPerSecondLast & " p/s" & @TAB & Round(_Io_GetBytesPerSecond($___hServerSocket, False) / 1024, 2) & ' KB/s' & @CR)
	_netcode_Send($___hServerSocket, 'DesktopPicture', 'Picture|' & _Screenshot_ReturnData(20), True)
EndFunc

Func _net_ConnectedToServer(Const $hSocket)
	$___hServerSocket = $hSocket
	ConsoleWrite("Connected " & $hSocket & @CRLF)

	_netcode_Sync_Netcode($___hServerSocket)
	Do
		_Io_Loop($___hServerSocket)
		if $___hServerSocket = 0 Then Return
	Until _netcode_Sync_Check($___hServerSocket)

	ConsoleWrite("Synchronized with " & $hSocket & @CRLF)
EndFunc

Func _net_Disconnected(Const $hSocket)
	$___hServerSocket = 0
	$___bSendPictures = False
	ConsoleWrite("Disconnected " & $hSocket & @CRLF)
EndFunc

Func _Sync_DevServer($hSocket, $sMode, $sData)
	Local $sServerVersion = 'Example Screenshot'

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