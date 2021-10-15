#NoTrayIcon
#Region ;**** Directives created by AutoIt3Wrapper_GUI ****
#AutoIt3Wrapper_Version=Beta
#AutoIt3Wrapper_Run_Au3Stripper=n
#EndRegion ;**** Directives created by AutoIt3Wrapper_GUI ****
#AutoIt3Wrapper_Au3stripper_OnError=ForceUse
#Au3Stripper_Ignore_Funcs=_net_*
#include-once
#include "..\..\_netcode.au3"
#include "_screenshot.au3"
#include <ButtonConstants.au3>
#include <GUIConstantsEx.au3>
#include <StaticConstants.au3>
#include <WindowsConstants.au3>
#Region ### START Koda GUI section ###
$f_fMain_Picture = GUICreate("Desktop Picture", 615, 454, -1, -1, BitOR($gui_ss_default_gui, $ws_maximizebox, $ws_sizebox, $ws_thickframe, $ws_tabstop))
$f_bStartStop_Picture = GUICtrlCreateButton("Start", 8, 8, 75, 25)
$f_bDisconnect_Picture = GUICtrlCreateButton("Disconnect", 96, 8, 75, 25)
$aParentPos = WinGetPos($f_fMain_Picture)
$f_fMainChild_Picture = GUICreate("TEST", $aParentPos[2] - 30, $aParentPos[3] - 105, -1, 50, $ws_popup, $ws_ex_mdichild, $f_fMain_Picture) ;$ws_popup
GUIRegisterMsg($wm_size, "_wm_size")
#EndRegion ### END Koda GUI section ###

_SwitchButton(False)

Global $___nServerIP = "0.0.0.0"
Global $___nServerPort = "1225"
Global $___hServerSocket = 0
Global $___hConnectedClient = 0
Global $___bClientIsSending = False

;~ _netcode_SetOption("DebugLogToConsole", True)
_netcode_SetOption("SetPacketSafety", False)
_netcode_SetOption("SetAutoSplitBigPackets", True)
_netcode_SetOption("EnableEncryption", "testpw")
_netcode_SetConnectionCallback("_net_NewSocket")
_netcode_SetDisconnectCallback("_net_SocketDis")
_netcode_SetCustomSocketEvent("DesktopPicture")
_netcode_SetNetworkCustomSync("ServerVersion", '!', 'Example Screenshot')
_netcode_SetNetworkCustomAllow("ServerVersion", True)

$___hServerSocket = _netcode_Listen($___nServerIP, $___nServerPort)
if @error Then Exit

ConsoleWrite("Example Server: Get and Show Desktop Picture Online" & @CRLF)

GUISetState(@SW_SHOW, $f_fMain_Picture)
GUISetState(@SW_SHOW, $f_fMainChild_Picture)

While True
	_Io_Loop($___hServerSocket)

	$nMsg = GUIGetMsg() ; "This function automatically idles the CPU when required"
	if $nMsg = $GUI_EVENT_CLOSE Then Exit

	if $___hConnectedClient = 0 Then ContinueLoop

	Switch $nMsg
		Case $f_bStartStop_Picture
			if Not $___bClientIsSending Then
				GUICtrlSetData($f_bStartStop_Picture, "Stop")
				_netcode_Send($___hConnectedClient, 'GetDesktopPicture', 'Start')
				$___bClientIsSending = True
			Else
				GUICtrlSetData($f_bStartStop_Picture, "Start")
				_netcode_Send($___hConnectedClient, 'GetDesktopPicture', 'Stop')
				$___bClientIsSending = False
			EndIf

		Case $f_bDisconnect_Picture
			_netcode_Send($___hConnectedClient, 'GetDesktopPicture', 'Exit')
			_Io_Disconnect($___hConnectedClient)

	EndSwitch
WEnd

Func _On_DesktopPicture(Const $hSocket, $sData)
	Local $arData = StringSplit($sData, '|', 1 + 2)

	Switch $arData[0]
		Case "Picture"
;~ 			ConsoleWrite("Got a Picture" & @CRLF)
			if $___bClientIsSending Then _SetPicture($arData[1])


	EndSwitch
EndFunc

Func _SetPicture($sData)
	_Screenshot_DrawOnGUi($f_fMainChild_Picture, Binary($sData))
EndFunc

Func _net_NewSocket(Const $hSocket)
	ConsoleWrite("New Client at Socket " & $hSocket & @CRLF)
	if $___hConnectedClient Then
		ConsoleWrite("Disconnecting" & @CRLF)
		_Io_Disconnect($hSocket)
		Return
	EndIf
	$___hConnectedClient = $hSocket
	_SwitchButton(True)
EndFunc

Func _net_SocketDis(Const $hSocket)
	ConsoleWrite("Client " & $hSocket & " disconnected" & @CRLF)
	$___hConnectedClient = 0
	_SwitchButton(False)
EndFunc

Func _SwitchButton($bOn)
	Local $nState = $GUI_DISABLE
	if $bOn Then $nState = $GUI_ENABLE

	GUICtrlSetState($f_bDisconnect_Picture, $nState)
	GUICtrlSetState($f_bStartStop_Picture, $nState)
EndFunc

Func _wm_size($hwnd, $imsg, $wparam, $lparam)
	$hgui = $f_fMain_Picture
	$hchildgui = $f_fMainChild_Picture
	If $hchildgui = "" Then Return $gui_rundefmsg
	If WinActive($hgui) Then
		$aparentpos = WinGetPos($hgui)
		If IsArray($aparentpos) Then
			WinMove($hchildgui, "", $aparentpos[0] + 10, $aparentpos[1] + 70, $aparentpos[2] - 20, $aparentpos[3] - 80)
			$tempchildpos = WinGetPos($hchildgui)
		EndIf
	EndIf
	Return $gui_rundefmsg
EndFunc