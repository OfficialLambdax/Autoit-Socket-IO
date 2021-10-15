#NoTrayIcon
#Region ;**** Directives created by AutoIt3Wrapper_GUI ****
#AutoIt3Wrapper_Change2CUI=y
#EndRegion ;**** Directives created by AutoIt3Wrapper_GUI ****
#include "..\_netcode.au3"

Local $sConnectToIP = '127.0.0.1'
Local $sConnectToPort = '1220'

if @Compiled Then
	Local $arSplit = StringSplit(InputBox("", "IP:PORT", "127.0.0.1:1220"), ':', 1 + 2)
	$sConnectToIP = $arSplit[0]
	$sConnectToPort = $arSplit[1]
EndIf

AutoItSetOption("TCPTimeout", 100) ; for TCPConnect
_netcode_SetOption("DebugLogToConsole", True)

;~ Local $hRelaySocket = _netcode_Relay(25565, $sConnectTo, 25565)
Local $hRelaySocket = _netcode_Relay(1225, $sConnectToIP, $sConnectToPort)

__netcode_RelayLoop(True)
