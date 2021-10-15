#NoTrayIcon
#Region ;**** Directives created by AutoIt3Wrapper_GUI ****
#AutoIt3Wrapper_Change2CUI=y
#AutoIt3Wrapper_Run_AU3Check=y
#AutoIt3Wrapper_Run_Au3Stripper=n
#EndRegion ;**** Directives created by AutoIt3Wrapper_GUI ****
#AutoIt3Wrapper_Au3stripper_OnError=ForceUse
#include "..\_netcode.au3"

AutoItSetOption("TCPTimeout", 100) ; for TCPConnect
_netcode_SetOption("DebugLogToConsole", True)

; autoit runs on a single thread.
; for _netcode it is easier to handle HTTPS then HTTP.
; so its best to split both proxies up to two applications.
; however both ports accept HTTP and HTTPS.
if @Compiled Then
	if $cmdline[0] <> 0 Then
		Switch $cmdline[1]
			Case '-http'
				_net_HTTPProxy()

			Case '-https'
				_net_HTTPSProxy()

		EndSwitch
		Exit

	Else

		ShellExecute(@ScriptFullPath, '-http')
		ShellExecute(@ScriptFullPath, '-https')

;~ 		Run(@ScriptFullPath & ' -http')
;~ 		Run(@ScriptFullPath & ' -https')

;~ 		While Sleep(50)
;~ 		WEnd

		Exit

	EndIf


Else
	;~ Local $hRelaySocket = _netcode_Relay(25565, $sConnectTo, 25565)
	;~ Local $hRelaySocket = _netcode_HttpProxy(8080)
	Local $hRelaySocket = _netcode_HttpProxy(8043)
	ConsoleWrite("HTTP/S Proxy is running on Port 8043" & @CRLF)

	__netcode_RelayLoop(True)
EndIf


Func _net_HTTPProxy()
	Local $hRelaySocket = _netcode_HttpProxy(8080)
	ConsoleWrite("HTTP Proxy is running on Port 8080" & @CRLF)
	__netcode_RelayLoop(True)
EndFunc

Func _net_HTTPSProxy()
	Local $hRelaySocket = _netcode_HttpProxy(8043)
	ConsoleWrite("HTTPS Proxy is running on Port 8043" & @CRLF)
	__netcode_RelayLoop(True)
EndFunc
