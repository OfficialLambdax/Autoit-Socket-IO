#Region ;**** Directives created by AutoIt3Wrapper_GUI ****
;~ #AutoIt3Wrapper_Version=Beta
#AutoIt3Wrapper_Change2CUI=n
#EndRegion ;**** Directives created by AutoIt3Wrapper_GUI ****
;~ #AutoIt3Wrapper_Run_After=start cmd /c client.exe
#include <ButtonConstants.au3>
#include <EditConstants.au3>
#include <GUIConstantsEx.au3>
#include <GuiListView.au3>
#include <StaticConstants.au3>
#include <GuiEdit.au3>
#include <ScrollBarConstants.au3>
#include <WindowsConstants.au3>
; Include IO core + the features we want to use for the client
#include "..\..\_netcode.au3"
#include "Serialize.au3"

; Set options
Opt("GUIOnEventMode", 1)
; Define some resources
Global $userList = ObjCreate("Scripting.Dictionary")

;~ _Io_DevDebug(True); Uncomment to attach deubber
;~ _netcode_SetOption("DebugLogToConsole", True)
_netcode_SetOption("EnableEncryption", "testpw")
_netcode_SetCustomSocketEvent('authRequest')
_netcode_SetCustomSocketEvent('authSuccessful')
_netcode_SetCustomSocketEvent('authUnSuccessful')
_netcode_SetCustomSocketEvent('userListUpdate')
_netcode_SetCustomSocketEvent('message')

; Connect to server
Global $socket = _netcode_connect(InputBox('', 'Connect to: ', '127.0.0.1'), 1225)
If Not $socket Then
	MsgBox(64, "Failed to connect to server", "Failed to connect to server, is the server running?")
	Exit
EndIf


; Main loop
While _Io_Loop($socket)
WEnd

Func closeClient()
;~ 	_netcode_Disconnect($socket)
	Exit
EndFunc   ;==>closeClient

#Region Actions
Func LoginGui()
	Global $loginGui = GUICreate("Please sign", 235, 157) ;, 244, 399
	GUICtrlCreateLabel("Username", 8, 8, 52, 17)
	GUICtrlCreateLabel("password", 8, 64, 26, 17)
	Global $nameInput = GUICtrlCreateInput(@UserName, 8, 32, 217, 21)
	Global $passwordInput = GUICtrlCreateInput("", 8, 88, 217, 21)
	Local Const $btnSignIn = GUICtrlCreateButton("Sign in", 8, 120, 219, 25)
	GUISetState(@SW_SHOW)
	GUICtrlSetOnEvent($btnSignIn, LoginToserver)
	;GUICtrlSetOnEvent($passwordInput, LoginToserver)
	;GUICtrlSetOnEvent($nameInput, LoginToserver)
	GUISetOnEvent($GUI_EVENT_CLOSE, closeClient)
EndFunc   ;==>LoginGui

Func MainGui()
	Global $mainWindow = GUICreate("Chat example", 645, 343) ;, 610, 718
	GUICtrlCreateGroup("Connected users", 8, 8, 161, 321)
	Global $UsersListView = GUICtrlCreateListView("Name|Joined at", 16, 24, 137, 289)

	GUICtrlCreateGroup("", -99, -99, 1, 1)
	GUICtrlCreateGroup("Chat", 176, 8, 457, 321)
	Global $chatWindow = GUICtrlCreateEdit("", 184, 24, 433, 250, BitOR($ES_AUTOHSCROLL, $ES_READONLY, $ES_WANTRETURN, $WS_VSCROLL), 0)
	Global $chatInput = GUICtrlCreateInput("", 184, 300, 433, 20)
	GUICtrlCreateGroup("", -99, -99, 1, 1)
	GUISetState(@SW_SHOW)
	GUISetOnEvent($GUI_EVENT_CLOSE, closeClient)
	GUICtrlSetOnEvent($chatInput, sendMessage)
	;HotKeySet("{enter}", sendMessage)
EndFunc   ;==>MainGui

Func LoginToserver()
	; Grab input
	Local $name = GUICtrlRead($nameInput)
	Local $password = GUICtrlRead($passwordInput)
	; Send auth request to server
	_netcode_Send($socket, "auth", _Io_sParams($name, $password))
EndFunc   ;==>LoginToserver

Func refreshUserList()

	_GUICtrlListView_DeleteAllItems($UsersListView)
	For $user In $userList.items()
		GUICtrlCreateListViewItem($user.item("name") & "|" & $user.item("joined_at"),  $UsersListView)
	Next

EndFunc   ;==>refreshUserList

Func sendMessage()
	_netcode_Send($socket, "message", GUICtrlRead($chatInput))
	GUICtrlSetData($chatInput, "")
EndFunc   ;==>sendMessage
#EndRegion

#Region Io events
Func _On_authRequest(Const $socket)
	#forceref $socket
	LoginGui()
EndFunc   ;==>_On_authRequest

Func _On_authSuccessful(Const $socket)
	#forceref $socket
	; Close login gui
	GUIDelete($loginGui)
	; Start main chat window
	MainGui()
EndFunc   ;==>_On_authSuccessful

Func _On_authUnSuccessful(Const $socket)
	MsgBox(64, "Client", "Failed to login, wrong username or password", 10, $loginGui)
EndFunc


Func _On_userListUpdate(Const $socket, $oList)
	$userList = _UnSerialize($oList)
	refreshUserList()
EndFunc   ;==>_On_userListUpdate

Func _On_message(Const $socket, $message)
	#forcedef $chatWindow
	Local Const $oldText = GUICtrlRead($chatWindow)
	Local Const $newText = $oldText & @CRLF & $message & @LF

	GUICtrlSetData($chatWindow, $newText)

	; Scroll down text window
	Local Const $iEnd = StringLen($newText)
	_GUICtrlEdit_SetSel($chatWindow, $iEnd, $iEnd)
	_GUICtrlEdit_Scroll($chatWindow, $SB_SCROLLCARET)
EndFunc   ;==>_On_message
#EndRegion Io events
