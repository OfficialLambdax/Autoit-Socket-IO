; Make this an console application
#AutoIt3Wrapper_Change2CUI=Y
;~ #AutoIt3Wrapper_Run_After=start cmd /c server.exe
; Include IO core + the features we want to use for the server
#include "..\..\_netcode.au3"
#include "Serialize.au3"

;~ _Io_DevDebug(True) ; Uncomment to attach deubber
_netcode_SetOption("DebugLogToConsole", True)
_netcode_SetOption("EnableEncryption", "testpw")
_netcode_SetConnectionCallback('_Net_connection')
_netcode_SetDisconnectCallback('_Net_disconnect')
_netcode_SetCustomSocketEvent('auth')
_netcode_SetCustomSocketEvent('message')

; Define some resources
Global $userList = ObjCreate("Scripting.Dictionary")

; Attempt to listen on port 1000
Global $ServerSocket = _netcode_listen('0.0.0.0', 1225)

If Not $ServerSocket Then
	MsgBox(64, "Failed to start server", "Failed to listen on port 1000. Is it already listening?")
	Exit
EndIf

; Main loop
While _Io_Loop($ServerSocket)
WEnd


#Region Io events

Func _Net_connection(Const $socket)
	; We want the user to identify themselfs
	_netcode_Send($socket, 'authRequest')
EndFunc   ;==>_On_connection

Func _On_auth(Const $socket, $name, $password)

	; retrieve password from the given user

	Local $userPwd = IniRead("database.ini", "users", $name, "")
	; Check if the passwords match
	If $userPwd == $password And $password <> "" Then
		; Add users to our "userList"
		Local $oUser = ObjCreate("scripting.dictionary")

		$oUser.add("name", $name)
		$oUser.add("joined_at", StringFormat("%s/%s %d:%s", @MDAY, @MON, @HOUR, @MIN))

		$userList.add($socket, $oUser)

		; tell the user the auth was successful
		_netcode_Send($socket, 'authSuccessful')
		; Send updated userlist to everyone
		_netcode_Broadcast($ServerSocket, 'userListUpdate', _Serialize($userList))
		; Send welcome message to everyone
		_netcode_Broadcast($ServerSocket, "message", StringFormat("%s just joined the chat!", $name))
		; Send welcome message to user
		_netcode_Send($socket, "message", StringFormat("Welcome to the chat %s, type /help to see a list of commands", $name))

	Else
		; tell the user the auth was unsuccessful (IE bad password)
		_netcode_Send($socket, 'authUnSuccessful')
	EndIf

EndFunc   ;==>_On_auth

Func _Net_disconnect(Const $socket)

	; Update the list only if the disconnected socket did not exist
	If $userList.exists($socket) Then
		$userList.remove($socket)
		_netcode_Broadcast($ServerSocket, 'userListUpdate', _Serialize($userList))
	EndIf

EndFunc   ;==>_On_disconnect

Func _On_Message(Const $socket, $message)
	; Get current timestamp (YYYY-MM-DD HH:MM:SS)
	Local Const $now = StringFormat("%s-%s-%s %s:%s:%s", @YEAR, @MON, @MDAY, @HOUR, @MIN, @SEC)
	; Fetch user by socket
	Local Const $oUser = $userList.item($socket)
	; To prevent everyne to see what / commands they are using, we flag the usage so we do not broadcast that info!
	Local $bSlashCommandUsed = StringLeft($message, 1) == "/"

	; Prepend timestamp, username and password to new message
	Local Const $newMessage = StringFormat("[%s] %s: %s", $now, $oUser.item("name"), $message)

	If Not $bSlashCommandUsed Then
		;Broadcast message to everyone
		_netcode_Broadcast($ServerSocket, "message", $newMessage)
	Else
		;Broadcast message to initator
		_netcode_Send($socket, "message", $newMessage)
	EndIf

	; If a message starts with a slash, its a special message
	If $bSlashCommandUsed Then

		Local Const $command = StringMid($message, 2)

		; Emotes
		If $command == "dance" Then
			; Broadcast dance emote to everyone
			Return _netcode_Broadcast($ServerSocket, "message", StringFormat("%s bursts into dance!", $oUser.item("name")))

		ElseIf $command == "help" Then

			_netcode_Send($socket, "message", "/help (See all commands)" & @CRLF & "/dance (dance for the chat)" & @CRLF & "/joinedAt (See when you joined the chat)" & @CRLF & "/changePassword [newPassword] (Change your current password)" & @CRLF & "/new-user [username] [password] (Creates a new user)")

		ElseIf $command == "joinedAt" Then

			; Emit private info
			_netcode_Send($socket, "message", "[Only you will see this message]: %s" & $oUser.item("joined_at"))

		ElseIf StringRegExp($command, "(?i)^changePassword") Then

			; Passwor change request
			Local $sNewPassword = StringRegExp($message, "(?i)changePassword\h*(.+)", 1)

			If Not @error Then
				$sNewPassword = $sNewPassword[0]
				; Write new password to database
				IniWrite("database.ini", "users", $oUser.item("name"), $sNewPassword)
				; Emit private message that the password was successfully created
				_netcode_Send($socket, "message", "Password successfully changed!")
			Else
				; Invalid password
				_netcode_Send($socket, "message", "Invalid password")
			EndIf

		ElseIf StringRegExp($command, "(?i)new-user\h*(.*)\h+(.*)") Then

			; NEw user request
			Local $aNewUser = StringRegExp($message, "(?i)new-user\h*(.*)\h+(.*)", 1)

			If Not @error Then
				Local $userName = $aNewUser[0]
				Local $password = $aNewUser[1]


				; Check that the user does not exists
				If IniRead("database.ini", "users", $userName, "") == "" Then
					; Write to database
					IniWrite("database.ini", "users", $userName, $password)
					_netcode_Send($socket, "message", StringFormat("The user %s was successfully created", $userName))
				Else
					_netcode_Send($socket, "message", StringFormat("The username %s is already taken. please select another one", $userName))
				EndIf
			Else
				; Invalid user creation
				_netcode_Send($socket, "message", "Invalid syntax. /new-user username password")
			EndIf

		Else

			; No command found
			_netcode_Send($socket, "message", "Invalid command " & $message)
		EndIf

	EndIf

EndFunc   ;==>_On_Message

#EndRegion Io events

