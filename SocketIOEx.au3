#cs

 SocketIOEx UDF is a heaviely customized Variant of SocketIO UDF.
 To improve this UDF further, part of it, consists of parts from other UDF's.

 Informations regarding other UDF's _

 _LogEx.au3 UDF
	No Public Link

 _ccrypt.au3 UDF
	No Public Link

 _storageS.au3 UDF
	No Public Link

 winsock.au3 UDF
	made by https://www.autoitscript.com/forum/profile/74111-j0kky/
 	Public Link https://www.autoitscript.com/forum/topic/181645-winsock-udf/

 SocketIO.au3 UDF
	made by https://www.autoitscript.com/forum/profile/65348-tarretarretarre/
	Public Link https://www.autoitscript.com/forum/topic/188991-autoit-socket-io-networking-in-autoit-made-simple
	License _
	Copyright (c) 2017-2020 TarreTarreTarre <tarre.islam@gmail.com>

	Permission is hereby granted, free of charge, to any person obtaining a copy
	of this software and associated documentation files (the "Software"), to deal
	in the Software without restriction, including without limitation the rights
	to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
	copies of the Software, and to permit persons to whom the Software is
	furnished to do so, subject to the following conditions:

	The above copyright notice and this permission notice shall be included in all
	copies or substantial portions of the Software.

	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
	IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
	FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
	AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
	LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
	OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
	SOFTWARE.
#ce
#include-once
#include <Crypt.au3>
#include <Array.au3> ; for development
#Au3Stripper_Ignore_Funcs=_On_*
;~ #AutoIt3Wrapper_Au3Check_Para meters=-q -d -w 1 -w 2 -w 3 -w 4 -w 5 -w 6 -w 7
Global Const $g__io_sVer = "3.0.0"
Global Enum $_IO_SERVER, $_IO_CLIENT
Global $g__io_DevDebug = False, _
		$g__io_isActive = Null, _
		$g__io_vCryptKey = Null, _
		$g__io_vCryptAlgId = Null, _
		$g__io_sOnEventPrefix = Null, _
		$g__iBiggestSocketI = 0, _
		$g__io_sockets[1] = [0], _
		$g__io_aBanlist[1] = [0], _
		$g__io_socket_rooms[1] = [0], _
		$g__io_aMiddlewares[1] = [0], _
		$g__io_whoami, _
		$g__io_max_dead_sockets_count = 0, _
		$g__io_events[1000] = [0], _
		$g__io_mySocket, _
		$g__io_dead_sockets_count = 0, _
		$g__io_conn_ip, _
		$g__io_conn_port, _
		$g__io_UsedProperties[1] = [0], _
		$g__io_AutoReconnect = Null, _
		$g__io_nPacketSize = Null, _
		$g__io_nMaxPacketSize = Null, _
		$g__io_nMaxConnections = Null, _
		$g__Io_socketPropertyDomain = Null

Global $g__Io_bSetBytesPerSecond = False, _
		$g__Io_sPacketSeperator = '2nYx14Z0Rn', _
		$g__Io_sPacketSeperatorInternal = '7Ofq155Osh', _
		$g__Io_sPacketSeperatorLen = '89E1dI07LM', _
		$g__Io_bPacketValidation = False, _
		$g__Io_nPacketSafetyMinimumLen = 1000, _
		$g__Io_bPacketSafety = False, _
		$g__Io_bPacketEncryption = False, _
		$g__Io_bFloodPrevention = True, _
		$g__Io_nGlobalTimeoutTime = 1000 * 10, _
		$g__Io_bAcceptUnecryptedTraffic = False, _
		$g__Io_bParamSplitBinary = False, _
		$g__Io_sParamSplitSeperator = 'eUwc99H4Vc', _
		$g__Io_sParamIndicatorString = 'NDs2GA59Wj', _
		$g__Io_bPacketValidationMode_Hash = True, _
		$g__Io_sEncryptionCallback = "", _
		$g__Io_sDecryptionCallback = "", _
		$g__Io_bToggleSendOnlyWhenLoop = False

Global $g__Io_sSerializationIndicator = '4i8lwnpc6w' ; 10 bytes - keep them always exactly 10 bytes long
Global $g__Io_sSerializeArrayIndicator = '6v934Y71fS' ; 10 bytes
Global $g__Io_sSerializeObjectIndicator = '3mGil33aAz' ; 10 bytes
Global $g__Io_sSerializeArraySeperator = '152b7l27E6'
Global $g__Io_sSerializeObjectSeperator = 'zdxQ078yY4'

Global	$g__Io_sCustomSocketIO = '0.1', _
		$g__Io_hMeassurementSend, _
		$g__Io_hMeassurementRecv, _
		$g__Io_nMeassureMentSend = 0, _
		$g__Io_nMeassureMentRecv = 0, _
		$g__Io_arAllSockets[0][2], _
		$g__Io_bFloodPreventionFix = False, _
		$g__Io_hFloodPreventionFix = "NOTSET", _
		$g__Io_nPacketSafetyBufferSize = 0, _
		$g__Io_sSendOnlyWhenLoopSocketArray = "", _
		$g__Io_hWs2_32 = -1


;~ 		$g__Io_arPacketSafety_Cache[0][2], _
;~ 		$g__Io_arPacketSafety_CorruptedPacktes[0][2]
;~ 		$g__Io_bPacketCustomPacket = False, _
;~ 		$g__Io_sPacketCustomCallback = "", _
;~ 		$g__Io_bSetEmitSize = False, _
;~ 		$g__Io_arFloodPrevention[0][2]
;~ 		$g__Io_arBytesPerSecond[0][4], _
;~ 		$g__Io_hBytesPerSecondTimer = TimerInit()
;~ 		$g__Io_nDefaultTCPTimeout = 100
;~ 		$g__Io_sLastValidationPacket = "", _
;~ 		$g__Io_sLastValidationPacketResponse = "", _
;~ 		$g__Io_bPacketSafetyOldMode = False


; #FUNCTION# ====================================================================================================================
; Name ..........: _Io_RegisterMiddleware
; Description ...: Middlewares are ran before the event is fired which makes it a great tool for validation, data manipulation and debugging.
; Syntax ........: _Io_RegisterMiddleware($sEventName, $fCallback)
; Parameters ....: $sEventName          - a string value.
;                  $fCallback           - a floating point value.
; Return values .: True if middleware registrered with success.
; Author ........: TarreTarreTarre
; Modified ......:
; Remarks .......: Set $sEventName to * to trigger the middleware on every event. The $fCallback must be a valid function and the function MUST have these params (const $socket, ByRef $params, const $sEventName, ByRef $fCallbackName) and return true or false. False prevents the event from being fired.
; Related .......: _Io_unRegisterMiddleware, _Io_unRegisterEveryMiddleware
; Link ..........:
; Example .......: No
; ===============================================================================================================================
Func _Io_RegisterMiddleware($sEventName, $fCallback)

	If Not IsFunc($fCallback) Then Return SetError(1, 0, Null)

	If Not __Io_ValidEventName($sEventName) Then Return SetError(2, 0, Null)

	Local $aRet = [$sEventName, FuncName($fCallback), $fCallback]

	__Io_Push($g__io_aMiddlewares, $aRet)

	Return True ; $mwFuncCallback($socket, $r_params, $sEventName, $fCallbackName)

EndFunc   ;==>_Io_RegisterMiddleware

; #FUNCTION# ====================================================================================================================
; Name ..........: _Io_unRegisterMiddleware
; Description ...: Unregister a previously created middleware
; Syntax ........: _Io_unRegisterMiddleware($sEventName, $fCallback)
; Parameters ....: $sEventName          - a string value.
;                  $fCallback           - a floating point value.
; Return values .: None
; Author ........: TarreTarreTarre
; Modified ......:
; Remarks .......:
; Related .......: _Io_RegisterMiddleware, _Io_unRegisterEveryMiddleware
; Link ..........:
; Example .......: No
; ===============================================================================================================================
Func _Io_unRegisterMiddleware($sEventName, $fCallback)

	Local $success = False

	For $i = 1 To $g__io_aMiddlewares[0]
		Local $cur = $g__io_aMiddlewares[$i]

		Local $mwTargetEvent = $cur[0]
		Local $mwFuncName = $cur[1]

		If $sEventName == $mwTargetEvent And FuncName($fCallback) == $mwFuncName Then
			$g__io_aMiddlewares[$i] = Null
			$success = True
		EndIf
	Next

	Return $success

EndFunc   ;==>_Io_unRegisterMiddleware

; #FUNCTION# ====================================================================================================================
; Name ..........: _Io_unRegisterEveryMiddleware
; Description ...: Unregister every created middleware.
; Syntax ........: _Io_unRegisterEveryMiddleware()
; Parameters ....:
; Return values .: None
; Author ........: TarreTarreTarre
; Modified ......:
; Remarks .......:
; Related .......: _Io_unRegisterMiddleware, _Io_RegisterMiddleware
; Link ..........:
; Example .......: No
; ===============================================================================================================================
Func _Io_unRegisterEveryMiddleware()

	If $g__io_aMiddlewares[0] == 0 Then Return False

	For $i = 1 To $g__io_aMiddlewares[0]
		$g__io_aMiddlewares[$i] = Null
	Next

	Return True
EndFunc   ;==>_Io_unRegisterEveryMiddleware

; #FUNCTION# ====================================================================================================================
; Name ..........: _Io_setPropertyDomainPrefix
; Description ...: Server-side only. Sets the prefix for all props in _Io_socketSetProperty. Only use this if you are experiencing bugs with eval
; Syntax ........: _Io_setPropertyDomainPrefix($sDomain)
; Parameters ....: $sDomain             - a string value.
; Return values .: None
; Author ........: TarreTarreTarre
; Modified ......:
; Remarks .......: Only use this if you are experiencing bugs with eval
; Related .......: _Io_socketGetProperty, _Io_socketSetProperty
; Link ..........:
; Example .......: No
; ===============================================================================================================================
Func _Io_setPropertyDomainPrefix($sDomain)
	If $g__io_DevDebug Then ConsoleWrite("-" & @TAB & "_Io_setPropertyDomainPrefix: $g__Io_socketPropertyDomain = " & $sDomain & @LF)
	$g__Io_socketPropertyDomain = $sDomain
EndFunc   ;==>_Io_setPropertyDomainPrefix

; #FUNCTION# ====================================================================================================================
; Name ..........: _Io_whoAmI
; Description ...: Returns either `$_IO_SERVER` for server or `$_IO_CLIENT` for client
; Syntax ........: _Io_whoAmI([$verbose = false])
; Parameters ....: $verbose             - [optional] a variant value. Default is false.
; Return values .: Bool|String
; Author ........: TarreTarreTarre
; Modified ......:
; Remarks .......: This value is changed when invoking _Io_listen and _Io_Connect. If you set $verbose to `true`. This function retruns either "SERVER" or "CLIENT" instead of the constants
; Related .......: _Io_listen, _Io_Connect, _Io_IsServer, _Io_IsClient
; Link ..........:
; Example .......: No
; ===============================================================================================================================
Func _Io_whoAmI($verbose = False)
	Return Not $verbose ? $g__io_whoami : _Io_IsServer() ? 'SERVER' : 'CLIENT'
EndFunc   ;==>_Io_whoAmI

; #FUNCTION# ====================================================================================================================
; Name ..........: _Io_IsServer
; Description ...: Determines if _Io_whoAmI() == $_IO_SERVER
; Syntax ........: _Io_IsServer()
; Parameters ....:
; Return values .: Bool
; Author ........: TarreTarreTarre
; Modified ......:
; Remarks .......: This value is changed when invoking _Io_listen and _Io_Connect
; Related .......:  _Io_listen, _Io_Connect, _Io_whoAmI, _Io_IsClient
; Link ..........:
; Example .......: No
; ===============================================================================================================================
Func _Io_IsServer()
	Return $g__io_whoami == $_IO_SERVER
EndFunc   ;==>_Io_IsServer

; #FUNCTION# ====================================================================================================================
; Name ..........: _Io_IsClient
; Description ...: Determines if _Io_whoAmI() == $_IO_CLIENT
; Syntax ........: _Io_IsClient()
; Parameters ....:
; Return values .: Bool
; Author ........: TarreTarreTarre
; Modified ......:
; Remarks .......: This value is changed when invoking _Io_listen and _Io_Connect
; Related .......:   _Io_listen, _Io_Connect, _Io_IsServer, _Io_whoAmI
; Link ..........:
; Example .......: No
; ===============================================================================================================================
Func _Io_IsClient()
	Return $g__io_whoami == $_IO_CLIENT
EndFunc   ;==>_Io_IsClient

; #FUNCTION# ====================================================================================================================
; Name ..........: _Io_DevDebug
; Description ...: Enables debugging in console.
; Syntax ........: _Io_DevDebug($bState)
; Parameters ....: $bState              - a boolean value.
; Return values .: None
; Author ........: TarreTarreTarre
; Modified ......:
; Remarks .......:
; Related .......:
; Link ..........:
; Example .......: No
; ===============================================================================================================================
Func _Io_DevDebug($bState)
	$g__io_DevDebug = $bState
	ConsoleWrite("-" & @TAB & "_Io_DevDebug: @AutoItVersion = " & @AutoItVersion & @LF)
EndFunc   ;==>_Io_DevDebug

; #FUNCTION# ====================================================================================================================
; Name ..........: _Io_Listen
; Description ...:  Server-side only. Listens for incomming connections.
; Syntax ........: _Io_Listen($iPort[, $sAddress = @IPAddress1[, $iMaxPendingConnections = Default[,
;                  $iMaxDeadSocketsBeforeTidy = 1000[, $iMaxConnections = 100000]]]])
; Parameters ....: $iPort               - an integer value.
;                  $sAddress            - [optional] a string value. Default is @IPAddress1.
;                  $iMaxPendingConnections- [optional] an integer value. Default is Default.
;                  $iMaxDeadSocketsBeforeTidy- [optional] an integer value. Default is 1000.
;                  $iMaxConnections     - [optional] an integer value. Default is 100000.
; Return values .: integer. Null + @error if error
; Author ........: TarreTarreTarre
; Modified ......:
; Remarks .......: If `$iMaxDeadSocketsBeforeTidy` is set to `False`, you have to manually call `_Io_TidyUp` to get rid of dead sockets, otherwise the `iMaxConnections + 1` client that connects, will be instantly disconnected.
; Related .......: _Io_Connect
; Link ..........:
; Example .......: No
; ===============================================================================================================================
Func _Io_Listen($iPort, $sAddress = @IPAddress1, $iMaxPendingConnections = Default, $iMaxDeadSocketsBeforeTidy = 1000, $iMaxConnections = 100000)
	If Not __Io_Init() Then Return SetError(1, 0, Null)
	Local $socket = TCPListen($sAddress, $iPort, $iMaxPendingConnections)
	If @error Then Return SetError(2, @error, Null)
	$g__io_whoami = $_IO_SERVER
	$g__io_mySocket = $socket
	$g__io_max_dead_sockets_count = $iMaxDeadSocketsBeforeTidy
	$g__io_nMaxConnections = $iMaxConnections * 3 ; * 3 because all elementz
	$g__io_isActive = True
	;Global $g__io_events[1001] = [0]
	Global $g__io_sockets[($iMaxConnections * 3) + 1] = [0] ; *3 for all elements
	Global $g__io_socket_rooms[$iMaxConnections + 1] = [0]
	Global $g__io_aBanlist[(($iMaxConnections / 4) * 5) + 1] = [0] ; 25% of max connections * 5 etries +1 for sizeslot
	__Io_Ban_LoadToMemory()

	_Io_On('Internal_FloodPrevention', Null, $socket)
	_Io_On('Internal_PacketSafety', Null, $socket)

	_Io_setPropertyDomainPrefix('default')

	If $g__io_DevDebug Then
		ConsoleWrite("-" & @TAB & "_Io_Listen: $g__io_sVer " & $g__io_sVer & @LF)
		ConsoleWrite("-" & @TAB & "_Io_Listen: $sAddress " & $sAddress & @LF)
		ConsoleWrite("-" & @TAB & "_Io_Listen: $iPort " & $iPort & @LF)
		ConsoleWrite("-" & @TAB & "_Io_Listen: $g__io_whoami " & ($g__io_whoami == $_IO_SERVER ? 'Server' : 'Client') & @LF)
		ConsoleWrite("-" & @TAB & "_Io_Listen: $g__io_mySocket " & $g__io_mySocket & @LF)
		ConsoleWrite("-" & @TAB & "_Io_Listen: $g__io_max_dead_sockets_count " & $g__io_max_dead_sockets_count & @LF)
		ConsoleWrite("-" & @TAB & "_Io_Listen: $g__io_nMaxConnections " & ($g__io_nMaxConnections / 3) & @LF)
		ConsoleWrite("-" & @TAB & "_Io_Listen: $g__io_isActive " & $g__io_isActive & @LF)
		ConsoleWrite("-" & @TAB & "_Io_Listen: $g__io_vCryptKey " & $g__io_vCryptKey & @LF)
	EndIf

	Return $socket
EndFunc   ;==>_Io_Listen

; #FUNCTION# ====================================================================================================================
; Name ..........: _Io_Connect
; Description ...: Attempts to connect to a Server.
; Syntax ........: _Io_Connect($sAddress, $iPort[, $bAutoReconnect = True])
; Parameters ....: $sAddress            - a string value.
;                  $iPort               - an integer value.
;                  $bAutoReconnect      - [optional] a boolean value. Default is True.
; Return values .: integer. Null + @error if unable to connect.
; Author ........: TarreTarreTarre
; Modified ......:
; Remarks .......: if `$bAutoReconnect` is set to `False`. You must use `_Io_Connect` or `_Io_Reconnect` to establish a new connection.
; Related .......: _Io_Reconnect
; Link ..........:
; Example .......: No
; ===============================================================================================================================
 Func _Io_Connect($sAddress, $iPort, $bAutoReconnect = True)
	If Not __Io_Init() Then Return SetError(1, 0, Null)
	Local $socket = TCPConnect($sAddress, $iPort)
;~ 	Local $socket = _ASockConnect(_ASocket(), $sAddress, $iPort)
;~ 	Local $socket = __Io_TCPConnect($sAddress, $iPort)
	If @error Then Return SetError(2, @error, Null)
	;Global $g__io_events[1001] = [0]
	$g__io_whoami = $_IO_CLIENT
	$g__io_mySocket = $socket
	$g__io_conn_ip = $sAddress
	$g__io_conn_port = $iPort
	$g__io_AutoReconnect = $bAutoReconnect
	$g__io_isActive = True

	; registering these Events for the Client
	_Io_On('Internal_FloodPrevention', Null, $socket)
	_Io_On('Internal_Safety', Null, $socket)

	If $g__io_DevDebug Then
		ConsoleWrite("-" & @TAB & "_Io_Connect: $g__io_sVer " & $g__io_sVer & @LF)
		ConsoleWrite("-" & @TAB & "_Io_Connect: $sAddress " & $sAddress & @LF)
		ConsoleWrite("-" & @TAB & "_Io_Connect: $iPort " & $iPort & @LF)
		ConsoleWrite("-" & @TAB & "_Io_Connect: $g__io_whoami " & ($g__io_whoami == $_IO_SERVER ? 'Server' : 'Client') & @LF)
		ConsoleWrite("-" & @TAB & "_Io_Connect: $g__io_mySocket " & $g__io_mySocket & @LF)
		ConsoleWrite("-" & @TAB & "_Io_Connect: $g__io_conn_ip " & $g__io_conn_ip & @LF)
		ConsoleWrite("-" & @TAB & "_Io_Connect: $g__io_conn_port " & $g__io_conn_port & @LF)
		ConsoleWrite("-" & @TAB & "_Io_Connect: $g__io_AutoReconnect " & String($g__io_AutoReconnect) & @LF)
		ConsoleWrite("-" & @TAB & "_Io_Connect: $g__io_isActive " & $g__io_isActive & @LF)
		ConsoleWrite("-" & @TAB & "_Io_Connect: $g__io_vCryptKey " & $g__io_vCryptKey & @LF)
	EndIf

	Return $socket
EndFunc   ;==>_Io_Connect

; if you dont want to use _ccrypt.au3 and you use _Io_SetEncryptionCallback() to have your own encryptions methods going
; then this function, which is needed to enable encryption will still derive the key and open the dll
; for this to not take effect just call _Io_SetEncryptionCallback() and _Io_SetDecryptionCallback() before _Io_EnableEncryption()
Func _Io_EnableEncryption($sFileOrKey, $CryptAlgId = $CALG_AES_256)
	Local Const $sTestString = "2 legit 2 quit"
	If FileExists($sFileOrKey) Then
		$hOpen = FileOpen($sFileOrKey) ; i encounterd issues with out opening it myself first. so we do that just in case
		if @error Then Return SetError(1, 0, False) ; cant open file
		$sFileOrKey = FileRead($hOpen)
		FileClose($hOpen)
		if $sFileOrKey = "" Then Return SetError(2, 0, False) ; file is empty
	EndIf

;~ 	if BinaryToString(_ccrypt_DecData(_ccrypt_EncData($sTestString, $sFileOrKey), $sFileOrKey)) = $sTestString Then
	Local $sTest = BinaryToString(__Io_Decrypt(__Io_Encrypt($sTestString, $sFileOrKey), $sFileOrKey))
	if $sTest = $sTestString Then
		$g__io_vCryptKey = $sFileOrKey
		Return True
	Else
;~ 		MsgBox(0, "", "")
		Return SetError(3, 0, False) ; encryption and decryption failed
	EndIf
EndFunc

Func _Io_DisableEncryption()
	if $g__io_vCryptKey = Null Then Return SetError(1, 0, False)
;~ 	__ccrypt_initialize($g__io_vCryptKey, True) ; we cant use that because of a bug in crypt.au3 with _crypt_shutdown()
	if $g__Io_sEncryptionCallback <> "" Then
		$g__io_vCryptKey = Null
		Return
	EndIf

	__ccrypt_Crypt_DestroyKey($g__io_vCryptKey)

	$g__io_vCryptKey = Null
	Return True
EndFunc

; #FUNCTION# ====================================================================================================================
; Name ..........: _Io_setRecvPackageSize
; Description ...: Sets the maxlen for [TCPRecv](https://www.autoitscript.com/autoit3/docs/functions/TCPRecv.htm)
; Syntax ........: _Io_setRecvPackageSize([$iPackageSize = 4096])
; Parameters ....: $iPackageSize        - [optional] a general number value. Default is 4096
; Return values .: None
; Author ........: TarreTarreTarre
; Modified ......:
; Remarks .......:
; Related .......:
; Link ..........:
; Example .......: No
; ===============================================================================================================================
Func _Io_setRecvPackageSize($iPackageSize = 4096)
	$g__io_nPacketSize = $iPackageSize
EndFunc   ;==>_Io_setRecvPackageSize

; #FUNCTION# ====================================================================================================================
; Name ..........: _Io_setMaxRecvPackageSize
; Description ...: Sets the threshold for the `flood` event
; Syntax ........: _Io_setMaxRecvPackageSize([$iMaxPackageSize = $g__io_nPacketSize])
; Parameters ....: $iMaxPackageSize     - [optional] a general number value. Default is $g__io_nPacketSize.
; Return values .: None
; Author ........: TarreTarreTarre
; Modified ......:
; Remarks .......:
; Related .......:
; Link ..........:
; Example .......: No
; ===============================================================================================================================
Func _Io_setMaxRecvPackageSize($iMaxPackageSize = $g__io_nPacketSize)
	$g__io_nMaxPacketSize = $iMaxPackageSize
EndFunc   ;==>_Io_setMaxRecvPackageSize

; #FUNCTION# ====================================================================================================================
; Name ..........: _Io_Reconnect
; Description ...: Attempts to reconnect to the server
; Syntax ........: _Io_Reconnect(ByRef $socket)
; Parameters ....: $socket              - [in/out] a socket.
; Return values .: a new socket ID
; Author ........: TarreTarreTarre
; Modified ......:
; Remarks .......: Client-side only. This function invokes `_Io_TransferSocket` which will cause the param $socket passed, to be replaced with the new socket.
; Related .......: _Io_Connect, _Io_TransferSocket
; Link ..........:
; Example .......: No
; ===============================================================================================================================
Func _Io_Reconnect(ByRef $socket)
	; Create new socket
	Local $new_socket = _Io_Connect($g__io_conn_ip, $g__io_conn_port)
	; Transfer socket and events
	_Io_TransferSocket($socket, $new_socket)
	Return $socket
EndFunc   ;==>_Io_Reconnect

; #FUNCTION# ====================================================================================================================
; Name ..........: _Io_Subscribe
; Description ...: Server-side only. Subscribes a socket to a room.
; Syntax ........: _Io_Subscribe(Const $socket, $sRoomName)
; Parameters ....: $socket              - [in/out] a string value.
;                  $sRoomName           - a string value.
; Return values .: None
; Author ........: TarreTarreTarre
; Modified ......:
; Remarks .......:
; Related .......: _Io_BroadcastToRoom, _Io_Unsubscribe
; Link ..........:
; Example .......: No
; ===============================================================================================================================
Func _Io_Subscribe(Const $socket, $sRoomName)
	__Io_Push2x($g__io_socket_rooms, $socket, $sRoomName)
EndFunc   ;==>_Io_Subscribe

; #FUNCTION# ====================================================================================================================
; Name ..........: _Io_Unsubscribe
; Description ...: Server-side only. Unsubscribes a socket from a room.
; Syntax ........: _Io_Unsubscribe(Const $socket, $sRoomName)
; Parameters ....: $socket              - [in/out] a string value.
;                  $sRoomName           - a string value.
; Return values .: None
; Author ........: TarreTarreTarre
; Modified ......:
; Remarks .......: If $sRoomName is null, every subscription will expire for the given socket.
; Related .......: _Io_Subscribe
; Link ..........:
; Example .......: No
; ===============================================================================================================================
Func _Io_Unsubscribe(Const $socket, $sDesiredRoomName = Null)

	For $i = 1 To $g__io_socket_rooms[0] Step +2
		If $g__io_socket_rooms[$i] == $socket And ($g__io_socket_rooms[$i + 1] == $sDesiredRoomName Or $sDesiredRoomName == Null) Then
			$g__io_socket_rooms[$i] = Null
			$g__io_socket_rooms[$i + 1] = Null
		EndIf
	Next

EndFunc   ;==>_Io_Unsubscribe

; #FUNCTION# ====================================================================================================================
; Name ..........: _Io_Disconnect
; Description ...: Manually disconnect as Client or server / Disconnects a client
; Syntax ........: _Io_Disconnect([$socket = Null])
; Parameters ....: $socket              - [optional] a string value. Default is Null.
; Return values .: None
; Author ........: TarreTarreTarre
; Modified ......:
; Remarks .......: This function will purge any previously set `_Io_LoopFacade` and cause `_Io_Loop` to return false. If the `$socket` parameter is set when running as a server, the id of that socket will be disconnected.
; Related .......:
; Link ..........:
; Example .......: No
; ===============================================================================================================================
Func _Io_Disconnect($socket = Default)
	If $g__io_whoami == $_IO_SERVER And @NumParams == 1 Then
		Return TCPCloseSocket($socket)
	EndIf
	$g__io_isActive = False
	AdlibUnRegister("_Io_LoopFacade")
	__Io_Shutdown()
	Return True
EndFunc   ;==>_Io_Disconnect

; #FUNCTION# ====================================================================================================================
; Name ..........: _Io_LoopFacade
; Description ...: A substitute for the `_Io_Loop`.
; Syntax ........: _Io_LoopFacade()
; Parameters ....:
; Return values .: None
; Author ........: TarreTarreTarre
; Modified ......:
; Remarks .......: Should only be used with AdlibRegister. If `_Io_Disconnect` is invoked, this facade will also be un-registered. This function will not work properly if more than 1 `_Io_Connect` or `_Io_Listen` exists in the same script.
; Related .......: _Io_Loop
; Link ..........:
; Example .......: No
; ===============================================================================================================================
Func _Io_LoopFacade()
	_Io_Loop($g__io_mySocket)
EndFunc   ;==>_Io_LoopFacade

; #FUNCTION# ====================================================================================================================
; Name ..........: _Io_Loop
; Description ...: The event handler for this UDF.
; Syntax ........: _Io_Loop(Byref $socket)
; Parameters ....: $socket              - [in/out] a string value.
; Return values .: None
; Author ........: TarreTarreTarre
; Modified ......:
; Remarks .......: Should only be used as the main While loop. The function will return false if the function `_Io_Disconnect` is invoked
; Related .......: _Io_LoopFacade
; Link ..........:
; Example .......: No
; ===============================================================================================================================
Func _Io_Loop(ByRef $socket, $whoAmI = $g__io_whoami)
	Local $package, $aParams = Null

	if $g__Io_bToggleSendOnlyWhenLoop Then __Io_SendInLoop()

	Switch $whoAmI
		Case $_IO_SERVER

			; -------------
			;	Check for incomming connections
			; -------------

			Local $connectedSocket = TCPAccept($socket)

			If $connectedSocket <> -1 Then

				; Check if we have room for another one (Even dead sockets takes spaces, so therefore were not including $g__io_dead_sockets_count)
				If $g__io_sockets[0] + 1 <= $g__io_nMaxConnections Then ; $g__io_nMaxConnections has *3 so it will not be bothered by the dim size
					; Create an socket with more info, but in an separate array
					Local $aExtendedSocket = __Io_createExtendedSocket($connectedSocket)

;~ 					; Check if banned
					Local $isBanned = _Io_IsBanned($aExtendedSocket[1])

					If $isBanned > 0 Then

						;get banned-data
						Local $aBannedInfo = _Io_getBanlist($isBanned)

						; Emit ban notification
						_Io_Emit($connectedSocket, "banned", _Io_sParams($aBannedInfo[1], $aBannedInfo[2], $aBannedInfo[3], $aBannedInfo[4]))

						; Close socket
						_Io_Disconnect($connectedSocket)

						; Return
						Return $g__io_isActive

					EndIf

					; This is done to exit any $g__io_socket's loop and break when we know we are not going to find anything more
					;If $connectedSocket > $g__iBiggestSocketI Then $g__iBiggestSocketI = $connectedSocket + 1
					$g__iBiggestSocketI += 3

					; Save socket
					__Io_Push3x($g__io_sockets, $aExtendedSocket[0], $aExtendedSocket[1], $aExtendedSocket[2])

					; Adding Events to the Client socket. Server Side
					_Io_On('Internal_FloodPrevention', Null, $connectedSocket)
;~ 					_Io_On('Internal_FloodPrevention', Null, $socket)
					_Io_On('Internal_Safety', Null, $connectedSocket)
;~ 					_Io_On('Internal_Safety', Null, $socket)

					; add socket
					__Io_AddSocket($socket, $connectedSocket)

					; Fire connection event
					__Io_FireEvent($connectedSocket, $aParams, "connection", $socket)

				Else
					; Close socket because were full!
					_Io_Disconnect($connectedSocket)
				EndIf
			EndIf

			; -------------
			;	Check client alive-status and see if any data was transmitted to the server
			; -------------

			Local $aDeadSockets[1] = [0]

			For $i = 1 To $g__io_sockets[0] Step +3
				Local $client_socket = $g__io_sockets[$i]

				; Ignore dead sockets
				If Not $client_socket > 0 Then ContinueLoop

				$package = __Io_RecvPackage($client_socket)

				Switch @error
					Case 1 ; Dead client
						; Add socket ID to array of dead sockets
						__Io_Push($aDeadSockets, $i)

						; Incr dead count
						$g__io_dead_sockets_count += 1

						ContinueLoop
					Case 2 ; Client flooding (Exceeding $g__io_nMaxPacketSize)
						__Io_FireEvent($client_socket, $aParams, "flood", $socket)
				EndSwitch

				; Collect all Processed data, so we can invoke them all at once instead of one by one
				__Io_handlePackage($client_socket, $package, $socket)

				; Check if we can abort this loop
				If $i >= $g__iBiggestSocketI Then ExitLoop
			Next

			; -------------
			;	Handle all dead sockets
			; -------------

			For $i = 1 To $aDeadSockets[0]
				Local $aDeadSocket_index = $aDeadSockets[$i]
				Local $deadSocket = $g__io_sockets[$aDeadSocket_index]

				; Unsubscribe socket from everything
				_Io_Unsubscribe($deadSocket)

				; Fire event
				__Io_FireEvent($deadSocket, $aParams, "disconnect", $socket)

				; delete it from the Flood Prevention
				__Io_DelFloodPrevention($deadSocket, False)

				; delte socket
				__Io_DelSocket($deadSocket) ; i had this commented - but why

				; Mark socket as dead.
				$g__io_sockets[$aDeadSocket_index] = Null

				; Null out every possible set property on the deadsocket (Exactly like assign but without checks (for speed)
				For $j = 1 To $g__io_UsedProperties[0]
					Local $sProp = $g__io_UsedProperties[$j]
					Local $fqdn = $g__Io_socketPropertyDomain & "_" & $socket & $sProp
					Assign($fqdn, Null, 2)
				Next

			Next

			; -------------
			;	Determine if we need to tidy up (Remove all dead sockets)
			; -------------
			If $g__io_max_dead_sockets_count > 0 And $g__io_dead_sockets_count >= $g__io_max_dead_sockets_count Then
				_Io_TidyUp()
			EndIf

		Case $_IO_CLIENT
			; -------------
			;	Recv data from server
			; -------------

			$package = __Io_RecvPackage($socket)

			; -------------
			;	Check server alive-status
			; -------------

			Switch @error
				Case 1 ; Disconnected from server (Not by user)
					__Io_FireEvent($socket, $aParams, "disconnect", $socket) ; $socket two times is correct.

					; delete it from the Flood Prevention
					__Io_DelFloodPrevention($socket, False)

					; delete socket
					__Io_DelSocket($socket)

					; Reconnect if we need to
					If $g__io_AutoReconnect Then
						_Io_Reconnect($socket)
					EndIf

					Return SetError(1, 0, $g__io_isActive) ; needs testing

				Case 2 ; Flooded by server
					__Io_FireEvent($socket, $aParams, "flood", $socket) ; $socket two times is correct.
			EndSwitch


			; -------------
			;	Parse incomming data
			; -------------

			__Io_handlePackage($socket, $package, $socket) ; $socket two times is correct.

	EndSwitch

	Return $g__io_isActive
EndFunc   ;==>_Io_Loop

; #FUNCTION# ====================================================================================================================
; Name ..........: _Io_setOnPrefix
; Description ...: Set the default prefix for `_Io_On` if not passing callback.
; Syntax ........: _Io_setOnPrefix(Const $sPrefix)
; Parameters ....: $sPrefix             - [const] a string value.
; Return values .: @error if invalid prefix
; Author ........: TarreTarreTarre
; Modified ......:
; Remarks .......: only function-friendly names are allowed
; Related .......: _Io_On
; Link ..........:
; Example .......: No
; ===============================================================================================================================
Func _Io_setOnPrefix(Const $sPrefix = '_On_')
	If Not StringRegExp($sPrefix, '(?i)[a-z_]+[a-z_0-9]*') Then
		If $g__io_DevDebug Then ConsoleWrite("-" & @TAB & "_Io_setOnPrefix: failed to set prefix ($sPrefix) to '" & $sPrefix & "'" & @LF)
		Return SetError(1)
	EndIf

	$g__io_sOnEventPrefix = $sPrefix

	If $g__io_DevDebug Then ConsoleWrite("-" & @TAB & "_Io_setOnPrefix: successfully set ($sPrefix) to '" & $sPrefix & "'" & @LF)
EndFunc   ;==>_Io_setOnPrefix

; #FUNCTION# ====================================================================================================================
; Name ..........: _Io_On
; Description ...: Binds an event
; Syntax ........: _Io_On(Const $sEventName[, $fCallback = Null[, $socket = $g__io_mySocket]])
; Parameters ....: $sEventName          - [Const] a string value.
;                  $fCallback           - [optional] a floating point value. Default is Null.
;                  $socket              - [optional] a string value. Default is $g__io_mySocket.
; Return values .: None
; Author ........: TarreTarreTarre
; Modified ......:
; Remarks .......: If $fCallback is set to null, the function will assume the prefix "_On_" is applied. Eg (_Io_On('test') will look for "Func _On_Test(...)" etc
; Related .......: _Io_setOnPrefix
; Link ..........:
; Example .......: No
; ===============================================================================================================================
Func _Io_On(Const $sEventName, Const $fCallback = Null, $socket = $g__io_mySocket)
	Local $fCallbackName = IsFunc($fCallback) ? FuncName($fCallback) : $fCallback

	If $fCallback == Null And Not StringRegExp($sEventName, '(?i)^[a-z_0-9]*$') Then
		If $g__io_DevDebug Then
			ConsoleWrite("-" & @TAB & StringFormat('_Io_On: Failed to bind event "%s". Invalid eventname for autoCallback.', $sEventName) & @LF)
		EndIf
		Return SetError(1)
	EndIf

	If Not $fCallbackName Then
		$fCallbackName = $g__io_sOnEventPrefix & $sEventName
	EndIf


	If $g__io_DevDebug Then
		ConsoleWrite("-" & @TAB & StringFormat('_Io_On: Bound new event: %s => %s', $sEventName, $fCallbackName) & @LF)
	EndIf

	__Io_Push3x($g__io_events, $sEventName, $fCallbackName, $socket)
EndFunc   ;==>_Io_On

; if you set $p1, leave $p2 empty and then set $p3, then this function will only process $p1 as it expects any Default param to be the last.
Func _Io_sParams($p1, $p2 = Default, $p3 = Default, $p4 = Default, $p5 = Default, $p6 = Default, $p7 = Default, $p8 = Default, $p9 = Default, $p10 = Default, $p11 = Default, $p12 = Default, $p13 = Default, $p14 = Default, $p15 = Default, $p16 = Default)
	Local $sParams = $g__Io_sParamIndicatorString

	For $i = 1 To 16
		$sEvalParam = Eval("p" & $i)
		if $sEvalParam = Default Then ExitLoop

		if $g__Io_bParamSplitBinary Then $sEvalParam = StringToBinary($sEvalParam)
		$sParams &= __Io_CheckParamAndSerialize($sEvalParam) & $g__Io_sParamSplitSeperator
	Next

	Return StringTrimRight($sParams, StringLen($g__Io_sParamSplitSeperator))


	#cs ; you can set $p1, leave $p2 empty, and set $p3. It will work. $p3 will still in position Call($p1, $p2, $p3). $p2 will be Null. However this will call all 16 params on your func
	Local $sParams = $g__Io_sParamIndicatorString
	For $i = 1 To 16
		$sEvalParam = Eval("p" & $i)
		if $sEvalParam = Default Then $sEvalParam = Null

		if $g__Io_bParamSplitBinary Then $sEvalParam = StringToBinary($sEvalParam)

		$sParams &= $sEvalParam & $g__Io_sParamSplitSeperator
	Next

	Return StringTrimRight($sParams, StringLen($g__Io_sParamSplitSeperator))
	#ce
EndFunc

;~ Func _Io_Emit(Const $socket, $sEventName, $p1 = Default, $p2 = Default, $p3 = Default, $p4 = Default, $p5 = Default, $p6 = Default, $p7 = Default, $p8 = Default, $p9 = Default, $p10 = Default, $p11 = Default, $p12 = Default, $p13 = Default, $p14 = Default, $p15 = Default, $p16 = Default)
Func _Io_Emit(Const $socket, $sEventName, $sParams = Default, $bNoSafeOverwrite = False, $bNoPacketEncryption = False, $bInternal_IgnoreFlood = False)

	$g__Io_hMeassurementSend = TimerInit()

	; only arrays and objects get serialized
	$sParams = __Io_CheckParamAndSerialize($sParams)

	; No goof names allowed
;~ 	If Not __Io_ValidEventName($sEventName) Then Return SetError(1, 0, Null) ; temporarely disabled

	Local $package = __Io_createPackage($sEventName, $sParams, $bNoPacketEncryption, $socket)
	Local $packageLen = @extended

	if $g__Io_bFloodPrevention Then
		; if we would exceed the Recv Buffer then Return Error
		if __Io_CheckFloodPrevention($socket) + (StringLen($package) / 2) >= $g__io_nMaxPacketSize Then
;~ 			MsgBox(0, StringLen($sParams), StringLeft($package, 100))
			if Not $bInternal_IgnoreFlood Then

				if Not $g__Io_bFloodPreventionFix Then
					if $g__Io_hFloodPreventionFix = "NOTSET" Then $g__Io_hFloodPreventionFix = TimerInit()

					if TimerDiff($g__Io_hFloodPreventionFix) > $g__Io_nGlobalTimeoutTime Then
;~ 						ConsoleWrite("<<<========== FLOOOOOOD FIX SEND" & @CRLF)
						$g__Io_bFloodPreventionFix = True
						$attempt = _Io_Emit($socket, 'Internal_FloodPrevention', 'STATUS', False, False, True) ; lets try to fix ourself in case the server isnt stuck and a prevention packet is just missing
						Return SetError(@error, @extended, $attempt)
					EndIf
				EndIf

				Return SetError(2, 1, 0)
			EndIf
		EndIf

		; if the server just hung
		if $g__Io_hFloodPreventionFix <> "NOTSET" And Not $bInternal_IgnoreFlood Then
			$g__Io_hFloodPreventionFix = "NOTSET"
			$g__Io_bFloodPreventionFix = False
		EndIf
	EndIf

;~ 	ConsoleWrite("SEND " & $sEventName & @CRLF)

	; attempt to send request
	if $g__Io_bPacketSafety And StringLen($package) < $g__Io_nPacketSafetyMinimumLen Then $bNoSafeOverwrite = True

	; add bytes to Flood Prevention counter
	if $sEventName <> 'Internal_FloodPrevention' And $sEventName <> 'Internal_Safety' Then __Io_AddFloodPrevention($socket, $packageLen) ; send in binary

	if $g__Io_bPacketSafety And Not $bNoSafeOverwrite Then
		$hParentSocket = __Io_CheckSocket($socket)
		if $hParentSocket = False Then $hParentSocket = $socket
		if $g__Io_bToggleSendOnlyWhenLoop Then
			$attempt = __Io_RegisterLoopSend($socket, $package, $hParentSocket)
		Else
			$attempt = __Io_TransportPackage_Safe($socket, $package, $hParentSocket)
		EndIf
	Else
		if $g__Io_bToggleSendOnlyWhenLoop Then
			$attempt = __Io_RegisterLoopSend($socket, $package)
		Else
			$attempt = __Io_TransportPackage($socket, $package)
		EndIf
	EndIf
	$nError = @error
	$nExtended = @extended

	__Io_BytesPerSecond($socket, $attempt, False)

	; measure and save time it took to Emit
	$g__Io_nMeassureMentSend = TimerDiff($g__Io_hMeassurementSend)
	Return SetError($nError, $nExtended, $attempt)

EndFunc   ;==>_Io_Emit

; #FUNCTION# ====================================================================================================================
; Name ..........: _Io_Broadcast
; Description ...: Server-side only. Emit an event every connected socket but not the passed $socket
; Syntax ........: _Io_Broadcast(Const $socket, $sEventName[, $p1 = Default[, $p2 = Default[, $p3 = Default[, $p4 = Default[,
;                  $p5 = Default[, $p6 = Default[, $p7 = Default[, $p8 = Default[, $p9 = Default[, $p10 = Default]]]]]]]]]])
; Parameters ....: $socket              - [in/out] a string value.
;                  $sEventName          - a string value.
;                  $p1                  - [optional] a pointer value. Default is Default.
;                  $p2                  - [optional] a pointer value. Default is Default.
;                  $p3                  - [optional] a pointer value. Default is Default.
;                  $p4                  - [optional] a pointer value. Default is Default.
;                  $p5                  - [optional] a pointer value. Default is Default.
;                  $p6                  - [optional] a pointer value. Default is Default.
;                  $p7                  - [optional] a pointer value. Default is Default.
;                  $p8                  - [optional] a pointer value. Default is Default.
;                  $p9                  - [optional] a pointer value. Default is Default.
;                  $p10                 - [optional] a pointer value. Default is Default.
; Return values .: Integer. Bytes sent
; Author ........: TarreTarreTarre
; Modified ......:
; Remarks .......: To pass more than 16 parameters, a special array can be passed in lieu of individual parameters. This array must have its first element set to "CallArgArray" and elements 1 - n will be passed as separate arguments to the function. If using this special array, no other arguments can be passed
; Related .......: _Io_Emit, _Io_BroadcastToAll, _Io_BroadcastToRoom
; Link ..........:
; Example .......: No
; ===============================================================================================================================
;~ Func _Io_Broadcast(Const $socket, $sEventName, $p1 = Default, $p2 = Default, $p3 = Default, $p4 = Default, $p5 = Default, $p6 = Default, $p7 = Default, $p8 = Default, $p9 = Default, $p10 = Default, $p11 = Default, $p12 = Default, $p13 = Default, $p14 = Default, $p15 = Default, $p16 = Default)
Func _Io_Broadcast(Const $socket, $sEventName, $sParams = Default, $bNoSafeOverwrite = False, $bNoPacketEncryption = False) ; , $bInternal_IgnoreFlood = False)

	; change notice _
	; even tho creating the packet first and then sending it to each socket is faster then creating it for each socket,
	; if the user chooses to use a different password for each socket then this will not work.
	; so since we do no longer use the serilisation UDF this isnt much of an issue anymore.

	; No goof names allowed
;~ 	If Not __Io_ValidEventName($sEventName) Then Return SetError(1, 0, Null)

	; What to send
;~ 	Local $aParams = [$p1, $p2, $p3, $p4, $p5, $p6, $p7, $p8, $p9, $p10, $p11, $p12, $p13, $p14, $p15, $p16]

	; Determine if a CallArgArray call is valid
;~ 	If @NumParams == 3 And IsArray($p1) And $p1[0] == 'CallArgArray' Then
;~ 		$aParams = $p1
;~ 	EndIf

	; Prepare package
;~ 	Local $package = __Io_createPackage($sEventName, $aParams, @NumParams)
	Local $bytesSent = 0

	For $i = 1 To $g__io_sockets[0] Step +3
		Local $client_socket = $g__io_sockets[$i]

		; Ignore dead sockets and "self"
		If Not $client_socket > 0 Or $socket == $client_socket Then ContinueLoop

		; Send da package
;~ 		$bytesSent += __Io_TransportPackage($client_socket, $package)
		$bytesSent += _Io_Emit($client_socket, $sEventName, $sParams, $bNoSafeOverwrite, $bNoPacketEncryption)

		; Check if we can abort this loop
		If $i >= $g__iBiggestSocketI Then ExitLoop

	Next

	Return $bytesSent

EndFunc   ;==>_Io_Broadcast

; #FUNCTION# ====================================================================================================================
; Name ..........: _Io_BroadcastToAll
; Description ...: Server-side only. Emit an event every connected socket including the passed $socket
; Syntax ........: _Io_BroadcastToAll(Const $socket, $sEventName[, $p1 = Default[, $p2 = Default[, $p3 = Default[, $p4 = Default[,
;                  $p5 = Default[, $p6 = Default[, $p7 = Default[, $p8 = Default[, $p9 = Default[, $p10 = Default]]]]]]]]]])
; Parameters ....: $socket              - [in/out] a string value.
;                  $sEventName          - a string value.
;                  $p1                  - [optional] a pointer value. Default is Default.
;                  $p2                  - [optional] a pointer value. Default is Default.
;                  $p3                  - [optional] a pointer value. Default is Default.
;                  $p4                  - [optional] a pointer value. Default is Default.
;                  $p5                  - [optional] a pointer value. Default is Default.
;                  $p6                  - [optional] a pointer value. Default is Default.
;                  $p7                  - [optional] a pointer value. Default is Default.
;                  $p8                  - [optional] a pointer value. Default is Default.
;                  $p9                  - [optional] a pointer value. Default is Default.
;                  $p10                 - [optional] a pointer value. Default is Default.
; Return values .: Integer. Bytes sent
; Author ........: TarreTarreTarre
; Modified ......:
; Remarks .......: To pass more than 16 parameters, a special array can be passed in lieu of individual parameters. This array must have its first element set to "CallArgArray" and elements 1 - n will be passed as separate arguments to the function. If using this special array, no other arguments can be passed
; Related .......: _Io_Emit, _Io_Broadcast, _Io_BroadcastToRoom
; Link ..........:
; Example .......: No
; ===============================================================================================================================
;~ Func _Io_BroadcastToAll(Const $socket, $sEventName, $p1 = Default, $p2 = Default, $p3 = Default, $p4 = Default, $p5 = Default, $p6 = Default, $p7 = Default, $p8 = Default, $p9 = Default, $p10 = Default, $p11 = Default, $p12 = Default, $p13 = Default, $p14 = Default, $p15 = Default, $p16 = Default)
Func _Io_BroadcastToAll(Const $socket, $sEventName, $sParams = Default, $bNoSafeOverwrite = False, $bNoPacketEncryption = False) ; , $bInternal_IgnoreFlood = False)
	#forceref $socket
	; No goof names allowed
;~ 	If Not __Io_ValidEventName($sEventName) Then Return SetError(1, 0, Null)

	; What to send
;~ 	Local $aParams = [$p1, $p2, $p3, $p4, $p5, $p6, $p7, $p8, $p9, $p10, $p11, $p12, $p13, $p14, $p15, $p16]

	; Determine if a CallArgArray call is valid
;~ 	If @NumParams == 3 And IsArray($p1) And $p1[0] == 'CallArgArray' Then
;~ 		$aParams = $p1
;~ 	EndIf

	; Prepare package
;~ 	Local $package = __Io_createPackage($sEventName, $aParams, @NumParams)
	Local $bytesSent = 0

	For $i = 1 To $g__io_sockets[0] Step +3
		Local $client_socket = $g__io_sockets[$i]

		; Ignore dead sockets only
		If Not $client_socket > 0 Then ContinueLoop

		; Send da package
;~ 		$bytesSent += __Io_TransportPackage($client_socket, $package)
		$bytesSent += _Io_Emit($client_socket, $sEventName, $sParams, $bNoSafeOverwrite, $bNoPacketEncryption)

		; Check if we can abort this loop
		If $i >= $g__iBiggestSocketI Then ExitLoop

	Next

	Return $bytesSent

EndFunc   ;==>_Io_BroadcastToAll

; #FUNCTION# ====================================================================================================================
; Name ..........: _Io_BroadcastToRoom
; Description ...: Server-side only. Emit an event to every socket subscribed to a given room
; Syntax ........: _Io_BroadcastToRoom(Const $socket, $sDesiredRoomName, $sEventName[, $p1 = Default[, $p2 = Default[, $p3 = Default[,
;                  $p4 = Default[, $p5 = Default[, $p6 = Default[, $p7 = Default[, $p8 = Default[, $p9 = Default[,
;                  $p10 = Default[, $p11 = Default[, $p12 = Default[, $p13 = Default[, $p14 = Default[, $p15 = Default[,
;                  $p16 = Default]]]]]]]]]]]]]]]])
; Parameters ....: $socket              - [in/out] a string value.
;                  $sDesiredRoomName    - a string value.
;                  $sEventName          - a string value.
;                  $p1                  - [optional] a pointer value. Default is Default.
;                  $p16                 - [optional] a pointer value. Default is Default.
; Return values .: Integer. Bytes sent
; Author ........: TarreTarreTarre
; Modified ......:
; Remarks .......: To pass more than 16 parameters, a special array can be passed in lieu of individual parameters. This array must have its first element set to "CallArgArray" and elements 1 - n will be passed as separate arguments to the function. If using this special array, no other arguments can be passed
; Related .......: _Io_Emit, _Io_Broadcast, _Io_BroadcastToAll, _Io_Subscribe
; Link ..........:
; Example .......: No
; ===============================================================================================================================
;~ Func _Io_BroadcastToRoom(Const $socket, $sDesiredRoomName, $sEventName, $p1 = Default, $p2 = Default, $p3 = Default, $p4 = Default, $p5 = Default, $p6 = Default, $p7 = Default, $p8 = Default, $p9 = Default, $p10 = Default, $p11 = Default, $p12 = Default, $p13 = Default, $p14 = Default, $p15 = Default, $p16 = Default)
Func _Io_BroadcastToRoom(Const $socket, $sDesiredRoomName, $sEventName, $sParams = Default, $bNoSafeOverwrite = False, $bNoPacketEncryption = False) ; , $bInternal_IgnoreFlood = False)
	#forceref $socket
	; No goof names allowed
;~ 	If Not __Io_ValidEventName($sEventName) Then Return SetError(1, 0, Null)

	; What to send
;~ 	Local $aParams = [$p1, $p2, $p3, $p4, $p5, $p6, $p7, $p8, $p9, $p10, $p11, $p12, $p13, $p14, $p15, $p16]

	; Determine if a CallArgArray call is valid
;~ 	If @NumParams == 4 And IsArray($p1) And $p1[0] == 'CallArgArray' Then
;~ 		$aParams = $p1
;~ 	EndIf

	; Prepare package
;~ 	Local $package = __Io_createPackage($sEventName, $aParams, @NumParams - 1) ; - 1 since we have more params
	Local $bytesSent = 0

	For $i = 1 To $g__io_socket_rooms[0] Step +2
		Local $client_socket = $g__io_socket_rooms[$i]

		; Ignore dead sockets
		If Not $client_socket > 0 Then ContinueLoop

		Local $sRoomName = $g__io_socket_rooms[$i + 1]

		; Check if this is the room we want to send to
		If $sDesiredRoomName == $sRoomName Then
;~ 			$bytesSent += __Io_TransportPackage($client_socket, $package)
			$bytesSent += _Io_Emit($client_socket, $sEventName, $sParams, $bNoSafeOverwrite, $bNoPacketEncryption)
		EndIf

	Next

	Return $bytesSent

EndFunc   ;==>_Io_BroadcastToRoom

; #FUNCTION# ====================================================================================================================
; Name ..........: _Io_socketGetProperty
; Description ...:  Server-side only. Retrieves information about the socket.
; Syntax ........: _Io_socketGetProperty(Const $socket[, $sProp = Default[, $default = null]])
; Parameters ....: $socket              - [const] a string value.
;                  $sProp               - [optional] a string value. Default is Default.
;                  $default             - [optional] a binary variant value. Default is null.
; Return values .: Mixed
; Author ........: TarreTarreTarre
; Modified ......:
; Remarks .......: If $sProp is set to `Default` then an array containing two elements will be returned.
; Related .......: _Io_socketSetProperty, _Io_getFirstByProperty, _Io_getAllByProperty
; Link ..........:
; Example .......: No
; ===============================================================================================================================
Func _Io_socketGetProperty(Const $socket, $sProp = Default, $default = Null)

	; Get property from socket
	For $i = 1 To $g__io_sockets[0] Step +3

		If Not $g__io_sockets[$i] > 0 Then ContinueLoop

		If $g__io_sockets[$i] == $socket Then

			; Return all
			If $sProp == Default Then
				Local $aExtendedSocket = [$g__io_sockets[$i], $g__io_sockets[$i + 1], $g__io_sockets[$i + 2]]
				Return $aExtendedSocket
			EndIf

			; Return specific
			Switch $sProp
				Case "ip"
					Return $g__io_sockets[$i + 1]
				Case "date"
					Return $g__io_sockets[$i + 2]
				Case "socket" ; Redundant but required for code consistency
					Return $socket
				Case Else

					; If we have a custom prop. This is what it should be called
					Local $fqdn = $g__Io_socketPropertyDomain & "_" & $socket & $sProp

					If Not IsDeclared($fqdn) Then Return $default

					Return Eval($fqdn)

			EndSwitch

		EndIf

		; Check if we can abort this loop
		If $i >= $g__iBiggestSocketI Then ExitLoop

	Next

	Return SetError(1, 0, Null)
EndFunc   ;==>_Io_socketGetProperty

; #FUNCTION# ====================================================================================================================
; Name ..........: _Io_getFirstByProperty
; Description ...: Searches through every alive socket to find and return the first result of the desired properties.
; Syntax ........: _Io_getFirstByProperty($sPropToSearchFor, $valueToSearchFor, $propsToReturn[, $default = Null])
; Parameters ....: $sPropToSearchFor    - a string value.
;                  $valueToSearchFor    - a variant value.
;                  $propsToReturn        - a pointer value.
;                  $default             - [optional] a binary variant value. Default is Null.
; Return values .: Mixed
; Author ........: TarreTarreTarre
; Modified ......:
; Remarks .......: You can retrieve multiple properties by using commas. If nothing was found @error will be set and the $default value will be used.
; Related .......:  _Io_socketGetProperty, _Io_socketSetProperty, _Io_getAllByProperty
; Link ..........:
; Example .......: No
; ===============================================================================================================================
Func _Io_getFirstByProperty($sPropToSearchFor, $valueToSearchFor, $propsToReturn, $default = Null)
	Return __Io_makeSocketCollection($sPropToSearchFor, $valueToSearchFor, $propsToReturn, $default, False)
EndFunc   ;==>_Io_getFirstByProperty

; #FUNCTION# ====================================================================================================================
; Name ..........: _Io_getAllByProperty
; Description ...: Searches through every alive socket to find and return an array of results with the desired properties.
; Syntax ........: _Io_getAllByProperty($sPropToSearchFor, $valueToSearchFor, $propsToReturn)
; Parameters ....: $sPropToSearchFor    - a string value.
;                  $valueToSearchFor    - a variant value.
;                  $propsToReturn        - a pointer value.
; Return values .: Mixed
; Author ........: TarreTarreTarre
; Modified ......:
; Remarks .......:  You can retrieve multiple properties by using commas. If nothing was found an empty array will be returned. no @error
; Related .......:  _Io_socketGetProperty, _Io_socketSetProperty, _Io_getFirstByProperty
; Link ..........:
; Example .......: No
; ===============================================================================================================================
Func _Io_getAllByProperty($sPropToSearchFor, $valueToSearchFor, $propsToReturn)
	Return __Io_makeSocketCollection($sPropToSearchFor, $valueToSearchFor, $propsToReturn, Default, True)
EndFunc   ;==>_Io_getAllByProperty

; #FUNCTION# ====================================================================================================================
; Name ..........: _Io_socketSetProperty
; Description ...: Server-side only. Bind a custom property to a socket, which can be used later on
; Syntax ........: _Io_socketSetProperty(Const $socket, $sProp, $value)
; Parameters ....: $socket              - [const] a string value.
;                  $sProp               - a string value.
;                  $value               - a variant value.
; Return values .: True if successfull, @error if error.
; Author ........: TarreTarreTarre
; Modified ......:
; Remarks .......: the props `socket`, `ip` and `date` is reserved. @Error 1 = reserved prop name used. @Error 2 = invalid property name. Only a-zA-Z 0-9 and _ is allowed.
; Related .......: _Io_socketGetProperty, _Io_getFirstByProperty, _Io_getAllByProperty
; Link ..........:
; Example .......: No
; ===============================================================================================================================
Func _Io_socketSetProperty(Const $socket, $sProp, $value)

	If StringRegExp($sProp, "^(ip|date|socket)$") Then Return SetError(1, 0, Null)
	If Not StringRegExp($sProp, "(?i)^[a-z0-9_]+$") Then Return SetError(2, 0, Null)

	Local $fqdn = $g__Io_socketPropertyDomain & "_" & $socket & $sProp

	; Save prop so we can use it to tidy up dead sockets later
	__Io_Push($g__io_UsedProperties, $sProp)

	If $g__io_DevDebug Then ConsoleWrite("-" & @TAB & "_Io_socketSetProperty: Assigning an " & VarGetType($value) & " to " & $fqdn & @LF)

	Return Assign($fqdn, $value, 2) == 1

EndFunc   ;==>_Io_socketSetProperty

; #FUNCTION# ====================================================================================================================
; Name ..........: _Io_getVer
; Description ...: Returns the version of the UDF
; Syntax ........: _Io_getVer()
; Parameters ....:
; Return values .: SEMVER string (X.Y.Z)
; Author ........: TarreTarreTarre
; Modified ......:
; Remarks .......: See more on semver @ http://semver.org/
; Related .......:
; Link ..........:
; Example .......: No
; ===============================================================================================================================
Func _Io_getVer()
	Return $g__io_sVer
EndFunc   ;==>_Io_getVer

; #FUNCTION# ====================================================================================================================
; Name ..........: _Io_getSocketsCount
; Description ...:  Server-side only. Returns the number of all sockets regardless of state.
; Syntax ........: _Io_getSocketsCount()
; Parameters ....:
; Return values .: integer
; Author ........: TarreTarreTarre
; Modified ......:
; Remarks .......: Includes disconnected sockets.
; Related .......: _Io_getDeadSocketCount, _Io_getActiveSocketCount, _Io_getSockets
; Link ..........:
; Example .......: No
; ===============================================================================================================================
Func _Io_getSocketsCount()
	Return Int($g__io_sockets[0] / 3)
EndFunc   ;==>_Io_getSocketsCount

; #FUNCTION# ====================================================================================================================
; Name ..........: _Io_getDeadSocketCount
; Description ...:  Server-side only. Returns the number of all dead sockets.
; Syntax ........: _Io_getDeadSocketCount()
; Parameters ....:
; Return values .: integer
; Author ........: TarreTarreTarre
; Modified ......:
; Remarks .......:
; Related .......: _Io_getSocketsCount, _Io_getActiveSocketCount, _Io_getSockets
; Link ..........:
; Example .......: No
; ===============================================================================================================================
Func _Io_getDeadSocketCount()
	Return $g__io_dead_sockets_count
EndFunc   ;==>_Io_getDeadSocketCount

; #FUNCTION# ====================================================================================================================
; Name ..........: _Io_getActiveSocketCount
; Description ...: Server-side only. Returns the number of all active sockets.
; Syntax ........: _Io_getActiveSocketCount()
; Parameters ....:
; Return values .: integer
; Author ........: TarreTarreTarre
; Modified ......:
; Remarks .......:
; Related .......: _Io_getSocketsCount, _Io_getDeadSocketCount, _Io_getSockets
; Link ..........:
; Example .......: No
; ===============================================================================================================================
Func _Io_getActiveSocketCount()
	Return _Io_getSocketsCount() - _Io_getDeadSocketCount()
EndFunc   ;==>_Io_getActiveSocketCount

; #FUNCTION# ====================================================================================================================
; Name ..........: _Io_getSockets
; Description ...: Returns all stored sockets, [$i + 0] = socket, [$i + 1] = ip, [$i + 2] = Date joined (YYYY-MM-DD HH:MM:SS)
; Syntax ........: _Io_getSockets([$bForceUpdate = False[, $socket = $g__io_mySocket[, $whoAmI = $g__io_whoami]]])
; Parameters ....: $bForceUpdate        - [optional] a boolean value. Default is False.
;                  $socket              - [optional] a string value. Default is $g__io_mySocket.
;                  $whoAmI              - [optional] an unknown value. Default is $g__io_whoami.
; Return values .: Array
; Author ........: TarreTarreTarre
; Modified ......:
; Remarks .......: Ubound wont work propery with this array, so use The `$aArr[1]` element to retrive the size. `For $i = 1 to $aArr[1] step +3 ......`. the socket is (Keyowrd) "Null" if the socket is dead.
; Related .......: _Io_getSocketsCount, _Io_getDeadSocketCount, _Io_getActiveSocketCount
; Link ..........:
; Example .......: No
; ===============================================================================================================================
Func _Io_getSockets($bForceUpdate = False, $socket = $g__io_mySocket, $whoAmI = $g__io_whoami)

	If $bForceUpdate Then _Io_Loop($socket, $whoAmI)

	Return $g__io_sockets

EndFunc   ;==>_Io_getSockets

; #FUNCTION# ====================================================================================================================
; Name ..........: _Io_getMaxConnections
; Description ...:  Server-side only.Returns the maximum allowed connections
; Syntax ........: _Io_getMaxConnections()
; Parameters ....:
; Return values .: integer
; Author ........: TarreTarreTarre
; Modified ......:
; Remarks .......:
; Related .......:
; Link ..........:
; Example .......: No
; ===============================================================================================================================
Func _Io_getMaxConnections()
	Return $g__io_nMaxConnections
EndFunc   ;==>_Io_getMaxConnections

; #FUNCTION# ====================================================================================================================
; Name ..........: _Io_getMaxDeadSocketsCount
; Description ...: Returns the maximum dead sockets before an `_Io_TidyUp() ` is triggered
; Syntax ........: _Io_getMaxDeadSocketsCount()
; Parameters ....:
; Return values .: integer
; Author ........: TarreTarreTarre
; Modified ......:
; Remarks .......:
; Related .......: _Io_TidyUp
; Link ..........:
; Example .......: No
; ===============================================================================================================================
Func _Io_getMaxDeadSocketsCount()
	Return $g__io_max_dead_sockets_count
EndFunc   ;==>_Io_getMaxDeadSocketsCount

; #FUNCTION# ====================================================================================================================
; Name ..........: _Io_getBanlist
; Description ...: Server-side only. Returns all / specific banlist entry.
; Syntax ........: _Io_getBanlist([$iEntry = Default])
; Parameters ....: $iEntry              - [optional] an integer value. Default is Default.
; Return values .: Array
; Author ........: TarreTarreTarre
; Modified ......:
; Remarks .......:
; Related .......: _Io_Ban, _Io_Sanction, _Io_IsBanned
; Link ..........:
; Example .......: No
; ===============================================================================================================================
Func _Io_getBanlist($iEntry = Default)
	If $iEntry == Default Then Return $g__io_aBanlist
	; ip, created_at, expires_at, reason, issued_by
	Local $aRet = [$g__io_aBanlist[$iEntry], $g__io_aBanlist[$iEntry + 1], $g__io_aBanlist[$iEntry + 2], $g__io_aBanlist[$iEntry + 3], $g__io_aBanlist[$iEntry + 4]]
	Return $aRet
EndFunc   ;==>_Io_getBanlist

; #FUNCTION# ====================================================================================================================
; Name ..........: _Io_Ban
; Description ...: Server-side only. Ip ban and prevent incomming connections from a given ip.
; Syntax ........: _Io_Ban($socketOrIp[, $nTime = 3600[, $sReason = "Banned"[, $sIssuedBy = "system"]]])
; Parameters ....: $socketOrIp          - a string value.
;                  $nTime               - [optional] a general number value. Default is 3600.
;                  $sReason             - [optional] a string value. Default is "Banned".
;                  $sIssuedBy           - [optional] a string value. Default is "system".
; Return values .: None
; Author ........: TarreTarreTarre
; Modified ......:
; Remarks .......: $nTime is seconds. Default is therefore 1 hour. A banned client will receive the `banned` event when trying to connect. If you close the server. All bans will persist when you start it up again.
; Related .......: _Io_getBanlist, _Io_Sanction, _Io_IsBanned
; Link ..........:
; Example .......: No
; ===============================================================================================================================
Func _Io_Ban($socketOrIp, $nTime = 3600, $sReason = "Banned", $sIssuedBy = "system")
	Local Const $created_at = __Io_createTimestamp()
	Local Const $expires_at = $created_at + $nTime
	Local $isSocket = False, $originalSocket = Null

	; Convert sockets to ip
	If StringRegExp($socketOrIp, "^\d+$") Then
		; Save the socket for later use
		$originalSocket = $socketOrIp
		$socketOrIp = _Io_socketGetProperty($socketOrIp, "ip")
		$isSocket = True
	EndIf

	If $g__io_DevDebug Then ConsoleWrite("-" & @TAB & "_Io_Ban: $socketOrIp = " & $socketOrIp & @LF)

	; Save to memory
	Local $iSlot = $g__io_aBanlist[0]
	$g__io_aBanlist[$iSlot + 1] = $socketOrIp
	$g__io_aBanlist[$iSlot + 2] = $created_at
	$g__io_aBanlist[$iSlot + 3] = $expires_at
	$g__io_aBanlist[$iSlot + 4] = $sReason
	$g__io_aBanlist[$iSlot + 5] = $sIssuedBy
	$g__io_aBanlist[0] = $iSlot + 5

	; If this was a socket, we kick them out
	If $isSocket Then
		_Io_Disconnect($originalSocket)
	EndIf

	Return True

EndFunc   ;==>_Io_Ban

; #FUNCTION# ====================================================================================================================
; Name ..........: _Io_Sanction
; Description ...: Server-side only. Remove a previously set ban.
; Syntax ........: _Io_Sanction($socketOrIp)
; Parameters ....: $socketOrIp          - a string value.
; Return values .: Bool. `True` if successfully unbanned. `False` if socket was not found.
; Author ........: TarreTarreTarre
; Modified ......:
; Remarks .......:
; Related .......: _Io_getBanlist, _Io_Ban, _Io_IsBanned
; Link ..........:
; Example .......: No
; ===============================================================================================================================
Func _Io_Sanction($socketOrIp)
	; Convert sockets to ip
	If StringRegExp($socketOrIp, "^\d+$") Then $socketOrIp = _Io_socketGetProperty($socketOrIp, "ip")

	Local $isBanned = _Io_IsBanned($socketOrIp)

	If $g__io_DevDebug Then ConsoleWrite("-" & @TAB & "_Io_Sanction: $isBanned = " & ($isBanned ? 'true' : 'false') & @LF)

	; Mask
	If $isBanned > 0 Then
		$g__io_aBanlist[$isBanned] = ""
		$g__io_aBanlist[$isBanned + 1] = ""
		$g__io_aBanlist[$isBanned + 2] = ""
		$g__io_aBanlist[$isBanned + 3] = ""
		$g__io_aBanlist[$isBanned + 4] = ""
		If $g__io_DevDebug Then ConsoleWrite("-" & @TAB & "_Io_Sanction: return false" & @LF)
		Return True
	EndIf

	If $g__io_DevDebug Then ConsoleWrite("-" & @TAB & "_Io_Sanction: return true" & @LF)
	Return False
EndFunc   ;==>_Io_Sanction

; #FUNCTION# ====================================================================================================================
; Name ..........: _Io_IsBanned
; Description ...: Server-side only. Checks if an socket or ip exists in the banlist
; Syntax ........: _Io_IsBanned($socketOrIp)
; Parameters ....: $socketOrIp          - a string value.
; Return values .: Returns the `$index` of the banned ip if found, returns false if not found.
; Author ........: TarreTarreTarre
; Modified ......:
; Remarks .......: If a `$socket` is passed, the ip will be retrived from the socket.
; Related .......: _Io_getBanlist, _Io_Ban, _Io_Sanction
; Link ..........:
; Example .......: No
; ===============================================================================================================================
Func _Io_IsBanned($socketOrIp)
	; Convert sockets to ip
	If StringRegExp($socketOrIp, "^\d+$") Then $socketOrIp = _Io_socketGetProperty($socketOrIp, "ip")
	Local Const $now = __Io_createTimestamp()
	Local $isBanned

	If $g__io_DevDebug Then ConsoleWrite("-" & @TAB & "_Io_IsBanned: $socketOrIp = " & $socketOrIp & @LF)

	; Note the 1 INDex here
	For $i = 1 To $g__io_aBanlist[0] Step +5

		; We cannot return on the first hit since the same ip can be banned multiple times.
		If $g__io_aBanlist[$i] == $socketOrIp Then
			$isBanned = $now < $g__io_aBanlist[$i + 2] ? $i : False
			; only return if banned
			If $isBanned > 0 Then
				If $g__io_DevDebug Then ConsoleWrite("-" & @TAB & "_Io_IsBanned: $isBanned = true" & @LF)
				Return $isBanned
			EndIf
		EndIf

	Next

	If $g__io_DevDebug Then ConsoleWrite("-" & @TAB & "_Io_IsBanned: $isBanned = false" & @LF)
	Return False

EndFunc   ;==>_Io_IsBanned

; #FUNCTION# ====================================================================================================================
; Name ..........: _Io_ClearEvents
; Description ...: Removes all events from the script.
; Syntax ........: _Io_ClearEvents()
; Parameters ....:
; Return values .: None
; Author ........: TarreTarreTarre
; Modified ......:
; Remarks .......:
; Related .......:
; Link ..........:
; Example .......: No
; ===============================================================================================================================
Func _Io_ClearEvents()
	If $g__io_DevDebug Then ConsoleWrite("-" & @TAB & "_Io_ClearEvents: All events cleared" & @LF)
	Global $g__io_events[1001] = [0]
EndFunc   ;==>_Io_ClearEvents

; #FUNCTION# ====================================================================================================================
; Name ..........: _Io_TransferSocket
; Description ...: Transfer the socket id and events to a new Socket.
; Syntax ........: _Io_TransferSocket(Byref $from, Const Byref $to)
; Parameters ....: $from                - [in/out] a floating point value.
;                  $to                  - [in/out] a dll struct value.
; Return values .: None
; Author ........: TarreTarreTarre
; Modified ......:
; Remarks .......: $from is replaced by $to. So there is no need to do something like this "$to = _Io_TransferSocket($from, $to)"
; Related .......:
; Link ..........:
; Example .......: No
; ===============================================================================================================================
Func _Io_TransferSocket(ByRef $from, Const ByRef $to)

	; Transfer socket events
	For $i = 1 To $g__io_events[0] Step +3
		If $g__io_events[$i + 2] == $from Then $g__io_events[$i + 2] = $to
	Next

	; Transfer main socket identifier
	$from = $to

EndFunc   ;==>_Io_TransferSocket

; #FUNCTION# ====================================================================================================================
; Name ..........: _Io_TidyUp
; Description ...:  Server-side only. Frees some memory by rebuilding arrays and more.
; Syntax ........: _Io_TidyUp()
; Parameters ....:
; Return values .: None
; Author ........: TarreTarreTarre
; Modified ......:
; Remarks .......:
; Related .......:
; Link ..........:
; Example .......: No
; ===============================================================================================================================
Func _Io_TidyUp()

	If $g__io_DevDebug Then ConsoleWrite("-" & @TAB & "_Io_TidyUp: Start! " & @LF)

	; Store sockets, bans and rooms temporarly.
	Local $aTmpSocket = $g__io_sockets
	Local $aTmpRooms = $g__io_socket_rooms
	Local $aTmpBans = $g__io_aBanlist
	Local $aTmpMiddlewares = $g__io_aMiddlewares

	; Reset everything
	$g__io_sockets[0] = 0
	$g__io_socket_rooms[0] = 0
	$g__io_aBanlist[0] = 0
	$g__io_aMiddlewares[0] = 0
	$g__iBiggestSocketI = 0

	; Rebuild sockets
	For $i = 1 To $aTmpSocket[0] Step +3
		; ignore all dead sockets
		If Not $aTmpSocket[$i] > 0 Then ContinueLoop
		__Io_Push3x($g__io_sockets, $aTmpSocket[$i], $aTmpSocket[$i + 1], $aTmpSocket[$i + 2])

		$g__iBiggestSocketI += 3
	Next

	; Rebuild subscriptions
	For $i = 1 To $aTmpRooms[0] Step +2
		If $aTmpRooms[$i] = Null Then ContinueLoop
		__Io_Push2x($g__io_socket_rooms, $aTmpRooms[$i], $aTmpRooms[$i + 1])
	Next

	; Rebuild banlist
	Local $x = 0
	Local Const $now = __Io_createTimestamp()
	For $i = 1 To $aTmpBans[0] Step +5

		; Keep all active bans
		If $aTmpBans[$i + 2] > $now Then
			$g__io_aBanlist[$x + 1] = $aTmpBans[$i] ; IP
			$g__io_aBanlist[$x + 2] = $aTmpBans[$i + 1] ; Created_at
			$g__io_aBanlist[$x + 3] = $aTmpBans[$i + 2] ; Expires_at
			$g__io_aBanlist[$x + 4] = $aTmpBans[$i + 3] ; Issued_by
			$g__io_aBanlist[$x + 5] = $aTmpBans[$i + 4] ; reason
			$x += 1
		EndIf

	Next
	$g__io_aBanlist[0] = $x

	; Rebuild middlewares
	For $i = 1 To $aTmpMiddlewares[0] Step +3
		If $aTmpMiddlewares[$i] == Null Then ContinueLoop
		__Io_Push($g__io_aMiddlewares, $aTmpMiddlewares[$i])
	Next

	; Reset deathcounter
	$g__io_dead_sockets_count = 0

	If $g__io_DevDebug Then ConsoleWrite("-" & @TAB & "_Io_TidyUp: Stop! " & @LF)

EndFunc   ;==>_Io_TidyUp

Func _Io_SetBytesPerSecond($bEnable)
	if IsBool($bEnable) Then $g__Io_bSetBytesPerSecond = $bEnable
EndFunc

Func _Io_GetBytesPerSecond($hSocket, $bRecvMode)
	__Io_BytesPerSecond($hSocket, 0, False) ; updating it

	Local $sMode = "SEND"
	if $bRecvMode Then $sMode = "RECV"

	$nBytesPerSecond = _storageS_Read($hSocket & 'LASBYTES' & $sMode) / 2
	if $nBytesPerSecond = 0 Then $nBytesPerSecond = _storageS_Read($hSocket & 'CURBYTES' & $sMode) / 2
	Return $nBytesPerSecond
EndFunc

Func _Io_GetLastMeassurements()
	Local $arTmp[2][2]
	$arTmp[0][0] = "Send"
	$arTmp[0][1] = $g__Io_nMeassureMentSend
	$arTmp[1][0] = "Recv"
	$arTmp[1][1] = $g__Io_nMeassureMentRecv

	Return $arTmp
EndFunc

Func _Io_SetPacketValidation($bSet)
	$g__Io_bPacketValidation = $bSet
EndFunc

Func _Io_SetPacketSafety($bSet)
	$g__Io_bPacketSafety = $bSet
EndFunc

Func _Io_SetFloodPrevention($bSet)
	$g__Io_bFloodPrevention = $bSet
;~ 	$g__Io_nFloodPrevention = 0
EndFunc

Func _Io_SetAcceptUnecryptedTraffic($bSet)
	$g__Io_bAcceptUnecryptedTraffic = $bSet
EndFunc

Func _Io_SetEncryptionCallback($sEncryptionCallback)
	$g__Io_sEncryptionCallback = $sEncryptionCallback
EndFunc

Func _Io_SetDecryptionCallback($sDecryptionCallback)
	$g__Io_sDecryptionCallback = $sDecryptionCallback
EndFunc

Func _Io_SetOnlySendInLoop($Set)
	$g__Io_bToggleSendOnlyWhenLoop = $Set
EndFunc

Func _Io_SetGlobalTimeout($Set)
	$g__Io_nGlobalTimeoutTime = Number($Set)
EndFunc

Func _On_Internal_FloodPrevention(Const $socket, $sData)
;~ 	ConsoleWrite("Flood Prevention" & @TAB & __Io_CheckFloodPrevention($socket) & @TAB & '-' & @TAB & $sData & @TAB & '=' & @TAB)
	if $sData = "ALL" Then
		; we only reset if $g__Io_hFloodPreventionFix is a Timer
		if $g__Io_hFloodPreventionFix = "NOTSET" Then Return
		__Io_DelFloodPrevention($socket, "ALL")
	ElseIf $sData = "STATUS" Then
		_Io_Emit($socket, 'Internal_FloodPrevention', 'ALL') ; needs testing
	Else
		__Io_DelFloodPrevention($socket, Number($sData))
	EndIf
;~ 	ConsoleWrite(__Io_CheckFloodPrevention($socket) & @CRLF)
EndFunc

Func _On_Internal_Safety(Const $socket, $sData)
;~ 	if $g__Io_bPacketSafety Then $g__Io_sLastValidationPacketResponse = $sData
	_storageS_Overwrite($socket & '_InternalSafety_Response', $sData)
;~ 	$g__Io_sLastValidationPacketResponse = $sData
EndFunc

; ~ Internal functions

Func __Io_AddFloodPrevention($hSocket, $nBytes)
	if Not $g__Io_bFloodPrevention Then Return


	$nStorage = _storageS_Read($hSocket & "FLOOD")
	if Not $nStorage Then $nStorage = 0

	Return _storageS_Overwrite($hSocket & "FLOOD", $nStorage + $nBytes)
EndFunc

Func __Io_DelFloodPrevention($hSocket, $nMinus)
	if Not $g__Io_bFloodPrevention Then Return

	if $nMinus = "ALL" Then
		$g__Io_bFloodPreventionFix = False
		$g__Io_hFloodPreventionFix = "NOTSET"
		Return _storageS_Overwrite($hSocket & "FLOOD", 0)
	Else
		$nCurrentFlood = _storageS_Read($hSocket & "FLOOD")
		if $nCurrentFlood - $nMinus <= 0 Then
			Return _storageS_Overwrite($hSocket & "FLOOD", 0)
		Else
			Return _storageS_Overwrite($hSocket & "FLOOD", $nCurrentFlood - $nMinus)
		EndIf
	EndIf
EndFunc

Func __Io_CheckFloodPrevention($hSocket)
	if Not $g__Io_bFloodPrevention Then Return 0

	$nStorage = _storageS_Read($hSocket & "FLOOD")
	if $nStorage Then Return $nStorage
	Return 0
EndFunc

Func __Io_makeSocketCollection($sPropToSearchFor, $valueToSearchFor, $propsToReturn, $default = Null, $bArray = True)
	Local $aReturn[1] = [0]
	; Get property from socket
	For $i = 1 To $g__io_sockets[0] Step +3

		; Ignore dead sockets
		If Not $g__io_sockets[$i] > 0 Then ContinueLoop

		Local $searchvalue, $fqdn

		; Determine what we search for
		Switch $sPropToSearchFor
			Case "ip"
				$searchvalue = $g__io_sockets[$i + 1]
			Case "date"
				$searchvalue = $g__io_sockets[$i + 2]
			Case "socket"
				$searchvalue = $g__io_sockets[$i]
			Case Else
				; If we have a custom prop. This is what it should be called
				$fqdn = $g__Io_socketPropertyDomain & "_" & $g__io_sockets[$i] & $sPropToSearchFor

				$searchvalue = IsDeclared($fqdn) ? Eval($fqdn) : $default
		EndSwitch

		; If we struck gold. Make a collection
		If $valueToSearchFor == $searchvalue Then

			Local $valuesToReturn[1] = [0]

			Local $propsToReturnSplitted = StringSplit($propsToReturn, ',')

			; Loop throgu all desired lrops to use
			For $j = 1 To $propsToReturnSplitted[0]
				Local $propToReturn = $propsToReturnSplitted[$j]
				Local $valueToReturn

				Switch $propToReturn
					Case "ip"
						$valueToReturn = $g__io_sockets[$i + 1]
					Case "date"
						$valueToReturn = $g__io_sockets[$i + 2]
					Case "socket"
						$valueToReturn = $g__io_sockets[$i]
					Case Else
						; If we have a custom prop. This is what it should be called
						$fqdn = $g__Io_socketPropertyDomain & "_" & $g__io_sockets[$i] & $propToReturn

						$valueToReturn = IsDeclared($fqdn) ? Eval($fqdn) : $default
				EndSwitch
				__Io_Push($valuesToReturn, $valueToReturn)
			Next

			If $bArray Then
				__Io_Push($aReturn, $valuesToReturn)
			Else
				Return $valuesToReturn
			EndIf

		EndIf


		; Check if we can abort this loop
		If $i >= $g__iBiggestSocketI Then ExitLoop
	Next


	Return $bArray ? $aReturn : SetError(1, 0, $default)
EndFunc   ;==>__Io_makeSocketCollection

Func __Io_FireEvent(Const $socket, ByRef $r_params, Const $sEventName, Const ByRef $parentSocket)

	If $g__io_DevDebug Then
		ConsoleWrite("-" & @TAB & "__Io_FireEvent: attempting to fire event '" & $sEventName & "' with socket " & $socket & " from parentSocket " & $parentSocket & @LF)
	EndIf

	For $i = 1 To $g__io_events[0] Step +3

		If $g__io_events[$i] == $sEventName And $g__io_events[$i + 2] == $parentSocket Then

			Local $fCallbackName = $g__io_events[$i + 1]

			If $g__io_DevDebug Then
				ConsoleWrite("-" & @TAB & "__Io_FireEvent: Event found!" & @LF)
			EndIf

			For $j = 1 To $g__io_aMiddlewares[0]
				Local $mw = $g__io_aMiddlewares[$j]
				Local $mwTargetEvent = $mw[0]
				; +1 is the fucnname() of the callback. Only used for administration
				Local $mwFuncCallback = $mw[2] ;

				If $mwTargetEvent == $sEventName Or $mwTargetEvent == '*' Then

					; IF the middleware returns false. We should not continue this loop and go to next
					If Not $mwFuncCallback($socket, $r_params, $sEventName, $fCallbackName) Then
						If $g__io_DevDebug Then ConsoleWrite("-" & @TAB & "__Io_FireEvent: Middleware '" & $mwTargetEvent & "' returned false. Not firing event. ContinueLoop 2" & @LF)
						ContinueLoop 2
					EndIf
				EndIf
			Next

			__Io_InvokeCallback($socket, $r_params, $fCallbackName)

			Return True
		EndIf
	Next

	If $g__io_DevDebug Then
		ConsoleWrite("-" & @TAB & "__Io_FireEvent: No event found on parentSocket" & @LF)
	EndIf

	Return False

EndFunc   ;==>__Io_FireEvent

Func __Io_r_Params2ar_Params($hSocket, $r_params)
	Local $nIndicatorLen = StringLen($g__Io_sParamIndicatorString)
	Local $aTmp[2]

	; these elements are everywhere the same
	$aTmp[0] = 'CallArgArray'
	$aTmp[1] = $hSocket

	if $r_params = Null Or $r_params = '' Then ; if no params
		Return $aTmp
;~ 		Return $hSocket

	Elseif StringLeft($r_params, $nIndicatorLen) <> $g__Io_sParamIndicatorString Then ; if not merged by _Io_sParams
		ReDim $aTmp[3]
		$aTmp[2] = __Io_CheckParamAndUnserialize($r_params)
		Return $aTmp

	Else ; if merged
		$arParams = StringSplit(StringTrimLeft($r_params, $nIndicatorLen), $g__Io_sParamSplitSeperator, 1)
		ReDim $aTmp[2 + $arParams[0]]

		For $i = 1 To $arParams[0]
			if $g__Io_bParamSplitBinary Then $arParams[$i] = $arParams[$i]
			$aTmp[1 + $i] = __Io_CheckParamAndUnserialize($arParams[$i])
		Next

		Return $aTmp
	EndIf

EndFunc

Func __Io_InvokeCallback(Const $socket, ByRef $r_params, Const $fCallbackName)

	$r_params = __Io_r_Params2ar_Params($socket, $r_params)

	If $g__io_DevDebug Then
		ConsoleWrite("-" & @TAB & "__Io_InvokeCallback: attempting to invoke " & $fCallbackName & " with " & UBound($r_params) - 1 & " parameters. $socket-param included." & @LF)
	EndIf

	$g__Io_nMeassureMentRecv = TimerDiff($g__Io_hMeassurementRecv)
	Call($fCallbackName, $r_params)

	If @error == 0xDEAD And @extended == 0xBEEF Then

		If $g__io_DevDebug Then
			ConsoleWrite("-" & @TAB & '__Io_InvokeCallback: the callback "' & $fCallbackName & '" failed with DEAD BEEF' & @LF)
		EndIf

		Return False
	EndIf


	If $g__io_DevDebug Then
		ConsoleWrite("-" & @TAB & '__Io_InvokeCallback: Successfully invoked "' & $fCallbackName & '".' & @LF)
	EndIf


	Return True

EndFunc   ;==>__Io_InvokeCallback

Func __Io_createPackage(ByRef $sEventName, ByRef $sParams, $bNoEncryptionForThisPacket = False, $hOptionalSocket = 0)
	; simple Formating instead of cpu intensive serialization. Because Autoit is slow
	;
	; if the event or the Data contains the Seperator Chars then the Packet Handler
	; will have issues Seperating it. You could Binary the Event or Data, but you dont want to.
	; Because if you do this then you will atleast double the Packet Size.
	; The SocketIo uses 10 bytes long unique seperators. There is just a very small chance that
	; the Event or the Data contain the same 10 bytes.
	; if so you could change the Seperators <- todo
	;
	; take this example packet
	; 2nYx14Z0Rnnetcode_sync7Ofq155OshSyncMaxPackageSize|40962nYx14Z0Rn
	;
	; and compare it to this with binarized event and data
	; 2nYx14Z0Rn0x6E6574636F64655F73796E637Ofq155Osh0x53796E634D61785061636B61676553697A657C343039362nYx14Z0Rn
	;
	; both still contain the same data but the packet got much larger

	if $g__Io_bPacketValidation Then
;~ 		#cs
		if $g__Io_bPacketValidationMode_Hash Then
			$sValidationPacket = _Crypt_HashData($sEventName & $sParams, $CALG_MD5) ; slower but safer
		Else
			$sValidationPacket = StringLen($sEventName & $sParams) ; just faster
		EndIf
		$sPacketContent = $sValidationPacket & $g__Io_sPacketSeperatorInternal & $sEventName & $g__Io_sPacketSeperatorInternal & $sParams

		if $g__io_vCryptKey <> Null And Not $bNoEncryptionForThisPacket Then $sPacketContent = __Io_Encrypt($sPacketContent, $g__io_vCryptKey, $hOptionalSocket)

;~ 		$sPacketContent = $g__Io_sPacketSeperator & $sPacketContent & $g__Io_sPacketSeperator
		$sPacketContent = $g__Io_sPacketSeperatorLen & $g__Io_sPacketSeperator & $sPacketContent & $g__Io_sPacketSeperator
		Return SetError(0, StringLen($sPacketContent), StringToBinary($sPacketContent))
;~ 		#ce
	Else
		$sPacketContent = $sEventName & $g__Io_sPacketSeperatorInternal & $sParams

		if $g__io_vCryptKey <> Null And Not $bNoEncryptionForThisPacket Then $sPacketContent = __Io_Encrypt($sPacketContent, $g__io_vCryptKey, $hOptionalSocket)

;~ 		$sPacketContent = $g__Io_sPacketSeperator & $sPacketContent & $g__Io_sPacketSeperator
		$sPacketContent = $g__Io_sPacketSeperatorLen & $g__Io_sPacketSeperator & $sPacketContent & $g__Io_sPacketSeperator
		Return SetError(0, StringLen($sPacketContent), StringToBinary($sPacketContent))
	EndIf

EndFunc

; marked for recoding because its a mess and throws issues
Func __Io_handlePackage(Const $socket, ByRef $sPackage, ByRef $parentSocket, $bOnlySafetyPacket = False)
	Local Static $sPacketCacheIf_bOnlySafetyPacket = ""
	Local $nFloodPrevention_PacketSize = 0, $sDeleteSafetyPacket = ""

	if $sPacketCacheIf_bOnlySafetyPacket <> "" Then
		$sPackage = $sPacketCacheIf_bOnlySafetyPacket & $sPackage
		$sPacketCacheIf_bOnlySafetyPacket = ""
	EndIf

	if StringLen($sPackage) = 0 Then Return

	Local $arPackets = StringSplit($sPackage, $g__Io_sPacketSeperator, 1)

	For $i = 1 To $arPackets[0]
		if $arPackets[$i] = "" Then ContinueLoop

		$arParts = StringSplit($arPackets[$i], $g__Io_sPacketSeperatorInternal, 1)
		if $arParts[0] < 2 Then ; it always needs to go in here if packet encryption is enabled

			if $g__io_vCryptKey <> Null Then ; if encryption is enabled
;~ 				$arParts = StringSplit(BinaryToString(_ccrypt_DecData($arPackets[$i], $g__io_vCryptKey)), $g__Io_sPacketSeperatorInternal, 1)
				$arParts = StringSplit(__Io_Decrypt($arPackets[$i], $g__io_vCryptKey, $socket), $g__Io_sPacketSeperatorInternal, 1)
				if $arParts[0] < 2 Then ; its not encrypted but coruppted
					if $g__Io_bPacketSafety Then _Io_Emit($socket, 'Internal_Safety', 'XX', True)
					ContinueLoop
				EndIf
			Else ; the packet is just bad
				if $g__Io_bPacketSafety Then _Io_Emit($socket, 'Internal_Safety', 'XX', True)
				ContinueLoop
			EndIf

;~ 			ContinueLoop ; packet is corrupted, but still we need to send a packet flood prevention back <--------- todo
		Else
			if $g__io_vCryptKey <> Null And Not $g__Io_bAcceptUnecryptedTraffic Then ContinueLoop ; we dont accept unecrypted traffic
		EndIf

		if $arParts[0] = 3 Then ; Packet Validation
;~ 			#cs
			if $g__Io_bPacketValidationMode_Hash Then
				$sValidationHash = _Crypt_HashData($arParts[2] & $arParts[3], $CALG_MD5) ; slower but safer
			Else
				$sValidationHash = StringLen($arParts[2] & $arParts[3]) ; just faster
			EndIf

			if $sValidationHash <> $arParts[1] Then
				if $g__Io_bPacketSafety Then _Io_Emit($socket, 'Internal_Safety', 'XX', True)
				ContinueLoop ; packet gets discarded because its corrupted
			EndIf

			if $arParts[2] <> 'Internal_FloodPrevention' And $arParts[2] <> 'Internal_Safety' Then
				$nFloodPrevention_PacketSize += StringLen($g__Io_sPacketSeperator & $arPackets[$i] & $g__Io_sPacketSeperator)
				; / 2 because the package is send in binary
				if $g__Io_bPacketSafety And StringLen($sPackage) * 2 + 2 >= $g__Io_nPacketSafetyMinimumLen Then
					_Io_Emit($socket, 'Internal_Safety', 'OK', True)
				EndIf
			EndIf

			if $bOnlySafetyPacket Then
				if $arParts[2] = 'Internal_FloodPrevention' Or $arParts[2] = 'Internal_Safety' Then
;~ 				if $arParts[2] = 'Internal_Safety' Then
					$sDeleteSafetyPacket = $g__Io_sPacketSeperator & $arPackets[$i] & $g__Io_sPacketSeperator
					if $sPacketCacheIf_bOnlySafetyPacket = "" Then
						$sPacketCacheIf_bOnlySafetyPacket = StringReplace($sPackage, $sDeleteSafetyPacket, '')
					Else
						$sPacketCacheIf_bOnlySafetyPacket = StringReplace($sPacketCacheIf_bOnlySafetyPacket, $sDeleteSafetyPacket, '')
					EndIf

					__Io_PacketExecution($socket, $arParts[3], $arParts[2], $parentSocket)

;~ 					Return
					ContinueLoop
				Else
					ContinueLoop ; we dont want to execute anything
				EndIf
			EndIf

			__Io_PacketExecution($socket, $arParts[3], $arParts[2], $parentSocket)
;~ 			#ce
		Else ; no packet validation

			__Io_PacketExecution($socket, $arParts[2], $arParts[1], $parentSocket)

			if $arParts[1] <> 'Internal_FloodPrevention' And $arParts[1] <> 'Internal_Safety' Then
				$nFloodPrevention_PacketSize += StringLen($g__Io_sPacketSeperator & $arPackets[$i] & $g__Io_sPacketSeperator)
			EndIf

		EndIf

	Next

	if $g__Io_bFloodPrevention And $nFloodPrevention_PacketSize > 0 Then _Io_Emit($socket, 'Internal_FloodPrevention', $nFloodPrevention_PacketSize, True)

EndFunc

Func __Io_PacketExecution($hSocket, $sContent, $sEventName, $parentSocket)
	__Io_FireEvent($hSocket, $sContent, $sEventName, $parentSocket)
EndFunc

Func __Io_TransportPackage(Const $socket, ByRef $sPackage)
;~ 	$attempt = TCPSend($socket, $sPackage)
	$attempt = __Io_TCPSend($socket, $sPackage)
	Return SetError(@error, @extended, $attempt)
EndFunc   ;==>__Io_TransportPackage

; marked for recoding
Func __Io_TransportPackage_Safe(Const $socket, ByRef $sPackage, $parentSocket) ; , $parentSocket
	if Not $g__Io_bPacketValidation Then
		Return __Io_TransportPackage($socket, $sPackage)
	EndIf

	_storageS_Overwrite($socket & '_InternalSafety_Response', '')
	Local $hTimeoutTimer = TimerInit()
	Local $sNewPackages = "", $nError = 0
	Local $nSendBytes = __Io_TransportPackage($socket, $sPackage)
;~ 	Local $nSendBytes = __Io_TCPSend($socket, $sPackage)
	if $nSendBytes = 0 Then Return SetError(@error, @extended, 0) ; connection invalid?

	While True
		$sNewPackages = __Io_RecvPackage($socket)
		$nError = @error
		if $nError Then Return SetError($nError, 0, 0) ; if any error
		if $sNewPackages Then __Io_handlePackage($socket, $sNewPackages, $parentSocket, True)

		$sPotentialResponse = _storageS_Read($socket & '_InternalSafety_Response')
		if $sPotentialResponse <> "" Then

			Switch $sPotentialResponse

				Case "OK" ; validated
					ExitLoop

				Case "XX" ; failed - resend
					$nSendBytes = __Io_TransportPackage($socket, $sPackage)
					if $nSendBytes = 0 Then
						Return SetError(@error, @extended, 0) ; connection invalid?
					EndIf

			EndSwitch

			_storageS_Overwrite($socket & '_InternalSafety_Response', '')
			$hTimeoutTimer = TimerInit() ; reset because we got a response. Will be toggleable
		EndIf

		if TimerDiff($hTimeoutTimer) > $g__Io_nGlobalTimeoutTime Then Return SetError(1, 0, $nSendBytes) ; timeout
	WEnd

	Return $nSendBytes

EndFunc

; marked for recode
Func __Io_RecvPackage(Const $socket, Const $bRawPackets = False)
;~ 	Local $package = TCPRecv($socket, 1, 1)
	Local $package = __Io_TCPRecv($socket, 1, 1)
	$nError = @error
;~ 	if $nError Then MsgBox(0, "", $nError)
	If $nError Then Return SetError(1, 0, Null) ; Connection lost
	If $package == "" Then Return Null

	$g__Io_hMeassurementRecv = TimerInit()

	; Fetch all data from the buffer
	Do
;~ 		Local $TCPRecv = TCPRecv($socket, $g__io_nPacketSize, 1)
		Local $TCPRecv = __Io_TCPRecv($socket, $g__io_nPacketSize, 1)
		$package &= BinaryToString($TCPRecv)

		If StringLen($package) >= $g__io_nMaxPacketSize Then Return SetError(2, 0, Null)
	Until $TCPRecv == ""

	__Io_BytesPerSecond($socket, StringLen($package), True)

	$package = __Io_RecvPackageValidate($socket, $package)
	if $package = Null Then Return Null

	Return Not $bRawPackets ? BinaryToString($package) : $package
EndFunc   ;==>__Io_RecvPackage

; marked for recoding - make it faster or move it to the packet handler
Func __Io_RecvPackageValidate($hSocket, $sPackage)

	Local $sReturnString = ''
	Local $sPackageBuffer = ''
	__Io_IncompletePackageBuffer($sPackageBuffer, $hSocket)
	if $sPackageBuffer = Null Then
		; bad packet, do something
		$sPackageBuffer = ''
	EndIf
	$sPackage = $sPackageBuffer & $sPackage

	Local $arPackage = StringSplit($sPackage, $g__Io_sPacketSeperatorLen, 1)
	For $i = 1 To $arPackage[0]
		if $arPackage[$i] = '' Then ContinueLoop

		$arPacket = StringSplit($arPackage[$i], $g__Io_sPacketSeperator, 1)
		if $arPacket[0] = 3 Then
			$sReturnString &= $arPackage[$i]
			ContinueLoop
		EndIf

		__Io_IncompletePackageBuffer($sPackageBuffer, $hSocket, $g__Io_sPacketSeperatorLen & $arPackage[$i])
	Next

	if $sReturnString = '' Then Return Null
	Return $sReturnString
EndFunc

Func __Io_IncompletePackageBuffer(ByRef $packetbuffer, $hSocket, $sPackage = -1)
	if $sPackage <> -1 Then
		$packetbuffer = _storageS_Read($hSocket & '_IncompletePacketBuffer')
		if $packetbuffer = False Then $packetbuffer = ''

		if StringLen($packetbuffer) > $g__io_nMaxPacketSize Then
			; packet either to big or bad
			_storageS_Overwrite($hSocket & '_IncompletePacketBuffer', '') ; emptying
			$packetbuffer = Null
			Return
		EndIf

		_storageS_Overwrite($hSocket & '_IncompletePacketBuffer', $packetbuffer & $sPackage)
		$packetbuffer = ''
		Return
	Else
		$packetbuffer = _storageS_Read($hSocket & '_IncompletePacketBuffer')
		if $packetbuffer = False Then
			$packetbuffer = ''
			Return ; nothing buffered
		EndIf

		if StringLen($packetbuffer) > $g__io_nMaxPacketSize Then
			; packet either to big or bad
			_storageS_Overwrite($hSocket & '_IncompletePacketBuffer', '') ; emptying
			$packetbuffer = Null
			Return
		EndIf

		_storageS_Overwrite($hSocket & '_IncompletePacketBuffer', '') ; emptying
		Return
	EndIf
EndFunc

Func __Io_createExtendedSocket(ByRef $socket) ;Actual socket, ip address, date
	Local $aExtendedSocket = [$socket, __Io_SocketToIP($socket), StringFormat("%s-%s-%s %s:%s:%s", @YEAR, @MON, @MDAY, @HOUR, @MIN, @SEC)]
	Return $aExtendedSocket
EndFunc   ;==>__Io_createExtendedSocket

Func __Io_Ban_LoadToMemory($sBanlistFile = @ScriptName & ".banlist.ini")
	If Not FileExists($sBanlistFile) Then Return False
	Local Const $now = __Io_createTimestamp()

	Local $aSectionNames = IniReadSectionNames($sBanlistFile)
	If @error Then Return SetError(@error)
	Local $x = 0

	For $i = 1 To $aSectionNames[0]
		Local $aSection = IniReadSection($sBanlistFile, $aSectionNames[$i])

		; Ignore if ban if expired
		If $now > $aSection[3][1] Then ContinueLoop

		$g__io_aBanlist[$x + 1] = $aSection[1][1] ; IP
		$g__io_aBanlist[$x + 2] = $aSection[2][1] ; created_at
		$g__io_aBanlist[$x + 3] = $aSection[3][1] ; expires_at
		$g__io_aBanlist[$x + 4] = $aSection[4][1] ; issued_by
		$g__io_aBanlist[$x + 5] = $aSection[5][1] ; reason

		$x += 5
	Next

	$g__io_aBanlist[0] = $x

	; Remove cache
	If FileExists($sBanlistFile) Then FileDelete($sBanlistFile)

	Return True

EndFunc   ;==>__Io_Ban_LoadToMemory

Func __Io_Ban_SaveToFile($sBanlistFile = @ScriptName & ".banlist.ini")

	; Remove cache
	If FileExists($sBanlistFile) Then FileDelete($sBanlistFile)

	Local $x = 0

	For $i = 1 To $g__io_aBanlist[0] Step +5

		; Ignore sanctioned bans
		If $g__io_aBanlist[$i] <> "" Then
			IniWrite($sBanlistFile, $x, "ip", $g__io_aBanlist[$i])
			IniWrite($sBanlistFile, $x, "created_at", $g__io_aBanlist[$i + 1])
			IniWrite($sBanlistFile, $x, "expires_at", $g__io_aBanlist[$i + 2])
			IniWrite($sBanlistFile, $x, "issued_by", $g__io_aBanlist[$i + 3])
			IniWrite($sBanlistFile, $x, "reason", $g__io_aBanlist[$i + 4])
			$x += 1
		EndIf
	Next

EndFunc   ;==>__Io_Ban_SaveToFile

Func __Io_SocketToIP(Const $socket) ;ty javiwhite
	Local Const $hDLL = "Ws2_32.dll"
	Local $structName = DllStructCreate("short;ushort;uint;char[8]")
	Local $sRet = DllCall($hDLL, "int", "getpeername", "int", $socket, "ptr", DllStructGetPtr($structName), "int*", DllStructGetSize($structName))
	If Not @error Then
		$sRet = DllCall($hDLL, "str", "inet_ntoa", "int", DllStructGetData($structName, 3))
		If Not @error Then Return $sRet[0]
	EndIf
	Return StringFormat("~%s.%s.%s.%s", Random(1, 255, 1), Random(1, 255, 1), Random(0, 10, 1), Random(1, 255, 1)) ;We assume this is a fake socket and just generate a random IP
EndFunc   ;==>__Io_SocketToIP

Func __Io_Init()
	Local Static $firstInit = True

	If $firstInit Then
		; Set default settings for first use
		If Not $g__io_nPacketSize Then _Io_setRecvPackageSize()
		If Not $g__io_nMaxPacketSize Then _Io_setMaxRecvPackageSize()
		If Not $g__io_sOnEventPrefix Then _Io_setOnPrefix()
;~ 		__Io_RecalSafetyBufferMaxSize()
;~ 		__Io_GetSafetyBufferID()
		$firstInit = False
;~ 	EndIf

		If StringRegExp(@AutoItVersion, "^3.3.1\d+\.\d+$") Then
	;~ 		If Not @Compiled Or $g__io_DevDebug Then
	;~ 			If $g__io_DevDebug Then
	;~ 				ConsoleWrite("-" & @TAB & "SocketIO.au3: Because you are using Autoit version " & @AutoItVersion & " Opt('TCPTimeout') has been set to 5. You could manually use another value by putting Opt('TCPTimeout', 5) (once) after _Io_Connect or _Io_listen. Why this is done you could read more about here: https://www.autoitscript.com/trac/autoit/ticket/3575" & @LF)
	;~ 			EndIf
	;~ 		EndIf
			Opt('TCPTimeout', 5)
		EndIf

		OnAutoItExitRegister("__Io_Shutdown")
	EndIf ; <-

	TCPStartup()
	UDPStartup()

	Return True
EndFunc   ;==>__Io_Init

Func __Io_Shutdown()
	If $g__io_whoami == $_IO_SERVER Then
		__Io_Ban_SaveToFile()
	EndIf
	TCPShutdown()
EndFunc   ;==>__Io_Shutdown

Func __Io_Push(ByRef $a, $v, $bRedim = True)
	If $bRedim Then
		ReDim $a[$a[0] + 2]
	EndIf
	$a[$a[0] + 1] = $v
	$a[0] += 1
	Return $a[0]
EndFunc   ;==>__Io_Push

Func __Io_Push2x(ByRef $a, $v1, $v2)
	$a[$a[0] + 1] = $v1
	$a[$a[0] + 2] = $v2
	$a[0] += 2
	Return $a[0]
EndFunc   ;==>__Io_Push2x

Func __Io_Push3x(ByRef $a, $v1, $v2, $v3)
	$a[$a[0] + 1] = $v1
	$a[$a[0] + 2] = $v2
	$a[$a[0] + 3] = $v3
	$a[0] += 3
	Return $a[0]
EndFunc   ;==>__Io_Push3x

Func __Io_createTimestamp()
	Return (@YEAR * 31556952) + (@MON * 2629746) + (@MDAY * 86400) + (@HOUR * 3600) + (@MIN * 60) + @SEC
EndFunc   ;==>__Io_createTimestamp

Func __Io_createFakeSocket($connectedSocket = Random(100, 999, 1))
	Local $aExtendedSocket = __Io_createExtendedSocket($connectedSocket)
	; Extend socket with some data
	__Io_Push3x($g__io_sockets, $aExtendedSocket[0], $aExtendedSocket[1], $aExtendedSocket[2])
	; Increment our $g__iBiggestSocketI += 3
	$g__iBiggestSocketI += 3
	; return our faked socket
	Return $connectedSocket
EndFunc   ;==>__Io_createFakeSocket

Func __Io_ValidEventName(Const $sEventName)
	Return StringRegExp($sEventName, "^[a-zA-Z 0-9_.:-]+$")
EndFunc   ;==>__Io_ValidEventName

; check if this Socket exists and return parentsocket
; will parse only $g__Io_arAllSockets[n][x]
; If exists = returns SetError(0, Array Index, parentsocket)
; If not exits = return SetError(1, 0, False)
Func __Io_CheckSocket($hSocket)
	Local $nArSize = UBound($g__Io_arAllSockets)
	if $nArSize = 0 Then Return SetError(1, 0, False)

	Local $nIndex = -1
	For $i = 0 To $nArSize - 1
		if $g__Io_arAllSockets[$i][1] = "" Then ContinueLoop

		$arSockets = StringSplit($g__Io_arAllSockets[$i][1], '|', 1)
		For $iS = 1 To $arSockets[0]
			if $arSockets[$iS] = $hSocket Then
				$nIndex = $i
				ExitLoop 2
			EndIf
		Next
	Next

	if $nIndex = -1 Then Return SetError(1, 0, False)

	Return SetError(0, $nIndex, $g__Io_arAllSockets[$nIndex][0])
EndFunc

; temporary
Func __Io_GetClientSockets($hParentSocket)
	Local $nArSize = UBound($g__Io_arAllSockets)
	if $nArSize = 0 Then Return SetError(1, 0, False)

	For $i = 0 To $nArSize - 1
		if $g__Io_arAllSockets[$i][0] = $hParentSocket Then Return StringSplit($g__Io_arAllSockets[$i][1], '|', 1)
	Next

	Return False
EndFunc

Func __Io_AddSocket($hParentSocket, $hClientSocket = 0)
	Local $nArSize = UBound($g__Io_arAllSockets)

	; if array is not empty
	if $nArSize <> 0 Then

		; search for parentsocket if exists add if set clientsocket and return
		For $i = 0 To $nArSize - 1
			if $g__Io_arAllSockets[$i][0] = $hParentSocket Then
				if $hClientSocket <> 0 Then $g__Io_arAllSockets[$i][1] &= $hClientSocket & '|'
				Return
			EndIf
		Next

	EndIf

	; if array is empty or parent not found then add parentsocket and if set also clientsocket
	ReDim $g__Io_arAllSockets[$nArSize + 1][2]
	$g__Io_arAllSockets[$nArSize][0] = $hParentSocket
	if $hClientSocket <> 0 Then $g__Io_arAllSockets[$nArSize][1] = $hClientSocket & '|'

	Return
EndFunc

Func __Io_DelSocket($hSocket, $bParent = False)
	if $bParent Then
		$nArSize = UBound($g__Io_arAllSockets)
		if $nArSize = 0 Then Return SetError(2, 0, False) ; array is empty

		Local $nIndex = -1
		For $i = 0 To $nArSize - 1
			if $g__Io_arAllSockets[$i][0] = $hSocket Then
				$nIndex = $i
				ExitLoop
			EndIf
		Next

		if $nIndex = -1 Then Return SetError(3, 0, False) ; socket not in array

		$g__Io_arAllSockets[$nIndex][0] = $g__Io_arAllSockets[$nArSize - 1][0]
		$g__Io_arAllSockets[$nIndex][1] = $g__Io_arAllSockets[$nArSize - 1][1]
		ReDim $g__Io_arAllSockets[$nArSize - 1][2]

	Else
		if Not __Io_CheckSocket($hSocket) Then Return SetError(1, 0, False) ; client socket doesnt exist in array
		$nIndex = @extended
		$g__Io_arAllSockets[$nIndex][1] = StringReplace($g__Io_arAllSockets[$nIndex][1], $hSocket & '|', '')
	EndIf
EndFunc

; marked for recoding
Func __Io_BytesPerSecond($hSocket, $nSize, $bRecvMode)
	if Not $g__Io_bSetBytesPerSecond Then Return

	Local $sMode = "SEND"
	if $bRecvMode Then $sMode = "RECV"

	$hTimer = _storageS_Read($hSocket & 'BYTEPERSECONDTIMER')
	if $hTimer = False Then
		_storageS_Overwrite($hSocket & 'BYTEPERSECONDTIMER', TimerInit())
		$hTimer = 0
	EndIf

	if TimerDiff($hTimer) > 2000 Then
		_storageS_Overwrite($hSocket & 'LASBYTESSEND', _storageS_Read($hSocket & 'CURBYTESSEND'))
		_storageS_Overwrite($hSocket & 'LASBYTESRECV', _storageS_Read($hSocket & 'CURBYTESRECV'))

		_storageS_Overwrite($hSocket & 'CURBYTESSEND', $nSize)
		_storageS_Overwrite($hSocket & 'CURBYTESRECV', $nSize)

		_storageS_Overwrite($hSocket & 'BYTEPERSECONDTIMER', TimerInit())

		Return
	EndIf

	if $nSize = 0 Then Return

	_storageS_Overwrite($hSocket & 'CURBYTES' & $sMode, _storageS_Read($hSocket & 'CURBYTES' & $sMode) + $nSize)
EndFunc

Func __Io_Encrypt($sData, $sPW, $hOptionalSocket = 0)
	if $g__Io_sEncryptionCallback <> "" Then
		$sEnc = BinaryToString(Call($g__Io_sEncryptionCallback, $sData, $sPW, $hOptionalSocket))
		Return $sEnc
	EndIf

	Return BinaryToString(_ccrypt_EncData($sData, $sPW))
EndFunc

Func __Io_Decrypt($sData, $sPW, $hOptionalSocket = 0)
	if IsString($sData) Then $sData = StringToBinary($sData)
	if $g__Io_sDecryptionCallback <> "" Then
		$sDec = BinaryToString(Call($g__Io_sDecryptionCallback, $sData, $sPW, $hOptionalSocket))
		Return $sDec
	EndIf

	Return BinaryToString(_ccrypt_DecData($sData, $sPW))
EndFunc

; we only serialize arrays and dictionary objects
; todo - if the array or object count is to big, show a warning. Also do more error checking to protect the code from DDOS
; todo - recode object serilization because i messed it up
Func __Io_CheckParamAndSerialize($sParam, $bNoIndication = False)
	Switch VarGetType($sParam)
		Case 'Array'
			Return __Io_SerializeArray($sParam)

;~ 		Case 'Object'
;~ 			Return __Io_SerializeObject($sParam, $bNoIndication)

		Case Else
			Return $sParam

	EndSwitch
EndFunc

; you cannot serialize 2d arrays - yet
Func __Io_SerializeArray($sParam)
	Local $sReturnString = $g__Io_sSerializationIndicator & $g__Io_sSerializeArrayIndicator
	Local $nArSize = UBound($sParam)
	For $i = 0 To $nArSize - 1
		if $g__Io_bParamSplitBinary Then $sParam[$i] = StringToBinary($sParam[$i])
		$sReturnString &= $sParam[$i] & $g__Io_sSerializeArraySeperator
	Next

	Return $sReturnString
EndFunc

#cs
Func __Io_SerializeObject($sParam, $bNoIndication = False)
	Local $sReturnString = $g__Io_sSerializationIndicator & $g__Io_sSerializeObjectIndicator
	if $bNoIndication Then $sReturnString = ''
	Local $nObjSize = $sParam.count ; ()
	Local $arKeys = $sParam.keys
	Local $arItems = $sParam.items

	For $i = 0 to $nObjSize - 1
		$arItems[$i] = __Io_CheckParamAndSerialize($arItems[$i], True)

		if $g__Io_bParamSplitBinary Then
			$arKeys[$i] = StringToBinary($arKeys[$i])
			$arItems[$i] = StringToBinary($arItems[$i])
		EndIf

		$sReturnString &= $arKeys[$i] & $g__Io_sSerializeObjectSeperator & $arItems[$i] & $g__Io_sSerializeObjectSeperator
	Next

	Return $sReturnString
EndFunc
#ce

Func __Io_CheckParamAndUnserialize($sParam)
	if StringLeft($sParam, 10) <> $g__Io_sSerializationIndicator Then Return $sParam
	$sParam = StringTrimLeft($sParam, 10)

	Switch StringLeft($sParam, 10)
		Case $g__Io_sSerializeArrayIndicator
			Return __Io_UnserializeArray(StringTrimLeft($sParam, 10))

;~ 		Case $g__Io_sSerializeObjectIndicator
;~ 			Return __Io_UnserializeObject(StringTrimLeft($sParam, 10))

		Case Else
			Return $sParam

	EndSwitch
EndFunc

Func __Io_UnserializeArray($sParam)
	Local $arParam = StringSplit($sParam, $g__Io_sSerializeArraySeperator, 1 + 2)
	ReDim $arParam[UBound($arParam) - 1]

	if $g__Io_bParamSplitBinary Then
		For $i = 0 To UBound($arParam) - 1
			$arParam[$i] = BinaryToString($arParam[$i])
		Next
	EndIf

	Return $arParam
EndFunc

#cs
Func __Io_UnserializeObject($sParam)
	Local $oReturnObject = ObjCreate("Scripting.Dictionary")
	Local $arParam = StringSplit($sParam, $g__Io_sSerializeObjectSeperator, 1)
	ReDim $arParam[$arParam[0] - 1]

	_ArrayDisplay($arParam)

	For $i = 1 To $arParam[0] - 1 Step 2
		if $g__Io_bParamSplitBinary Then
			$arParam[$i] = BinaryToString($arParam[$i])
			$arParam[$i + 1] = BinaryToString($arParam[$i + 1])
		EndIf

		$oReturnObject.add($arParam[$i], __Io_CheckParamAndUnserialize($arParam[$i + 1]))
	Next

	Return $oReturnObject
EndFunc
#ce

Func __Io_SendInLoop()
	if $g__Io_sSendOnlyWhenLoopSocketArray = "" Then Return

	Local $arSockets = StringSplit($g__Io_sSendOnlyWhenLoopSocketArray, '|', 1)
	Local $arPackets[0]
	Local $nBytes = 0

	For $i = 1 To $arSockets[0]
		if $arSockets[$i] = "" Then ContinueLoop

		$arPackets = _storageS_Read($arSockets[$i] & '_PacketsSendWhenLoop')
		if $arPackets = False Then ContinueLoop ; should never happen
		if Not IsArray($arPackets) Then ContinueLoop ; this not too

		$nBytes = 0

		For $iS = 0 To UBound($arPackets) - 1
			if $arPackets[$iS][1] <> -1 Then
				$nBytes += __Io_TransportPackage_Safe($arSockets[$i], $arPackets[$iS][0], $arPackets[$iS][1])
			Else
				$nBytes += __Io_TransportPackage($arSockets[$i], $arPackets[$iS][0])
			EndIf
		Next

		_storageS_Overwrite($arSockets[$i] & '_PacketsSendWhenLoop', '')
		__Io_BytesPerSecond($arSockets[$i], $nBytes, False)
	Next

	$g__Io_sSendOnlyWhenLoopSocketArray = ''
EndFunc

Func __Io_RegisterLoopSend($hSocket, $sPackage, $hParentSocket = -1)
	if StringInStr($g__Io_sSendOnlyWhenLoopSocketArray, $hSocket) = 0 Then $g__Io_sSendOnlyWhenLoopSocketArray &= $hSocket & '|'

	Local $arPackets = _storageS_Read($hSocket & '_PacketsSendWhenLoop')
	if $arPackets = False Then $arPackets = __Io_CreateLoopSendArray()

	Local $nArSize = UBound($arPackets)
	ReDim $arPackets[$nArSize + 1][2]
	$arPackets[$nArSize][0] = $sPackage
	$arPackets[$nArSize][1] = $hParentSocket ; if parentsocket is <> -1 it is a packet safety packet

	_storageS_Overwrite($hSocket & '_PacketsSendWhenLoop', $arPackets)

	Return 0
EndFunc

Func __Io_CreateLoopSendArray()
	Local $arArray[0][2]
	Return $arArray
EndFunc

#cs
; this Packetsafety feature isnt going to be build in. Because it works with the assumption that atleast
; some bytes of a packet are always right to identify and recall it. thats a dumb assumption. So its discarded.
Func __Io_RecalSafetyBufferMaxSize()
	$g__Io_nPacketSafetyBufferSize = $g__io_nMaxPacketSize * 2.5
EndFunc

Func __Io_CreateSafetyBuffer($hSocket)
	Local $arBuffer[0][2]
	_storageS_Overwrite($hSocket & '_PacketSafetyBuffer', $arBuffer)
	_storageS_Overwrite($hSocket & '_PacketSafetyBufferSize', 0)
EndFunc

Func __Io_DeleteCompleteSafetyBuffer($hSocket)
	_storageS_Overwrite($hSocket & '_PacketSafetyBuffer', '')
	_storageS_Overwrite($hSocket & '_PacketSafetyBufferSize', 0)
EndFunc

Func __Io_GetSafetyBufferID($hSocket = 0)
	Local Static $arRandomChars[0]
	If UBound($arRandomChars) = 0 Then
		ReDim $arRandomChars[1000]

		Local $sRandomChar = ""

		For $i = 0 To 999
			For $iS = 1 To 5
				$sRandomChar &= __ccrypt_RandomChar()
			Next
			$arRandomChars[$i] = $sRandomChar
			$sRandomChar = ""
		Next
	EndIf

	Local $sRandomID = $arRandomChars[Random(0, 999, 1)]
	if $hSocket = 0 Then Return $sRandomID

	Local $arBuffer = _storageS_Read($hSocket & '_PacketSafetyBuffer')
	Local $bFound = False
	Do
		$bFound = False
		For $i = 0 To UBound($arBuffer) - 1
			If $arBuffer[$i][0] = $sRandomID Then
				$bFound = True
				ExitLoop
			EndIf
		Next

		if $bFound Then $sRandomID = __Io_GetSafetyBufferID()

	Until Not $bFound

	Return $sRandomID
EndFunc

Func __Io_WriteToSafetyBuffer($hSocket, $sData, $sBufferID)
	Local $nBufferSize = _storageS_Read($hSocket & '_PacketSafetyBufferSize')
	Local $arBuffer = _storageS_Read($hSocket & '_PacketSafetyBuffer')
	Local $nArSize = UBound($arBuffer)
	Local $nDataLen = StringLen($sData)

	if $nBufferSize + $nDataLen > $g__Io_nPacketSafetyBufferSize Then
		; remove items
;~ 		Local $nItemAmount = 0
		Local $sItems = ''

		For $i = 0 To $nArSize - 1
;~ 			$nItemAmount += 1
			$sItems &= $i & '|'
			$nBufferSize -= StringLen($arBuffer[$i][1])

			if $nBufferSize + $nDataLen < $g__Io_nPacketSafetyBufferSize Then ExitLoop
		Next

		Local $arItems = StringSplit($sItems, '|', 1)
		For $i = $arItems[0] To 1 Step -1 ; go backward
			if $arItems[$i] = '' Then ContinueLoop
			__Io_DeleteSingleIDFromSafetyBuffer($hSocket, $arItems[$i])
		Next

		Return __Io_WriteToSafetyBuffer($hSocket, $sData, $sBufferID)
	EndIf

	ReDim $arBuffer[$nArSize + 1][2]
	$arBuffer[$nArSize][0] = $sBufferID
	$arBuffer[$nArSize][1] = $sData

	_storageS_Overwrite($hSocket & '_PacketSafetyBuffer', $arBuffer)
	_storageS_Overwrite($hSocket & '_PacketSafetyBufferSize', $nBufferSize + $nDataLen)
EndFunc

Func __Io_DeleteSingleIDFromSafetyBuffer($hSocket, $nBufferIndex)
	Local $arBuffer = _storageS_Read($hSocket & '_PacketSafetyBuffer')
	Local $nBufferSize = _storageS_Read($hSocket & '_PacketSafetyBufferSize')
	Local $nIndexLen = StringLen($arBuffer[$nBufferIndex][1])
	Local $nArSize = UBound($arBuffer)

;~ 	$arBuffer[$nBufferIndex][0] = $arBuffer[$nArSize - 1][0]
;~ 	$arBuffer[$nBufferIndex][1] = $arBuffer[$nArSize - 1][1]

	; even tho it is fast, actually its not if you have a high item count. need to find a better way
	For $i = $nBufferIndex To $nArSize - 1
		if $i = $nArSize - 1 Then ExitLoop
		$arBuffer[$i][0] = $arBuffer[$i + 1][0]
		$arBuffer[$i][1] = $arBuffer[$i + 1][1]
	Next

	ReDim $arBuffer[$nArSize - 1][2]

	_storageS_Overwrite($hSocket & '_PacketSafetyBuffer', $arBuffer)
	_storageS_Overwrite($hSocket & '_PacketSafetyBufferSize', $nBufferSize - $nIndexLen)
EndFunc

Func __Io_ReadFromSafetyBuffer($hSocket, $sBufferID)
	Local $arBuffer = _storageS_Read($hSocket & '_PacketSafetyBuffer')
	Local $nArSize = UBound($arBuffer)

	For $i = 0 To $nArSize - 1
		if $arBuffer[$i][0] = $sBufferID Then Return $arBuffer[$i][1]
	Next

	Return SetError(1, 0, False)
EndFunc
#ce

Func __Io_WSAGetLastError()
	If $g__Io_hWs2_32 = -1 Then $g__Io_hWs2_32 = DllOpen( "Ws2_32.dll" )
	Local $iRet = DllCall($g__Io_hWs2_32, "int", "WSAGetLastError")
	If @error Then
		ConsoleWrite("+> _WSAGetLastError(): WSAGetLastError() failed. Script line number: " & @ScriptLineNumber & @CRLF)
		SetExtended(1)
		Return 0
	EndIf
	Return $iRet[ 0 ]
EndFunc   ;==>_WSAGetLastError

Func __Io_TCPSend($hSocket, $sData)
	Local $nLen = BinaryLen($sData)

	if $g__Io_hWs2_32 = -1 Then $g__Io_hWs2_32 = DllOpen("Ws2_32.dll")

	Local $stAddress_Data = DllStructCreate('byte[' & $nLen & ']') ; why + 2?
	DllStructSetData($stAddress_Data, 1, $sData)

	Local $arRet = DllCall($g__Io_hWs2_32, "int", "send", "ptr", $hSocket, "ptr", DllStructGetPtr($stAddress_Data), "int", DllStructGetSize($stAddress_Data), "int", 0)

	Local $nError = __Io_WSAGetLastError()
	if $nError = 10035 Then
		; temp. Could cause Recursion issues
		Sleep(10) ; "minimum is 10 milliseconds"
		$nSend = __Io_TCPSend($hSocket, $sData)
		$nError = @error
	EndIf
	if $nError Then Return SetError($nError, 0, 0)

	Return $arRet[0]
EndFunc

; Below are a couple of Functions from different UDF's that helped improving SocketIoEx.
; ====================================================================================================================================

; This is a part of the _logEx.au3 UDF

; This is a part of the _storageS.au3 UDF

Func _storageS_Overwrite($Element0, $Element1)
	Return Assign("__storageS_" & StringToBinary($Element0), $Element1, 2)
EndFunc

Func _storageS_Append($Element0, $Element1)
	if Not IsDeclared("__storageS_" & StringToBinary($Element0)) Then Return _storageS_Overwrite($Element0, $Element1)

	Return Assign("__storageS_" & StringToBinary($Element0), Eval("__storageS_" & StringToBinary($Element0)) & $Element1, 2)
EndFunc

Func _storageS_Read($Element0)
	if Not IsDeclared("__storageS_" & StringToBinary($Element0)) Then Return False
	Return Eval("__storageS_" & StringToBinary($Element0))
EndFunc

; This is a part of _ccrypt.au3 UDF

Func _ccrypt_EncData($sData, $sPW)
	Local $hDerive = __ccrypt_initialize($sPW)
	$sEncrypt = _Crypt_EncryptData($sData, $hDerive, 0)
	if @error Then Return SetError(@error, @extended, False)
;~ 	Return StringTrimLeft($sEncrypt, 2)
	Return $sEncrypt
EndFunc

; this Function is always returning in Binary
Func _ccrypt_DecData($sData, $sPW)
	Local $hDerive = __ccrypt_initialize($sPW)
;~ 	$sDecrypt = _Crypt_DecryptData('0x' & $sData, $hDerive, 0)
	$sDecrypt = _Crypt_DecryptData($sData, $hDerive, 0)
	if @error then Return SetError(@error, @extended, 0)
;~ 	Return BinaryToString($sDecrypt)
	Return $sDecrypt
EndFunc

Func __ccrypt_initialize($sPW, $bDestroy = False) ;change pw to initialize again
	Local Static $hDerive = "", $sSamePW = $sPW
	if Not $bDestroy Then
		if $sSamePW = $sPW Then
			if $hDerive <> "" Then Return $hDerive ;dont rederive key just return it since we already have it
		Else
			__ccrypt_Crypt_DestroyKey($hDerive)
		EndIf

		$hDerive = _Crypt_DeriveKey($sPW, $CALG_AES_256)
		Return $hDerive
	Else
		if $hDerive = "" Then Return False
		If Not __ccrypt_Crypt_DestroyKey($hDerive) Then Return False
		_Crypt_Shutdown()
		Return True
	EndIf
EndFunc

Func __ccrypt_RandomChar()
	Local Static $arRandomChars[0], $nChars = 0
	if $nChars <> 0 Then
		Return $arRandomChars[Random(1, $nChars, 1)]
	Else
		$sChars = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
		$arRandomChars = StringSplit($sChars, '', 1)
		$nChars = $arRandomChars[0]
		Return $arRandomChars[Random(1, $nChars, 1)]
	EndIf
EndFunc

Func __ccrypt_RandomPW($nLenght = 12, $sChoice = '5', $sPass = '')
	Local Static $key[5]
	Local $i
	if $key[0] = "" Then
		$key[0] = '1234567890'
		$key[1] = __ccrypt_StringRepeat($key[0], 4) & 'abcdefghijklmnopqrstuvwxyz'
		$key[2] = $key[1] & 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
		$key[3] = $key[2] & 'öäüÖÄÜß'
		$key[4] = $key[3] & '@€µ²³°!§$%&/()=<>|,.-;:_#+*~?\' & Chr(34) & Chr(39)
	EndIf

	For $i = 1 To $nLenght
		$sPass &= StringMid($key[$sChoice-1], Random(1, StringLen($key[$sChoice-1]), 1), 1)
	Next
	Return $sPass
EndFunc

; #FUNCTION# ====================================================================================================================
; Author ........: Jeremy Landes <jlandes at landeserve dot com>
; Modified.......: guinness - Removed Select...EndSelect statement and replaced with an If...EndIf as well as optimised the code.
; ===============================================================================================================================
Func __ccrypt_StringRepeat($sString, $iRepeatCount)
	; Casting Int() takes care of String/Int, Numbers.
	$iRepeatCount = Int($iRepeatCount)
	If $iRepeatCount = 0 Then Return "" ; Return a blank string if the repeat count is zero.
	; Zero is a valid repeat integer.
	If StringLen($sString) < 1 Or $iRepeatCount < 0 Then Return SetError(1, 0, "")
	Local $sResult = ""
	While $iRepeatCount > 1
		If BitAND($iRepeatCount, 1) Then $sResult &= $sString
		$sString &= $sString
		$iRepeatCount = BitShift($iRepeatCount, 1)
	WEnd
	Return $sString & $sResult
EndFunc   ;==>_StringRepeat

; #FUNCTION# ====================================================================================================================
; Author ........: Andreas Karlsson (monoceres)
; Modified ......: jpm
; ===============================================================================================================================
Func __ccrypt_Crypt_DestroyKey($hCryptKey)
	Local $aRet = DllCall(__Crypt_DllHandle(), "bool", "CryptDestroyKey", "handle", $hCryptKey)
	Local $iError = @error, $iExtended = @extended
	If Not $aRet[0] Then $iExtended = _WinAPI_GetLastError()
;~ 	_Crypt_Shutdown()
	If $iError Or Not $aRet[0] Then
		Return SetError($iError + 10, $iExtended, False)
	Else
		Return True
	EndIf
EndFunc   ;==>_Crypt_DestroyKey

; This is a part of winsock.au3 UDF

;~ #cs
; #FUNCTION# ====================================================================================================================
; Name...........: _TCPRecv
; Description ...: Receives data from a connected socket.
; Syntax.........: _TCPRecv($iMainsocket, $iMaxLen, $iFlag = 0)
; Parameters ....: $iMainsocket - The array as returned by _TCPAccept
;				   				  or the connected socket identifier (SocketID) as returned by _TCPConnect.
;                  $iMaxLen - max # of characters to receive (usually 2048).
;                  $iFlag - values can be added together
;                  |$TCP_DATA_DEFAULT (0) - Text data. [Default]
;                  |$TCP_DATA_BINARY (1) - Binary data.
;                  |$TCP_DATA_EOT (2) - Returns data received and
;				   				  		set @error to -6 when it reaches the End of Text ASCII character (Chr(3))
; Return values .: On success it returns the binary/string sent by the connected socket.
;                  On failure it returns "" and sets the @error or @extended flag to non-zero:
;                  @error values:
;                  |-1 - internal error
;                  |-2 - missing DLL (Ws2_32.dll)
;                  |-3 - undefined error
;                  |-4 - invalid parameter
;                  |Any Windows Socket Error Code retrieved by WSAGetLastError
;                  @extended values:
;                  |1 - connection closed
;                  |2 - End of Text reached
; Author ........: j0kky
; Modified ......: 1.0.0
; Remarks .......: If Unicode strings need to be transmitted they must be encoded/decoded with StringToBinary()/BinaryToString().
; 				   $iFlag = 2 must be set in couple with _TCPSend
; 				   You must check for both @error and @extended, @extended could be set with @error set to zero
; Links .........: recv:		https://msdn.microsoft.com/en-us/library/windows/desktop/ms740121(v=vs.85).aspx
;				   error codes:	https://msdn.microsoft.com/en-us/library/windows/desktop/ms740668(v=vs.85).aspx
; ===============================================================================================================================
Func __Io_TCPRecv($iMainsocket, $iMaxLen, $iFlag = 0)
	If IsArray($iMainsocket) And (UBound($iMainsocket, 0) = 1) And (UBound($iMainsocket) > 0) Then $iMainsocket = $iMainsocket[0]
	If $iFlag = Default Then $iFlag = 0
	$iMainsocket = Number($iMainsocket)
	$iMaxLen = Number($iMaxLen)
	$iFlag = Number($iFlag)
	If $iMainsocket < 0 Or _
			$iMaxLen < 1 Or _
			Not ($iFlag = 0 Or $iFlag = 1 Or $iFlag = 2) Then Return SetError(-4, 0, -1) ; invalid parameter

	if $g__Io_hWs2_32 = -1 Then $g__Io_hWs2_32 = DllOpen('Ws2_32.dll')
	Local $hWs2 = $g__Io_hWs2_32
;~ 	If @error Then Return SetError(-2, 0, -1) ;missing DLL
	Local $bError = 0, $nCode = 0, $nExtended = 0

	If Not $bError Then
		$aRet = DllCall($hWs2, "int", "ioctlsocket", "uint", $iMainsocket, "long", 0x8004667e, "ulong*", 1) ;FIONBIO
		If @error Then
			$bError = -1
		ElseIf $aRet[0] <> 0 Then ;SOCKET_ERROR
			$bError = 1
		EndIf
	EndIf

	Local $tBuf
	If $iFlag Then
		$tBuf = DllStructCreate("byte[" & $iMaxLen & "]")
	Else
		$tBuf = DllStructCreate("char[" & $iMaxLen & "]")
	EndIf
	$aRet = DllCall($hWs2, "int", "recv", "uint", $iMainsocket, "ptr", DllStructGetPtr($tBuf), "int", $iMaxLen, "int", 0)
	If @error Then
		$bError = -1
	ElseIf ($aRet[0] = -1) Or ($aRet[0] = 4294967295) Then ;SOCKET_ERROR
		$bError = 1
		$aRet = DllCall($hWs2, "int", "WSAGetLastError")
		If @error Then
			$bError = -1
		ElseIf $aRet[0] = 0 Or $aRet[0] = 10035 Then ;WSAEWOULDBLOCK
			$nCode = -10 ;internal function value, it means no error
		EndIf
	ElseIf $aRet[0] = 0 Then
		$bError = 1
		$nCode = -10
		$nExtended = 1 ;connection closed
	Else
;~ 		Local $sResult = DllStructGetData($tBuf, 1) ;data
		Local $sResult = BinaryMid(DllStructGetData($tBuf, 1), 1, $aRet[0]) ; "If no error occurs, recv returns the number of bytes received and the buffer pointed to by the buf parameter will contain this data received"
;~ 		If BitAND($iFlag, 2) = 2 Then ;EOT
;~ 			If StringRight($sResult, 1) = Chr(3) Then
;~ 				$sResult = StringTrimRight($sResult, 1)
;~ 				$nExtended = 2 ;End of Text reached
;~ 			EndIf
;~ 		EndIf
	EndIf

	If $bError < 0 Then
		$nCode = -1 ;internal error
		$nReturn = "" ;failure
	ElseIf $bError > 0 Then
		If Not $nCode Then
			$aRet = DllCall($hWs2, "int", "WSAGetLastError")
			If @error Then
				$nCode = -1
			Else
				$nCode = $aRet[0]
			EndIf
			If $nCode = 0 Then $nCode = -3 ;undefined error
		EndIf
		If $nCode = -10 Then $nCode = 0
		$nReturn = ""
	Else
		$nReturn = $sResult
	EndIf
;~ 	DllClose($hWs2)
	Return SetError($nCode, $nExtended, $nReturn)
EndFunc   ;==>_TCPRecv

; #FUNCTION# ====================================================================================================================
; Name...........: _TCPAccept
; Description ...: Permits an incoming connection attempt on a socket.
; Syntax.........: _TCPAccept($iMainsocket)
; Parameters ....: $iMainsocket - The main socket identifier (SocketID) as returned by _TCPListen function.
; Return values .: On success it returns an array:
;                  |[0] - The connected socket identifier.
;                  |[1] - The external address of the client
;                  |[2] - The external port which the client are communicating on
;                  On failure it returns -1 and sets @error to non zero:
;                  |-1 - internal error
;                  |-2 - missing DLL (Ws2_32.dll)
;                  |-3 - undefined error
;                  |-4 - invalid parameter (not used in this function)
;                  |Any Windows Socket Error Code retrieved by WSAGetLastError
; Author ........: j0kky
; Modified ......: 1.0.0
; Links .........: accept:		https://msdn.microsoft.com/en-us/library/windows/desktop/ms737526(v=vs.85).aspx
;				   error codes:	https://msdn.microsoft.com/en-us/library/windows/desktop/ms740668(v=vs.85).aspx
; ===============================================================================================================================
Func __Io_TCPAccept($iMainsocket)
	$iMainsocket = Number($iMainsocket)
	If $iMainsocket < 0 Then Return SetError(-4, 0, -1) ; invalid parameter

	if $g__Io_hWs2_32 = -1 Then $g__Io_hWs2_32 = DllOpen('Ws2_32.dll')
	Local $hWs2 = $g__Io_hWs2_32
;~ 	If @error Then Return SetError(-2, 0, -1) ;missing DLL

	Local $bError = 0, $nCode = 0, $hSock = 0
	Local $tagSockAddr = "short sin_family; ushort sin_port; " & _
			"STRUCT; ulong S_addr; ENDSTRUCT; " & _ ;sin_addr
			"char sin_zero[8]"

	If Not $bError Then
		$aRet = DllCall($hWs2, "int", "ioctlsocket", "uint", $iMainsocket, "long", 0x8004667e, "ulong*", 1) ;FIONBIO
		If @error Then
			$bError = -1
		ElseIf $aRet[0] <> 0 Then ;SOCKET_ERROR
			$bError = 1
		EndIf
	EndIf

	If Not $bError Then
		$tSockAddr = DllStructCreate($tagSockAddr)

		$aRet = DllCall($hWs2, "uint", "accept", "uint", $iMainsocket, "ptr", DllStructGetPtr($tSockAddr), "int*", DllStructGetSize($tSockAddr))
		If @error Then
			$bError = -1
		ElseIf ($aRet[0] = 4294967295) Or ($aRet[0] = -1) Then ;INVALID_SOCKET
			$bError = 1
			$aRet = DllCall($hWs2, "int", "WSAGetLastError")
			If @error Then
				$bError = -1
			ElseIf ($aRet[0] = 0) Or ($aRet[0] = 10035) Then ;WSAEWOULDBLOCK
				$nCode = -10 ;internal function value, it means no error
			EndIf
		Else
			$hSock = $aRet[0]
;~ 			$aRet = DllCall($hWs2, "ptr", "inet_ntoa", "ulong", DllStructGetData($tSockAddr, "S_addr"))
;~ 			If @error Then
;~ 				$bError = -1
;~ 			ElseIf $aRet[0] = Null Then
;~ 				$bError = 1
;~ 			Else
;~ 				$sIPAddr = DllStructGetData(DllStructCreate("char[15]", $aRet[0]), 1)
;~ 				$aRet = DllCall($hWs2, "ushort", "ntohs", "ushort", DllStructGetData($tSockAddr, "sin_port"))
;~ 				If @error Then
;~ 					$bError = -1
;~ 				Else
;~ 					$nPort = $aRet[0]
;~ 					Local $aResult[3] = [$hSock, $sIPAddr, $nPort]
;~ 				EndIf
;~ 			EndIf
		EndIf
	EndIf

	If $bError < 0 Then
		$nCode = -1 ;internal error
		$nReturn = -1 ;failure
		If $hSock Then TCPCloseSocket($hSock)
	ElseIf $bError > 0 Then
		If Not $nCode Then
			$aRet = DllCall($hWs2, "int", "WSAGetLastError")
			If @error Then
				$nCode = -1
			Else
				$nCode = $aRet[0]
			EndIf
			If $nCode = 0 Then $nCode = -3 ;undefined error
		EndIf
		If $nCode = -10 Then $nCode = 0
		$nReturn = -1
		If $hSock Then TCPCloseSocket($hSock)
	Else
		$nReturn = $hSock
	EndIf
;~ 	DllClose($hWs2)
	Return SetError($nCode, 0, $nReturn)
EndFunc   ;==>_TCPAccept

; #FUNCTION# ====================================================================================================================
; Name...........: _TCPConnect
; Description ...: Create a socket connected to an existing server.
; Syntax.........: _TCPConnect($sIPAddr, $iDestPort, $sSourceAddr = "", $iSourcePort = 0, $iTimeOut = 0)
; Parameters ....: $sIPAddr - Destination IP.
;                  |Internet Protocol dotted address(IpV4) as "192.162.1.1".
;                  $iDestPort - Destination port.
;                  |1 : 65534 - port on which the created socket will be connected.
;                  $sSourceAddr - Source IP
;                  |Internet Protocol dotted address(IpV4) as "192.162.1.1". [Default = ""]
;                  $iSourcePort - Source port.
;                  |1 : 65534 - port on which the created socket will be bind (on the local PC). [Default = 0]
;                  $iTimeOut - The maximum time in milliseconds for _TCPConnect to wait for connection.
;                  |Any value > 0 [Default = 0 and it will be equal to Opt("TCPTimeout")].
; Return values .: On success it returns the main socket identifier.
;                  |Any value > 0
;                  On failure it returns -1 and sets @error to non zero:
;                  |-1 - internal error
;                  |-2 - missing DLL (Ws2_32.dll)
;                  |-3 - undefined error
;                  |-4 - invalid parameter
;                  |-5 - not connected
;                  |-6 - timed out
;                  |Any Windows Socket Error Code retrieved by WSAGetLastError
; Author ........: j0kky
; Modified ......: 1.0.0
; Remarks .......: This function is used by a client to communicate with the server and it allows to choose a source IP,
;				   a source port and to set a timeout for the connection.
; Links .........: bind:		https://msdn.microsoft.com/en-us/library/windows/desktop/ms737550(v=vs.85).aspx
;				   connect:		https://msdn.microsoft.com/en-us/library/windows/desktop/ms737625(v=vs.85).aspx
;				   select:		https://msdn.microsoft.com/en-us/library/windows/desktop/ms740141(v=vs.85).aspx
;				   error codes:	https://msdn.microsoft.com/en-us/library/windows/desktop/ms740668(v=vs.85).aspx
; ===============================================================================================================================
Func __Io_TCPConnect($sIPAddr, $iDestPort, $sSourceAddr = "", $iSourcePort = 0, $iTimeOut = 0)
	If $sSourceAddr = Default Then $sSourceAddr = ""
	If $iSourcePort = Default Then $iSourcePort = 0
	If $iTimeOut = Default Then $iTimeOut = 0
	$sIPAddr = String($sIPAddr)
	$iDestPort = Number($iDestPort)
	$sSourceAddr = String($sSourceAddr)
	$iSourcePort = Number($iSourcePort)
	$iTimeOut = Number($iTimeOut)
	If Not ($iDestPort > 0 And $iDestPort < 65535) Or _
			Not ($iSourcePort >= 0 And $iSourcePort < 65535) Or _
			Not ($iTimeOut >= 0) Then Return SetError(-4, 0, -1) ; invalid parameter
	StringRegExp($sIPAddr, "((?:\d{1,3}\.){3}\d{1,3})", 3) ;$STR_REGEXPARRAYGLOBALMATCH
	If @error Then Return SetError(-4, 0, -1)
	If $sSourceAddr <> "" Then
		StringRegExp($sSourceAddr, "((?:\d{1,3}\.){3}\d{1,3})", 3) ;$STR_REGEXPARRAYGLOBALMATCH
		If @error Then Return SetError(-4, 0, -1)
	EndIf

	if $g__Io_hWs2_32 = -1 Then $g__Io_hWs2_32 = DllOpen('Ws2_32.dll')
	Local $hWs2 = $g__Io_hWs2_32
;~ 	If @error Then Return SetError(-2, 0, -1) ;missing DLL
	Local $bError = 0, $nCode = 0
	Local $tagSockAddr = "short sin_family; ushort sin_port; " & _
			"STRUCT; ulong S_addr; ENDSTRUCT; " & _ ;sin_addr
			"char sin_zero[8]"

	Local $hSock = DllCall($hWs2, "uint", "socket", "int", 2, "int", 1, "int", 6); AF_INET, SOCK_STREAM, IPPROTO_TCP
	If @error Then
		$bError = -1
	ElseIf ($hSock[0] = 4294967295) Or ($hSock[0] = -1) Then ;INVALID_SOCKET
		$bError = 1
	Else
		$hSock = $hSock[0]
	EndIf

	If Not $bError Then
		$aRet = DllCall($hWs2, "ulong", "inet_addr", "str", $sIPAddr)
		If @error Then
			$bError = -1
		ElseIf ($aRet[0] = -1) Or ($aRet[0] = 4294967295) Or ($aRet[0] = 0) Then ;INADDR_NONE or INADDR_ANY
			$bError = 1
		Else
			$sIPAddr = $aRet[0]
		EndIf
	EndIf

	If Not $bError Then
		$aRet = DllCall($hWs2, "ushort", "htons", "ushort", $iDestPort)
		If @error Then
			$bError = -1
		Else
			$iDestPort = $aRet[0]
		EndIf
	EndIf

	If (Not $bError) And ($sSourceAddr <> "") Then
		$aRet = DllCall($hWs2, "ulong", "inet_addr", "str", $sSourceAddr)
		If @error Then
			$bError = -1
		ElseIf ($aRet[0] = -1) Or ($aRet[0] = 4294967295) Or ($aRet[0] = 0) Then ;INADDR_NONE or INADDR_ANY
			$bError = 1
		Else
			$sSourceAddr = $aRet[0]
		EndIf
	EndIf

	If (Not $bError) And $iSourcePort Then
		$aRet = DllCall($hWs2, "ushort", "htons", "ushort", $iSourcePort)
		If @error Then
			$bError = -1
		Else
			$iSourcePort = $aRet[0]
		EndIf
	EndIf

	If (Not $bError) And ($sSourceAddr Or $iSourcePort) Then
		$tSockAddr = DllStructCreate($tagSockAddr)
		DllStructSetData($tSockAddr, "sin_family", 2) ;AF_INET
		If $iSourcePort Then
			DllStructSetData($tSockAddr, "sin_port", $iSourcePort)
		Else
			DllStructSetData($tSockAddr, "sin_port", 0)
		EndIf
		If $sSourceAddr Then
			DllStructSetData($tSockAddr, "S_addr", $sSourceAddr)
		Else
			DllStructSetData($tSockAddr, "S_addr", 0x00000000) ;INADDR_ANY
		EndIf

		$aRet = DllCall($hWs2, "int", "bind", "uint", $hSock, "ptr", DllStructGetPtr($tSockAddr), "int", DllStructGetSize($tSockAddr))
		If @error Then
			$bError = -1
		ElseIf $aRet[0] <> 0 Then ;SOCKET_ERROR
			$bError = 1
		EndIf
		$tSockAddr = 0
	EndIf

	If Not $bError Then
		$aRet = DllCall($hWs2, "int", "ioctlsocket", "uint", $hSock, "long", 0x8004667e, "ulong*", 1) ;FIONBIO
		If @error Then
			$bError = -1
		ElseIf $aRet[0] <> 0 Then ;SOCKET_ERROR
			$bError = 1
		EndIf
	EndIf

	If Not $bError Then
		$tSockAddr = DllStructCreate($tagSockAddr)
		DllStructSetData($tSockAddr, "sin_family", 2) ;AF_INET
		DllStructSetData($tSockAddr, "sin_port", $iDestPort)
		DllStructSetData($tSockAddr, "S_addr", $sIPAddr)
		$aRet = DllCall($hWs2, "int", "connect", "uint", $hSock, "ptr", DllStructGetPtr($tSockAddr), "int", DllStructGetSize($tSockAddr))
		If @error Then
			$bError = -1
		ElseIf $aRet[0] <> 0 Then ;SOCKET_ERROR -> functional with connect() on non-blocking sockets
			$aRet = DllCall($hWs2, "int", "WSAGetLastError")
			If @error Then
				$bError = -1
			ElseIf ($aRet[0] <> 0) And ($aRet[0] <> 10035) Then ;WSAEWOULDBLOCK
				$bError = 1
			EndIf
		EndIf
		$tSockAddr = 0
	EndIf

	If Not $bError Then
		If $iTimeOut = 0 Then $iTimeOut = Opt("TCPTimeout")
		If $iTimeOut < 1 Then $iTimeOut = 100

		Local $tagFd_set = "uint fd_count; uint fd_array[64]"
		Local $tFd_set_writefds = DllStructCreate($tagFd_set)
		DllStructSetData($tFd_set_writefds, "fd_count", 1)
		DllStructSetData($tFd_set_writefds, "fd_array", $hSock, 1)
		Local $tFd_set_exceptfds = DllStructCreate($tagFd_set)
		DllStructSetData($tFd_set_exceptfds, "fd_count", 1)
		DllStructSetData($tFd_set_exceptfds, "fd_array", $hSock, 1)
		Local $tTimeval = DllStructCreate("long tv_sec; long tv_usec")
		DllStructSetData($tTimeval, "tv_sec", Floor($iTimeOut / 1000))
		DllStructSetData($tTimeval, "tv_usec", Round(Mod($iTimeOut, 1000) * 1000))
		$aRet = DllCall($hWs2, "int", "select", _
				"int", $hSock, "ptr", 0, "ptr", DllStructGetPtr($tFd_set_writefds), "ptr", DllStructGetPtr($tFd_set_exceptfds), "ptr", DllStructGetPtr($tTimeval))
		If @error Then
			$bError = -1
		ElseIf $aRet[0] = 0 Then ;time expired
			$bError = 1
			$nCode = -6 ;timed out, similar to WSAETIMEDOUT
		ElseIf ($aRet[0] = -1) Or ($aRet[0] = 4294967295) Then ;SOCKET_ERROR
			$bError = 1
		Else
			If Not (DllStructGetData($tFd_set_writefds, "fd_count") = 1) Then
				$bError = 1
				If DllStructGetData($tFd_set_exceptfds, "fd_count") = 1 Then
					$tBuf = DllStructCreate("int")
					$aRet = DllCall("Ws2_32.dll", "int", "getsockopt", _
							"uint", $hSock, "int", 0xffff, "int", 0x1007, "ptr", DllStructGetPtr($tBuf), "int*", DllStructGetSize($tBuf)) ;SO_ERROR
					If @error Then
						$bError = -1
					ElseIf $aRet[0] = 0 Then
						$nCode = DllStructGetData($tBuf, 1)
					EndIf
				Else
					$nCode = -5 ;NOT_CONNECTED
				EndIf
			EndIf
		EndIf
	EndIf

	If $bError < 0 Then
		$nCode = -1 ;internal error
		$nReturn = -1 ;failure
		If $hSock Then TCPCloseSocket($hSock)
	ElseIf $bError > 0 Then
		If Not $nCode Then
			$aRet = DllCall($hWs2, "int", "WSAGetLastError")
			If @error Then
				$nCode = -1
			Else
				$nCode = $aRet[0]
			EndIf
			If $nCode = 0 Then $nCode = -3 ;undefined error
		EndIf
		$nReturn = -1
		If $hSock Then TCPCloseSocket($hSock)
	Else
		$nReturn = $hSock
	EndIf
;~ 	DllClose($hWs2)
	Return SetError($nCode, 0, $nReturn)
EndFunc   ;==>_TCPConnect