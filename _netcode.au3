#include-once
#include <Array.au3> ; for development
#include "SocketIOEx.au3"
#cs
	_netcode.au3 depends on a Custom SocketIO.au3 named SocketIOEx.au3
	if you dont have it then this lib will throw errors.

	Known Bugs
		Minor -	If a Flood appears then the Server wont send a FloodPrevention Packet because the packet's are discarded.
			This isnt an Issue if Packet Safety is enabled. Every Flood call can safely be ignored then.
			Otherwise - the netcode will ask the server if its hung, if not the Prevention gets reset.

		Major -	If the Server calls _Io_Disconnect() then the Client wont notice the
			disconnect. maybe the same if the Client calls it. Its a known issue.

		Minor -	The "smallest Server" Example has an issue with the auto Spliter from _netcode_Send()

		Minor -	If the Server disconnected while the Client believes the Server will be flooded with the next send then it will hang
			in _netcode_Send(). This is partly fixed. It will exitloop after it tried to check if the server is hung and notices therefore
			the diconnection.

		Minor -	When Server uses _netcode_SetOption("EnableEncryption") and the Client _netcode_SetOption("SetEncryptionPassword").
			And the Server wants to Custom Sync Data with the Client - like client auth - then it will Fail. Because the Clients last Syn
			enabled Encryption and therefore the Auth from the Server is unencrypted while the Client only accepts encrypted data then.
			By now each SYN is unencrypted if _netcode_SetOption("SetAcceptUnecryptedTraffic") is set.
			The Solution will be to add a PreSyn functionality. The PreSyn would always be unencrypted and contains only the
			Encryption status. The Syn itself would then be encrypted. The "SetAcceptUnecryptedTraffic" would become obsolete for this then

		Minor -	The server side is missing the __netcode_SetTCPTimeout...

		Minor - The Chat Example has an issue. When ever the Second user joins he (all?) have a lag

		Minor - There maybe is a bug with parent socket keeping saved in the SocketArray
				because they dont get removed with __Io_DelSocket()

		Major - Relay mode has issues with disconnectting....

	Ideas and Changes to do
		-	Add SocketIO - set maximum allowed connections

		-	_netcode_GetSockets() etc. is Server Side only. Change that

		-	Add a feature to enable packet stacking.
			Mainly for flood prevention and safety. So they can be send at once

		-	Change the Packet Safety. Make it faster. Dont go with the assumption that atleast one byte of a packet is right.
			We can easiely cache packets, the code is already there. But how do we identify bad packets without using any information from the bad packet?
			Idea ~ Create an array cache of about 100 elements. Have it so its the same on each socket. The server and the client have the exact same array.
			Whenever a packet is created add it to the cache. Add the current cache index to the package. The Receiver then extracts the index from the packet and
			compares it with its own cache index. In Theory it has to be the same. If its not the same the receiver knows it didnt got a packet and it knows also which.
			When a packet is lost or bad the receiver sends a internal_safety packet with the missing or bad ID and then the sender resends it. All packets that got
			send while the receiver waits for the missing or bad packet should be buffered. Packets need to be executed in Order. Also think about what you do
			if multiple packets are lost or bad.
			In this Idea the packet cache should be limited by the max packet size * 2.5. So the cache array should be cleaned on every call if it exceeds the max size.
			Otherwise sending 100 times 2 mb packets would end up using 200mb of RAM. The packet buffer should also be limited to prevent DDOS.

		-	Better logging. The User should be able to Set the level of logging. And the Logging should be machine friendly.
			0 = No logging
			1 = Setup Logging. Only should log specific functions that are set before _netcode_Listen/Connect is called.
			2 = Simple Logging like showing a new Con- Disconnection and when a packet is send and recv
			3 = Warning Logging like 2 + warnings. A high Ping to the other party for example.
			4 = Error Logging like 2 + typical errors like unknown events but no Warnings
			5 = Extensive Error Logging like 2 + 3 + 4
			6 = Log all and everything
			The user should be able to Set a Callback or a Var where certain things, even if no log level ist set, will be send to.
			It should be possible to identify unusall Traffic. If thats important to the User then he would have a way here because the netcode itself
			cant know whats unusual. So for example the misusage of the netcode_bigmessage buffer used by the AutoSplitter which would trigger
			a "Could not Allocate Memory" DDOS if used by to many Clients without finishing.
			The User gets a way of monitoring the netcode through this and can code protection meassures.

		-	There should be a Recv and Send Buffer. The user should be a Toggle for the user
			if he want to sends the stuff imidiatly or only when The loop gets called

		-	In case the User uses adlibs or any OnEvent instructions he will have issues when he changes netcode options on the
			fly. Because if the netcode is in any of the major funcs while adlib or OnEvent hits with an Option change then
			the code will very likely crash. The Set Options should all be moved to netcode and be on hold until all major
			funcs are done. _netcode_Send could for example wait or return an error because an option change is triggered
			and waiting. This would make the netcode more redundant and should be easy to implement.

		-	Add LZMA Compression, maybe even LZMA2
			https://www.autoitscript.com/forum/topic/134350-file-to-base64-string-code-generator-v120-build-2020-06-05-embed-your-files-easily/
			https://www.autoitscript.com/forum/topic/112273-lzma-compression-udf/
			https://www.autoitscript.com/forum/topic/85094-7zip/
			https://www.7-zip.org/sdk.html
			https://www.autoitscript.com/forum/topic/167823-lzma2-for-compress-data-in-memory-not-files/
			https://www.autoitscript.com/forum/topic/153593-calling-7zdll/

	Before Release
		-	Search for %release%
		-	Rename Variables

#ce
#cs
	This _netcode UDF depends on SocketIOEx UDF.
	_netcode UDF
		Public Link: %release%

	SocketIOEx UDF
		Public Link: https://github.com/OfficialLambdax/Autoit-Socket-IO

	To further improve this UDF it partly consists of parts from other UDF's.
	Information regarding other UDF's _

	CryptoNG UDF
		Public Link: https://www.autoitscript.com/forum/topic/201002-cryptong-udf-cryptography-api-next-gen

	If you choose to use the Autoit 3 Wrapper and Stripper then add these to the
	#Region

	#AutoIt3Wrapper_Au3stripper_OnError=ForceUse
	#Au3Stripper_Ignore_Funcs=FunctionYouCall

	#EndRegion

	that be every Func that gets Called or you set via
	_netcode_SetConnectionCallback()
	_netcode_SetDisconnectCallback()
	_netcode_Set...

	if you give every Call function a prefix like _Call_Connection where "_Call_" is the Prefix
	then its enough if you just use #Au3Stripper_Ignore_Funcs=_Call_*

#ce
#Au3Stripper_Ignore_Funcs=_On_*
#Au3Stripper_Ignore_Funcs=__netcode_*

Global $__net_nInt_Version = '0.1'
if $g__Io_sCustomSocketIO <> $__net_nInt_Version Then
	ConsoleWrite("! Netcode Version and Custom SocketIO Version mismatch." & @CRLF)
	ConsoleWrite("! Netcode Version " & $__net_nInt_Version & @CRLF)
	ConsoleWrite("! SocketIO Version " & $g__Io_sCustomSocketIO & @CRLF)
	ConsoleWrite("! Netcode might work or might not." & @CRLF)
EndIf

__Io_Init()
;~ __netcode_CheckProcessorCompatibilityForTimerTiff() ; comment this if you know that every cpu is compatibly. Otherwise the UDF always do a test taking atleast 1 SEC.

; Dont change any of the Vars manually. Change them by calling their apropiate functions.
; ################# Internal Vars
Global $__net_nInt_MaxRecvLength = $g__io_nMaxPacketSize ; if a Packet exceeds this char len, the data is dismissed
Global $__net_nInt_MaxPacketContentSize = $__net_nInt_MaxRecvLength - ((StringLen($g__Io_sPacketSeperator) * 2) + StringLen($g__Io_sPacketSeperatorInternal))
Global $__net_sInt_BigPacketSplitSeperator = "Tgqw86jD38109"
Global $__net_bInt_EnabledEncryptionThroughSync = False ; if Encryption got enabled through Sync then it will be disabled automatically once disconnected
Global $__net_nInt_MaximumBigPacketSize = 1048576 * 100 ; Maximum Buffer Size for the AutoPacketSplitter
; Each of Autoit's own TCP function has a set timeout that can be set with AutoitSetOption().
; If a ping is > the current set timeout then the TCP Func will fail.
; So in this UDF each Socket has a ping bind to it. So the timeout is set to this before calling TCP functions.
Global $__net_nInt_TCPTimeoutDefault = 100 ; Default Timeout for TCP Functions.
Global $__net_nInt_PingUnusual = 5000 ; a timeout can never be higher then that
Global $__net_nInt_PingReEvalIfHigherThen = 2000 ; if the ping is higher then this it will always try to reeval the ping
Global $__net_nInt_PingUsual = 20 ; 20ms https://www.speedtest.net/global-index
Global $__net_nInt_PingDynamic = 10 ; will be added to the ping result because the ping will vary
Global $__net_nInt_PingDefault = 5 ; the TCPTimeout's Default is 5. The Timeout can never be below that.
Global $__net_nInt_TCPTimeoutAddOnConnect = 0 ; The timeout isnt just affected by the ping but also on when the server TCPAccept(). If the Server is on load then setting this with extra ms helps. Only __netcode_SetTCPTimeout_ByIP() is affected
Global $__net_hInt_bcryptdll = -1
Global $__net_hInt_hAlgorithmProvider = -1
Global $__net_sInt_CryptionProvider = 'Microsoft Primitive Provider'
Global $__net_nInt_CryptionIterations = 1000
Global $__net_sInt_CryptionAlgorithm = 'AES'
Global $__net_sInt_CryptionIV = Binary("0x000102030405060708090A0B0C0D0E0F")
Global $__net_hInt_ntdll = -1
Global $__net_hInt_TCPConnectAutoTimeWait = 0
Global $__net_arInt_RelaySockets[0]

; ################# Default events
Global $__net_sEvent_ConCall = "" ; user can specify the Function he wants to be called on that Event
Global $__net_sEvent_DisCall = ""
Global $__net_sEvent_MesCall = ""
Global $__net_sEvent_FloCall = ""
Global $__net_sEvent_Customs = ""

; ################# Options
Global $__net_bOption_DebugLogToConsole = False
Global $__net_nOption_TCPRecvDefault = $g__io_nPacketSize ; $__net_nInt_MaxRecvLength
Global $__net_bOption_PacketValidation = $g__Io_bPacketValidation
Global $__net_bOption_PacketSafety = $g__Io_bPacketSafety
Global $__net_bOption_FloodPrevention = $g__Io_bFloodPrevention
Global $__net_bOption_WaitForPreventionPacket = True
Global $__net_bOption_SetAutoSplitBigPackets = False ; DDOSable so at Default its turned off until thats dealt with. If True then the maximum buffer size is $__net_nInt_MaximumBigPacketSize
Global $__net_bOption_EncryptionStatus = False ; only to be toggled by calling a func
Global $__net_bOption_AcceptUnecryptedTraffic = $g__Io_bAcceptUnecryptedTraffic
Global $__net_sOption_SetPasswordForEncryption = ""
Global $__net_bOption_NoFloodEventIfPacketSafetyOn = True
Global $__net_sOption_CryptionMode = "netcode" ; default | netcode | custom
Global $__net_sOption_CryptionNetcodeSalt = 'zTB60LR692V4cG9l2nMO'
Global $__net_bOption_SetTCPConnectAutoTimeWait = True ; you can spam _netcode_Connect(). If this is true it will wait atleast for (time in next var) before it attempts again. Be aware that it wont wait that time. It Returns False until the TimeWait is over
Global $__net_nOption_SetTCPConnectAutoTimeWait = 1000 ; 1 sec
;~ Global $__net_bOption_SetNetcodeBroadcastWorkLikeInSocketIo = False ; ~ todo

; ################# Options Allow
Global $__net_bAllowSend_MaxPackageSize = True
Global $__net_bAllowSend_PacketValidation = True
Global $__net_bAllowSend_PacketSafety = True
Global $__net_bAllowSend_FloodPrevention = True
Global $__net_bAllowSend_TCPRecvDefault = True
Global $__net_bAllowSend_EncryptionStatus = True
Global Const $__net_sAllowSend_VarString = '__net_bAllowSend_'

; ################# Sync
Global $__net_bSync_MaxPackageSize = False
Global $__net_bSync_PacketValidation = False
Global $__net_bSync_PacketSafety = False
Global $__net_bSync_FloodPrevention = False
Global $__net_bSync_TCPRecvDefault = False
Global $__net_bSync_EncryptionStatus = False
Global $__net_sSync_SyncOnEachSocket = '' ; + custom Sync
Global $__net_sSync_IpSync = _netcode_GetIP() ; todo ~ in case we are actually in the network we can switch how TCPSend() works
Global Const $__net_sSync_VarString = '__net_bSync_'

__netcode_SetNetworkSyncAuto(True)
_netcode_SetEncryptionCallback("__netcode_Encrypt")
_netcode_SetDecryptionCallback("__netcode_Decrypt")
_netcode_SetOption("SetMaxPackageSize", 1048576) ; the default is set here to 1 MB

Func _netcode_Loop($hSocket)
	$vReturn = _Io_Loop($hSocket)
	; todo

	Return $vReturn
EndFunc

Func _netcode_Connect($sIP, $sPort)

	if $__net_bOption_SetTCPConnectAutoTimeWait Then
		if $__net_hInt_TCPConnectAutoTimeWait = 0 Then
			$__net_hInt_TCPConnectAutoTimeWait = TimerInit()
		Else
			if TimerDiff($__net_hInt_TCPConnectAutoTimeWait) < $__net_nOption_SetTCPConnectAutoTimeWait Then Return SetError(2, 0, False)
			$__net_hInt_TCPConnectAutoTimeWait = TimerInit()
		EndIf
	EndIf

	$nPing = __netcode_SetTCPTimeout_ByIP($sIP, $__net_nInt_TCPTimeoutAddOnConnect)
	$hSocket = _Io_Connect($sIP, $sPort)
	if @error Then Return SetError(1, 0, False)
	__netcode_BindTCPTimeout_IpAndPingToSocket($sIP, $nPing, $hSocket)
	__netcode_TCPTimeout_Default()

	_netcode_Events($hSocket)
	_On_connection($hSocket)

	Return $hSocket
EndFunc

; use this if you want _netcode todo the Connection stuff.
; it will only Return once the Connection is UP and if $bSync all is Synced.
; The Syn has a toggleable Timeout. If it Timeouts this function disconnects.
; Return then will be False
; Else it will be the Socket
; Be aware that the connection event will be called once we connected.
Func _netcode_ConnectAuto($sIP, $sPort, $bSync = True, $nSyncTimeOut = $g__Io_nGlobalTimeoutTime)
	Local $hSocket = False
	Local $hTimeoutTimer

	; loop until we connected
	While True
		$hSocket = _netcode_Connect($sIP, $sPort)
		if $hSocket <> False Then ExitLoop
		Sleep($__net_nOption_SetTCPConnectAutoTimeWait)
	WEnd

	if Not $bSync Then Return $hSocket

	; trigger Sync
	_netcode_Sync_Netcode($hSocket)
	$hTimeoutTimer = TimerInit()

	; wait for Sync
	While _Io_Loop($hSocket)
		if _netcode_Sync_Check($hSocket) Then ExitLoop
		if TimerDiff($hTimeoutTimer) > $nSyncTimeOut Then
			_Io_Disconnect($hSocket)
			Return False
		EndIf
	WEnd

	Return $hSocket
EndFunc

Func _netcode_Listen($sIP, $sPort, $iMaxPendingConnections = Default, $iMaxDeadSocketsBeforeTidy = 1000, $iMaxConnections = 100000)
	; $iMaxConnections sets the maximum amount of connections the SocketIO allows. not at once - at all. if $iMaxConnections is reached it will never
	; accept anymore connections, not even when all previous Connections are disconnected. This has to be changed

	__netcode_SetNetworkSyncAuto(False) ; needs to be toggleable in case of a relay for example

	$hSocket = _Io_Listen($sPort, $sIP, $iMaxPendingConnections, $iMaxDeadSocketsBeforeTidy, $iMaxConnections)
	if @error Then Return SetError(@error, 0, False)

	_netcode_Events($hSocket)

	Return $hSocket
EndFunc

Func _netcode_Listen_Off($hSocket)
	Return _Io_Disconnect($hSocket)

	; todo
EndFunc

; marked for recoding
; the whole tor part is highly work in progress.
; at all its just made working and nothing more.
; if you choose to use Tor set the global timeout higher if you face issues with timeouts.
Func _netcode_ConnectTor($sTorIP, $sSocksPort, $sOnionAdress, $sOnionPort)

	Local $hexportLeft = StringLeft(Hex($sOnionPort, 4), 2)
	Local $hexportRight = StringRight(Hex($sOnionPort, 4), 2)
	Local $sSeq = Chr(4) & Chr(1) & Chr("0x" & $hexportLeft) & Chr("0x" & $hexportRight) & Chr(0) & Chr(0) & Chr(0) & Chr(255) & "" & Chr(0) & $sOnionAdress & Chr(0)

	if $__net_bOption_SetTCPConnectAutoTimeWait Then
		if $__net_hInt_TCPConnectAutoTimeWait = 0 Then
			$__net_hInt_TCPConnectAutoTimeWait = TimerInit()
		Else
			if TimerDiff($__net_hInt_TCPConnectAutoTimeWait) < $__net_nOption_SetTCPConnectAutoTimeWait Then Return SetError(2, 0, False)
			$__net_hInt_TCPConnectAutoTimeWait = TimerInit()
		EndIf
	EndIf

	$nPing = __netcode_SetTCPTimeout_ByIP($sTorIP, $__net_nInt_TCPTimeoutAddOnConnect)
	$hSocket = _Io_Connect($sTorIP, $sSocksPort)
	if @error Then Return SetError(1, 0, False)
	__netcode_BindTCPTimeout_IpAndPingToSocket($sTorIP, $nPing, $hSocket)
	__netcode_TCPTimeout_Default()

	TCPSend($hSocket, Binary($sSeq))

	_netcode_Events($hSocket)
	_On_connection($hSocket)

	Return $hSocket
EndFunc

;~ _netcode_SetupTor(@ScriptDir & "\torServer\tor.exe", '1225', True, True)
;~ _netcode_SetupTor(@ScriptDir & "\torClient\tor.exe", '9051', False, True)
; marked for recoding
Func _netcode_SetupTor($sTorPath, $sDesiredPort, $bForListen = False, $bStartTor = False)
	Local $sTorDir = StringLeft($sTorPath, StringInStr($sTorPath, '\', 0, -1) - 1)
	Local $sTorConfigFile = $sTorDir & "\TorConfig.tor"
	Local $sTorServiceHostnameFile = $sTorDir & "\Service\hostname" ; cat that be specified in the config?
	Local $sTorData = ".\TorData"
	Local $sTorServiceDir = ".\Service"
	Local $sTorPidFile = ".\pid.tor"

;~ 	if Not FileExists($sTorConfigFile) Then
		Local $hOpenConfigFile = FileOpen($sTorConfigFile, 2)
		if $bForListen Then
			FileWrite($hOpenConfigFile, 'DataDirectory ' & $sTorData & @CRLF & _
										'HiddenServiceDir ' & $sTorServiceDir & @CRLF & _
										'HiddenServicePort ' & $sDesiredPort & ' 127.0.0.1:' & $sDesiredPort & @CRLF & _
										'PidFile ' & $sTorPidFile)
		Else
			FileWrite($hOpenConfigFile, 'DataDirectory ' & $sTorData & @CRLF & _
										'SocksListenAddress 127.0.0.1' & @CRLF & _
										'SocksPort ' & $sDesiredPort & @CRLF & _
										'PidFile ' & $sTorPidFile)
		EndIf
		FileClose($hOpenConfigFile)
;~ 	EndIf

	if $bStartTor Then Return _netcode_StartTor($sTorPath)
	Return True
EndFunc

; marked for recoding
Func _netcode_StartTor($sTorPath, $vShow = @SW_SHOW, $sTorConfig = 'TorConfig.tor', $sTorService = '\Service')
	If Not FileExists($sTorPath) Then Return False

	Local $sTorDir = StringLeft($sTorPath, StringInStr($sTorPath, '\', 0, -1) - 1)
	$sTorService = $sTorDir & $sTorService

	if Not ShellExecute($sTorPath, '-f ' & $sTorConfig, $sTorDir, 'open', $vShow) Then Return False

	if Not FileExists($sTorService) Then Return True

	$hOpenHostnameFile = FileOpen($sTorService & '\hostname', 0)
	$sHostname = FileRead($hOpenHostnameFile)
	FileClose($hOpenHostnameFile)

	Return $sHostname
EndFunc

Func _netcode_Events($hSocket) ;client and server side
	_Io_On('netcode_message', Null, $hSocket)
	_Io_On('netcode_messagebig', Null, $hSocket)
	_Io_On('netcode_getsync', Null, $hSocket)
	_Io_On('netcode_postsync', Null, $hSocket)
	_Io_On('connection', Null, $hSocket)
	_Io_On('disconnect', Null, $hSocket)
	_Io_On('flood', Null, $hSocket)

	; marked for recoding
	if $__net_bOption_SetAutoSplitBigPackets Then _Io_On('netcode_bigpacket', Null, $hSocket)

	; if the user as set Custom Events he wants to be Set on every new Socket
	if $__net_sEvent_Customs <> "" Then
		Local $arCustomEvents = StringSplit($__net_sEvent_Customs, '|', 1)
		For $i = 1 To $arCustomEvents[0]
			if $arCustomEvents[$i] = "" Then ContinueLoop
			_Io_On($arCustomEvents[$i], Null, $hSocket)
		Next
	EndIf
EndFunc

Func _netcode_Send($hSocket, $sEvent, $sData = Null, $bNoPacketSafety = False, $bNoPacketEncryption = False, $bAutoSplit_Internal = False)
	__netcode_Debug("Sending " & StringLen($sData) & " Bytes to " & $hSocket & " Event " & $sEvent)

	; get maximum Packet content size. $sData shouldnt be bigger then this - 5 % safety marge
	Local $nMaxPacketContentSize = _netcode_GetMaxPacketContentSize($sEvent, 0.95)

	; if the User wants to have the _netcode_Send() manage big packets
	if $__net_bOption_SetAutoSplitBigPackets And Not $bAutoSplit_Internal Then

		; if $sData is bigger then Split Packets and send them one by one
		$nDataSize = StringLen($sData)
		if $nDataSize > $nMaxPacketContentSize And $nDataSize < $__net_nInt_MaximumBigPacketSize Then

			Local $nCountSendBytes = 0, $nError = 0, $nExtended = 0

			$nMaxPacketContentSize -= (StringLen($__net_sInt_BigPacketSplitSeperator) * 2) - StringLen('netcode_bigpacket') - StringLen($sEvent) - 2

			Do
				$nCountSendBytes += _netcode_Send($hSocket, 'netcode_bigpacket', $sEvent & $__net_sInt_BigPacketSplitSeperator & StringLeft($sData, $nMaxPacketContentSize), $bNoPacketSafety, $bNoPacketEncryption, True)
				$nError = @error
				$nExtended = @extended

				if $nError Then
					$nCountSendBytes = 0
					ExitLoop
				EndIf

				$sData = StringTrimLeft($sData, $nMaxPacketContentSize)
			Until $sData = ""

			if $sData = "" And Not $nError Then $nCountSendBytes += _netcode_Send($hSocket, 'netcode_bigpacket', $sEvent & $__net_sInt_BigPacketSplitSeperator & $__net_sInt_BigPacketSplitSeperator & 'OK', $bNoPacketSafety, $bNoPacketEncryption) ; no error check here

			Return SetError($nError, $nExtended, $nCountSendBytes)

		Else ; if its not bigger set $bAutoSplit_Internal so we wont check the Len again
			$bAutoSplit_Internal = True
		EndIf
	EndIf

	; check if the $sData is to big. If return error
	if Not $bAutoSplit_Internal Then
		if StringLen($sData) > $nMaxPacketContentSize Then
			__netcode_Debug("Message to Big on " & $hSocket)
			Return SetError(8, 0, 0)
		EndIf
	EndIf

	; if the user wants the _netcode_Send() to automatically wait for the FloodPreventionPacket
	if $__net_bOption_WaitForPreventionPacket Then

		__netcode_SetTCPTimeout_BySocket($hSocket)
		While True
			$attempt = _Io_Emit($hSocket, $sEvent, $sData, $bNoPacketSafety, $bNoPacketEncryption)
			$nError = @error
			$nExtended = @extended
			if $nError <> 2 Then ExitLoop

			$hParentSocket = __Io_CheckSocket($hSocket)
			if $hParentSocket = False Then $hParentSocket = $hSocket

			_Io_Loop($hParentSocket)
		WEnd ; toggleable timeout needed
		__netcode_TCPTimeout_Default()

		Return SetError($nError, $nExtended, $attempt)

	Else ; or if he wants to manage that himself

		__netcode_SetTCPTimeout_BySocket($hSocket)
		$attempt = _Io_Emit($hSocket, $sEvent, $sData, $bNoPacketSafety, $bNoPacketEncryption)
		__netcode_TCPTimeout_Default()
		Return SetError(@error, @extended, $attempt)

	EndIf

EndFunc

; _netcode_Broadcast() is different from _Io_Broadcast()
; give the parentsocket, thats the listening socket. The message will be broadcasted to each client of this parent.
; if you want to have one or more sockets to be ignored use _netcode_GetSocketsBut() e.g. _netcode_Broadcast(_netcode_GetSocketsBut(parent, SocketsToIgnore), event, data).
; The reason this works different is that you maybe are running multiple Listeners and you only want to broadcast to one.
Func _netcode_Broadcast($hSocket, $sEvent, $sData, $bNoPacketSafety = False, $bNoPacketEncryption = False)
	Local $arSockets[0][2]
	Local $nBytes = 0

	if Not IsArray($hSocket) Then
		$arSockets = _netcode_GetSockets($hSocket)
		if Not IsArray($arSockets) Then Return 0
	Else
		$arSockets = $hSocket
	EndIf

	$arSockets = StringSplit($arSockets[0][1], '|', 1)

	For $i = 0 To $arSockets[0]
		$nBytes += _netcode_Send($arSockets[$i], $sEvent, $sData, $bNoPacketSafety, $bNoPacketEncryption)
	Next

	Return $nBytes

EndFunc

; broadcast to all and every socket no matter the parent.
; only Relay sockets get ignored.
Func _netcode_BroadcastToAll($sEvent, $sData, $bNoPacketSafety = False, $bNoPacketEncryption = False)
	Local $arSockets = _netcode_GetSockets()
	Local $arCurrentList[0]
	Local $nBytes = 0

	If Not IsArray($arSockets) Then Return 0

	For $i = 0 To UBound($arSockets) - 1
		$arCurrentList = StringSplit($arSockets[$i][1], '|', 1)

		For $i = 1 To $arCurrentList[0]
			if $arCurrentList[$i] = "" Then ContinueLoop

			$nBytes += _netcode_Send($arCurrentList[$i], $sEvent, $sData, $bNoPacketSafety, $bNoPacketEncryption)
		Next
	Next

	Return $nBytes

EndFunc

; Call this to get the maximum Packet Content Size you can send to not exceed $g__io_nMaxPacketSize
; @extended holds the bytes that you have left to add
Func _netcode_GetMaxPacketContentSize($sEventName = "", $nSafetyMarge = 0.9)
	$nMaxPacketContentSize = ($__net_nInt_MaxPacketContentSize - StringLen($sEventName))
	Return SetError(0, $nMaxPacketContentSize * (1 - $nSafetyMarge), $nMaxPacketContentSize * $nSafetyMarge)
EndFunc

; Call this to get the Default SetTCPRecvDefault Size if you want to send packets as big as that
; This is usefull when sending over the Internet in some cases.
; _netcode_SetOption("SetTCPRecvDefault", x) should be set, otherwise you end up sending the default len which is 4096
Func _netcode_GetDefaultPacketContentSize($nMarge = 1)
	Return $__net_nOption_TCPRecvDefault * $nMarge
EndFunc

Func _netcode_GetSocketParent($hSocket)
	Return __Io_CheckSocket($hSocket)
EndFunc

; $hParentSocket is Optional
; each client be seperated by '|' then.
Func _netcode_GetSockets($hParentSocket = 0)
	if $hParentSocket = 0 Then Return $g__Io_arAllSockets

	Local $nArSize = UBound($g__Io_arAllSockets)
	if $nArSize = 0 Then Return SetError(1, 0, False) ; no sockets saved

	Local $nIndex = -1
	For $i = 0 To $nArSize - 1
		if $g__Io_arAllSockets[$i][0] = $hParentSocket Then
			$nIndex = 0
			ExitLoop
		EndIf
	Next

	if $nIndex = -1 Then Return SetError(2, 0, False) ; parent not found

	Local $arReturn[1][2]
	$arReturn[0][0] = $g__Io_arAllSockets[$nIndex][0]
	$arReturn[0][1] = $g__Io_arAllSockets[$nIndex][1]

	Return $arReturn

	#cs
	$arReturn = StringSplit($g__Io_arAllSockets[$nIndex][1], '|', 1)
	ReDim $arReturn[$arReturn[0]]
	$arReturn[0] -= 1

	Return $arReturn
	#ce
EndFunc

; $arClientsToIgnore needs either to be a 1 based array or a string holding the sockets seperated by '|'
Func _netcode_GetSocketsBut($hParent, $arClientsToIgnore)
	Local $arClientSockets = _netcode_GetSockets($hParent)

	if Not IsArray($arClientsToIgnore) Then
		$arClientsToIgnore = StringSplit($arClientsToIgnore, '|', 1)
	EndIf

	For $i = 1 To $arClientsToIgnore[0]
		if $arClientsToIgnore = "" Then ContinueLoop
		$arClientSockets[0][1] = StringReplace($arClientSockets[0][1], $arClientsToIgnore[$i] & '|', '')
	Next

	Return $arClientSockets
EndFunc

Func _netcode_Relay($sRelayPort, $sRelayTo, $sRelayToPort, $vIPList = False, $bIPListIsBlacklist = False) ; $arWhiteList todo
	Local $hRelaySocket = TCPListen('0.0.0.0', $sRelayPort)
	if $hRelaySocket = -1 Then Return SetError(@error, 0, False) ; port taken?

	_storageS_Overwrite($hRelaySocket & '_RelayToIP', $sRelayTo)
	_storageS_Overwrite($hRelaySocket & '_RelayToPort', $sRelayToPort)
	If $vIPList <> False Then _netcode_RelayUpdateIPList($hRelaySocket, $vIPList, $bIPListIsBlacklist)

	__netcode_AddRelaySocket($hRelaySocket)

	Return $hRelaySocket
EndFunc

Func _netcode_RelayStop(Const $hParentSocket)
	TCPCloseSocket($hParentSocket)
	__Io_DelSocket($hParentSocket, True)
EndFunc

Func _netcode_RelayUpdateIPList($hRelaySocket, $vIPList, $bIPListIsBlacklist = False)
	Local $sIPList
	If IsArray($vIPList) Then
		For $i = 0 To UBound($vIPList) - 1
			$sIPList &= $vIPList[$i] & '|'
		Next
	Else
		$sIPList = $vIPList
	EndIf

	_storageS_Overwrite($hRelaySocket & '_RelayIPList', $sIPList)
	_storageS_Overwrite($hRelaySocket & '_RelayIPListMode', $bIPListIsBlacklist)
EndFunc

Func _netcode_HttpProxy($hProxyPort, $vIPListConnect = False, $vIPListConnectTo = False, $bIPListIsBlacklist = False)
	Return _netcode_Proxy($hProxyPort, '__netcode_HttpProxyFromClient', False, $vIPListConnect, $vIPListConnectTo, $bIPListIsBlacklist)
EndFunc

Func _netcode_Proxy($hProxyPort, $sCallbackConnect, $sCallbackConnectTo, $vIPListConnect, $vIPListConnectTo, $bIPListIsBlacklist = False)
	Local $hRelaySocket = _netcode_Relay($hProxyPort, '', '', $vIPListConnect, $bIPListIsBlacklist)

	_storageS_Overwrite($hRelaySocket & '_RelayIsProxy', True)
	_storageS_Overwrite($hRelaySocket & '_RelayProxyCallbackConnect', $sCallbackConnect)
;~ 	_storageS_Overwrite($hRelaySocket & '_RelayProxyCallbackConnectTo', $sCallbackConnectTo)
	_storageS_Overwrite($hRelaySocket & '_RelayProxyIPListConnectTo', $vIPListConnectTo)
	_storageS_Overwrite($hRelaySocket & '_RelayProxyIPListIsBlacklist', $bIPListIsBlacklist)

	Return $hRelaySocket
EndFunc

; ===========================================================================================

; Set a Event that you want to have bind to every new Socket. _Io_On() will be called for each of these Events on each NEW Socket
; including the listener socket. Again, only on NEW sockets. So you set these before you _netcode_Connect() or _netcode_Listen()
Func _netcode_SetCustomSocketEvent($sCallback)
	$__net_sEvent_Customs &= $sCallback & '|'
EndFunc

; Remove a Socket Event added from _netcode_SetCustomSocketEvent(). it will not be removed from connected sockets.
; this event will just not be bind to each new socket.
Func _netcode_RemoveCustomSocketEvent($sCallback)
	$__net_sEvent_Customs = StringReplace($__net_sEvent_Customs, $sCallback & '|', '')
EndFunc

; You do not need to set this, but if you do then you get this Event Called when someone Connects
Func _netcode_SetConnectionCallback($sCall)
	if $sCall = "" Then Return SetError(1, 0, False)
	$__net_sEvent_ConCall = $sCall
EndFunc

; You do not need to set this, but if you do then you get this Event Called when someone Disconnects
Func _netcode_SetDisconnectCallback($sCall)
	if $sCall = "" Then	Return SetError(1, 0, False)
	$__net_sEvent_DisCall = $sCall
EndFunc

; Standard Messages can be send to 'netcode_message'. Set this for a Callback
Func _netcode_SetMessageCallback($sCall) ; will only be called once all data is received
	if $sCall = "" Then Return SetError(1, 0, False)
	$__net_sEvent_MesCall = $sCall
EndFunc

; if a Client exceeds $g__io_nMaxPacketSize the data will not just be discarded but you also get a notification to the set Callback.
; atleast if you want to know about such cases.
Func _netcode_SetFloodCallback($sCall)
	if $sCall = "" Then	Return SetError(1, 0, False)
	$__net_sEvent_FloCall = $sCall
EndFunc

; you can code your own encryption functions. SocketIO will call this in __Io_CreatePackage().
; Input will be String and you need to Output encrypted data in String. Just use BinaryToString().
; Why? The Packet isnt wrapped up yet. It will be Binarized in the last step. Binarizing subparts of the package would
; heaviely increase the overall size of the packet.
; Try to keep the Output size similiar to the input size. Smaller is always ok, but Greater can be bad. A difference of about 10 % should be acceptable.
; But that depends on if you send packets that are nearly as big as the $g__io_nMaxPacketSize.
; In case you rise the size > 10 % - use _netcode_GetMaxPacketContentSize() to split your Data and set the $nSafetyMarge higher.
; if you set this, call _netcode_SetOption("SetCryptionMode", "custom") before.
; And also make sure you enable encryption only after you set the callbacks.
; Because otherwise either _netcode or SocketIO will open up unnessesary dlls.
; Also it will check, when enabling encryption, if your functions can actually encrypt and decrypt a preset string.
; if you want to reset the callbacks use _netcode_SetOption('SetCryptionMode', 'default') or 'netcode'.
Func _netcode_SetEncryptionCallback($sCall)
	If $sCall = '' Then Return
	_Io_SetEncryptionCallback($sCall)
;~ 	$__net_sOption_CryptionMode = 'custom' ; dont set here
EndFunc

Func _netcode_SetDecryptionCallback($sCall)
	If $sCall = '' Then Return
	_Io_SetDecryptionCallback($sCall)
;~ 	$__net_sOption_CryptionMode = 'custom'
EndFunc

; set certain netcode Options
Func _netcode_SetOption($sOption, $Set)
	Switch $sOption

		; ###################	General

		; Log Debug to Console. This is not _Io_DevDebug()
		; Subject to heavy changes.
		Case "DebugLogToConsole"
			if IsBool($Set) Then
				$__net_bOption_DebugLogToConsole = $Set
				__netcode_Debug("Set Value $__net_bOption_DebugLogToConsole = " & $Set)
			EndIf

		; ################### 	Below are Sync Options where the server / client can be asked to send these Configurations.
		;						Normaly the Client tries to Sync with the Server. If the Server has any of these set to False, it wont Sync these
		;						~ Moved ~

;~ 		Case "SendMaxPackageSize" ; Send the $g__io_nMaxPacketSize
;~ 			if IsBool($Set) Then
;~ 				$__net_bAllowSend_MaxPackageSize = $Set
;~ 				__netcode_Debug("Set Value $__net_bAllowSend_MaxPackageSize = " & $Set)
;~ 			EndIf

;~ 		Case "AllowPacketValidation" ; Send $__net_bAllowSend_PacketValidation
;~ 			if IsBool($Set) Then
;~ 				$__net_bAllowSend_PacketValidation = $Set
;~ 				__netcode_Debug("Set Value $__net_bAllowSend_PacketValidation = " & $Set)
;~ 			EndIf

;~ 		Case "AllowPacketSafety" ; Send $__net_bAllowSend_PacketSafety
;~ 			if IsBool($Set) Then
;~ 				$__net_bAllowSend_PacketSafety = $Set
;~ 				__netcode_Debug("Set Value $__net_bAllowSend_PacketSafety = " & $Set)
;~ 			EndIf

;~ 		Case "AllowFloodPrevention" ; Send $__net_bAllowSend_FloodPrevention
;~ 			if IsBool($Set) Then
;~ 				$__net_bAllowSend_FloodPrevention = $Set
;~ 				__netcode_Debug("Set Value $__net_bAllowSend_FloodPrevention = " & $Set)
;~ 			EndIf

		; ################### Netcode Options

		; Set $g__io_nMaxPacketSize. The Recv Buffer discards the Buffer if its size is bigger then that and it will Call the Flood Event then.
		; The Default is 4096 B in SocketIO and 1 MB if you use _netcode.
		Case "SetMaxPackageSize"
			if IsNumber($Set) Then
				$__net_nInt_MaxRecvLength = $Set
				_Io_setMaxRecvPackageSize($__net_nInt_MaxRecvLength)
				__netcode_CalMaxPacketContentSize()
				__netcode_Debug("Set Value $__net_nInt_MaxRecvLength = " & $Set)
			EndIf

		; TCPRecv(socket, SetTCPRecvDefault). if TCPRecv called it will only retrieve this much data per Call.
		; You can also set this as a general Packet Splitter for _netcode_GetDefaultPacketContentSize()
		; The Default is 4096 B
		Case "SetTCPRecvDefault"
			if IsNumber($Set) Then
				$__net_nOption_TCPRecvDefault = $Set
				_Io_setRecvPackageSize($__net_nOption_TCPRecvDefault)
				__netcode_Debug("Set Value $__net_nOption_TCPRecvDefault = " & $Set)
			EndIf

		; When set the Packet Handler will Check if either the Hash or the Size is right. If not it will discard the packet.
		; You basically wont end up with bad packets in your Functions.
		; If you ask yourself for what this is usefull then think about issues you may have with corrupted data.
		; yes TCP uses checksums but according to several Articels a weak algo is used.
		; You can set the Validation Mode with ######### ~ todo
		; Default Validation Mode is ########
		; Default is False
		Case "SetPacketValidation"
			$Set = __netcode_Bool($Set)
			if Not @error Then
				$__net_bOption_PacketValidation = $Set
				_Io_SetPacketValidation($__net_bOption_PacketValidation)
				__netcode_Debug("Set Value $__net_bOption_PacketValidation = " & $Set)
			EndIf

		; WIP - The SocketIO will wait for a Validation Confirmation of the receiver before it Continues. Timeout is 10 seconds
		; Packet Safety heaviely slows down the Transmission of the Sending side, because it waits for an answer.
		; Also the Packet Safety only takes place if the packet is greater then $g__Io_nPacketSafetyMinimumLen.
		; In a couple of cases this Feature also improves the Recv Speed as the Time Consuming "Packet for Completion Check" isnt so
		; heaviely used. This Feature depends on PacketValidation.
		; Toggle to True if you face Packet loss.
		; Minimum Len can be set with #############
		; Default Minimum Len is #########
		; Function is Subject to heavy Change.
		; Default is False
		Case "SetPacketSafety"
			$Set = __netcode_Bool($Set)
			if Not @error Then
				$__net_bOption_PacketSafety = $Set
				_Io_SetPacketSafety($__net_bOption_PacketSafety)
				__netcode_Debug("Set Value $__net_bOption_PacketSafety = " & $Set)
			EndIf

		; The _Io_Emit() function will guess how much space is left in the receivers buffer limited by $g__io_nMaxPacketSize and not Send if its
		; probably to full to receive another packet without flooding it. Also the receiver will return a 'Internal_FloodPrevention' Packet
		; with the Size of the last received packets.
		; So it prevents flooding..
		; Default is True
		Case "SetFloodPrevention"
			$Set = __netcode_Bool($Set)
			if Not @error Then
				$__net_bOption_FloodPrevention = $Set
				_Io_SetFloodPrevention($__net_bOption_FloodPrevention)
				__netcode_Debug("Set Value $__net_bOption_FloodPrevention = " & $Set)
			EndIf

		; If the Receive Buffer is probably Full then instead of Returning from _netcode_Send() we will Wait in a Loop until the
		; 'Internal_FloodPrevention' Packet is here and then Send. There is no timeout - yet. But after $g__Io_nGlobalTimeoutTime SocketIO will check
		; if the server is either hung or the prevention packet just got lost. If the Connection is gone, it will Return from _netcode_Send().
		; Default is True
		Case "SetFloodWaitForPreventionPacket"
			$Set = __netcode_Bool($Set)
			if Not @error Then
				$__net_bOption_WaitForPreventionPacket = $Set
				__netcode_Debug("Set Value $__net_bOption_WaitForPreventionPacket = " & $Set)
			EndIf

		; WIP - Set if you want the netcode to manage big packets on itself
		; you can basically call _netcode_Send() with a really big Data Size. Netcode will split it up if its bigger then $g__io_nMaxPacketSize,
		; the Event is called once the packet is complete.
		; Both Parties need to have it toggled On if they want to use it
		; However it can be used to crash the app by connecting alot of sockets and have them all fill up the packet buffer
		; the Buffer can at maximum be filled with $__net_nInt_MaximumBigPacketSize per socket
		; so at default this is turned off and you need to True this before you call _netcode_Connect() or _netcode_Listen().
		; Because otherwise the corresponding Event 'netcode_bigpacket' isnt bind. But you can troubleshoot this by binding it yourself.
		; You can set the buffer size with Option 'SetMaximumPacketSplitBufferSize'
		Case "SetAutoSplitBigPackets"
			$Set = __netcode_Bool($Set)
			if not @error Then
				$__net_bOption_SetAutoSplitBigPackets = $Set
				__netcode_Debug("Set Value $__net_bOption_SetAutoSplitBigPackets = " & $Set)
			EndIf

		; True this if you want to have your Transmissions encrypted.
		; SocketIO uses _ccrypt.au3 UDF based on crypt.au3.
		; _netcode uses a stripped variant of CryptoNG.au3 UDF based on bcrypt.au3.
		; You can also Choose to code your own encryption functions.
		; See Option 'SetCryptionMode'.
		; At default the Cryption mode is 'netcode'
		; Also see Option 'SetEncryptionPassword' and 'SetAcceptUnecryptedTraffic'.
		; Default is False
		Case "EnableEncryption"
;~ 			If IsBinary($Set) Then $Set = BinaryToString($Set)
			if IsString($Set) Or IsBinary($Set) Or IsPtr($Set) Then ; needs to be the pw
				if $__net_sOption_CryptionMode = 'netcode' Then $Set = __netcode_DeriveKey($Set, $__net_sOption_CryptionNetcodeSalt)
				_Io_EnableEncryption($Set)
				$__net_bOption_EncryptionStatus = True
				__netcode_Debug("Set Value $__net_bOption_EncryptionStatus = True")
			EndIf

		Case "DisableEncryption"
			$Set = __netcode_Bool($Set)
			if not @error And $Set Then
				if $__net_sOption_CryptionMode = 'netcode' Then
					__netcode_DestroyKey($Set) ; not yet coded
					__netcode_CryptShutdown()
				EndIf
				_Io_DisableEncryption()
				$__net_bOption_EncryptionStatus = False
				$__net_bInt_EnabledEncryptionThroughSync = False
				__netcode_Debug("Set Value $__net_bOption_EncryptionStatus = False")
			EndIf

		; you dont need to set this if you call "EnableEncryption".
		; this is in case the server requires encryption but the client hasnt it set yet
		; it will then use this password.
		Case "SetEncryptionPassword"
			if IsString($Set) Or IsBinary($Set) Or IsPtr($Set) Then
				$__net_sOption_SetPasswordForEncryption = $Set
				__netcode_Debug("Set Value $__net_sOption_SetPasswordForEncryption = False")
			EndIf


		; this Option enables the accepting of unencrypted traffic when encryption is enabled
		; it also disables the encryption of all Syn packets so the client can read these. be aware of that.
		; It needs to be Set True if you use Option 'SetEncryptionPassword' on the Client but not 'EnableEncryption'
		Case "SetAcceptUnecryptedTraffic"
			$Set = __netcode_Bool($Set)
			if not @error Then
				_Io_SetAcceptUnecryptedTraffic($Set)
				$__net_bOption_AcceptUnecryptedTraffic = $Set
				__netcode_Debug("Set Value $__net_bOption_AcceptUnecryptedTraffic = " & $Set)
			EndIf

		;
		Case "SetMaximumPacketSplitBufferSize"
			if IsNumber($Set) Then
				$__net_nInt_MaximumBigPacketSize = $Set
				__netcode_Debug("Set Value $__net_nInt_MaximumBigPacketSize = " & $Set)
			EndIf

		; set this if you want that the specific Sending of Packets only happens once you call _netcode_Loop() or _Io_Loop()
		; sometimes this also can fix certain issues.
		; once set _netcode_Send() and _Io_Send() will no longer Return the count of the send bytes.
		; _netcode_Send() does call _netcode_Loop() if the FloodPrevention is triggered. You can turn that of by SetOption 'SetFloodWaitForPreventionPacket' to False
		; but then the Packet that triggered the Prevention will not be Saved for Sending.
		; if you need to check for errors in case the TCPSend fails for some reason, then you can use ####### ~ todo
		Case "SetOnlySendInLoop"
			If IsBool($Set) Then
				_Io_SetOnlySendInLoop($Set)
				__netcode_Debug("Set Value $g__Io_bToggleSendOnlyWhenLoop = " & $Set)
			EndIf

		Case "SetGlobalTimeout"
			If IsNumber($Set) Then
				_Io_SetGlobalTimeout($Set)
				__netcode_Debug("Set Value $g__Io_nGlobalTimeoutTime = " & $Set)
			EndIf

		; call this before the Option EnableEncryption if you want to switch the Mode.
		; available modes are
		; default = use the SocketIO own encryption which relies on _ccryptS.au3 and advapi.dll
		; netcode = (this is the default) use the netcode frameworks own encryption which relies on CryptoNG UDF and bcrypt.dll
		; custom = use when you want to use your own encryption funcs - see _netcode_SetEncryptionCallback()
		; you can reset the custom setting then by calling this Option with either default or netcode
		; regarding speed advapi.dll isnt slower or faster then bcrypt.dll.
		; Both variants encrypt in AES. This can not be changed.
		; If you want to use CryptoNG UDF in its full glory then you need to code it and use 'custom'.
		Case "SetCryptionMode"
			if IsString($Set) Then
				Switch $Set
					Case "default"
						__netcode_Debug("Set Value $__net_sOption_CryptionMode = " & $Set)
						$__net_sOption_CryptionMode = "default"
						_Io_SetEncryptionCallback('')
						_Io_SetDecryptionCallback('')

					Case "netcode"
						__netcode_Debug("Set Value $__net_sOption_CryptionMode = " & $Set)
						$__net_sOption_CryptionMode = "netcode"
						_Io_SetEncryptionCallback('__netcode_Encrypt')
						_Io_SetDecryptionCallback('__netcode_Decrypt')

					Case "custom"
						__netcode_Debug("Set Value $__net_sOption_CryptionMode = " & $Set)
						$__net_sOption_CryptionMode = "custom"

				EndSwitch
			EndIf

		Case Else
			__netcode_Debug("Unknown Option: " & $sOption)
			Return SetError(1, 0, False) ; Unknown Option
	EndSwitch
EndFunc

; for seting _netcode.au3 internal related syncs.
; All these internal Configurations will be Requested and Set when _netcode_Sync_Netcode() is called.
; at Default all Syncs are Set to True.
Func _netcode_SetNetworkSync($sEvent, $Set)
	Switch $sEvent

		; Sync $g__io_nMaxPacketSize
		Case "MaxPackageSize"
			if IsBool($Set) Then
				$__net_bSync_MaxPackageSize = $Set
				__netcode_SyncString($sEvent & '|', $Set)
				__netcode_SyncSetDataToEvent($sEvent, '$', '__net_nInt_MaxRecvLength', "?", "__netcode_Sync_MaxRecvLength", "Number")
				__netcode_Debug("Set Sync $__net_bSync_MaxPackageSize = " & $Set)
			EndIf

		Case "PacketValidation"
			if IsBool($Set) Then
				$__net_bSync_PacketValidation = $Set
				__netcode_SyncString($sEvent & '|', $Set)
				__netcode_SyncSetDataToEvent($sEvent, '$', '__net_bOption_PacketValidation', "?", "__netcode_Sync_PacketValidation", "Bool")
				__netcode_Debug("Set Sync $__net_bSync_PacketValidation = " & $Set)
			EndIf

		Case "PacketSafety"
			if IsBool($Set) Then
				$__net_bSync_PacketSafety = $Set
				__netcode_SyncString($sEvent & '|', $Set)
				__netcode_SyncSetDataToEvent($sEvent, '$', '__net_bOption_PacketSafety', "?", "__netcode_Sync_PacketSafety", "Bool")
				__netcode_Debug("Set Sync $__net_bSync_PacketSafety = " & $Set)
			EndIf

		Case "FloodPrevention"
			if IsBool($Set) Then
				$__net_bSync_FloodPrevention = $Set
				__netcode_SyncString($sEvent & '|', $Set)
				__netcode_SyncSetDataToEvent($sEvent, '$', '__net_bOption_FloodPrevention', "?", "__netcode_Sync_FloodPrevention", "Bool")
				__netcode_Debug("Set Sync $__net_bSync_FloodPrevention = " & $Set)
			EndIf

		Case "TCPRecvDefault"
			if IsBool($Set) Then
				$__net_bSync_TCPRecvDefault = $Set
				__netcode_SyncString($sEvent & '|', $Set)
				__netcode_SyncSetDataToEvent($sEvent, '$', '__net_nOption_TCPRecvDefault', "?", "__netcode_Sync_TCPRecvDefault", "Number")
				__netcode_Debug("Set Sync $__net_bSync_TCPRecvDefault = " & $Set)
			EndIf

		Case "EncryptionStatus"
			if IsBool($Set) Then
				$__net_bSync_EncryptionStatus = $Set
;~ 				__netcode_SyncString($sEvent & '|', $Set)
				__netcode_SyncSetDataToEvent($sEvent, '$', '__net_bOption_EncryptionStatus', "?", "__netcode_Sync_EncryptionStatus", "Bool")
				__netcode_Debug("Set Sync $__net_bSync_EncryptionStatus = " & $Set)
			EndIf

	EndSwitch
EndFunc

#cs
 custom synchronizations
 looks complex but is easy to use
 Maybe Subject to Change. Lets see what the Community says.
 You can Set Custom Syncs. Lets say you want to always know a identifier of a connecting Client to auth it or something.

 $sEvent			= Specify the Name of the Sync Event
 $sDataSourceType	= you can specify 3 different types '!', '$', '?'.
 					All these types specify what, if the event is called, todo with $vDataSource.
					if '!' is set it will assume the $vDataSource is a Value (e.g. String) and will directly Return that
					if '$' is set it will assume the $vDataSource is a Var and will Eval() it.
					you use that if the $vDataSource is Dynamic
					if '?' is set it will assume the $vDataSource is a Func and will Call() it.
					The call will have 3 Params. $hSocket, $sMode, $sData
					$sMode can be "GET" or "POST". "GET" means that the, in this Case, Server requests the identifier.
					You basically evaluate the identifier and Return it. "POST" is where the Result of "GET" is going to.
					So in this case the Server will get a "POST" with the Clients Identifier.

 $vDataSource		= The Name of the Source, can be the Source if $sDataSourceType is '!'
 $sDataGoToType		= as $sDataSourceType. '!' is impossible.
 $sDataGoTo			= Specify where the data from "GET" goes. To a Var or a Func. Func $sMode will be "POST"
 $sDataType			= Is the "POST" Data Type. The Default Type will always be String. So if you Synced a Bool var, you will end up
					with e.g. $var = "False" which would be True in 'if $var Then'.
					So you can Set this to the vartype you need. If this is dynamice then set a Sync before this to just Sync the
					the DataType of the next. Available Types are
					"String", "Number", "Int", "Bool", "Binary", "Ptr", "HWnd"

 $bEnable			= Set True if you want to Request this Event to be Synced from this Side.

 You also need to Specify this Sync Event if you just want to provide the Sync Data. In that Case $bEnable = False
 If you Specify in $sDataSourceType '?' and the $vDataSource is the same as $sDataGoTo then you can leave $sDataGotoType and $sDataGoto empty.
 It will assume then that "GET" and "POST" is the same.

 All Sync Events need to be Allowed, to prevent unwanted Data leak.
 For this use _netcode_SetNetworkCustomAllow().
 And to prevent unwanted Configuration Setting you need to enable the Sync either with $bEnable or _netcode_SetSyncState().
 Only allowed Syncs can "GET".
 Only enabled Syncs can "POST".

 For the example Case with the Identifier it could look like that

 1.
 Server
	_netcode_SetNetworkCustomSync("ClientAuth", '?', '_Net_ClientAuth', '', '', 'String', True)

 Client
	_netcode_SetNetworkCustomSync("ClientAuth", '!', 'My name is Jeff')
	_netcode_SetNetworkCustomAllow("ClientAuth", True)

 2.
 Server
	_netcode_SetNetworkCustomSync("ClientAuth", '?', '_Net_ClientAuth', '', '', 'Number', True)

 Client
	_netcode_SetNetworkCustomSync("ClientAuth", '?', '_Net_MyAuth')
	_netcode_SetNetworkCustomAllow("ClientAuth", True)


 Func _Net_MyAuth($hSocket, $sMode, $sData)
	Switch $sMode
		Case "GET"
			Return Random(11111, 99999, 1)

		Case "POST"
			;nothing

	EndSwitch
 EndFunc

 Func _Net_ClientAuth($hSocket, $sMode, $sData)
	Switch $sMode
		Case "GET"
			; nothing

		Case "POST
			ConsoleWrite($hSocket & ' authes as ' & $sData & @CRLF)

	EndSwitch
 EndFunc

#ce
Func _netcode_SetNetworkCustomSync($sEvent, $sDataSourceType, $vDataSource, $sDataGoToType = "", $sDataGoTo = "", $sDataType = "String", $bEnable = False)
	__netcode_SyncSetDataToEvent($sEvent, $sDataSourceType, $vDataSource, $sDataGoToType, $sDataGoTo, $sDataType)
	Assign($__net_sSync_VarString & $sEvent, $bEnable, 2)
	__netcode_SyncString($sEvent & '|', $bEnable)
	__netcode_Debug("Set Custom Sync " & $sEvent)
EndFunc

; you can forcefully enable or disable existing syncs.
; for turning on/off internal _netcode syncs please use _netcode_SetNetworkSync().
; this function is more thought to be used on Custom Events.
Func _netcode_SetSyncState($sEvent, $Set)
	if _storageS_Read($sEvent & 'SyncSetDataToEvent') = False Then Return False
	$Set = __netcode_Bool($Set)
	if Not @error Then
		__netcode_SyncString($sEvent, $Set)
		Assign($__net_sSync_VarString & $sEvent, $Set, 2)
	EndIf
	Return True
EndFunc

; you can disable internal _netcode syncs with _netcode_SetNetworkSync()
; if you also want that no client can even "GET" the Configuration data you can also Disallow them Individually
Func _netcode_SetNetworkAllow($sEvent, $Set)
	$Set = __netcode_Bool($Set)
	if @error Then Return SetError(1, 0, False)

	__netcode_Debug('Set Allow $' & $__net_sAllowSend_VarString & $sEvent & ' = ' & $Set)
	Return Assign($__net_sAllowSend_VarString & $sEvent, $Set, 4)
EndFunc

; only allowed sync get send. if the client asks for the encryption key, but the server doesnt allow to transmit it with this func
; then it will fail. Dont worry encryption keys dont get synced
Func _netcode_SetNetworkCustomAllow($sEvent, $Set)
	$Set = __netcode_Bool($Set)
	if @error Then Return SetError(1, 0, False)

	__netcode_Debug('Set Custom Allow $' & $__net_sAllowSend_VarString & $sEvent & ' = ' & $Set)
	Return Assign($__net_sAllowSend_VarString & $sEvent, $Set, 2)
EndFunc

; Trigger the Synchronization after a Connection. it will Send (and not wait for) the Configuration
Func _netcode_Sync_Netcode($hSocket)
	if $__net_bSync_EncryptionStatus Then __netcode_SyncString('EncryptionStatus|', True)
	__netcode_SyncAdd($hSocket, $__net_sSync_SyncOnEachSocket)

	Local $arSync = StringSplit($__net_sSync_SyncOnEachSocket, '|', 1)

	; send sync requests
	For $i = 1 To $arSync[0]
		if $arSync[$i] = "" Then ContinueLoop
		Sleep(1)
		_netcode_Send($hSocket, 'netcode_getsync', $arSync[$i], True)
	Next

	if $__net_bSync_EncryptionStatus Then __netcode_SyncString('EncryptionStatus|', False)
EndFunc

; Check if all Synchronizations are done, if it is Returns True
; is to be used when you dont want the Code to continue until all Synchronization is done
; if the other Side doesnt allow or enabled the Syn of all or a part of the requested Syn's then this function will never Return True.
; if @error is 2 then @extended holds the SocketID. By calling _StorageS_Read(socket & "SYNC") you will get the left over Syns divided by '|'
Func _netcode_Sync_Check($hSocket)
	$bDone = __netcode_SyncCheck($hSocket)
	Return SetError(@error, @extended, $bDone)
EndFunc

; everything below is Internal and not to be used individually
; ===========================================================================================

; marked for recoding
; can be exploited when alot of sockets fill their maximum buffer. Will just crash. Buffer Overflow isnt a thing in Autoit
Func _On_netcode_bigpacket(Const $hSocket, $sData)
	if Not $__net_bOption_SetAutoSplitBigPackets Then Return
	Local $arData = StringSplit($sData, $__net_sInt_BigPacketSplitSeperator, 1)

	if $arData[0] = 3 Then
		$sParams = _storageS_Read($hSocket & $arData[1] & 'PACKET')
		_storageS_Overwrite($hSocket & $arData[1] & 'PACKET', '')
		_storageS_Overwrite($hSocket & $arData[1] & 'PACKETSIZE', '')

;~ 		__Io_InvokeCallback($hSocket,$sParams, '_On_' & $arData[1])
		$hParentSocket = __Io_CheckSocket($hSocket)
		if $hParentSocket = False Then $hParentSocket = $hSocket
		__Io_PacketExecution($hSocket, $sParams, $arData[1], $hParentSocket)
		Return
	EndIf

	$nNewPacketSize = _storageS_Read($hSocket & $arData[1] & 'PACKETSIZE') + StringLen($arData[2])
	if $nNewPacketSize > $__net_nInt_MaximumBigPacketSize Then
		__netcode_Debug("Packet Exceeding Maximum Size in netcode_bigpacket")
		Return
	EndIf
	_storageS_Overwrite($hSocket & $arData[1] & 'PACKETSIZE', $nNewPacketSize)
	_storageS_Append($hSocket & $arData[1] & 'PACKET', $arData[2])
	Return
EndFunc

Func _On_netcode_message(Const $hSocket, $sData)
	if $__net_sEvent_MesCall = "" Then
		__netcode_Debug("Message, but Callback not set")
		Return
	EndIf

	Call($__net_sEvent_MesCall, $hSocket, $sData)
EndFunc

Func _On_connection(Const $hSocket)
	if $__net_sEvent_ConCall = "" Then
		__netcode_Debug("Connection, but Callback not set")
		Return
	EndIf

	Call($__net_sEvent_ConCall, $hSocket)
EndFunc

Func _On_disconnect(Const $hSocket)
	if $__net_bInt_EnabledEncryptionThroughSync Then _netcode_SetOption("DisableEncryption", True)
	if $__net_sEvent_DisCall = "" Then
		__netcode_Debug("Disconnect, but Callback not set")
		Return
	EndIf

;~ 	if @error Then Return ; if Sync wasnt finished yet
	Call($__net_sEvent_DisCall, $hSocket)
EndFunc

Func _On_flood(Const $hSocket)
	if $__net_bOption_PacketSafety And $__net_bOption_NoFloodEventIfPacketSafetyOn Then Return
	if $__net_sEvent_FloCall = "" Then
			__netcode_Debug("Flood, but Callback not set")
		Return
	EndIf
	Call($__net_sEvent_FloCall, $hSocket)
EndFunc

Func _On_netcode_getsync(Const $hSocket, $sData)
	Local $arData = StringSplit($sData, '|', 1 + 2)

	; check if Syn allowed
	$bGetAllowStatus = Eval($__net_sAllowSend_VarString & $arData[0])
	if Not $bGetAllowStatus Or $bGetAllowStatus = "" Then Return False ; either disallowed or not set

	; Switch for type to read
	Local $sPost = ""
	Switch _storageS_Read($arData[0] & 'SyncSetDataToEventType')
		Case '!'
			$sPost = _storageS_Read($arData[0] & 'SyncSetDataToEvent')

		Case '$'
			$sPost = Eval(_storageS_Read($arData[0] & 'SyncSetDataToEvent'))

		Case '?'
			$sPost = Call(_storageS_Read($arData[0] & 'SyncSetDataToEvent'), $hSocket, 'GET', '')

	EndSwitch

	if $sPost == "" Then Return False ; nothing in $sEvent & 'SyncSetDataToEvent'

	_netcode_Send($hSocket, 'netcode_postsync', $arData[0] & '|' & $sPost, True, $__net_bOption_AcceptUnecryptedTraffic)

EndFunc

Func _On_netcode_postsync(Const $hSocket, $sData)
	Local $arData = StringSplit($sData, '|', 1 + 2)

	; check if syn allowed
	$bGetAllowStatus = Eval($__net_sSync_VarString & $arData[0])
	if Not $bGetAllowStatus Or $bGetAllowStatus = "" Then Return False ; this sync isnt set

;~ 	MsgBox(0, "", $arData[0])

	Switch _storageS_Read($arData[0] & 'SyncSetPostEventType')
		Case '!'
			__netcode_Debug("Wrong Syn Setting: " & $arData[0])

		Case '$'
			Assign(_storageS_Read($arData[0] & 'SyncSetPostEvent'), __netcode_ConvertDataType($arData[1], _storageS_Read($arData[0] & 'SyncSetPostEventDataType')), 2)

		Case '?'
			Call(_storageS_Read($arData[0] & 'SyncSetPostEvent'), $hSocket, 'POST', __netcode_ConvertDataType($arData[1], _storageS_Read($arData[0] & 'SyncSetPostEventDataType')))

	EndSwitch

	__netcode_SyncDel($hSocket, $arData[0] & '|')
EndFunc

; ===========================================================================================
; types _
; ! fixed String
; $ var
; ? Func to call
; leave post empty if its the same as on Get
; you need to set the Post Data type because any return is String this is usefull if you want to Syn only Variables and they need to be of a certain type.
; Data Types are String, Number, Int, Bool, Binary, Ptr, HWnd
Func __netcode_SyncSetDataToEvent($sEvent, $nGetOption, $vGet, $nPostOption = "", $vPost = "", $sPostDataType = "String")
	_storageS_Overwrite($sEvent & 'SyncSetDataToEvent', $vGet)
	_storageS_Overwrite($sEvent & 'SyncSetDataToEventType', $nGetOption)

	if $nPostOption = "" Then
		_storageS_Overwrite($sEvent & 'SyncSetPostEvent', $vGet)
		_storageS_Overwrite($sEvent & 'SyncSetPostEventType', $nGetOption)

	Else
		_storageS_Overwrite($sEvent & 'SyncSetPostEvent', $vPost)
		_storageS_Overwrite($sEvent & 'SyncSetPostEventType', $nPostOption)

	EndIf

	if $sPostDataType = "" Then $sPostDataType = "String"
	_storageS_Overwrite($sEvent & 'SyncSetPostEventDataType', $sPostDataType)
EndFunc

Func __netcode_ConvertDataType($vData, $sDataType)
	if $sDataType = "String" Then Return $vData

	Switch $sDataType
		Case "Number"
			Return Number($vData)

		Case "Int"
			Return Int($vData)

		Case "Bool"
			if $vData = "True" Then Return True
			if $vData = "False" Then Return False
			if $vData = True Then Return True
			if $vData = False Then Return False

		Case "Binary"
			Return Binary($vData)

		Case "Ptr"
			Return Ptr($vData)

		Case "HWnd"
			Return HWnd($vData)

	EndSwitch
EndFunc

; recalculates the max packet content size. needs to be called once any of these get changed $__net_nInt_MaxRecvLength, $g__Io_sPacketSeperator or $g__Io_sPacketSeperatorInternal
Func __netcode_CalMaxPacketContentSize()
	$__net_nInt_MaxPacketContentSize = $__net_nInt_MaxRecvLength - ((StringLen($g__Io_sPacketSeperator) * 2) + StringLen($g__Io_sPacketSeperatorInternal) + StringLen($g__Io_sPacketSeperatorLen))
EndFunc

Func __netcode_Debug($String)
	if $__net_bOption_DebugLogToConsole Then ConsoleWrite($String & @CRLF)

	; debug
;~ 	Local Static $hOpen = FileOpen(@ScriptDir & "\debug.txt", 2)
;~ 	FileWrite($hOpen, $String & @CRLF)
EndFunc

Func __netcode_SyncAdd($hSocket, $sConnectionEvent)
	Return _storageS_Append($hSocket & 'SYNC', $sConnectionEvent)
EndFunc

Func __netcode_SyncDel($hSocket, $sConnectionEvent)
	if $sConnectionEvent = "ALL" Then
		Return _storageS_Overwrite($hSocket & 'SYNC', "")
	Else
		Return _storageS_Overwrite($hSocket & 'SYNC', StringReplace(_storageS_Read($hSocket & 'SYNC'), $sConnectionEvent, ''))
	EndIf
EndFunc

Func __netcode_SyncCheck($hSocket)
	$sStorage = _storageS_Read($hSocket & 'SYNC')
	if Not $sStorage Then SetError(1, 0, False)

	if $sStorage = "" Then Return True
	Return SetError(2, $hSocket, False)
EndFunc

Func __netcode_SyncString($sConnectionEvent, $Set)
	If $Set Then
		$__net_sSync_SyncOnEachSocket &= $sConnectionEvent
	Else
		$__net_sSync_SyncOnEachSocket = StringReplace($__net_sSync_SyncOnEachSocket, $sConnectionEvent, '')
	EndIf
EndFunc

; big brain
Func __netcode_Bool($var)
	if $var = "True" Then Return True
	if $var = "False" Then Return False
	if $var = True Then Return True
	if $var = False Then Return False
	Return SetError(1) ; if not a bool
EndFunc

; socket and option being ignored here
; but be usefull later when we bind certain options to a socket
Func __netcode_Sync_MaxRecvLength($hSocket, $sOption, $sData)
	_netcode_SetOption("SetMaxPackageSize", $sData)
EndFunc

Func __netcode_Sync_PacketValidation($hSocket, $sOption, $sData)
	_netcode_SetOption("SetPacketValidation", $sData)
EndFunc

Func __netcode_Sync_PacketSafety($hSocket, $sOption, $sData)
	_netcode_SetOption("SetPacketSafety", $sData)
EndFunc

Func __netcode_Sync_FloodPrevention($hSocket, $sOption, $sData)
	_netcode_SetOption("SetFloodPrevention", $sData)
EndFunc

Func __netcode_Sync_TCPRecvDefault($hSocket, $sOption, $sData)
	_netcode_SetOption("SetTCPRecvDefault", $sData)
EndFunc

Func __netcode_Sync_EncryptionStatus($hSocket, $sOption, $sData)
	if Not $sData Then Return

	if $__net_bOption_EncryptionStatus Then Return ; already activated

	if $__net_sOption_SetPasswordForEncryption <> "" Then
		_netcode_SetOption("EnableEncryption", $__net_sOption_SetPasswordForEncryption)
		$__net_bInt_EnabledEncryptionThroughSync = True
	Else
		__netcode_Debug("Server has Encryption enabled. But Client has no Password Set.")
	EndIf
EndFunc

Func __netcode_SetNetworkSyncAuto($bEnable)
	_netcode_SetNetworkSync('MaxPackageSize', $bEnable)
	_netcode_SetNetworkSync('PacketValidation', $bEnable)
	_netcode_SetNetworkSync('PacketSafety', $bEnable)
	_netcode_SetNetworkSync('FloodPrevention', $bEnable)
	_netcode_SetNetworkSync('TCPRecvDefault', $bEnable)
	_netcode_SetNetworkSync('EncryptionStatus', $bEnable)
EndFunc

; returns Ping
Func __netcode_SetTCPTimeout_ByIP($sIP, $nAddOptional = 0)
	Local $nPing = __netcode_EvalPing($sIP)
	if $nPing = 0 Then Return SetError(@error, @extended, 0)

	Opt("TCPTimeout", $nPing + $nAddOptional)
	Return $nPing
EndFunc

; returns Ping
; ment to be used at default. *_ByIP should just be used when there is no socket yet.
; to be able to use this the ping has to be bind to the socket first
; todo - we could SocketToIP and bind it ourself to create redundancy and less error
; checking for the user.
Func __netcode_SetTCPTimeout_BySocket($hSocket)
	Local Static $nLastPing = 0
	Local $nPing = _storageS_Read($hSocket & '_TCPTimeout_PING')
	if $nPing = "" Then Return SetError(1, 0, 0) ; not yet Bind

	if $nPing > $__net_nInt_PingReEvalIfHigherThen Then
		Local $nPingEval = __netcode_ReEvalTCPTimeout_BySocket($hSocket)
		if $nPingEval > 0 Then $nPing = $nPingEval
;~ 		Return SetError(@error, @extended, $nPing)
	EndIf

	if $nLastPing = $nPing Then Return $nPing ; im not quite sure how well setting autoitoption often works
	$nLastPing = $nPing

	Opt("TCPTimeout", $nPing)
	Return $nPing
EndFunc

Func __netcode_BindTCPTimeout_IpAndPingToSocket($sIP, $nPing, $hSocket)
	if $nPing = 0 Then Return SetError(1, 0, 0)

	_storageS_Overwrite($hSocket & '_TCPTimeout_IP', $sIP)
	_storageS_Overwrite($hSocket & '_TCPTimeout_PING', $nPing)

	Return True
EndFunc

; call this to remove the data
Func __netcode_ResetTCPTimeout_BySocket($hSocket)
	_storageS_Overwrite($hSocket & '_TCPTimeout_IP', '')
	_storageS_Overwrite($hSocket & '_TCPTimeout_PING', '')
EndFunc

Func __netcode_ReEvalTCPTimeout_BySocket($hSocket)
	Local $sIP = _storageS_Read($hSocket & '_TCPTimeout_IP')
;~ 	__netcode_ResetTCPTimeout_BySocket($hSocket)

	Local $nPing = __netcode_EvalPing($sIP)
	if $nPing = 0 Then Return SetError(@error, @extended, 0)

	_storageS_Overwrite($hSocket & '_TCPTimeout_PING', $nPing)

	Return $nPing
EndFunc

Func __netcode_TCPTimeout_Default()
	Opt("TCPTimeout", $__net_nInt_PingDefault)
EndFunc

Func __netcode_EvalPing($sIP)
	Local $nPing = Ping($sIP, $__net_nInt_PingUnusual)
	if $nPing = 0 Then Return SetError(@error, @extended, 0)

	if $nPing <= 5 Then Return $__net_nInt_PingDefault ; localhost or same network $__net_nInt_PingDefault is minimum

	if $nPing <= $__net_nInt_PingUsual Then Return $__net_nInt_PingUsual + $__net_nInt_PingDynamic
	Return $nPing + $__net_nInt_PingDynamic
EndFunc

; this is my simplified form of CryptoNG v.1.7.0 by TheXman from https://www.autoitscript.com/forum/topic/201002-cryptong-udf-cryptography-api-next-gen
; it doesnt do much of error checking and stuff that the UDF normally does. So its really just made to be used internaly.
; why this cut? the UDF is about ~200 KB in size. thats to much and i had to fasten it up for this netcode.
; In case you code your own encryption: the Socket is optional. In case you have different encryptions or passwords for each socket then there you go.
; the socket will 0 when no socket is being given for example when you enable encryption it will automatically test it.
Func __netcode_Encrypt($sData, $sPW, $hOptionalSocket)

	if IsString($sData) Then
		$sData = StringToBinary($sData, 4)
	Else
		$sData = Binary($sData)
	EndIf

;~ 	if $__net_hInt_ntdll <> -1 Then $sData = __netcode_lzntcompress($sData)

	Local $tDataBuffer = DllStructCreate(StringFormat('byte data[%i]', BinaryLen($sData)))
	DllStructSetData($tDataBuffer, 1, $sData)

	Local $tIVBuffer = DllStructCreate(StringFormat('byte data[%i]', BinaryLen($__net_sInt_CryptionIV)))
	DllStructSetData($tIVBuffer, 1, $__net_sInt_CryptionIV)

	; get size of encrypted output
	Local $arEncrypt = DllCall($__net_hInt_bcryptdll, "int", "BCryptEncrypt", _
						   "handle",   $sPW, _
						   "struct*",  $tDataBuffer, _
						   "ulong",    DllStructGetSize($tDataBuffer), _
						   "ptr",      Null, _
						   "struct*",  $tIVBuffer, _
						   "ulong",    DllStructGetSize($tIVBuffer), _
						   "ptr",      Null, _
						   "ulong*",   0, _
						   "ulong*",   Null, _
						   "ulong",    0x00000001 _
						   )

	Local $tOutputBuffer = DllStructCreate(StringFormat('byte data[%i]', $arEncrypt[9]))

	Local $arEncrypt = DllCall($__net_hInt_bcryptdll, "int", "BCryptEncrypt", _
						   "handle",   $sPW, _
						   "struct*",  $tDataBuffer, _
						   "ulong",    DllStructGetSize($tDataBuffer), _
						   "ptr",      Null, _
						   "struct*",  $tIVBuffer, _
						   "ulong",    DllStructGetSize($tIVBuffer), _
						   "struct*",  $tOutputBuffer, _
						   "ulong",    DllStructGetSize($tOutputBuffer), _
						   "ulong*",   Null, _
						   "ulong",    0x00000001 _
						   )


	Return DllStructGetData($tOutputBuffer, 1)

EndFunc

Func __netcode_Decrypt($sData, $sPW, $hOptionalSocket)
	if IsString($sData) Then
		$sData = StringToBinary($sData, 4)
	Else
		$sData = Binary($sData)
	EndIf

	Local $tDataBuffer = DllStructCreate(StringFormat('byte data[%i]', BinaryLen($sData)))
	DllStructSetData($tDataBuffer, 1, $sData)

	Local $tIVBuffer = DllStructCreate(StringFormat('byte data[%i]', BinaryLen($__net_sInt_CryptionIV)))
	DllStructSetData($tIVBuffer, 1, $__net_sInt_CryptionIV)

	; get size of encrypted output
	Local $arDecrypt = DllCall($__net_hInt_bcryptdll, "int", "BCryptDecrypt", _
						   "handle",   $sPW, _
						   "struct*",  $tDataBuffer, _
						   "ulong",    DllStructGetSize($tDataBuffer), _
						   "ptr",      Null, _
						   "struct*",  $tIVBuffer, _
						   "ulong",    DllStructGetSize($tIVBuffer), _
						   "ptr",      Null, _
						   "ulong*",   0, _
						   "ulong*",   Null, _
						   "ulong",    0x00000001 _
						   )

	Local $tOutputBuffer = DllStructCreate(StringFormat('byte data[%i]', $arDecrypt[9]))

	Local $arDecrypt = DllCall($__net_hInt_bcryptdll, "int", "BCryptDecrypt", _
						   "handle",   $sPW, _
						   "struct*",  $tDataBuffer, _
						   "ulong",    DllStructGetSize($tDataBuffer), _
						   "ptr",      Null, _
						   "struct*",  $tIVBuffer, _
						   "ulong",    DllStructGetSize($tIVBuffer), _
						   "struct*",  $tOutputBuffer, _
						   "ulong",    DllStructGetSize($tOutputBuffer), _
						   "ulong*",   Null, _
						   "ulong",    0x00000001 _
						   )
;~ 	ConsoleWrite(StringLen($sData) & @TAB & @TAB & StringLen(DllStructGetData($tOutputBuffer, 1)) & @CRLF)

	$sData = BinaryMid(DllStructGetData($tOutputBuffer, 1), 1, $arDecrypt[9])
;~ 	if $__net_hInt_ntdll <> -1 Then $sData = __netcode_lzntdecompress($sData)

	Return $sData

EndFunc

Func __netcode_DeriveKey($vKey, $sSalt)
	__netcode_CryptStartup()

	; create PBKDF2
	Local $arOpenProvider = DllCall($__net_hInt_bcryptdll, 'int', 'BCryptOpenAlgorithmProvider', 'handle*', 0, 'wstr', 'SHA1', 'wstr', $__net_hInt_hAlgorithmProvider, 'ulong', 0x00000008)
	Local $hHashProvider = $arOpenProvider[1]

	Local $sPassword = StringToBinary($vKey, 4)
	Local $tPasswordBuffer = DllStructCreate(StringFormat('byte data[%i]', BinaryLen($sPassword)))
	DllStructSetData($tPasswordBuffer, 1, $sPassword)

	if IsString($sSalt) Then
		Local $vSalt = StringToBinary($sSalt, 4)
	Else
		Local $vSalt = Binary($sSalt)
	EndIf
	Local $tSaltBuffer = DllStructCreate(StringFormat('byte data[%i]', BinaryLen($vSalt)))
	DllStructSetData($tSaltBuffer, 1, $sSalt)

	Local $tKeyBuffer = DllStructCreate(StringFormat('byte data[%i]', 128 / 8))

	Local $arDeriveKey = DllCall($__net_hInt_bcryptdll, "int", "BCryptDeriveKeyPBKDF2", _
                       "handle",   $hHashProvider, _
                       "struct*",  $tPasswordBuffer, _
                       "ulong",    DllStructGetSize($tPasswordBuffer), _
                       "struct*",  $tSaltBuffer, _
                       "ulong",    DllStructGetSize($tSaltBuffer), _
                       "uint64",   $__net_nInt_CryptionIterations, _
                       "struct*",  $tKeyBuffer, _
                       "ulong",    DllStructGetSize($tKeyBuffer), _
                       "ulong",    0 _
                       )

	Local $vPBKDF2  = DllStructGetData($tKeyBuffer, 1)

	__netcode_CryptCloseProvider($hHashProvider)

	; generate symmetric key
	if IsString($vPBKDF2) Then
		$vPBKDF2 = StringToBinary($vPBKDF2, 4)
	Else
		$vPBKDF2 = Binary($vPBKDF2)
	EndIf

	Local $tKeyBuffer = DllStructCreate(StringFormat('byte data[%i]', BinaryLen($vPBKDF2)))
	DllStructSetData($tKeyBuffer, 1, $vPBKDF2)

	Local $arSymmetricKey = DllCall($__net_hInt_bcryptdll, "int", "BCryptGenerateSymmetricKey", _
                       "handle",   $__net_hInt_hAlgorithmProvider, _
                       "handle*",  Null, _
                       "ptr",      Null, _
                       "ulong",    0, _
                       "struct*",  $tKeyBuffer, _
                       "ulong",    DllStructGetSize($tKeyBuffer), _
                       "ulong",    0 _
                       )

	Local $hEncryptionKey = $arSymmetricKey[2]

	Return $hEncryptionKey

EndFunc

Func __netcode_DestroyKey($hDerive)
	; todo
EndFunc

Func __netcode_CryptCloseProvider($hHandle)
	DllCall($__net_hInt_bcryptdll, "int", "BCryptCloseAlgorithmProvider", "handle",  $hHandle, "ulong", 0)
EndFunc

Func __netcode_CryptStartup()
	if $__net_hInt_bcryptdll = -1 Then
		$__net_hInt_bcryptdll = DllOpen('bcrypt.dll')
		if $__net_hInt_bcryptdll = -1 Then Return SetError(1, 0, False)
	EndIf

	if $__net_hInt_hAlgorithmProvider = -1 Then
		$arCall = DllCall($__net_hInt_bcryptdll, "int", "BCryptOpenAlgorithmProvider", _
                       "handle*", 0, _
                       "wstr",    $__net_sInt_CryptionAlgorithm, _
                       "wstr",    $__net_sInt_CryptionProvider, _
                       "ulong",   0 _
                       )
		$__net_hInt_hAlgorithmProvider = $arCall[1]

		; Set block chaining mode
		$arCheck = DllCall($__net_hInt_bcryptdll, "int", "BCryptSetProperty", _
							"handle",   $__net_hInt_hAlgorithmProvider, _
							"wstr",     'ChainingMode', _
							"wstr",     'ChainingModeCBC', _
							"ulong",    BinaryLen('ChainingModeCBC'), _
							"ulong",    0 _
							)
	EndIf

	if $__net_hInt_ntdll = -1 Then
		$__net_hInt_ntdll = DllOpen('ntdll.dll')
	EndIf

	Return True
EndFunc

Func __netcode_CryptShutdown()
	if $__net_hInt_hAlgorithmProvider <> -1 Then
		__netcode_CryptCloseProvider($__net_hInt_hAlgorithmProvider)
		$__net_hInt_hAlgorithmProvider = -1
	EndIf

	if $__net_hInt_bcryptdll <> -1 Then
		DllClose($__net_hInt_bcryptdll)
		$__net_hInt_bcryptdll = -1
	EndIf

	if $__net_hInt_ntdll <> -1 Then
		DllClose($__net_hInt_ntdll)
		$__net_hInt_ntdll = -1
	EndIf
EndFunc

; compression is part of the cryption mode 'netcode'
Func __netcode_lzntdecompress($bbinary)
	Local $tinput = DllStructCreate("byte[" & BinaryLen($bbinary) & "]")
	DllStructSetData($tinput, 1, $bbinary)

	Local $tbuffer = DllStructCreate("byte[" & 16 * DllStructGetSize($tinput) & "]")

	Local $a_call = DllCall($__net_hInt_ntdll, "int", "RtlDecompressBuffer", "ushort", 2, "ptr", DllStructGetPtr($tbuffer), "dword", DllStructGetSize($tbuffer), "ptr", DllStructGetPtr($tinput), "dword", DllStructGetSize($tinput), "dword*", 0)
;~ 	if @ScriptName = '1server.au3' Then _ArrayDisplay($a_call)
	If @error OR $a_call[0] Then
		Return SetError(1, 0, "")
	EndIf

	Local $toutput = DllStructCreate("byte[" & $a_call[6] & "]", DllStructGetPtr($tbuffer))
	Return SetError(0, 0, DllStructGetData($toutput, 1))
EndFunc

Func __netcode_lzntcompress($vinput, $icompressionformatandengine = 2)
	If NOT ($icompressionformatandengine = 258) Then
		$icompressionformatandengine = 2
	EndIf

	Local $tinput = DllStructCreate("byte[" & BinaryLen($vinput) & "]")
	DllStructSetData($tinput, 1, $vinput)

	Local $a_call = DllCall($__net_hInt_ntdll, "int", "RtlGetCompressionWorkSpaceSize", "ushort", $icompressionformatandengine, "dword*", 0, "dword*", 0)
	If @error OR $a_call[0] Then
		Return SetError(1, 0, "")
	EndIf

	Local $tworkspace = DllStructCreate("byte[" & $a_call[2] & "]")
	Local $tbuffer = DllStructCreate("byte[" & 16 * DllStructGetSize($tinput) & "]")
	Local $a_call = DllCall($__net_hInt_ntdll, "int", "RtlCompressBuffer", "ushort", $icompressionformatandengine, "ptr", DllStructGetPtr($tinput), "dword", DllStructGetSize($tinput), "ptr", DllStructGetPtr($tbuffer), "dword", DllStructGetSize($tbuffer), "dword", 4096, "dword*", 0, "ptr", DllStructGetPtr($tworkspace))

	If @error OR $a_call[0] Then
		Return SetError(2, 0, "")
	EndIf

	Local $toutput = DllStructCreate("byte[" & $a_call[7] & "]", DllStructGetPtr($tbuffer))
	Return SetError(0, 0, DllStructGetData($toutput, 1))
EndFunc

; only timeouts are influenced by that. A Difference of 500ms isnt severe but indicates that something is wrong.
; Just test your networking code a bit if that is the case. At all there arent much timeouts placed.
Func __netcode_CheckProcessorCompatibilityForTimerTiff()
	__netcode_Debug("Checking Processor Compatibility for TimerDiff")
	Local $nCurrSec = @SEC
	Local $hTimer = TimerInit() ; pre declaration
	Local $nDifference = 0
	Local $nAcceptableUpDifference = 500
	Local $nAcceptableDoDifference = -500

	While $nCurrSec = @SEC
	WEnd

	$nCurrSec = @SEC
	$hTimer = TimerInit()

	While $nCurrSec = @SEC
	WEnd

	$nDifference = TimerDiff($hTimer) - 1000

	if $nDifference > $nAcceptableUpDifference Or $nDifference < $nAcceptableDoDifference Then
		ConsoleWrite("! _netcode UDF encountered an Error." & @CRLF)
		ConsoleWrite("! This processor seems to have issues with the TimerDiff function. See the AutoIt Helpfile." & @CRLF)
		ConsoleWrite("! Or is the CPU just on heavy load?" & @CRLF)
		ConsoleWrite("! We Waited for one Second to pass, but the Timer calculated: " & $nDifference + 1000 & ' ms' & @CRLF)
		ConsoleWrite("! Use _netcode.au3 UDF with caution." & @CRLF)
		ConsoleWrite("! You can deactivate this Notice by commenting __netcode_CheckProcessorCompatibilityForTimerTiff() in this UDF." & @CRLF)
	EndIf
	__netcode_Debug("Test done")
EndFunc


#cs
	_storageS_Overwrite($hRelaySocket & '_RelayIsProxy', True)
	_storageS_Overwrite($hRelaySocket & '_RelayProxyCallbackConnect', $sCallbackConnect)
;~ 	_storageS_Overwrite($hRelaySocket & '_RelayProxyCallbackConnectTo', $sCallbackConnectTo)
	_storageS_Overwrite($hRelaySocket & '_RelayProxyIPListConnectTo', $vIPListConnectTo)
	_storageS_Overwrite($hRelaySocket & '_RelayProxyIPListIsBlacklist', $bIPListIsBlacklist)
#ce
; WIP - fasten it up
; bugs _
; - if the URL is a IP it cannot TCPNameToIP that
; - Opera seems to have some weird issue where we cannot connect to ANY given URL
; - every Request seems to have a HOST value. Should be faster to read that for the url
; - if the HTTP (not S) request goes to another port then 80 then it will fail, because we manually set port 80.
Func __netcode_HttpProxyFromClient($hSocket, $sSocketIP)
	Local $sPackage = ''
	Local $sTCPRecv = ''
	Do
		$sTCPRecv = __Io_TCPRecv($hSocket, 4096, 1)
		if @extended = 1 Then Return False
		$sPackage &= BinaryToString($sTCPRecv)
	Until $sTCPRecv = ''

	if $sPackage = '' Then Return Null

	Local $arContent = StringSplit($sPackage, @CRLF, 1 + 2)

	if StringLeft($arContent[0], 3) = "GET" Then
		$sIP = StringTrimLeft($arContent[0], 4)
		$sIP = StringLeft($sIP, StringInStr($sIP, ' '))
		if StringLeft($sIP, 7) = 'http://' Then $sIP = StringTrimLeft($sIP, 7)
		if StringLeft($sIP, 4) = 'www.' Then $sIP = StringTrimLeft($sIP, 4)

		$sIP = StringLeft($sIP, StringInStr($sIP, '/') - 1)

		Local $arIPAndPort[3]
		$arIPAndPort[0] = TCPNameToIP($sIP)
		$arIPAndPort[1] = 80
		$arIPAndPort[2] = $sPackage

	ElseIf StringLeft($arContent[0], 4) = "POST" Then
		$sIP = StringTrimLeft($arContent[0], 5)
		$sIP = StringLeft($sIP, StringInStr($sIP, ' '))
		if StringLeft($sIP, 7) = 'http://' Then $sIP = StringTrimLeft($sIP, 7)
		if StringLeft($sIP, 4) = 'www.' Then $sIP = StringTrimLeft($sIP, 4)

		$sIP = StringLeft($sIP, StringInStr($sIP, '/') - 1)

		Local $arIPAndPort[3]
		$arIPAndPort[0] = TCPNameToIP($sIP)
		$arIPAndPort[1] = 80
		$arIPAndPort[2] = $sPackage

	ElseIf StringLeft($arContent[0], 7) = "CONNECT" Then
		$sIPAndPort = StringTrimLeft($arContent[0], 8)
		$sIPAndPort = StringLeft($sIPAndPort, StringInStr($sIPAndPort, ' ')) ; URL dont have any white spaces
		$arIPAndPort = StringSplit($sIPAndPort, ':', 1 + 2)
		$arIPAndPort[0] = TCPNameToIP($arIPAndPort[0])
		$arIPAndPort[1] = Number($arIPAndPort[1])

		ReDim $arIPAndPort[3]

		__Io_TCPSend($hSocket, $sPackage)
;~ 		$arIPAndPort[2] = $sPackage

	Else
		_ArrayDisplay($arContent, "DEBUG Unknown HTTP Request")
		Return False
	EndIf

	; debug
	if $arIPAndPort[1] = 80 And $arIPAndPort[0] = '' Then
		ClipPut($sPackage)
		_ArrayDisplay($arContent, "DEBUG Http couldnt resolve IP")
		Return False
	EndIf

;~ 	_ArrayDisplay($arIPAndPort)

	__netcode_Debug("Relay HTTP Proxy Connecting to: " & $arIPAndPort[0] & ':' & $arIPAndPort[1])
;~ 	__netcode_Debug($sPackage)

	Return $arIPAndPort
EndFunc

Func __netcode_RelayCheckMiddleman($hRelaySocket, $hNewSocket, $sSocketIP)
	if Not _storageS_Read($hRelaySocket & '_RelayIsProxy') Then Return False

	Return Call(_storageS_Read($hRelaySocket & '_RelayProxyCallbackConnect'), $hNewSocket, $sSocketIP)
EndFunc

; todo _
; - recode TCPConnect. Make the sockets ASYNC to improve speed.
; - recode the function and split non interfeered relays from middlemaned relays to improve speed.
; - maybe change the display of "Relaying from @ XXX to XXX" into displaying the IP's with the Sockets in brackets
; - also maybe include the counting of send bytes.
Func __netcode_RelayLoop($bLoopDontStop = False)
	Local $nArSize = UBound($__net_arInt_RelaySockets)
	if $nArSize = 0 Then Return SetError(1, 0, False) ; no relays set

	Do
		$nTransferedPacketsThisLoop = 0

		; check for ClientsOnHold set by Proxy
		For $i = 0 To $nArSize - 1
			$arClientSockets = _storageS_Read($__net_arInt_RelaySockets[$i] & '_RelayClientsOnHold')
			if Not IsArray($arClientSockets) Then ContinueLoop

			For $iS = 0 To UBound($arClientSockets) - 1
				; call Middleman
				$sSocketIP = __Io_SocketToIP($arClientSockets[$iS][0])
				$arMiddleman = __netcode_RelayCheckMiddleman($__net_arInt_RelaySockets[$i], $arClientSockets[$iS][0], $sSocketIP)

				; querry the response from the middleman
				; if the middleman could retrieve a IP and PORT to connect to
				if IsArray($arMiddleman) Then
					$sConnectToIP = $arMiddleman[0]
					$sConnectToPort = $arMiddleman[1]

				; if the middleman couldnt retrieve anything yet
				; check the timeout then and diconnect if timeout
				ElseIf $arMiddleman = Null Then
					if TimerDiff($arClientSockets[$iS][1]) > 20000 Then
						TCPCloseSocket($arClientSockets[$iS][0])
						__netcode_RelayRemoveClientOnHold($__net_arInt_RelaySockets[$i], $arClientSockets[$iS][0])
						__netcode_Debug("Relay @ " & $__net_arInt_RelaySockets[$i] & " Socket didnt answer in time - Disconnected new Connection")
					EndIf
					ContinueLoop

				; if the middleman denies the socket or socket is closed
				Elseif $arMiddleman = False Then
					TCPCloseSocket($arClientSockets[$iS][0])
					__netcode_RelayRemoveClientOnHold($__net_arInt_RelaySockets[$i], $arClientSockets[$iS][0])
					__netcode_Debug("Relay @ " & $__net_arInt_RelaySockets[$i] & " Proxy denies Socket or Socket died - Disconnected new Connection")
					ContinueLoop
				EndIf

				; try to connect to the Destination
				$bIsUDP = False
				$hSocketTo = TCPConnect($sConnectToIP, $sConnectToPort)
				if $hSocketTo = -1 Then
					$hSocketTo = UDPOpen($sConnectToIP, $sConnectToPort)
					if $hSocketTo[0] = 0 Then
						TCPCloseSocket($arClientSockets[$iS][0])
						__netcode_RelayRemoveClientOnHold($__net_arInt_RelaySockets[$i], $arClientSockets[$iS][0])
						__netcode_Debug("Relay @ " & $__net_arInt_RelaySockets[$i] & " " & $sConnectToIP & ':' & $sConnectToPort & " unreachable - Disconnected new Connection")
						ContinueLoop
					EndIf

					$bIsUDP = True
					__netcode_Debug("Relay @ " & $__net_arInt_RelaySockets[$i] & " new Connection @ " & $arClientSockets[$iS][0] & " bind to @ " & $hSocketTo[1] & " (UDP)")
				Else
					__netcode_Debug("Relay @ " & $__net_arInt_RelaySockets[$i] & " new Connection @ " & $arClientSockets[$iS][0] & " bind to @ " & $hSocketTo)
				EndIf

				; check if Destination is white or black listed
				; ~ todo

				; if the middleman wants to send something to the destination
				if UBound($arMiddleman) = 3 Then
					if Not $bIsUDP Then
						__Io_TCPSend($hSocketTo, $arMiddleman[2])
					Else
						UDPSend($hSocketTo, $arMiddleman[2])
					EndIf
				EndIf


				; remove from OnHold array and bin the Sockets to the relay socket
				__netcode_RelayAddClient($__net_arInt_RelaySockets[$i], $arClientSockets[$iS][0], $hSocketTo, $sSocketIP, $bIsUDP)
				__netcode_RelayRemoveClientOnHold($__net_arInt_RelaySockets[$i], $arClientSockets[$iS][0])
			Next

		Next


		; check for new connections. One per RelaySocket for each loop to prevent TCPConnect spam attacks.
		For $i = 0 To $nArSize - 1
			$hSocket = __Io_TCPAccept($__net_arInt_RelaySockets[$i])
			if $hSocket = -1 Then ContinueLoop

			$sSocketIP = __Io_SocketToIP($hSocket)

			__netcode_Debug("Relay @ " & $__net_arInt_RelaySockets[$i] & " new Connection @ " & $hSocket & " from " & $sSocketIP)

			; check if ip white / black listed. We could Switch @error and Display better message. Is there Demand for that?
			If Not __netcode_RelayIPListCheck($__net_arInt_RelaySockets[$i], $sSocketIP) Then
				TCPCloseSocket($hSocket)
				__netcode_Debug("Relay @ " & $__net_arInt_RelaySockets[$i] & " IP is not Allowed - Disconnected new Connection")
				ContinueLoop
			EndIf

			; check if this relay is a proxy
			$arMiddleman = __netcode_RelayCheckMiddleman($__net_arInt_RelaySockets[$i], $hSocket, $sSocketIP)

			; querry the Result
			; if the middleman returned destination IP and PORT
			if IsArray($arMiddleman) Then
				$sConnectToIP = $arMiddleman[0]
				$sConnectToPort = $arMiddleman[1]

			; if the middleman couldnt resolve anything yet.
			; then check if we timeouted and disconnect if the case.
			Elseif $arMiddleman = Null Then
				__netcode_RelayAddClientOnHold($__net_arInt_RelaySockets[$i], $hSocket)
;~ 				__netcode_Debug("Relay @ " & $__net_arInt_RelaySockets[$i] & " Socket set on Hold
				ContinueLoop

			; in the case the Relay Sockets has no middleman or
			; ~ todo ~ the middleman denies the socket.
			Else
				$sConnectToIP = _storageS_Read($__net_arInt_RelaySockets[$i] & '_RelayToIP')
				$sConnectToPort = _storageS_Read($__net_arInt_RelaySockets[$i] & '_RelayToPort')
			EndIf

			; connect to Relay Destination
			$bIsUDP = False
;~ 			$hSocketTo = __Io_TCPConnect($sConnectToIP, $sConnectToPort)
			$hSocketTo = TCPConnect($sConnectToIP, $sConnectToPort)
			if $hSocketTo = -1 Then
				$hSocketTo = UDPOpen($sConnectToIP, $sConnectToPort)
				if $hSocketTo[0] = 0 Then
;~ 					MsgBox(0, $sConnectToIP, $sConnectToPort) ; for debug
					TCPCloseSocket($hSocket)
					__netcode_Debug("Relay @ " & $__net_arInt_RelaySockets[$i] & " RelayToServer unreachable - Disconnected new Connection")
					ContinueLoop
				EndIf

				$bIsUDP = True
				__netcode_Debug("Relay @ " & $__net_arInt_RelaySockets[$i] & " new Connection @ " & $hSocket & " bind to @ " & $hSocketTo[1] & " (UDP)")
			Else
				__netcode_Debug("Relay @ " & $__net_arInt_RelaySockets[$i] & " new Connection @ " & $hSocket & " bind to @ " & $hSocketTo)
			EndIf

			; that the Ubound() func fails when its not an array isnt an issue at all
			if UBound($arMiddleman) = 3 Then
				If Not $bIsUDP Then
					__Io_TCPSend($hSocketTo, $arMiddleman[2])
				Else
					UDPSend($hSocketTo, $arMiddleman[2])
				EndIf
			EndIf

			__netcode_RelayAddClient($__net_arInt_RelaySockets[$i], $hSocket, $hSocketTo, $sSocketIP, $bIsUDP)
		Next

		; querry each relay socket including those with a middleman
		For $i = 0 To $nArSize - 1
			$arClientSockets = _storageS_Read($__net_arInt_RelaySockets[$i] & '_RelayClients')
			if Not IsArray($arClientSockets) Then ContinueLoop

			; querry each client of the current relay socket
			For $iS = 0 To UBound($arClientSockets) - 1

				; Receive from client and relay to destination
				$nTransferedPacketsThisLoop += __netcode_RelayPackage($arClientSockets[$iS][0], $arClientSockets[$iS][1], $arClientSockets[$iS][2], True)
				; if either the client or the destination disconnected
				if @error Then
					__netcode_RelayRemoveClient($__net_arInt_RelaySockets[$i], $arClientSockets[$iS][0])
					ContinueLoop
				EndIf

				; Receive from destination and relay to client
				$nTransferedPacketsThisLoop += __netcode_RelayPackage($arClientSockets[$iS][1], $arClientSockets[$iS][0], $arClientSockets[$iS][2])
				; -"-
				if @error Then
					__netcode_RelayRemoveClient($__net_arInt_RelaySockets[$i], $arClientSockets[$iS][0])
					ContinueLoop
				EndIf
			Next
		Next

		; we wont sleep if we actually transmitting packets right now.
		; this should change because the next round could result in one or more transfers.
		; just because the current didnt result in none doenst mean the next will not too.
		; so we basically create lag here. I have to think about some rules.
		if $bLoopDontStop And $nTransferedPacketsThisLoop = 0 Then Sleep(10)
	Until Not $bLoopDontStop

	Return SetError(0, $nTransferedPacketsThisLoop, True)
EndFunc

; False always means that the IP is not allowed.
; Else True.
Func __netcode_RelayIPListCheck($hRelaySocket, $sIP)
	Local $sIPList = _storageS_Read($hRelaySocket & '_RelayIPList')
	if $sIPList = False Then Return True

	Local $bIPListIsBlacklist = _storageS_Read($hRelaySocket & '_RelayIPListMode')
	if $bIPListIsBlacklist Then
		If StringInStr($sIPList, $sIP) Then Return SetError(1, 0, False)
		Return SetError(2, 0, True)
	Else
		if StringInStr($sIPList, $sIP) Then Return SetError(3, 0, True)
		Return SetError(3, 0, False)
	EndIf
EndFunc

Func __netcode_RelayAddClientOnHold($hRelaySocket, $hSocket)
	Local $arReadClients = _storageS_Read($hRelaySocket & '_RelayClientsOnHold')
	Local $arClients[0][3]
	if IsArray($arReadClients) Then $arClients = $arReadClients

	Local $nArSize = UBound($arClients)
	ReDim $arClients[$nArSize + 1][2]

	$arClients[$nArSize][0] = $hSocket
	$arClients[$nArSize][1] = TimerInit()

	_storageS_Overwrite($hRelaySocket & '_RelayClientsOnHold', $arClients)
EndFunc

Func __netcode_RelayRemoveClientOnHold($hRelaySocket, $hSocket)
	Local $arReadClients = _storageS_Read($hRelaySocket & '_RelayClientsOnHold')
	If Not IsArray($arReadClients) Then Return SetError(1, 0, False) ; this relay socket has no clients

	Local $nArSize = UBound($arReadClients)
	Local $nIndex = -1

	For $i = 0 To $nArSize - 1
		if $arReadClients[$i][0] = $hSocket Then
			$nIndex = $i
			ExitLoop
		EndIf
	Next

	if $nIndex = -1 Then Return SetError(2, 0, False) ; this Client socket is not bind to this Relay Socket

	if $nArSize > 1 Then
		; overwrite the $nIndex with the last Index. No time consuming sorting here
		$arReadClients[$nIndex][0] = $arReadClients[$nArSize - 1][0]
		$arReadClients[$nIndex][1] = $arReadClients[$nArSize - 1][1]
		ReDim $arReadClients[$nArSize - 1][3]
	Else
		$arReadClients = False ; on purpose to check less in the Loop.
	EndIf

	_storageS_Overwrite($hRelaySocket & '_RelayClientsOnHold', $arReadClients)
EndFunc

Func __netcode_RelayAddClient($hRelaySocket, $hSocket, $hSocketTo, $sSocketIP, $bSocketToIsUDP = False)
	Local $arReadClients = _storageS_Read($hRelaySocket & '_RelayClients')
	Local $arClients[0][4]
	if IsArray($arReadClients) Then $arClients = $arReadClients

	Local $nArSize = UBound($arClients)
	ReDim $arClients[$nArSize + 1][4]

	$arClients[$nArSize][0] = $hSocket
	if Not $bSocketToIsUDP Then
		$arClients[$nArSize][1] = $hSocketTo
	Else
		$arClients[$nArSize][1] = __Io_CheckParamAndSerialize($hSocketTo) ; TEMP
	EndIf
	$arClients[$nArSize][2] = $bSocketToIsUDP
	$arClients[$nArSize][3] = $sSocketIP

	_storageS_Overwrite($hRelaySocket & '_RelayClients', $arClients)
EndFunc

; tidy _storageS vars or the mem will fillup over time
Func __netcode_RelayRemoveClient($hRelaySocket, $hSocket)
	Local $arReadClients = _storageS_Read($hRelaySocket & '_RelayClients')
	If Not IsArray($arReadClients) Then Return SetError(1, 0, False) ; this relay socket has no clients

	Local $nArSize = UBound($arReadClients)
	Local $nIndex = -1

	For $i = 0 To $nArSize - 1
		if $arReadClients[$i][0] = $hSocket Then
			$nIndex = $i
			ExitLoop
		EndIf
	Next

	if $nIndex = -1 Then Return SetError(2, 0, False) ; this Client socket is not bind to this Relay Socket

	if $nArSize > 1 Then
		; overwrite the $nIndex with the last Index. No time consuming sorting here
		$arReadClients[$nIndex][0] = $arReadClients[$nArSize - 1][0]
		$arReadClients[$nIndex][1] = $arReadClients[$nArSize - 1][1]
		$arReadClients[$nIndex][2] = $arReadClients[$nArSize - 1][2]
		$arReadClients[$nIndex][3] = $arReadClients[$nArSize - 1][3]
		ReDim $arReadClients[$nArSize - 1][4]
	Else
		$arReadClients = False ; on purpose to check less in the Loop.
	EndIf

	_storageS_Overwrite($hRelaySocket & '_RelayClients', $arReadClients)
EndFunc

Func __netcode_RelayPackage($hFromSocket, $hToSocket, $bIsUDP, $bIsClient = False)
	Local $nUDP = Null ; if no UDP

	If $bIsUDP And $bIsClient Then
		$hToSocket = __Io_CheckParamAndUnserialize($hToSocket) ; TEMP
		$nUDP = 2 ; if To is UDP
	Elseif $bIsUDP And Not $bIsClient Then
		Return 0
	EndIf

	Local $sPackage = __netcode_RelayRecvPackage($hFromSocket, $nUDP)
	if @error Then Return SetError(1, __netcode_RelayDisconnect($hFromSocket, $hToSocket, $nUDP), 0) ; if Client disconnected

	if $sPackage = Null Then Return 0

	if $nUDP = 2 Then
		__netcode_Debug("Relaying from @ " & $hFromSocket & " to " & $hToSocket[1] & @TAB & Round(BinaryLen($sPackage) / 1024, 2) & " KB (UDP)")
		UDPSend($hToSocket, $sPackage)
		if @error Then Return SetError(2, __netcode_RelayDisconnect($hFromSocket, $hToSocket, $nUDP), 0) ; If RelayToSocket is dead
	Else
		__netcode_Debug("Relaying from @ " & $hFromSocket & " to " & $hToSocket & @TAB & Round(BinaryLen($sPackage) / 1024, 2) & " KB")
		__Io_TCPSend($hToSocket, $sPackage)
		if @error Then Return SetError(2, __netcode_RelayDisconnect($hFromSocket, $hToSocket, $nUDP), 0) ; If RelayToSocket is dead
	EndIf

	Return 1
EndFunc

; the $hToSocket already need to be an array here if UDP
Func __netcode_RelayDisconnect($hFromSocket, $hToSocket, $nUDP)

	Switch $nUDP
		Case Null
			__netcode_Debug("Relay Disconnecting @ " & $hFromSocket & " and @ " & $hToSocket)
			TCPCloseSocket($hFromSocket)
			TCPCloseSocket($hToSocket)

		Case 1
			__netcode_Debug("Relay Disconnecting @ " & $hFromSocket[1] & " and @ " & $hToSocket & " (UDP)")
			UDPCloseSocket($hFromSocket)
			TCPCloseSocket($hToSocket)

		Case 2
			__netcode_Debug("Relay Disconnecting @ " & $hFromSocket & " and @ " & $hToSocket[1] & " (UDP)")
			TCPCloseSocket($hFromSocket)
			UDPCloseSocket($hToSocket)

	EndSwitch
EndFunc

Func __netcode_RelayRecvPackage(Const $hSocket, $nUDP)
	Local $sPackage = '', $sRecv = '', $hTimeout = TimerInit()
	Do
		If $nUDP = 1 Then
			Return Null
;~ 			$sRecv = UDPRecv($hSocket, 4096, 1)
;~ 			if @error Then Return SetError(1, 0, False) ; if disconnected
		Else
			$sRecv = __Io_TCPRecv($hSocket, 4096, 1)
			if @extended = 1 Then Return SetError(1, 0, False) ; if disconnected
		EndIf

		$sPackage &= BinaryToString($sRecv)
		if TimerDiff($hTimeout) > 50 Then ExitLoop ; if one socket takes to much time, all other get delayed.
	Until $sRecv = ''
	if $sPackage = '' Then Return Null

	Return StringToBinary($sPackage)
EndFunc

Func __netcode_CheckIfRelaySocket(Const $hParentSocket)
	Local $nArSize = UBound($__net_arInt_RelaySockets)
	if $nArSize = 0 Then Return False

	For $i = 0 To $nArSize - 1
		if $__net_arInt_RelaySockets[$i] = $hParentSocket Then Return True
	Next

	Return False
EndFunc

Func __netcode_AddRelaySocket(Const $hSocket)
	Local $nArSize = UBound($__net_arInt_RelaySockets)

	ReDim $__net_arInt_RelaySockets[$nArSize + 1]
	$__net_arInt_RelaySockets[$nArSize] = $hSocket
EndFunc

Func __netcode_RemoveRelaySocket(Const $hSocket)
	Local $nArSize = UBound($__net_arInt_RelaySockets)

	if $nArSize = 0 Then Return
	if $nArSize > 1 Then
		Local $nIndex = -1
		For $i = 0 To $nArSize - 1
			if $__net_arInt_RelaySockets[$i] = $hSocket Then
				$nIndex = $i
				ExitLoop
			EndIf
		Next
		if $nIndex = -1 Then Return ; socket not found

		$__net_arInt_RelaySockets[$nIndex] = $__net_arInt_RelaySockets[$nArSize - 1]
	Else
		if $__net_arInt_RelaySockets[0] <> $hSocket Then Return ; socket not found
	EndIf

	ReDim $__net_arInt_RelaySockets[$nArSize - 1]
EndFunc

; #FUNCTION# ====================================================================================================================
; Author ........: guinness, Mat
; ===============================================================================================================================
Func _netcode_GetIP()
	Local Const $GETIP_TIMER = 300000 ; Constant for how many milliseconds between each check. This is 5 minutes.
	Local Static $hTimer = 0 ; Create a static variable to store the timer handle.
	Local Static $sLastIP = 0 ; Create a static variable to store the last IP.

	If TimerDiff($hTimer) < $GETIP_TIMER And Not $sLastIP Then ; If still in the timer and $sLastIP contains a value.
		Return SetExtended(1, $sLastIP) ; Return the last IP instead and set @extended to 1.
	EndIf

	#cs
		Additional list of possible IP disovery sites by z3r0c00l12.
		http://corz.org/ip
		http://icanhazip.com
		http://ip.appspot.com
		http://ip.eprci.net/text
		http://ip.jsontest.com/
		http://services.packetizer.com/ipaddress/?f=text
		http://whatthehellismyip.com/?ipraw
		http://wtfismyip.com/text
		http://www.networksecuritytoolkit.org/nst/tools/ip.php
		http://www.telize.com/ip
		http://www.trackip.net/ip
		https://api.ipify.org
	#ce
	Local $aGetIPURL = ["http://checkip.dyndns.org", "http://www.myexternalip.com/raw", "http://bot.whatismyipaddress.com"], _
			$aReturn = 0, _
			$sReturn = ""

	For $i = 0 To UBound($aGetIPURL) - 1
		$sReturn = InetRead($aGetIPURL[$i])
		If @error Or $sReturn == "" Then ContinueLoop
		$aReturn = StringRegExp(BinaryToString($sReturn), "((?:\d{1,3}\.){3}\d{1,3})", 3) ; [\d\.]{7,15}
		If Not @error Then
			$sReturn = $aReturn[0]
			ExitLoop
		EndIf
		$sReturn = ""
	Next

	$hTimer = TimerInit() ; Create a new timer handle.
	$sLastIP = $sReturn ; Store this IP.
	If $sReturn == "" Then Return SetError(1, 0, -1)
	Return $sReturn
EndFunc   ;==>_GetIP