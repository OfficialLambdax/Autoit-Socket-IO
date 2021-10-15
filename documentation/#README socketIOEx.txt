

Changes To Functions
___________________________________________________________________________________________________

_Io_Emit()
	no longer features the ability to send $p1 - $p16.
	You need to use _Io_sParams() to send $p1 - $p16
	
	Example:
	before the change	_Io_Emit(socket, event, p1, p2, p3, -p16)
	now					_Io_Emit(socket, event, _Io_sParams(p1, p2, p3, -p16))
	
	If you use _Io_sParams() the packet on the receiving end will be split up
	and the Call() be called just how you used to.
	
	This is because _Io_Emit() now features a couple of bypass options
	These being
	
	$bNoSafeOverwrite
		Which if True disables the Packet Safety for the current packet
		
	$bNoPacketEncryption
		Which if True disables the Packet Encryption for the current packet
		
	$bInternal_IgnoreFlood
		Which if True ignores the Recv Buffer Guessing for the current packet
		and is mainly used internally when the SocketIO tries to figure out if the Server is hung up
		or if the Flood counter is just calculated wrong.
		
	_Io_Emit() will use the new Flood Prevention and Packet Safety Technic.
		

_Io_Listen()
	Now binds 2 new Events to the new Listening Socket those be
		Internal_FloodPrevention
		Internal_PacketSafety
		
	The usage is still the same.


_Io_Connect()
	Now binds 2 new Events to the Connected Socket those be
		Internal_FloodPrevention
		Internal_PacketSafety
		
	The usage is still the same.


_Io_EnableEncryption()
	The Encryption is completly changed. It now uses the _ccryptS.au3 UDF for faster
	encryption and decryption.
	
	The usage is still the same.
	
	Encryption can be disabled with _Io_DisableEncryption()
		

_Io_Loop()
	This function has not so much changed.
	
	In Case $_IO_SERVER
	every new $connectedSocket = TCPAccept($socket)
	will get 2 new Events to be binded those be
		Internal_FloodPrevention
		Internal_PacketSafety	


Internal Functions
__________________________________


__Io_createPackage()
	We no longer use the Serializatin UDF as it was to slow and bloated each packet.
	We now make usage of Packet Validation and restructured the Packet creation.
	Now nor the event neither the params get binarized any longer. We split the packet inside the packet handler with 10 bytes long unique seperators. But dont worry about sending unicode characters.
	The whole packet gets binarized once wrapped up.
	
	Packets now look like this
	
	with validation
		packetseperatorstring & validation & packetcontentseperator & eventname & packetcontentseperator & params & packetseperatorstring
	
	without validation
		packetseperatorstring & eventname & packetcontentseperator & $params & $packetseperatorstring

	Packet validation can be toggled with _Io_SetPacketValidation()
	
	If you worry about the packet content (the event and the params) being not binarized and that your params might contain this unique seperator string then you can simply binarize it yourself when you call _Io_Emit() or _netcode_Send(). But in practice i have send for testing 100 different files and on non of them i got any issue.
	
	If you want to change the seperator strings you can call ################. But both sides, the server and the client, need to have the same.
	
	If Encryption is toggled then the whole content gets encrypted that be
		validation & packetcontentseperator & eventname & packetcontentseperator & params
		
	Only the packetseperatorstring keeps unencrypted. This is intentionally.
	

__Io_handlePackage()
	The Packet handler is now completly changed and much more complex.
	It differentiates each packet. If it uses packet validation if it is encrypted and so on.
	Its actions can be controled with a couple of Options.
	
	#################
	If you want to accept unencrypted traffic for example set ###############


__Io_TransportPackage()
	Packet encryption got removed from this function. There also is a second function named
	__Io_TransportPackage_Safe(). Which is used for Packet Safety.


__Io_RecvPackage()
	Packet decryption got removed from this function. And i changed the way it now Receives data.
	At default it used to receive in binary. The packets get already send in binary so when receiving it with $TCP_DATA_BINARY we would always receive double the amount as the binary got binarized again.  This bloat got changed to now receiving forcefully in String. In my testings this was much much faster.



New Functions
__________________________________________________________________________________________________

_Io_sParams()
	Is used when calling _Io_Emit() to split up the params
	Example:
	before the change	_Io_Emit(socket, event, p1, p2, p3, -p16)
	now					_Io_Emit(socket, event, _Io_sParams(p1, p2, p3, -p16))
	
	In __Io_InvokeCallback() the function __Io_r_Params2ar_Params() will check if the params where merged with _Io_sParams() and unmerge them there. When Call(yourfunction, p1, p2, p3) then all params will be String() no matter if you parsed a Bool or Number into _Io_sParams(). This is a by product and subject to change.
	_netcode.au3 features __netcode_ConvertDataType(). You can convert your Data back with that until this issue is gone.
	
	Merged Params look like that:	
	$sParams = _Io_sParams(1, 2, 3)
	
	"NDs2GA59Wj1eUwc99H4Vc2eUwc99H4Vc3"
	
	as you can see each param is seperated with "eUwc99H4Vc".
	
	You can set #########() $g__Io_bParamSplitBinary to True to have all params Binarized
	
	You can also change #########() $g__Io_sParamIndicatorString and ############() $g__Io_sParamSplitSeperator
	
	
_Io_DisableEncryption()
	Call this to disable encryption. The current used derived key gets destroyed too


_Io_SetBytesPerSecond()
	Set to True if you want to enable the counting of all send and received bytes.
	Each Socket has its own Counter. Default is False.


_Io_GetBytesPerSecond()
	Call this to get the Counter values of the passed socket


_Io_GetLastMeassurements()
	For development and Optimization i set two timers. One for the Send and one for the recv function.
	
	The timer for the Send function starts right when _Io_Emit() is called and ends right before we Return from the same function.
	
	The timer for the Recv function starts right when __Io_RecvPackage() is called and ends right before the Call() in __Io_InvokeCallback()
	
	By calling _Io_GetLastMeassurements() you will get an array with both values in ms and can therefore guess how long the last operation took


_Io_SetPacketValidation()
	Enable Packet Validation. Is True by Default
	

_Io_SetPacketSafety()
	Enable Packet Safety. Is True by Default
	

_Io_SetFloodPrevention()
	Enable Flood Prevention. Is True by Default


_Io_SetAcceptUnecryptedTraffic()
	Enable the acceptance of unencrypted traffic. Is False by Default


Internal Functions
__________________________________


_On_Internal_FloodPrevention()
	A new Event bound to each Socket. The Receiver will send the len of the last received packet to this function


_On_Internal_Safety()
	A new Event bound to each Socket. If packet safety is set the receiver will send either a OK or a XX to this function to signalize the __Io_TransportPackage_Safe() function the packet is validated or not


__Io_AddFloodPrevention()
	Internal Function to Add Send bytes


__Io_DelFloodPrevention()
	Internal Function to Remove bytes from the counter


__Io_CheckFloodPrevention()
	Called Internaly by _Io_Emit() to check how much Bytes got send already since the last Flood Prevention packet from the Receiver. If __Io_CheckFloodPrevention(socket) + StringLen(nextpacket) is greater then $g__Io_nMaxPacketSize then _Io_Emit() will Return @error = 2 because if it would send then the receiver would call a flood event ---> discarding the packet.


__Io_r_Params2ar_Params()
	If _Io_sParams() is used. this function will unmerge the params into an CallArgArray for the Event Call()


__Io_PacketExecution()
	__Io_FireEvent() basically just got moved to this.


__Io_TransportPackage_Safe()
	A new function to transmit the data with packet safety. Once Send the function will wait for a confirmation from the Receiver that either the Packet is OK or bad. If bad it will resend the packet.
	
	The Function will Timeout after Default 10 Seconds. Defined in $g__Io_nGlobalTimeoutTime.


__Io_CheckSocket()
	I added my own Socket storage.
	Each socket is saved to its parent socket.
	[x][0] = parentsocket
	[0][x] = clientsocket 1|clientsocket 2 .. n
	
	SocketIO has its own socket array. But i will most probably recode that section. By now
	this function is used to get the parent of a socket. It is Server Side only, but that is subject to change.


__Io_AddSocket()
	Adding a Socket to the new Socket storage.


__Io_DelSocket()
	Deleting a Socket from the new Socket storage.


__Io_BytesPerSecond()
	Internal Function called by _Io_Emit() and __Io_RecvPackage() to add bytes they just send or received



New Inbuild UDFs
__________________________________________________________________________________________________


_storageS.au3
	The simple and stripped version of _storage.au3. This is only meant to store data to a socket. This is a faster method then storing them in a 2D Array. The _storage.au3 UDF is not public.
______________


_storageS_Overwrite()
	Stores Data and creates a storage. Works as a Write function.


_storageS_Append()
	Adds Data to already existing storage or calls _storageS_Overwrite() if the storage doesnt exists yet.
	This is like &= not +=


_storageS_Read()
	Read the Data from the storage



_ccryptS.au3
	The simple and stripped version of _ccrypt.au3. Ment to encrypt and decrypt data. It uses $CALG_AES_256 and derives the given key. The _ccrypt.au3 UDF is not public.
______________


_ccrypt_EncData()
	Encrypt Data with the given key. Give the raw key. If a derive handle already exists to it it will take that


_ccrypt_DecData()
	Decrypt data with the given key. Give the raw key. etc.


__ccrypt_initialize()
	Initialize _crypt.au3 and derive the given Key. the derive handle keeps stored in this function until a new key is passed or it gets destroyed. eg. Local Static $hDerive


__ccrypt_RandomChar()
	Returns a Random Character


__ccrypt_RandomPW()
	Creates a Random Passwort


__ccrypt_StringRepeat()
	Cut from <String.au3>. We only need this function so i cut it from there

__ccrypt_Crypt_DestroyKey()
	Cut from <crypt.au3>. _crypt_shutdown() commented to only use it when needed.
	crypt.au3 has a bug when caling shutdown in some cases.
	So instead of calling __ccrypt_initialize(key, True) to destroy the key and shutdown crypt.au3 which is intended in _ccrypt we only use __ccrypt_Crypt_DestroyKey() to destroy a key in SocketIO and _netcode.au3 until this bug is fixed.

