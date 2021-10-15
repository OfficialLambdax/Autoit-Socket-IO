#include-once
#include "..\..\_netcode.au3"
#include "CryptoNG.au3"

Global $__shared_bEnableConsole = False
Global $__shared_sKeyStore = @ScriptDir & "\tempRSAkeys\"
if Not FileExists($__shared_sKeyStore) Then DirCreate($__shared_sKeyStore)

Func _RSA_Console($sMessage, $hSocket = 0)
	if Not $__shared_bEnableConsole Then Return
	If $hSocket = 0 Then
		ConsoleWrite(@TAB & '_RSA' & @TAB & 'Action:' & @TAB & $sMessage & @CRLF)
	Else
		ConsoleWrite(@TAB & '_RSA' & @TAB & $hSocket & @TAB & 'Socket Action:' & @TAB & $sMessage & @CRLF)
	EndIf
EndFunc

Func _RSA_EnableConsole($Set)
	$__shared_bEnableConsole = $Set
EndFunc

Func _RSA_EnableRSA($Set)
	If $Set Then
		_netcode_SetOption("SetCryptionMode", "custom")
		_netcode_SetEncryptionCallback('_RSA_Encrypt')
		_netcode_SetDecryptionCallback('_RSA_Decrypt')
		_netcode_SetOption("EnableEncryption", "s6O7i0xC781p59ryV89L") ; while we dont have the public key we manually encrypt with _ccrypt
		_netcode_SetNetworkCustomSync("RSAPublic", '?', '_RSA_EvalPublicKey', '', '', '', True)
		_netcode_SetNetworkCustomAllow("RSAPublic", True)
	Else
		_netcode_SetOption("DisableEncryption", True)
		_netcode_SetOption("SetCryptionMode", "default")
		_netcode_SetSyncState("RSAPublic", False)
		_netcode_SetNetworkCustomAllow("RSAPublic", False)
	EndIf
EndFunc

Func _RSA_SocketAdd($hSocket, $key, $bPublic = True)
	if $bPublic Then
		_RSA_Console('Binding public key to socket', $hSocket)
		_storageS_Overwrite($hSocket & '_RSA_PublicKey', $key)
;~ 	Else
;~ 		_RSA_Console('Binding private key to socket', $hSocket)
;~ 		_storageS_Overwrite($hSocket & '_RSA_PrivateKey', $key)
	EndIf
EndFunc

Func _RSA_MyPublicAndPrivateKey($publickey, $privatekey)
	_RSA_Console('Setting my own keys')
	_storageS_Overwrite('My_RSA_PublicKey', $publickey)
	_storageS_Overwrite('My_RSA_PrivateKey', $privatekey)
EndFunc

Func _RSA_MyPrivateKey()
	Return _storageS_Read('My_RSA_PrivateKey')
EndFunc

Func _RSA_MyPublicKey()
	Return _storageS_Read('My_RSA_PublicKey')
EndFunc

Func _RSA_CreatePrivateAndPublicKeys($iKeyBitLength, $sPublicKeyPath, $sPrivateKeyPath)
	if FileExists($sPublicKeyPath) Or FileExists($sPrivateKeyPath) Then Return False
	_RSA_Console('Creating public and private keys')
	_CryptoNG_CreateRSAKeyPair($iKeyBitLength, $sPublicKeyPath, $sPrivateKeyPath, $CNG_BCRYPT_RSA_KEY_EXPORT_RSA)
EndFunc

Func _RSA_GetRSAFromSocket($hSocket, $bPublic = True)
	if $bPublic Then
		Return _storageS_Read($hSocket & '_RSA_PublicKey')
;~ 	Else
;~ 		Return _storageS_Read($hSocket & '_RSA_PrivateKey')
	EndIf
EndFunc

Func _RSA_Encrypt($sData, $sPW, $hSocket)
	$sEvalKey = _RSA_GetRSAFromSocket($hSocket)
	if $sEvalKey = False Then Return BinaryToString(_ccrypt_EncData($sData, $sPW)) ; if no key is yet stored

	$sMessage = _CryptoNG_RSA_EncryptData($sData, $sEvalKey) ; try to encrypt with public RSA
	$nError = @error
	if $nError Then
		$sMessage = BinaryToString(_ccrypt_EncData($sData, $sPW)) ; if it failed encrypt with _ccrypt
		if @error Then Return $sData ; dont encrypt if _ccrypt failed too
	Else
		_RSA_Console('Encrypting ' & StringLen($sData) & ' bytes' & @TAB & StringLeft($sData, 50), $hSocket)
	EndIf

	Return BinaryToString($sMessage)
EndFunc

Func _RSA_Decrypt($sData, $sPW, $hSocket)
	$sEvalKey = _RSA_GetRSAFromSocket($hSocket) ; check if the $hSocket already gave us his key
	if $sEvalKey = False Then Return BinaryToString(_ccrypt_DecData($sData, $sPW)) ; if no key is yet stored

	$sMessage = _CryptoNG_RSA_DecryptData($sData, _RSA_MyPrivateKey()) ; try to decrypt with private key
	if @error Then
		$sMessage = _ccrypt_DecData($sData, $sPW) ; if it failed decrypt with _ccrypt
		if @error Then Return $sData ; dont decrypt if _ccrypt failed too
	Else
		_RSA_Console('Decrypting ' & StringLen($sData) & ' bytes' & @TAB & StringLeft(BinaryToString($sMessage), 50), $hSocket)
	EndIf

	Return BinaryToString($sMessage)
EndFunc

Func _RSA_EvalPublicKey($hSocket, $sMode, $sData)
	Switch $sMode
		Case "GET"
			_RSA_Console('Sending RSA key', $hSocket)
			$hOpen = FileOpen(_RSA_MyPublicKey(), 16)
			$sMyKey = FileRead($hOpen)
			FileClose($hOpen)

			Return $sMyKey

		Case "POST"
			_RSA_Console('Saving RSA key', $hSocket)
			$hOpen = FileOpen($__shared_sKeyStore & $hSocket & '_public.blob', 18)
			FileWrite($hOpen, $sData)
			FileClose($hOpen)

			_RSA_SocketAdd($hSocket, $__shared_sKeyStore & $hSocket & '_public.blob')

	EndSwitch
EndFunc
