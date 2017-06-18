# AutoIt-SocketIo

Yep yep, this is pretty much an attempt to port the existing project's concept [https://socket.io/](https://socket.io/) to AutoIt's Codebase. So i will not go in to so much detail.


* This is how the communication is done http://i.imgur.com/0mMfsBD.png
* Each client is isolated to the server http://i.imgur.com/rVO2LFb.png


### Features
* Easy API
* VarType Translation (Example: If the server sends an int, the client will receive an int and vice versa)
* Fully featured examples
* Data encryption (Using Autoit's UDF Crypt.au3)

### Limitations / Drawbacks
* Every Broadcast/Emit is limited to a maximum of 16 parameters
* Every Callback Function has to have the same number of parameters as the Broadcasted/Emited event
* It is not possible to Broadcast/Emit an array as a parameter (**This will probably be supported soon**)
* Rooms and namespaces are not supported yet (**This will probably be supported soon**)


### Changelog
* **Version 1.0.0** (This update **DOES NOT** break scripts)
 * Added data encryption (Using Autoit's UDF Crypt.au3) See more at `_Io_EnableEncryption`
 * Added new method `_Io_Disconnect` which can be used with both servers and clients
 * Improved package-handling to increase performance
 * Increased the limit of Broadcasted/Emit parameters from 10 to 16

## Api methods

#### Server methods
* `_Io_Listen($iPort, $iAddress = @IPAddress1, $iMaxPendingConnections = Default, $iMaxDeadSocketsBeforeTidy = 1000)`

> Returns a TCP socket

* `_Io_Broadcast(ByRef $socket, $sEventName, $p1, $p2, ...$p10)`

> Emits an event to all connected sockets besides $socket
> Does not return anything

* `_Io_BroadcastToAll(ByRef $socket, $sEventName, $p1, $p2, ...$p10)`

> Emits an event to all connected sockets
> Does not return anything

* `_Io_socketGetProperty(ByRef $socket, $sProp = Default)`

> Retrieves information about the socket. Default = Array of all properties.
> Available properties: "ip", "date", "room"

* `_Io_getSocketsCount()`

> Returns the total amount of sockets regardles of state

* `_Io_getDeadSocketCount()`

> Returns the total amount of sockets regardles of state

#### Client methods
* `_Io_Connect($iAddress, $iPort, $bAutoReconnect = False)`

> Returns a TCP socket

* `_Io_Reconnect(ByRef $socket)`

 > Attempts to reconnect.
 > Returns a TCP socket

#### Server and Client methods
* `_Io_getVer()`

> Returns the current version

* `_Io_On(Const $sEventName, Const $fCallback)`

> Binds an event.
> Does not return anything

* `_Io_Emit(ByRef $socket, $sEventName, $p1, $p2, ...$p10)`

> Emits an event to the given socket.
> Does not return anything

* `_Io_Loop(ByRef $socket)`

> Used to recive and parse events.
> Should only be used as the main While loop

* `_Io_LoopFacade()`

> Should only be used with AdlibRegister.
> Is a replacement for the While _Io_Loop($socket) main-looop

* `_Io_EnableEncryption($sFileOrKey, $CryptAlgId = $CALG_AES_256)`

> Encrypts data between the server and the client with the use of Autoit's Crypt.au3.
> The encryption has to be enabled on both sides for it to work
> Returns true if successfully configured, else @error is set

* `_Io_Disconnect()`

> Use this method to manually disconnect and purge facade\main loop

## Default events

#### Server events
* `connection`

> Takes 1 parameter ($socket)

#### Server and Client events
* `disconnect`

> Takes 1 parameter ($socket)