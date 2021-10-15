Go To https://github.com/tarreislam/Autoit-Socket-IO for the Original SocketIO and its describtion.

This Fork Repository is the SocketIO Extended (SocketIOEx) repository for Version 3.0.0 of SocketIO and its netcode Framework.


First thing first. This Project is abandoned since 29.04.2021 (DD/MM/YYYY).
It was ment to improve SocketIO Speed wise, security wise and to add all kinds of new Options. However over time the whole UDF turned out to be just a massive playground for me. I learned alot if things while coding in it. And in the end i stumbled across multiple mayor bugs which required entire overhauls of the core. I decided against doing that, not just because it was alot of work but also because the UDF would no longer look like it was ever the SocketIO UDF. So i started coding my own TCP UDF and to take all knowledge i gained from modifying SocketIO to my own which can be found @ https://github.com/OfficialLambdax/_netcode_Core-UDF
Overall it is best that you never use this in any of your Projects. But maybe you can learn something just like i did or maybe the Original Authors finds something of use in this.


This Extended Version is released as is. There will be no updates, fixes and alike including support or documentation. I pretty much just dump it here to be never touched again. But you can ask me questions about certain systems, i might still be able to answer them.


SocketIOEx differs in a couple ways
- It is faster (up to 20 mb/s)
- It can hold alot more Clients (i cant name a number)
- It has a Incomplete Packet buffer. So incomplete packets wont bother you.
- It has a different packet format. Packets are smaller and can be processed faster.
- The serializer UDF was removed duo to it being slow and prone to crash and replaced with a faster but less featured serializer
- Certain easy ways to get the UDF to crash where removed (a wrong packet for example)
- The encryption Speed was improved
- A packet safety and validator feature was added to make sure that packets are not corrupted and actually received
- The core TCP Functions got replaced so TCP interactions got much faster
- A Flood prevention mechanism to make sure the Server and Client never receive more data then they can process was added
- and more i dont remember


I also coded a framework around the SocketIOEx which was ment to add additional options and automations. It featured
- Auto Syncing. A feature to syn custom data between the server and the client on connect
- A reduced version of CryptoNG by TheXman
- The abillity to route all traffic through Tor
- Differently working Send and Broadcast Functions
- A latency mechanic to auto set the Autoit Option "TCPTimeout" so that TCPSend() TCPConnect() doesnt fail because of a to short timeout. The feature became obsolete once these TCP functions got replaced
- A Proxy and Relay feature
- and more i dont remember


Overall both the SocketIOEx and netcode UDF are unfinished, have bugs, missing features and alot of systems would need entire overhauls to become solid. Certain things in these UDFs i touched for the first time and thats how the UDF looks. Messy and Garbage.
