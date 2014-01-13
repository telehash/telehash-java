
Telehash Java
====================

This is a Java implementation of the Telehash v2 protocol.

**NOTE: This code base is under active development, and should not be
used for production purposes at this time.**

Goals
--------------------

1. Implement the Telehash protocol.
2. The target platforms being considered are Android mobile devices and
   conventional JVM environments.
3. Care should be taken to keep the library's footprint as small as
   possible, so it can run efficiently on mobile devices with limited
   capability.
4. Platform-specific details (crypto, networking, storage) should be
   selectable and extendable by the application to provide maximum
   flexibility.

Warnings
--------------------

* This implementation is currently in the "proof of concept" stage to
  demonstrate the exchange of packets with other nodes and basic DHT
  maintenance.  There are no timeouts or other limits implemented, so
  resource usage will grow unbounded.
* This code in no way conforms to any Telehash API concept (yet).

Code conventions
--------------------

For lack of any better idea at the moment, I'm using the Android coding
conventions as described here:

http://source.android.com/source/code-style.html

Dependencies
--------------------

Bouncy Castle

http://www.bouncycastle.org/download/bcprov-jdk15on-149.jar

Bouncy Castle provides the basic cryptographic primitives.  A version of
Bouncy Castle is included within Android, which may reduce the Telehash
footprint on mobile devices.  However, it has not yet been confirmed that
Android's bundled Bouncy Castle library is suitable, robust, and available
on relevant Android releases.  

org.json

http://search.maven.org/remotecontent?filepath=org/codeartisans/org.json/20131017/org.json-20131017.jar

The org.json library is a simple JSON parser.  It is not as feature-rich
as other libaries such as Jackson or Gson, but it is bundled with Android
and so may reduce the Telehash footprint on mobile devices if we can deal
with its limitations.

Indirection
--------------------

Different target platforms have different needs with respect to certain
aspects of this library.  For instance, an application written for
deployment to a server might be bundled with many libraries (e.g. crypto
libraries) that would perhaps be redundant on an Android device, and
specific platforms may have further need for specialization.

To accommodate such needs, this library uses abstract interfaces for
several functions which are fulfilled by platform-specific implementations.
These implementations may be extended by the application developer to
further specialize the function.

These functions are:

1. Crypto
2. Networking
3. Storage
4. JSON encode/decode (?)

Storage:

* load the identity (telehash.pub, telehash.key)
* save the identity (telehash.pub, telehash.key)
* load the pre-authorized seeds, if present (telehash-seeds.json)
* optional:
    * load the acquired seeds (?)
    * save the acquired seeds (?)

For now, just have the switch take identity/seeds as arguments.

1. BasicSeed loads from files
2. Switch(KeyPair identityKeyPair, Set<Node> seeds);
3. Switch must randomize seed ordering

TODO
--------------------

* ~~Move "path" concerns (type, map generation, encode/deocde) to Endpoint
  and rename Endpoint to Path.~~
* ~~Factor network concerns out of the core and into a Reactor class.~~
* ~~Use the "Telehash" object as context for accessing the crypto/storage/network
  implementations, and remove the Util.get*Instance() methods.~~
* Line and Channel objects returned by the switch should have their references
  managed in such a way that they can be GC'ed and finalized if dereferenced
  from the application.
* The code needs some serious cleaning and refactoring at this point.
* Search for TODO items in the code, and do them.
* Implement timeouts and limits for bounded resource usage.
* More elaborate mesh testing (see: MeshTest).
* Improve the DHT to support node discovery based on hashname.
* Develop a fake network implementation that doesn't actually use the
  network.  This implementation will have programable parameters to
  allow for testing of NATs, lossy connections, congested links, etc.
* NAT considerations
    * The switch should learn its public IP address by performing a
      self-seek.
    * A switch initiating contact with a new node via peer/connect
      should also send a hole-punching open packet.
* Support IPv6
* The API currently requires the caller to successively open a line
  (Switch.openLine()) and a channel (Line.openChannel()) before communicating
  with a remote node (Channel.send()).  The Telehash protocol specification
  states that "an open is always triggered by the creation of a channel to a
  hashname, such that when a channel generates it's first packet the switch
  recognizes that a line doesn't exist yet and attempts to create one."
  Therefore, we should invert the initiation flow: Channel.send() should open a
  line and a channel the first time it is run.
* Specialized exception classes.
* Android
    * Decide on a minimum supported version of Android.
    * Evaluate Android's built-in Bouncy Castle.  (The built-in version
      is probably not full-featured enough on the versions of Android
      we'd like to target, and the Bouncy Castle API sometimes changes,
      so we'll probably end up bundling a specific version.)
    * What are the best practices for storing/managing private keys?
    * There's some talk of Android's NIO not being reliable.  Some people
      suggest using "old IO" (OIO) when using Netty on Android.  However, I
      haven't yet stumbled on a concrete description of this hypothetical
      trouble.


Acknowledgements
--------------------

Dennis Kubes performed some early work in investigating the
implementation of Telehash's cryptographic steps in Java:
https://github.com/kubes/telehash-java

