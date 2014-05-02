
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

For lack of any better idea at the moment, I'm (more or less) using the
Android coding conventions as described here:

http://source.android.com/source/code-style.html

Building Telehash Java
--------------------

Telehash Java uses [Gradle](http://www.gradle.org/) for building.  After
downloading and installing Gradle, run the following in the root of the
source tree to to build the library and run the unit tests:

    gradle build

To generate a jar file, run:

    gradle jar

Dependencies
--------------------

Spongy Castle

http://rtyley.github.io/spongycastle/

http://search.maven.org/remotecontent?filepath=com/madgag/spongycastle/core/1.50.0.0/core-1.50.0.0.jar
http://search.maven.org/remotecontent?filepath=com/madgag/spongycastle/prov/1.50.0.0/prov-1.50.0.0.jar

Spongy Castle is a repackaging of the Bouncy Castle cryptographic
library which has been modified to not conflict with the older Bouncy
Castle libraries that are frequently bundled with Android devices.

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

* load the local node keys (telehash.pub, telehash.key)
* save the local node keys (telehash.pub, telehash.key)
* load the pre-authorized seeds, if present (telehash-seeds.json)
* optional:
    * load the acquired seeds (?)
    * save the acquired seeds (?)

For now, just have the switch take local node parameters and seeds
as arguments.

1. BasicSeed loads from files
2. Switch(KeyPair localNodeKeyPair, Set<Node> seeds);
3. Switch must randomize seed ordering

TODO
--------------------

* Telehash core
    * Cipher sets
        * Cipher set specifics
            * CS1a: ECC SECP160r1 and AES-128
            * CS3a: NaCl
        * Update unit tests for checking crypto cipher set functions.
    * Line
        * When an open packet is received from a hashname for which a
          line is already established:
            * Same line id; recalculate keys.
            * Different line id; invalidate existing channels.
    * Channels
        * Reliable channels
            * Seq/ack sequencing.
            * Fixed window size of 100 packets (for now).
            * Packet reordering.
            * Packet retransmission via "miss".
            * Per-packet retransmission throttle of 1 second.
            * Half-closed channels (wait for ack after end).
    * Paths
        * Local path distinction and limit leaking local host address
          information.
    * DHT
        * Limited prefix seeks.
    * Switch
        * Bridge support: bridge channel, advertisement.
        * Persistent peer channels for relay (auto-bridge).
        * Path channel for network path negotiation.
* Cleanup
    * Search for TODO items in the code, and do them.
* Android
    * Decide on a minimum supported version of Android.
    * What are the best practices for storing/managing private keys?
    * There's some talk of Android's NIO not being reliable.  Some people
      suggest using "old IO" (OIO) when using Netty on Android.  However, I
      haven't yet stumbled on a concrete description of this hypothetical
      trouble.
* Eventually...
    * Line and Channel objects returned by the switch should have their references
      managed in such a way that they can be GC'ed and finalized if dereferenced
      from the application.
    * Test/solidify timeouts and limits.
    * The early exploratory code has many needless buffer copies for
      simplicity.  We need a new approach to minimize copies for greater
      performance.
    * Support IPv6
    * Specialized exception classes.
    * Opportunities to reduce redundancy
        * Consider not tracking the remote node in a Line object.
        * There's no need having a separate SeedNode object, if we don't
          track the full set of public keys for seeds.  When parsing the
          seeds.json, only extract the best csid/PK for our switch into
          PeerNode objects.
    * LAN multicast discovery
    * Seed hints
        * Persist a local seed hints list, so the switch doesn't need
          to rely on the master seed list.
        * DHT seed hints.
        * Local seed hints.
    * Testing
        * Add support to the network simulator for programmable parameters
          to allow for testing of NATs, lossy connections, congested links,
          etc.


Acknowledgements
--------------------

Dennis Kubes performed some early work in investigating the
implementation of Telehash's cryptographic steps in Java:
https://github.com/kubes/telehash-java

