
Telehash Java
====================

This is a Java implementation of the Telehash protocol.

**NOTE: This code base is only a skeleton for now, to demonstrate a
possible structure and design.**

Goals:
1. Implement the Telehash protocol.
2. The target platforms being considered are Android mobile devices and
conventional JVM environments.
3. Care should be taken to keep the library's footprint as small as
possible, so it can run efficiently on mobile devices with limited
capability.
4. Platform-specific details (crypto, networking, storage) should be
selectable and extendable by the application to provide maximum
flexibility.

The crypto work is based on Dennis Kubes's work in his telehash-java repo:
https://github.com/kubes/telehash-java

Warnings
--------------------

* This skeleton code in no way conforms to any Telehash API concept (yet).

Concerns
--------------------

There's some talk of Android's NIO not being reliable.  Some people suggest
using "old IO" (OIO) when using Netty on Android.  However, I haven't yet
stumbled on a concrete description of this hypothetical trouble.

Code conventions
--------------------

For lack of any better idea at the moment, I'm using the Android coding
conventions as described here:

http://source.android.com/source/code-style.html

Dependencies
--------------------

Bouncy Castle
http://central.maven.org/maven2/org/bouncycastle/bcprov-jdk16/1.40/bcprov-jdk16-1.40.jar

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
    - load the identity (telehash.pub, telehash.key)
    - save the identity (telehash.pub, telehash.key)
    - load the pre-authorized seeds, if present (telehash-seeds.json)
    - optional:
        - load the acquired seeds (?)
        - save the acquired seeds (?)

For now, just have the switch take identity/seeds as arguments.
1. BasicSeed loads from files
2. Switch(KeyPair identityKeyPair, Set<Node> seeds);
3. Switch must randomize seed ordering

TODO
--------------------

Evaluate Android's built-in Bouncy Castle.
    - robust/secure?
    - supports all needed ciphers/etc. in the minimum supported version of Android?

Specialized exception classes.

