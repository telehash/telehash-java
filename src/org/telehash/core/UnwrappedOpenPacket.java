package org.telehash.core;

import org.telehash.crypto.LinePublicKey;
import org.telehash.network.Path;

public class UnwrappedOpenPacket {
	public byte[] iv;
	public byte[] encryptedSignature;
	public byte[] encryptedInnerPacket;
	public Path path;
	public byte[] linePublicKeyBuffer;
	public LinePublicKey linePublicKey;
	public byte[] innerPacketKey;
	public byte[] innerPacketBuffer;
}

