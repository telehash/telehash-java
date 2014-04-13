package org.telehash.test.mesh;

import static org.junit.Assert.*;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.telehash.core.Channel;
import org.telehash.core.ChannelHandler;
import org.telehash.core.ChannelPacket;
import org.telehash.core.Flag;
import org.telehash.core.Log;
import org.telehash.core.TelehashException;
import org.telehash.test.network.NetworkSimulator;
import org.telehash.test.util.EchoChannelHandler;

public class LineAndChannelTest {
    
    private static final int PORT = 42424;
    private static final String TEST_STRING = "testing 123";
    private static final long NANOSECONDS_IN_MILLISECOND = 1000000L;
    
    private TelehashTestInstance node0, node1;
    
    @Before
    public void setUp() throws Exception {
        NetworkSimulator networkSimulator = new NetworkSimulator();
        
        // we use seedless nodes, and specify full information (path+pubkey)
        // when opening a line/channel, to avoid DHT concerns and restrict
        // this test to just the line/channel logic.
        node0 = new TelehashTestInstance(0, PORT, null);
        node0.setNetwork(networkSimulator.createNode("10.0.0."+0, PORT));
        node0.start();
        node1 = new TelehashTestInstance(1, PORT, null);
        node1.setNetwork(networkSimulator.createNode("10.0.0."+1, PORT));
        node1.start();
    }

    @After
    public void tearDown() throws Exception {
        node0.stop();
        node1.stop();
    }

    @Test
    public void basicTest() throws Throwable {
        TelehashTestInstance src = node0;
        TelehashTestInstance dst = node1;
        final Flag flag = new Flag();
        dst.getSwitch().registerChannelHandler(EchoChannelHandler.TYPE, new EchoChannelHandler());
        src.getSwitch().openChannel(dst.getNode(), EchoChannelHandler.TYPE, new ChannelHandler() {
            int echoResponsesReceived = 0;
            @Override
            public void handleOpen(Channel channel) {
                Log.i("channel event: open: "+channel);
                try {
                    channel.send(TEST_STRING.getBytes());
                } catch (TelehashException e) {
                    e.printStackTrace();
                }
            }

            @Override
            public void handleIncoming(Channel channel, ChannelPacket channelPacket) {
                String echo = new String(channelPacket.getBody());
                Log.i("channel event: incoming echo response #"+(echoResponsesReceived+1)+": "+echo);
                if (! echo.equals(TEST_STRING)) {
                    flag.signalError(new TelehashException("echo response does not match"));
                    return;
                }
                echoResponsesReceived++;
                if (echoResponsesReceived == 3) {
                    flag.signal();
                    return;
                }

                // send a fresh string to be echoed 
                try {
                    channel.send(TEST_STRING.getBytes());
                } catch (TelehashException e) {
                    e.printStackTrace();
                }
            }

            @Override
            public void handleError(Channel channel, Throwable error) {
                Log.i("channel event: error", error);
                flag.signalError(error);
            }
        });
        
        Throwable error = flag.waitForSignal();
        if (error != null) {
            throw error;
        }
    }
    
    private static final int CHANNEL_TIMEOUT = 2000;
    private static final int ALLOWED_TIMEOUT_VARIANCE = 200;

    @Test
    public void channelTimeoutTest() throws Throwable {
        TelehashTestInstance src = node0;
        TelehashTestInstance dst = node1;
        final Flag flag = new Flag();
        
        final class ChannelState {
            long openTime = 0L;
        }
        final ChannelState channelState = new ChannelState();
        
        dst.getSwitch().registerChannelHandler(EchoChannelHandler.TYPE, new EchoChannelHandler());
        src.getSwitch().openChannel(dst.getNode(), EchoChannelHandler.TYPE, new ChannelHandler() {
            @Override
            public void handleOpen(Channel channel) {
                Log.i("channel event: open: "+channel);
                channel.setTimeout(CHANNEL_TIMEOUT);
                channelState.openTime = System.nanoTime();
            }
            
            @Override
            public void handleIncoming(Channel channel, ChannelPacket channelPacket) {
            }
            
            @Override
            public void handleError(Channel channel, Throwable error) {
                flag.signalError(error);
            }
        });
        Throwable error = flag.waitForSignal(CHANNEL_TIMEOUT*2);

        // confirm the channel was actually opened and we recorded
        // an open time.
        assertTrue(channelState.openTime > 0L);
        
        // confirm we received a Telehash timeout exception
        assertNotNull(error);
        assertTrue(error instanceof TelehashException);
        assertTrue(error.getMessage().contains("timeout"));
        
        // if the flag timeout occurred, then our channel timeout did not.
        assertFalse(flag.timeoutOccurred());

        // confirm that the channel timeout occurred within an acceptable
        // interval of the timeout we specified.
        long elapsedTime = (System.nanoTime() - channelState.openTime)/NANOSECONDS_IN_MILLISECOND;
        Log.i("programmed timeout = "+CHANNEL_TIMEOUT+"  elapsed = "+elapsedTime);
        assertTrue(Math.abs(elapsedTime - CHANNEL_TIMEOUT) <= ALLOWED_TIMEOUT_VARIANCE);
    }
}
