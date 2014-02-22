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

public class LineAndChannelTest {
    
    private static final int PORT = 42424;
    private static final String TEST_STRING = "testing 123";
    
    private TelehashTestInstance node0, node1;
    
    @Before
    public void setUp() throws Exception {
        NetworkSimulator networkSimulator = new NetworkSimulator();
        
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
        
        dst.getSwitch().registerChannelHandler("echo", new ChannelHandler() {
            @Override
            public void handleOpen(Channel channel) {
                Log.i("new echo channel opened");
            }
            @Override
            public void handleIncoming(Channel channel, ChannelPacket channelPacket) {
                Log.i("echoing bytes...");
                try {
                    channel.send(channelPacket.getBody());
                } catch (TelehashException e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                }
            }
            @Override
            public void handleError(Channel channel, Throwable error) {
                Log.i("echo server error: ", error);
            }
        });

        final Flag flag = new Flag();
        
        src.getSwitch().openChannel(dst.getNode(), "echo", new ChannelHandler() {
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

}
