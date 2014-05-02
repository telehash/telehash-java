package org.telehash.test.network;

import org.telehash.core.Log;
import org.telehash.network.Datagram;
import org.telehash.network.DatagramHandler;
import org.telehash.network.InetPath;

import java.util.HashMap;
import java.util.Map;

public class Router {
    private long lastDatagramTime = 0L;

    private Map<InetPath,DatagramHandler> mNetworkMap =
            new HashMap<InetPath,DatagramHandler>();

    public void registerNetwork(FakeNetworkImpl network) {
        mNetworkMap.put(network.getPath(), network);
    }

    public void sendDatagram(Datagram datagram) {
        InetPath destination = new InetPath(((InetPath)datagram.getDestination()).getAddress(), 0);
        DatagramHandler handler = mNetworkMap.get(destination);
        if (handler != null) {
            synchronized (this) {
                lastDatagramTime = System.nanoTime();
            }
            handler.handleDatagram(datagram);
        }
    }

    public void waitForQuiescence(long time) {
        time = time * 1000000; // convert ms to ns
        long start = System.nanoTime();
        long now;
        do {
            final long diff;
            synchronized (this) {
                now = System.nanoTime();
                diff = now - lastDatagramTime;
            }
            Log.i("QUI: time since last datagram: "+diff+" ns  (wanting "+time+" ns)");
            if (diff >= time) {
                break;
            } else {
                try {
                    Thread.sleep(diff/1000000);
                } catch (InterruptedException e) {
                }
            }
        } while (true);
        Log.i(String.format(
                "Paused %7.3fs while waiting for network quiescence.",
                (now - start) / 1000000000.0));
    }
}
