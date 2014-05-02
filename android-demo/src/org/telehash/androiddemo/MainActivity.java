package org.telehash.androiddemo;

import android.app.ActionBar;
import android.app.ActionBar.Tab;
import android.app.Activity;
import android.app.Fragment;
import android.app.FragmentTransaction;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.Bundle;
import android.os.IBinder;
import android.view.Menu;

import org.telehash.androiddemo.TelehashService.TelehashBinder;

public class MainActivity extends Activity {

    private ActionBar.Tab mLogTab;
    private ActionBar.Tab mLineTab;
    private LogFragment mLogFragment = new LogFragment();
    private Fragment mLineFragment = new LineFragment();

    private TelehashService mService;
    private boolean mBound = false;

    /** Defines callbacks for service binding, passed to bindService() */
    private ServiceConnection mConnection = new ServiceConnection() {
        @Override
        public void onServiceConnected(ComponentName className, IBinder service) {
            // We've bound to LocalService, cast the IBinder and get LocalService instance
            TelehashBinder binder = (TelehashBinder) service;
            mService = binder.getService();
            mBound = true;
            mService.getLogger().setLogFragment(mLogFragment);
        }

        @Override
        public void onServiceDisconnected(ComponentName arg0) {
            if (mService != null) {
                mService.getLogger().setLogFragment(null);
            }
            mBound = false;
            mService = null;
        }
    };

    public class MyTabListener implements ActionBar.TabListener {
        Fragment fragment;

        public MyTabListener(Fragment fragment) {
            this.fragment = fragment;
        }

        @Override
        public void onTabSelected(Tab tab, FragmentTransaction ft) {
            ft.replace(R.id.fragment_container, fragment);
        }

        @Override
        public void onTabUnselected(Tab tab, FragmentTransaction ft) {
            ft.remove(fragment);
        }

        @Override
        public void onTabReselected(Tab tab, FragmentTransaction ft) {
            // nothing done here
        }
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        ActionBar actionBar = getActionBar();
        actionBar.setNavigationMode(ActionBar.NAVIGATION_MODE_TABS);

        mLogTab  = actionBar.newTab().setText("log");
        mLineTab = actionBar.newTab().setText("lines");

        mLogTab.setTabListener(new MyTabListener(mLogFragment));
        mLineTab.setTabListener(new MyTabListener(mLineFragment));

        actionBar.addTab(mLogTab);
        actionBar.addTab(mLineTab);
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is
        // present.
        getMenuInflater().inflate(R.menu.main, menu);
        return true;
    }

    @Override
    protected void onStart() {
        super.onStart();
        // Bind to LocalService
        Intent intent = new Intent(this, TelehashService.class);
        bindService(intent, mConnection, Context.BIND_AUTO_CREATE);
    }

    @Override
    protected void onStop() {
        super.onStop();
        if (mBound) {
            unbindService(mConnection);
            mBound = false;
        }
    }

}
