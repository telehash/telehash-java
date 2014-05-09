package org.telehash.androiddemo;

import android.app.Fragment;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ScrollView;

import org.telehash.core.LogEntry;

public class LogFragment extends Fragment {

    private ScrollView mScrollView;
    private LogView mLogView;
    private TelehashService mService = null;

    public void setService(TelehashService service) {
        mService = service;
    }

    @Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container,
            Bundle savedInstanceState){
        mScrollView = new ScrollView(this.getActivity());
        mLogView = new LogView(this.getActivity());
        if (mService != null) {
            mLogView.setText(mService.getLogger().render());
        }
        mScrollView.addView(mLogView);
        return mScrollView;
    }

    @Override
    public void onResume() {
        super.onResume();
        if (mService != null) {
            mLogView.setText(mService.getLogger().render());
        }
    }

    public void showEntry(LogEntry entry) {
        String text = AndroidLogger.renderEntry(entry);
        mLogView.append(text);
    }
}
