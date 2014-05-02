package org.telehash.androiddemo;

import android.app.Fragment;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;

import org.telehash.core.LogEntry;

public class LogFragment extends Fragment {

    private TextView mTextView;
    private TelehashService mService = null;

    public void setService(TelehashService service) {
        mService = service;
    }

    @Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container,
            Bundle savedInstanceState){
        mTextView = new TextView(this.getActivity());
        if (mService != null) {
            mTextView.setText(mService.getLogger().render());
        }
        return mTextView;
    }

    @Override
    public void onResume() {
        super.onResume();
        if (mService != null) {
            mTextView.setText(mService.getLogger().render());
        }
    }

    public void showEntry(LogEntry entry) {
        String text = AndroidLogger.renderEntry(entry);
        mTextView.append(text);
    }
}
