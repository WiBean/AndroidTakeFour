package com.wibean.android.wibean;

import android.app.Activity;
import android.app.Fragment;
import android.content.Context;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.Switch;
import android.widget.TimePicker;

import com.wibean.android.wibean.wibean.WiBeanSparkState;


/**
 * A simple {@link Fragment} subclass.
 * Activities that contain this fragment must implement the
 * {@link AlarmFragment.WiBeanAlarmFragmentInteractionListener} interface
 * to handle interaction events.
 * Use the {@link AlarmFragment#newInstance} factory method to
 * create an instance of this fragment.
 */
public class AlarmFragment extends Fragment implements
        View.OnClickListener {
    // TODO: Rename parameter arguments, choose names that match
    // the fragment initialization parameters, e.g. ARG_ITEM_NUMBER
    private static final String ARG_ALARMONTIME = "alarmOnTime";
    private static final String ARG_ALARMTIMEZONE = "alarmTimeZone";


    private WiBeanSparkState.WiBeanAlarmPackV1 mRemoteAlarm = new WiBeanSparkState.WiBeanAlarmPackV1();
    private WiBeanSparkState.WiBeanAlarmPackV1 mLocalAlarm = new WiBeanSparkState.WiBeanAlarmPackV1();
    private WiBeanAlarmFragmentInteractionListener mListener;

    private TimePicker mTimePicker;
    private Switch mArmedSwitch;
    private Button mSaveAlarmButton;

    public AlarmFragment() {
        // Required empty public constructor
    }

    /**
     * Use this factory method to create a new instance of
     * this fragment using the provided parameters.
     *
     * @param alarmPack The current remote alarm pack.
     * @return A new instance of fragment AlarmFragment.
     */
    // TODO: Rename and change types and number of parameters
    public static AlarmFragment newInstance(WiBeanSparkState.WiBeanAlarmPackV1 alarmPack) {
        AlarmFragment fragment = new AlarmFragment();
        Bundle args = new Bundle();
        args.putInt(ARG_ALARMONTIME, alarmPack.getOnTimeAsMinutesAfterMidnight());
        args.putInt(ARG_ALARMTIMEZONE, alarmPack.getUtcOffset());
        fragment.setArguments(args);
        return fragment;
    }

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        // pull in any case from prefs
        SharedPreferences prefs = getActivity().getPreferences(Context.MODE_PRIVATE);
        int minutesAfter = prefs.getInt(WiBeanSparkState.PREF_KEY_ALARM_TIME_HOUR, 0) * 60;
        minutesAfter += prefs.getInt(WiBeanSparkState.PREF_KEY_ALARM_TIME_MINUTE, 0);
        mLocalAlarm.setOnTimeAsMinutesAfterMidnight(minutesAfter);
        mLocalAlarm.setUtcOffset(prefs.getInt(WiBeanSparkState.PREF_KEY_DEVICE_TIMEZONE, 0));
        // if we have a bundle, bring it in
        if (getArguments() != null) {
            mRemoteAlarm.setOnTimeAsMinutesAfterMidnight(getArguments().getInt(ARG_ALARMONTIME, 480));
            mRemoteAlarm.setUtcOffset(getArguments().getInt(ARG_ALARMTIMEZONE, 0));
        }
        if (mRemoteAlarm.getAlarmArmed()) {
            mLocalAlarm = new WiBeanSparkState.WiBeanAlarmPackV1(mRemoteAlarm);
        }
    }

    @Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container,
                             Bundle savedInstanceState) {
        super.onCreateView(inflater, container, savedInstanceState);
        // Inflate the layout for this fragment
        View v = inflater.inflate(R.layout.fragment_alarm, container, false);
        mTimePicker = (TimePicker) v.findViewById(R.id.tp_timePicker);
        mArmedSwitch = (Switch) v.findViewById(R.id.sw_toggleAlarm);
        mSaveAlarmButton = (Button) v.findViewById(R.id.btn_saveAlarmSetting);
        mSaveAlarmButton.setOnClickListener(this);
        updateUiFromAlarms();
        return v;
    }

    @Override
    public void onActivityCreated(Bundle bundle) {
        super.onActivityCreated(bundle);
        setAlarmTime(mLocalAlarm.getOnTimeAsMinutesAfterMidnight());
    }

    @Override
    public void onAttach(Activity activity) {
        super.onAttach(activity);
        try {
            mListener = (WiBeanAlarmFragmentInteractionListener) activity;
        } catch (ClassCastException e) {
            throw new ClassCastException(activity.toString()
                    + " must implement WiBeanAlarmFragmentInteractionListener");
        }
    }

    @Override
    public void onPause() {
        super.onPause();
        storePrefs();
    }

    @Override
    public void onDetach() {
        super.onDetach();
        mListener = null;
    }

    // handle onClick in the fragment, yay Android Fragments
    @Override
    public void onClick(View v) {
        switch (v.getId()) {
            case R.id.btn_saveAlarmSetting:
                onClick_saveAlarm(v);
                break;
        }
    }

    private void storePrefs() {
        // save the users preferences
        SharedPreferences.Editor prefsEdit = getActivity().getPreferences(Context.MODE_PRIVATE).edit();
        prefsEdit.putInt(WiBeanSparkState.PREF_KEY_ALARM_TIME_HOUR, mTimePicker.getCurrentHour());
        prefsEdit.putInt(WiBeanSparkState.PREF_KEY_ALARM_TIME_MINUTE, mTimePicker.getCurrentMinute());
        prefsEdit.commit();
    }

    private void updateUiFromAlarms() {
        setAlarmTime(mLocalAlarm.getOnTimeAsMinutesAfterMidnight());
        mArmedSwitch.setChecked(mRemoteAlarm.getAlarmArmed());
    }

    private void onClick_saveAlarm(View v) {
        if (mArmedSwitch.isChecked()) {
            int minutesAfterMidnight = mTimePicker.getCurrentHour() * 60 + mTimePicker.getCurrentMinute();
            mLocalAlarm.setOnTimeAsMinutesAfterMidnight(minutesAfterMidnight);
        } else {
            // set the alarm to 2 minutes more than minutes in a day, then it is deactivated.
            mLocalAlarm.setOnTimeAsMinutesAfterMidnight(WiBeanSparkState.WiBeanAlarmPackV1.MINUTES_IN_DAY + 2);
        }
        SharedPreferences prefs = getActivity().getPreferences(Context.MODE_PRIVATE);
        mLocalAlarm.setUtcOffset(prefs.getInt(WiBeanSparkState.PREF_KEY_DEVICE_TIMEZONE, 0));
        // save the users preferences
        SharedPreferences.Editor prefsEdit = getActivity().getPreferences(Context.MODE_PRIVATE).edit();
        prefsEdit.putInt(WiBeanSparkState.PREF_KEY_ALARM_TIME_HOUR, mTimePicker.getCurrentHour());
        prefsEdit.putInt(WiBeanSparkState.PREF_KEY_ALARM_TIME_MINUTE, mTimePicker.getCurrentMinute());
        prefsEdit.commit();
        mListener.sendAlarmRequest(mLocalAlarm);
    }

    public boolean setAlarmTime(int minutesAfterMidnight) {
        if ((minutesAfterMidnight < 0) || (minutesAfterMidnight > (24 * 60))) {
            return false;
        }
        if (mTimePicker != null) {
            mTimePicker.setCurrentHour(minutesAfterMidnight / 60);
            mTimePicker.setCurrentMinute(minutesAfterMidnight % 60);
        }
        return true;
    }

    /**
     * UTILITIES
     */
    public void updateRemoteAlarm(final WiBeanSparkState.WiBeanAlarmPackV1 newAlarm) {
        // if the remote alarm was changed, update the UI to reflect its current state
        final boolean same = newAlarm.equals(mRemoteAlarm);
        if (!same) {
            mRemoteAlarm = new WiBeanSparkState.WiBeanAlarmPackV1(newAlarm);
            mLocalAlarm = new WiBeanSparkState.WiBeanAlarmPackV1(newAlarm);
            updateUiFromAlarms();
        }
    }

    public interface WiBeanAlarmFragmentInteractionListener {
        public boolean sendAlarmRequest(WiBeanSparkState.WiBeanAlarmPackV1 requestedAlarm);
    }

}
