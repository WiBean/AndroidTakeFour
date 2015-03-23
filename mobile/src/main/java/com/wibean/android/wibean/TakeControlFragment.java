package com.wibean.android.wibean;

import android.app.ActionBar;
import android.app.Activity;
import android.app.Fragment;
import android.content.Context;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Spinner;
import android.widget.Toast;

import com.google.zxing.integration.android.IntentIntegrator;
import com.wibean.android.wibean.wibean.WiBeanSparkState;

import java.text.DecimalFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.TimeZone;


/**
 * A simple {@link Fragment} subclass.
 * Activities that contain this fragment must implement the
 * {@link com.wibean.android.wibean.TakeControlFragment.TakeControlFragmentListener} interface
 * to handle interaction events.
 * Use the {@link TakeControlFragment#newInstance} factory method to
 * create an instance of this fragment.
 */
public class TakeControlFragment extends Fragment implements View.OnClickListener {

    private static final String ARG_CREDENTIALS_VALID = "in_control";
    private static final String PREF_KEY_TIMEZONE_SPINNER_POSITION = "TIMEZONE_SPINNER_POSITION";

    private boolean mCredentialsValid = false;

    private TakeControlFragmentListener mListener;

    private Button mConnectButton;
    private Button mScanAccessCode;
    private EditText mAccessCode_editText;
    private EditText mGoalTemperature_editText;
    private Spinner mTimeZoneSpinner;

    public TakeControlFragment() {
        // Required empty public constructor
    }

    /**
     * Use this factory method to create a new instance of
     * this fragment using the provided parameters.
     *
     * @param inControl Boolean describing whether or not the fragment state "in control" is active.
     * @return A new instance of fragment TakeControlFragment.
     */
    // TODO: Rename and change types and number of parameters
    public static TakeControlFragment newInstance(boolean inControl) {
        TakeControlFragment fragment = new TakeControlFragment();
        Bundle args = new Bundle();
        args.putBoolean(ARG_CREDENTIALS_VALID, inControl);
        fragment.setArguments(args);
        return fragment;
    }

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setHasOptionsMenu(true);
        if (getArguments() != null) {
            mCredentialsValid = getArguments().getBoolean(ARG_CREDENTIALS_VALID, false);
        }
    }

    @Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container,
                             Bundle savedInstanceState) {
        super.onCreateView(inflater, container, savedInstanceState);
        // Inflate the layout for this fragment
        View v = inflater.inflate(R.layout.fragment_take_control, container, false);

        // hookup convenience members
        mConnectButton = (Button) v.findViewById(R.id.btn_testCredentials);
        mScanAccessCode = (Button) v.findViewById(R.id.btn_scanSingleCode);
        mAccessCode_editText = (EditText) v.findViewById(R.id.et_accessCode);
        mGoalTemperature_editText = (EditText) v.findViewById(R.id.et_goalTemperature);
        mTimeZoneSpinner = (Spinner) v.findViewById(R.id.spn_dstOffset);
        // hookup the button here in the Fragment
        // (onClicks generated from buttons in Fragments get sent to their Activity
        // removing modularity)
        mConnectButton.setOnClickListener(this);
        mScanAccessCode.setOnClickListener(this);

        // setup the timezone stuff
        // populate the TZ spinner
        ArrayList<String> TZ1 = new ArrayList<String>();
        // if we have system TZ info use it, otherwise, take a default array
        //if( TZ.length > 0 ) {
        if (false) { // for now make this false, because the timezones are confusing when shifted by DST
            String[] TZ = TimeZone.getAvailableIDs();
            for (int i = 0; i < TZ.length; i++) {
                TimeZone tz = TimeZone.getTimeZone(TZ[i]);
                String display = new DecimalFormat("+00;-00").format(tz.getRawOffset() / 3600000) + " " + tz.getDisplayName();
                if (!TZ1.contains(display)) {
                    TZ1.add(display);
                }
            }
            Collections.sort(TZ1, Collections.reverseOrder());
            // find the first -01 netry
            int lastIndex = -1;
            for (int k = 0; k < TZ1.size(); ++k) {
                if (TZ1.get(k).startsWith("-01")) {
                    lastIndex = k;
                }
            }
            lastIndex += 1;
            if (lastIndex <= TZ1.size()) {
                // Then grab the negative chunk, reverse it, and prepend it
                Collections.sort(TZ1.subList(lastIndex, TZ1.size()));
            }
        } else {
            // use the default array
            TZ1 = new ArrayList<>(Arrays.asList(getActivity().getResources().getStringArray(R.array.simple_timezone_list)));
        }
        ArrayAdapter<String> tzAdapter = new ArrayAdapter<>(getActivity(), android.R.layout.simple_spinner_dropdown_item, TZ1);
        mTimeZoneSpinner.setAdapter(tzAdapter);
        ((Button) v.findViewById(R.id.btn_findTimezone)).setOnClickListener(this);
        return v;
    }

    @Override
    public void onActivityCreated(Bundle savedInstanceState) {
        super.onActivityCreated(savedInstanceState);
        // if we have a value in the store, load it and then connect
        String accessCode = "";
        String brewTemp = "";
        int utcSpinnerPos = 0;
        try {
            SharedPreferences prefs = getActivity().getPreferences(Context.MODE_PRIVATE);
            //deviceId = prefs.getString(WiBeanSparkState.PREF_KEY_DEVICE_ID, "");
            //accessToken = prefs.getString(WiBeanSparkState.PREF_KEY_ACCESS_TOKEN, "");
            accessCode = prefs.getString(WiBeanSparkState.PREF_KEY_ACCESS_CODE,"");
            brewTemp = prefs.getString(WiBeanSparkState.PREF_KEY_BREW_TEMP, "");
            utcSpinnerPos = prefs.getInt(PREF_KEY_TIMEZONE_SPINNER_POSITION, 0);
        } catch (Exception e) {
            System.out.println("FATAL Error: sharedPreference for credentials exists as wrong type???");
        }
        boolean testCredentials = false;
        boolean needCredential = false;
        if (!accessCode.isEmpty()) {
            // populate the dialog
            View v = getView();
            EditText ipText = (EditText) v.findViewById(R.id.et_accessCode);
            ipText.setText(accessCode);
            // try auto connect if we aren't in control
            testCredentials = true;
        } else {
            needCredential = true;
        }
        // set the spinner position
        mTimeZoneSpinner.setSelection(utcSpinnerPos);
        if (needCredential) {
            mListener.alertUser("Need setting", getString(R.string.alert_ip_error_message));
        }
        // populate the temperature
        if (!brewTemp.isEmpty()) {
            mGoalTemperature_editText.setText(brewTemp);
        }
        if (testCredentials) {
            if (!mCredentialsValid) {
                btn_saveSettings(getView());
            }
        }
        // ensure the UI is initialized to the right state
        if (mCredentialsValid) {
            setCredentialsValid();
        } else {
            setCredentialsInvalid();
        }
    }

    @Override
    public void onCreateOptionsMenu(Menu menu, MenuInflater inflater) {
        super.onCreateOptionsMenu(menu, inflater);
        //inflater.inflate(R.menu.brewing_program, menu);  We don't need extra menus here
        ActionBar actionBar = getActivity().getActionBar();
        actionBar.setNavigationMode(ActionBar.NAVIGATION_MODE_STANDARD);
        actionBar.setDisplayShowTitleEnabled(true);
        actionBar.setTitle("Take Control");
    }

    // handle onClick in the fragment, yay Android Fragments
    @Override
    public void onClick(View v) {
        switch (v.getId()) {
            case R.id.btn_testCredentials:
                btn_saveSettings(v);
                break;
            case R.id.btn_scanSingleCode:
                onClick_pullAccessCodeFromBarcode(v);
                break;
            case R.id.btn_findTimezone:
                takeDefaultTimeZone();
                break;
        }
    }

    @Override
    public void onAttach(Activity activity) {
        super.onAttach(activity);
        try {
            mListener = (TakeControlFragmentListener) activity;
        } catch (ClassCastException e) {
            throw new ClassCastException(activity.toString()
                    + " must implement TakeControlFragmentListener");
        }
    }

    @Override
    public void onDetach() {
        super.onDetach();
        mListener = null;
    }

    public void setCredentialsValid() {
        // assume whoever called this was finished with any network/pending operations
        enableInputs();
        mCredentialsValid = true;
    }

    public void setCredentialsInvalid() {
        // assume whoever called this was finished with any network/pending operations
        enableInputs();
        mCredentialsValid = false;
    };

    public void onClick_pullAccessCodeFromBarcode(View v) {
        mListener.setTargetControl(R.id.et_accessCode);
        IntentIntegrator integrator = new IntentIntegrator(getActivity());
        integrator.initiateScan();
    };

    public void btn_saveSettings(View v) {
        //toggle

        //disable buttons
        //disableInputs();

        // use the current values to update the database
        EditText etAccessCode = (EditText) getView().findViewById(R.id.et_accessCode);
        String accessCode = etAccessCode.getText().toString();

        final String currentTemp = mGoalTemperature_editText.getText().toString();
        if (accessCode.isEmpty()) {
            mListener.alertUser(getString(R.string.alert_ip_error_title), getString(R.string.alert_ip_error_message));
            mCredentialsValid = false;
            return;
        }
        // else continue
        SharedPreferences.Editor prefsEdit = getActivity().getPreferences(Context.MODE_PRIVATE).edit();
        prefsEdit.putString(WiBeanSparkState.PREF_KEY_ACCESS_CODE, accessCode);
        prefsEdit.putInt(PREF_KEY_TIMEZONE_SPINNER_POSITION, mTimeZoneSpinner.getSelectedItemPosition());
        Integer utcOffset = getIntegerFromTimeZoneSpinner(mTimeZoneSpinner.getSelectedItemPosition());
        prefsEdit.putInt(WiBeanSparkState.PREF_KEY_DEVICE_TIMEZONE, utcOffset);
        prefsEdit.putString(WiBeanSparkState.PREF_KEY_BREW_TEMP, currentTemp);
        prefsEdit.commit();
        Toast.makeText(getActivity(), R.string.action_testCredentials_toast, Toast.LENGTH_SHORT);
        try {
            mListener.statusPollLoop();
        } catch (Exception e) {
            //responseText.setText("Err chk heat: " + e.getMessage() + ' ' + e.getClass());
            System.out.println("TakeControl Failed: " + e.getMessage() + ' ' + e.getClass());
            //return false;
        }
    }

    private void enableInputs() {
        mConnectButton.setEnabled(true);
        mScanAccessCode.setEnabled(true);
        mAccessCode_editText.setEnabled(true);
        mGoalTemperature_editText.setEnabled(true);
        mTimeZoneSpinner.setEnabled(true);
    }

    private void disableInputs() {
        mConnectButton.setEnabled(false);
        mScanAccessCode.setEnabled(false);
        mAccessCode_editText.setEnabled(false);
        mGoalTemperature_editText.setEnabled(false);
        mTimeZoneSpinner.setEnabled(false);
    }

    /**
     * CONVENIENCE FUNCTIONS FOR TIMEZONE SPINNER
     */
    private void takeDefaultTimeZone() {
        spinnerSetSelectionChecked(mTimeZoneSpinner, findIntegerInTimeZoneSpinner(getDefaultTimeZone()));
    }

    private int getDefaultTimeZone() {
        TimeZone tz = TimeZone.getDefault();
        final int combinedOffset = tz.getRawOffset() / 3600000 + (tz.inDaylightTime(new Date()) ? 1 : 0);
        return combinedOffset;
    }

    private void spinnerSetSelectionChecked(Spinner spin, int index) {
        spinnerSetSelectionChecked(spin, index, false);
    }

    private void spinnerSetSelectionChecked(Spinner spin, int index, boolean animate) {
        final int count = spin.getAdapter().getCount();
        if ((count > 0) && (index < count)) {
            spin.setSelection(index, animate);
        } else { // do nothing
        }
    }

    private int getIntegerFromTimeZoneSpinner(int position) {
        if (mTimeZoneSpinner == null) {
            return 0;
        }
        try {
            String text = ((String) mTimeZoneSpinner.getItemAtPosition(position)).substring(0, 3);
            return getIntegerFromTimeZoneString(text);
        } catch (Exception e) {
            e.printStackTrace();
            return 0;
        }
    }

    private int getIntegerFromTimeZoneString(String text) {
        text = text.substring((text.charAt(0) == '+') ? 1 : 0, 3);
        return Integer.valueOf(text);
    }

    private int findIntegerInTimeZoneSpinner(int utcOffset) {
        if (mTimeZoneSpinner == null) {
            return 0;
        }
        Integer bigI = Integer.valueOf(utcOffset);
        // start at the offset, because we have at least one per offset
        int k = utcOffset;
        try {
            while (true) {
                String text = ((String) mTimeZoneSpinner.getItemAtPosition(k)).substring(0, 3);
                text = text.substring((text.charAt(0) == '+') ? 1 : 0, 3);
                if (Integer.valueOf(text).equals(bigI)) {
                    return k;
                }
                ++k;
            }
        } catch (Exception e) {
            // none found
            return -1;
        }
    }
    /**
     * END UTILITIES FOR TIMEZONE
     */


    /**
     * This interface must be implemented by activities that contain this
     * fragment to allow an interaction in this fragment to be communicated
     * to the activity and potentially other fragments contained in that
     * activity.
     */
    public interface TakeControlFragmentListener {
        public void alertUser(String title, String message);

        public void statusPollLoop();

        public void setTargetControl(int viewId);
    }

}
