package com.wibean.android.wibean;

import android.app.Activity;
import android.app.Fragment;
import android.content.Context;
import android.net.ConnectivityManager;
import android.net.DhcpInfo;
import android.net.NetworkInfo;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;
import android.os.AsyncTask;
import android.os.Bundle;
import android.os.Handler;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ProgressBar;

import com.integrity_project.smartconfiglib.FirstTimeConfig;
import com.integrity_project.smartconfiglib.FirstTimeConfigListener;

import java.net.InetAddress;


/**
 * A simple {@link Fragment} subclass.
 * Activities that contain this fragment must implement the
 * {@link com.wibean.android.wibean.SmartConfigFragment.SmartConfigFragmentListener} interface
 * to handle interaction events.
 * Use the {@link SmartConfigFragment#newInstance} factory method to
 * create an instance of this fragment.
 */
public class SmartConfigFragment extends Fragment
        implements View.OnClickListener,
        // this is used as a responder to the wifi interface
        FirstTimeConfigListener {

    private final FirstTimeConfigListener mSmartConfigListener = this;
    private SmartConfigFragmentListener mListener;
    // fields
    private EditText mSsid_field;
    private String mSsid;
    private EditText mPassword_field;
    private String mPassword;
    private EditText mAesKey_field;
    private String mAesKey = "";
    private ProgressBar mProgressBar;
    private String mGatewayIpAddress;
    private Button mConnectButton;
    private boolean mIsSearching = false;
    private FirstTimeConfig mWifiConfig;
    // Handler allows us to run actions on the GUI thread, and post delayed events
    private Handler mHandler = new Handler();

    public SmartConfigFragment() {
        // Required empty public constructor
    }

    /**
     * Use this factory method to create a new instance of
     * this fragment using the provided parameters.
     *
     * @return A new instance of fragment SmartConfigFragment.
     */
    public static SmartConfigFragment newInstance() {
        SmartConfigFragment fragment = new SmartConfigFragment();
        Bundle args = new Bundle();
        fragment.setArguments(args);
        return fragment;
    }

    /**
     * ****************
     * USER FUNCTIONS
     * ***************
     */
    // Utility used for convertin IP addresses below
    static public byte[] toIPByteArray(int addr) {
        return new byte[]{(byte) addr, (byte) (addr >>> 8), (byte) (addr >>> 16), (byte) (addr >>> 24)};
    }

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        if (getArguments() != null) {
        }
    }

    @Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container,
                             Bundle savedInstanceState) {
        super.onCreateView(inflater, container, savedInstanceState);
        // note here, we don't attachToParent because fragments auto-attach whatever is returned in onCreateView
        View v = inflater.inflate(
                R.layout.fragment_smart_config_wifi, container, false);
        mSsid_field = (EditText) v.findViewById(R.id.et_ssid);
        mPassword_field = (EditText) v.findViewById(R.id.et_password);
        mAesKey_field = (EditText) v.findViewById(R.id.et_aesKey);
        mConnectButton = (Button) v.findViewById(R.id.btn_startWifiConfig);
        mProgressBar = (ProgressBar) v.findViewById(R.id.config_progress);

        // hookup button
        ((Button) v.findViewById(R.id.btn_startWifiConfig)).setOnClickListener(this);
        return v;
    }

    @Override
    public void onAttach(Activity activity) {
        super.onAttach(activity);
        try {
            mListener = (SmartConfigFragmentListener) activity;
        } catch (ClassCastException e) {
            throw new ClassCastException(activity.toString()
                    + " must implement OnFragmentInteractionListener");
        }
    }

    @Override
    public void onDetach() {
        super.onDetach();
        mListener = null;
    }

    @Override
    public void onResume() {
        super.onResume();
        checkWifiDetails(getActivity());
    }

    /**
     * *************
     * INTERFACES
     * ***************
     */

    // handle onClick in the fragment, yay Android Fragments
    @Override
    public void onClick(View v) {
        switch (v.getId()) {
            case R.id.btn_startWifiConfig:
                onClick_testCredentials(v);
                break;
        }
    }

    /**
     * Callback for Failure or success of the SmartConfig.jar library api
     */
    @Override
    public void onFirstTimeConfigEvent(final FtcEvent arg0, final Exception arg1) {
        // this code comes from TI.  Would be nice to not need 'just in case?' measures...
        try {
            /**
             * Adding the Try catch just to ensure the event doesnt retrun null.Some times observed null from Lib file.Just a safety measure
             */
            arg1.printStackTrace();
        } catch (Exception e) {
        }
        mHandler.post(new Runnable() {
            @Override
            public void run() {
                handleFtcEventInMainThread(arg0, arg1);
            }
        });
    }

    public void handleFtcEventInMainThread(FtcEvent arg0, Exception arg1) {
        /**
         * According to https://github.com/george-hawkins we need to call stopBroadcasting no matter
         * what because sometimes the TI code doesn't stop broadcasting even if it should
         */
        try {
            AsyncTask<Void, Integer, Boolean> task = new SmartConfigToggleTransmitTask().execute();
        } catch (Exception e) {
            e.printStackTrace();
        }
        // Handle the rest
        switch (arg0) {
            case FTC_ERROR:
                // alert user fail
                mListener.alertUser(getString(R.string.alert_connectionFailure), getString(R.string.alert_connectionTimeout));
                break;
            case FTC_SUCCESS:
                // alert user success
                mListener.alertUser(getString(R.string.alert_noConnectionTitle), getString(R.string.alert_connectionSuccess));
                break;
            case FTC_TIMEOUT:
                // we just timed out
                mListener.alertUser(getString(R.string.alert_noConnectionTitle), getString(R.string.alert_connectionTimeout));
                break;
            default:
                break;
        }
        System.out.println("FTC Received!: " + arg0);
    }


    /**
     * *************
     * UI RESPONDERS
     * *************
     */

    public void onClick_testCredentials(View v) {
        try {
            AsyncTask<Void, Integer, Boolean> task = new SmartConfigToggleTransmitTask().execute();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    ;

    private void checkWifiDetails(Context context) {
        ConnectivityManager connManager = (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
        NetworkInfo networkInfo = connManager.getNetworkInfo(ConnectivityManager.TYPE_WIFI);
        if (networkInfo.isConnected()) {
            final WifiManager wifiManager = (WifiManager) context.getSystemService(Context.WIFI_SERVICE);
            final WifiInfo connectionInfo = wifiManager.getConnectionInfo();
            final DhcpInfo dhcp = wifiManager.getDhcpInfo();
            if (connectionInfo != null && !connectionInfo.getSSID().isEmpty()) {
                /**
                 * From http://developer.android.com/reference/android/net/wifi/WifiInfo.html#getSSID()
                 * If the SSID can be decoded as UTF-8, it will be returned surrounded by double
                 * quotation marks. Otherwise, it is returned as a string of hex digits. The SSID
                 * may be null if there is no network currently connected.
                 */
                mSsid = connectionInfo.getSSID().replace("\"", "");
                try {
                    mGatewayIpAddress = InetAddress.getByAddress(toIPByteArray(dhcp.gateway)).getHostAddress().toString();
                } catch (Exception e) {
                    System.out.println("Bad gateway IP address from DhcpInfo: " + String.valueOf(dhcp.gateway));
                }
            }
            mSsid_field.setText(mSsid);
            mSsid_field.setEnabled(false);
            mConnectButton.setEnabled(true);

        } else {
            mConnectButton.setEnabled(false);
            // notify user to connect to Wifi
            mListener.alertUser(getString(R.string.alert_noConnectionTitle), getString(R.string.alert_noConnection_wifiNotConnected));
        }
    }

    /**
     * This interface must be implemented by activities that contain this
     * fragment to allow an interaction in this fragment to be communicated
     * to the activity and potentially other fragments contained in that
     * activity.
     */
    public interface SmartConfigFragmentListener {
        public void alertUser(String title, String message);
    }

    private class SmartConfigToggleTransmitTask extends AsyncTask<Void, Integer, Boolean> {
        protected void onPreExecute() {
            mConnectButton.setEnabled(false);
            mSsid = mSsid_field.getText().toString().trim();
            mPassword = mPassword_field.getText().toString().trim();
            mAesKey = mAesKey_field.getText().toString().trim();
            if ((mAesKey == null) || (mAesKey.length() != 16)) {
                mAesKey = SmartConfigFragment.this.getActivity().getString(R.string.default_smartConfig_aes_key);
            }
            System.out.println("SmartConfig: ssid: " + mSsid + " pw: " + mPassword + " gateway: " + mGatewayIpAddress);

            // flip the button for visuals
            if (!mIsSearching) {
                mConnectButton.setBackgroundResource(R.drawable.smartconfig_btn_selector_running);
                mConnectButton.setText(getResources().getString(R.string.label_smartConfig_stop));
                mProgressBar.setVisibility(View.VISIBLE);
            } else {
                mConnectButton.setBackgroundResource(R.drawable.smartconfig_btn_selector_waiting);
                mConnectButton.setText(getResources().getString(R.string.label_smartConfig_start));
                mProgressBar.setVisibility(View.INVISIBLE);
            }
        }

        protected Boolean doInBackground(Void... voids) {
            if (mIsSearching) {
                // stop
                if (mWifiConfig == null) {
                    return false;
                }
                try {
                    mWifiConfig.stopTransmitting();
                    mIsSearching = false;
                } catch (Exception e) {
                    e.printStackTrace();
                    return false;
                }
            } else {
                try {
                    mWifiConfig = new FirstTimeConfig(mSmartConfigListener, mPassword, mAesKey.getBytes(), mGatewayIpAddress, mSsid);
                    mWifiConfig.transmitSettings();
                    mIsSearching = true;
                } catch (Exception e) {
                    e.printStackTrace();
                    return false;
                }
            }
            return true;
        }

        protected void onPostExecute(Boolean result) {
            mConnectButton.setEnabled(true);
        }
    }

}
