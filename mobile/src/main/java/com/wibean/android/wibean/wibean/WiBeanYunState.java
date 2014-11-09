package com.wibean.android.wibean.wibean;

import com.wibean.android.wibean.data.BrewingProgram;
import com.squareup.okhttp.OkHttpClient;
import com.squareup.okhttp.Request;
import com.squareup.okhttp.Response;

import java.util.concurrent.TimeUnit;

/**
 * Created by John-Michael on 7/7/2014.
 * This class models the state of a running WiBean unit so that we don't store the remote state
 * in the UI components of the client program (evil).
 */
public class WiBeanYunState {


    public static final String PREF_KEY_UNIT_IP = "REMOTE_IP_ADDRESS";
    public static final String PREF_KEY_BREW_TEMP = "BREW_TEMP_IDEAL";
    // constants
    public static final int MIN_TEMP = 20;
    public static final int MAX_TEMP = 120;
    // httpClient, make one to save resources
    private final OkHttpClient mHttpClient = new OkHttpClient();
    private WiBeanAlarmPack mAlarm = new WiBeanAlarmPack();
    // we are either in control or not.  In control means actively heating towards a goal temp.
    // REMEMBER: that goal temp can be really low, so effectively heating is 'off'
    private boolean mInControl = false;
    private int mDesiredTemperatureInCelsius = 45;
    private String mDeviceIp;
    private int mRequestTimeoutInSeconds;


    public WiBeanYunState() {
        setIpAddress("192.168.0.1");
        setRequestTimeout(5);
    }

    public boolean inControl() {
        return mInControl;
    }

    public boolean takeControl() {
        return takeControl(mDesiredTemperatureInCelsius);
    }

    // take control of the machine, so WiBean is in charge of heating
    public boolean takeControl(int desiredTemperature) {
        mDesiredTemperatureInCelsius = Math.min(Math.max(desiredTemperature, MIN_TEMP), MAX_TEMP);
        String targetURL = "http://" + mDeviceIp + "/arduino/heat/" + Integer.valueOf(desiredTemperature).toString();// + targetTempText.getText().toString().trim();
        Request request = new Request.Builder().url(targetURL).build();
        try {

            Response response = mHttpClient.newCall(request).execute();
            final String bodyAsString = response.body().string();
            //System.out.println("TakeControl Response: Header: " + response.code() + " Body: " + bodyAsString);
            if (bodyAsString.trim().startsWith("thermometerTemperatureInCelsius:")) {
                // only modify member if we know something happened
                mInControl = true;
                return true;
            }
        } catch (Exception e) {
            //responseText.setText("Err chk heat: " + e.getMessage() + ' ' + e.getClass());
            System.out.println("TakeControl Failed: " + e.getMessage() + ' ' + e.getClass());
        }
        return false;
    }

    // reset control of the WiBean device so the machine acts as if we aren't even there.
    public boolean returnControl() {
        if (!mInControl) {
            return false;
        }
        boolean success = false;
        String targetURL = "http://" + mDeviceIp + "/arduino/off/0";
        Request request = new Request.Builder().url(targetURL).build();
        try {
            Response response = mHttpClient.newCall(request).execute();
            final String bodyAsString = response.body().string();
            if (bodyAsString.trim().startsWith("STOP REQUESTED!")) {
                // only modify the member variable if we know something happened.
                mInControl = false;
                return true;
            }
        } catch (Exception e) {
            //responseText.setText("Err chk heat: " + e.getMessage() + ' ' + e.getClass());
            System.out.println("toggleHeating Failed: " + e.getMessage() + ' ' + e.getClass());
        }
        return false;
    }

    // reset control of the WiBean device so the machine acts as if we aren't even there.
    public boolean getTemperature(StringBuilder emptyBuilderForTemperatureReturn) {
        if (!mInControl) {
            return false;
        }
        String targetURL = "http://" + mDeviceIp + "/arduino/thermometer/0";
        Request request = new Request.Builder().url(targetURL).build();
        try {
            Response response = mHttpClient.newCall(request).execute();
            final String bodyAsString = response.body().string();
            final String tempPrefix = "thermometerTemperatureInCelsius:";
            final int charPointer = bodyAsString.lastIndexOf(tempPrefix);
            if (charPointer != -1) {
                emptyBuilderForTemperatureReturn.append(bodyAsString.substring(1 + charPointer + tempPrefix.length()).trim());
                return true;
            }
        } catch (Exception e) {
            //responseText.setText("Err chk heat: " + e.getMessage() + ' ' + e.getClass());
            System.out.println("getHeadTemperature Failed: " + e.getMessage() + ' ' + e.getClass());
        }
        // if we get here, something went wrong
        emptyBuilderForTemperatureReturn.append("ERR");
        return true;
    }

    // reset control of the WiBean device so the machine acts as if we aren't even there.
    public boolean runBrewProgram(BrewingProgram theProgram) {
        if (!mInControl) {
            return false;
        }
        boolean success = false;
        Integer[] onTimes = theProgram.getOnTimes();
        Integer[] offTimes = theProgram.getOffTimes();

        StringBuilder targetURL = new StringBuilder();
        targetURL.append("http://").append(mDeviceIp).append("/arduino/pump/");
        for (int k = 0; k < onTimes.length; ++k) {
            targetURL.append(onTimes[k]).append('/').append(offTimes[k]).append('/');
        }
        Request request = new Request.Builder().url(targetURL.toString()).build();
        try {
            Response response = mHttpClient.newCall(request).execute();
            final String bodyAsString = response.body().string();
            final int charPointer = bodyAsString.lastIndexOf("]");
            if (charPointer != -1) {
                return true;
            }
        } catch (Exception e) {
            //responseText.setText("Err chk heat: " + e.getMessage() + ' ' + e.getClass());
            System.out.println("runProgram Failed: " + e.getMessage() + ' ' + e.getClass());
        }
        return false;
    }


    /**
     * UTILITIES!
     */

    /**
     * Changes the target IP address of where to find the WiBean(Yun)
     *
     * @param ipAsString e.g. 192.168.1.144
     * @return
     */
    public boolean setIpAddress(CharSequence ipAsString) {
        if (ipAsString.length() > 19) {
            return false;
        }
        mDeviceIp = ipAsString.toString();
        return true;
    }

    /**
     * Sets the request timeout of all HTTP requests in the class, in seconds.
     *
     * @param timeout Requested timeout, in seconds.
     * @return True if requested timeout is greater than 1, otherwise false.
     */
    public boolean setRequestTimeout(int timeout) {
        if (timeout < 1) {
            return false;
        }
        mRequestTimeoutInSeconds = timeout;
        mHttpClient.setConnectTimeout(mRequestTimeoutInSeconds, TimeUnit.SECONDS);
        return true;
    }

    static public class WiBeanAlarmPack {
        public int mHeatTempInCelsius;
        public int mOnTimeAsMinutesAfterMidnight;
        public int mOnForInMinutes;

        public WiBeanAlarmPack() {
            mHeatTempInCelsius = 25;
            mOnTimeAsMinutesAfterMidnight = 480;
            mOnForInMinutes = 10;
        }
    }
}
