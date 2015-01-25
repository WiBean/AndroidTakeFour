package com.wibean.android.wibean.wibean;

import com.wibean.android.wibean.data.BrewingProgram;
import com.squareup.okhttp.FormEncodingBuilder;
import com.squareup.okhttp.MediaType;
import com.squareup.okhttp.OkHttpClient;
import com.squareup.okhttp.Request;
import com.squareup.okhttp.RequestBody;
import com.squareup.okhttp.Response;

import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.apache.http.HttpStatus;
import org.json.JSONObject;

import java.util.concurrent.TimeUnit;

/**
 * Created by John-Michael on 7/7/2014.
 * This class models the state of a running WiBean unit so that we don't store the remote state
 * in the UI components of the client program (evil).
 */
public class WiBeanSparkState {

    // single access code which can be used to generate the deviceID and accessToken
    public static final String PREF_KEY_ACCESS_CODE = "WIBEAN_ACCESS_CODE";
    public static final String PREF_KEY_BREW_TEMP = "BREW_TEMP_IDEAL";
    public static final String PREF_KEY_DEVICE_TIMEZONE = "SPARK_TIME_ZONE";
    public static final String PREF_KEY_ALARM_TIME_HOUR = "ALARM_TIME_HOUR";
    public static final String PREF_KEY_ALARM_TIME_MINUTE = "ALARM_TIME_MINUTE";

    public static final int RETURN_CODE_PUMP_SUCCESS = 1;
    public static final int RETURN_CODE_PUMP_INVALID_PROGRAM = -1;
    public static final int RETURN_CODE_PUMP_BUSY = -2;
    public static final int RETURN_CODE_PUMP_CANCELLED = 2;
    public static final int RETURN_CODE_BAD_CREDENTIALS = -3;
    public static final MediaType TEXT
            = MediaType.parse("application/json; charset=utf-8");
    // constants
    public static final int MIN_TEMP = 20;
    public static final int MAX_TEMP = 120;
    private final String SPARK_BASE_URL = "https://api.spark.io/v1/devices/";
    // httpClient, make one to save resources
    private final OkHttpClient mHttpClient = new OkHttpClient();
    // Status variables which are user modifiable
    private boolean mHeatingLocal = false;
    private boolean mHeatingRemote = false;
    private float mDesiredTemperatureInCelsiusLocal = 92;
    private float mDesiredTemperatureInCelsiusRemote = 92;
    private WiBeanAlarmPackV1 mAlarmLocal = new WiBeanAlarmPackV1();
    private WiBeanAlarmPackV1 mAlarmRemote = new WiBeanAlarmPackV1();
    // Status variables which are read-only
    private float mCurrentHeadTemperatureInCelsius = 0;
    private float mCurrentAmbientTemperatureInCelsius = 0;
    private boolean mBrewing = false;
    private boolean mHasConnected = false;
    private CONNECTION_STATE mConnectionState = CONNECTION_STATE.DISCONNECTED;
    private String mSparkDeviceId = "";
    private String mSparkAccessToken = "";
    private String mAccessCode = "";
    private int mRequestTimeoutInSeconds = 10; //sane default, updated later
    private int mMachineTimeAsMinutesAfterMidnight = 0;
    private SparkAuthenticator mAuthenticator = new SparkAuthenticator();

    public WiBeanSparkState() {
        setRequestTimeout(8);
    }

    public boolean isHeating() {
        return this.mHeatingRemote;
    }

    public boolean isHeatingLocal() {
        return this.mHeatingLocal;
    }

    public boolean isBrewing() {
        return this.mBrewing;
    }

    public boolean setHeating(boolean heating) {
        this.mHeatingLocal = heating;
        return true;
    };

    public boolean setTemperature(float desiredTemperature) {
        this.mDesiredTemperatureInCelsiusLocal = Math.min(Math.max(desiredTemperature, MIN_TEMP), MAX_TEMP);
        return true;
    };

    public boolean setAccessCode(String accessCode) {
        this.mAccessCode = accessCode;
        return mAuthenticator.setAccessCode(mAccessCode);
    };

    public boolean setAlarm(WiBeanAlarmPackV1 alarm) {
        mAlarmLocal = new WiBeanAlarmPackV1(alarm);
        return true;
    }

    public WiBeanAlarmPackV1 getAlarm() {
        return new WiBeanAlarmPackV1(this.mAlarmRemote);
    }


    /**
     * Send the request to set the heat temperature
     * NOTE: This should not be called unless mConnectionState is connected.
     * @return
     */
    private boolean sendTemperature() {
        if (mDesiredTemperatureInCelsiusLocal == mDesiredTemperatureInCelsiusRemote) {
            return true;
        }
        StringBuilder targetURL = new StringBuilder();
        targetURL.append(assembleBaseUrl()).append("heatTarget");
        StringBuilder paramBuilder = new StringBuilder();
        // it doesn't make sense to specify more than single degrees
        paramBuilder.append(String.format("%.0f", mDesiredTemperatureInCelsiusLocal));
        RequestBody formBody = new FormEncodingBuilder()
                .add("access_token", mSparkAccessToken)
                .add("params", paramBuilder.toString())
                .build();
        boolean success = (basicSparkFunctionPost(targetURL.toString(), formBody) == 1);
        if (success) {
            mDesiredTemperatureInCelsiusRemote = mDesiredTemperatureInCelsiusLocal;
        }
        return success;
    };


    /**
     * Take control of the machine, so WiBean is in charge of heating.
     * NOTE: This should not be called unless mConnectionState is connected.
     * @return
     */
    private boolean makeHeat() {
        setTemperature(mDesiredTemperatureInCelsiusLocal);
        mHeatingLocal = true;
        if (mHeatingRemote == mHeatingLocal) {
            return true;
        }
        StringBuilder targetURL = new StringBuilder();
        targetURL.append(assembleBaseUrl()).append("heatToggle");
        StringBuilder paramBuilder = new StringBuilder();
        // it doesn't make sense to specify more than single degrees
        paramBuilder.append(1);
        RequestBody formBody = new FormEncodingBuilder()
                .add("access_token", mSparkAccessToken)
                .add("params", paramBuilder.toString())
                .build();
        boolean success = (basicSparkFunctionPost(targetURL.toString(), formBody) == 1);
        if (success) {
            mHeatingRemote = true;
        }
        return success;
    }

    /**
     * Disable the heating circuit on the WiBean
     * NOTE: This should not be called unless mConnectionState is connected.
     * @return
     */
    private boolean makeHibernate() {
        mHeatingLocal = false;
        if (mHeatingRemote == mHeatingLocal) {
            return true;
        }
        StringBuilder targetURL = new StringBuilder();
        targetURL.append(assembleBaseUrl()).append("heatToggle");
        StringBuilder paramBuilder = new StringBuilder();
        // it doesn't make sense to specify more than single degrees
        paramBuilder.append(0);
        RequestBody formBody = new FormEncodingBuilder()
                .add("access_token", mSparkAccessToken)
                .add("params", paramBuilder.toString())
                .build();
        boolean success = (basicSparkFunctionPost(targetURL.toString(), formBody) == 1);
        if (success) {
            mHeatingRemote = false;
        }
        return success;
    }

    /**
     * Update the alarm, and timezone on the remote device.
     * NOTE: This should not be called unless mConnectionState is connected.
     * @return
     */
    private boolean sendAlarm() {
        if (mAlarmLocal.equals(mAlarmRemote)) {
            return true;
        }
        StringBuilder targetURL = new StringBuilder();
        targetURL.append(assembleBaseUrl()).append("toggleAlarm");
        StringBuilder paramBuilder = new StringBuilder();
        // it doesn't make sense to specify more than single degrees
        paramBuilder.append(mAlarmLocal.getOnTimeAsMinutesAfterMidnight());
        paramBuilder.append(",").append(mAlarmLocal.getUtcOffset());
        RequestBody formBody = new FormEncodingBuilder()
                .add("access_token", mSparkAccessToken)
                .add("params", paramBuilder.toString())
                .build();
        boolean success = (basicSparkFunctionPost(targetURL.toString(), formBody) == 1);
        if (success) {
            mAlarmRemote = new WiBeanAlarmPackV1(mAlarmLocal);
        }
        return success;
    }

    private int basicSparkFunctionPost(String targetUrl, RequestBody body) {
        Request.Builder builder = new Request.Builder().url(targetUrl);
        if (body != null) {
            builder.post(body);
        }
        Request request = builder.build();
        try {
            Response response = mHttpClient.newCall(request).execute();
            final JSONObject bodyAsObject = new JSONObject(response.body().string().trim().replace("\n", ""));
            if ((response.code() == 200) &&
                    bodyAsObject.has("return_value")) {
                int returnCode = Integer.valueOf(bodyAsObject.getString("return_value"));
                return returnCode;
            }
        } catch (Exception e) {
            //responseText.setText("Err chk heat: " + e.getMessage() + ' ' + e.getClass());
            System.out.println("basicSparkFunctionPost failed: " + e.getMessage() + ' ' + e.getClass());
        }
        return -99;
    }

    public float getHeadTemperature() {
        return mCurrentHeadTemperatureInCelsius;
    }

    /**
     * Sends a program to the machine for brewing.
     *
     * @param theProgram - program to brew
     * @return -1 on general failure
     * -2 if a program is already brewing
     */
    // reset control of the WiBean device so the machine acts as if we aren't even there.
    public int runBrewProgram(BrewingProgram theProgram) {
        if( !populateAccessCredentials() ) {
            return RETURN_CODE_BAD_CREDENTIALS;
        }
        boolean success = false;
        Integer[] onTimes = theProgram.getOnTimes();
        Integer[] offTimes = theProgram.getOffTimes();

        StringBuilder targetURL = new StringBuilder();
        targetURL.append(assembleBaseUrl()).append("pumpControl");
        StringBuilder paramBuilder = new StringBuilder();
        for (int k = 0; k < onTimes.length; ++k) {
            paramBuilder.append(onTimes[k]).append(',').append(offTimes[k]).append(',');
        }
        final String targetUrlAsString = targetURL.toString();
        final String paramsAsString = paramBuilder.toString();
        RequestBody formBody = new FormEncodingBuilder()
                .add("access_token", mSparkAccessToken)
                .add("params", paramsAsString)
                .build();
        Request request = new Request.Builder()
                .url(targetUrlAsString)
                .post(formBody)
                .build();
        try {
            Response response = mHttpClient.newCall(request).execute();
            final JSONObject bodyAsObject = new JSONObject(response.body().string().trim().replace("\n", ""));
            if ((response.code() == HttpStatus.SC_OK ) &&
                    bodyAsObject.has("return_value")) {
                int returnCode = Integer.valueOf(bodyAsObject.getString("return_value"));
                return returnCode;
            }
        } catch (Exception e) {
            //responseText.setText("Err chk heat: " + e.getMessage() + ' ' + e.getClass());
            System.out.println("runProgram Failed: " + e.getMessage() + ' ' + e.getClass());
        }
        return 1;
    }



    /**
     * Query and update status.
     * Reset control of the WiBean device so the machine acts as if we aren't even there.
     * @return
     */
    public CONNECTION_STATE queryStatus() {
        if( !populateAccessCredentials() ) {
            return CONNECTION_STATE.INVALID_CREDENTIALS;
        }
        String targetURL = assembleBaseUrl() + "status?" + "access_token=" + mSparkAccessToken;
        Request request = new Request.Builder().url(targetURL).build();
        try {
            if (mConnectionState == CONNECTION_STATE.DISCONNECTED) {
                mConnectionState = CONNECTION_STATE.CONNECTING;
            }
            Response response = mHttpClient.newCall(request).execute();
            final JSONObject bodyAsObject = new JSONObject(response.body().string().trim().replace("\n", ""));
            if ((response.code() == HttpStatus.SC_OK) &&
                    bodyAsObject.has("result")) {
                final JSONObject statusAsObject = new JSONObject(bodyAsObject.getString("result"));
                // object contains the following
                // ala: alarm active
                // alt: alarm time as minutes after midnight (values greater than minutes_in_day imply will never fire)
                // b: boolean is machine currently in pumping cycle?
                // h: boolean, is machine currently seeking a goal temperature
                mHeatingRemote = (statusAsObject.getInt("h") != 0);
                mBrewing = statusAsObject.getBoolean("b");
                mCurrentHeadTemperatureInCelsius = (float) statusAsObject.getDouble("t_h");
                mCurrentAmbientTemperatureInCelsius = (float) statusAsObject.getDouble("t_a");
                mMachineTimeAsMinutesAfterMidnight = statusAsObject.getInt("tn");
                mDesiredTemperatureInCelsiusRemote = (float) statusAsObject.getDouble("t_g");
                mAlarmRemote.setOnTimeAsMinutesAfterMidnight(statusAsObject.getInt("alt"));
                mAlarmRemote.setUtcOffset(statusAsObject.getInt("clktz"));
                // if we just connected, set the local alarm time equal to the remote so it doesn't
                // get overwritten
                if (mConnectionState == CONNECTION_STATE.CONNECTING) {
                    mAlarmLocal.setOnTimeAsMinutesAfterMidnight(mAlarmRemote.getOnTimeAsMinutesAfterMidnight());
                    mDesiredTemperatureInCelsiusLocal = mDesiredTemperatureInCelsiusRemote;
                }
                mConnectionState = CONNECTION_STATE.CONNECTED;
            } else if ((response.code() == HttpStatus.SC_FORBIDDEN)
                    || (response.code() == HttpStatus.SC_UNAUTHORIZED)) {
                mConnectionState = CONNECTION_STATE.INVALID_CREDENTIALS;
            } else if ((response.code() == HttpStatus.SC_REQUEST_TIMEOUT)
                    || (response.code() == HttpStatus.SC_NOT_FOUND)) {
                mConnectionState = CONNECTION_STATE.TIMEOUT;
            }
            // 200 is success
            // 408 is timeout
            // 403 is bad credentials
            return mConnectionState;
        } catch (Exception e) {
            //responseText.setText("Err chk heat: " + e.getMessage() + ' ' + e.getClass());
            System.out.println("queryStatus Failed: " + e.getMessage() + ' ' + e.getClass());
        }
        // if we get here, something went wrong
        return CONNECTION_STATE.DISCONNECTED;
    }

    public int getMachineTimeAsMinutesAfterMidnight() {
        return mMachineTimeAsMinutesAfterMidnight;
    }

    /**
     * UTILITIES!
     */

    private String assembleBaseUrl() {
        return (SPARK_BASE_URL + mSparkDeviceId + "/");
    }

    /**
     * Returns whether or not the state of the local simulated device matches that of the remote
     * device.
     * @return
     */
    public boolean isSynchronized() {
        boolean syncd = true;
        syncd &= (mConnectionState == CONNECTION_STATE.CONNECTED);
        syncd &= (mHeatingLocal == mHeatingRemote);
        syncd &= mAlarmLocal.equals(mAlarmRemote);
        syncd &= (mDesiredTemperatureInCelsiusLocal == mDesiredTemperatureInCelsiusRemote);
        return syncd;
    }

    /**
     * Does the actual work of sending all the relevant commands to bring the remote device
     * into sync with the local device state desired by the user.
     * @return
     */
    public boolean synchronizeWithRemote() {
        // if we aren't connected, try.
        if (mConnectionState != CONNECTION_STATE.CONNECTED) {
            queryStatus();
        }
        // if we still aren't connected fail
        if (mConnectionState != CONNECTION_STATE.CONNECTED) {
            return false;
        }
        boolean success = true;
        success &= sendTemperature();
        if (mHeatingLocal) {
            success &= makeHeat();
        } else {
            success &= makeHibernate();
        }
        // update the alarm and timezone if needed
        success &= sendAlarm();
        return success;
    }

    public CONNECTION_STATE getConnectionState() {
        return mConnectionState;
    }

    /**
     * Uses the authenticator to generate the deviceID and AccessToken needed to send all
     * spark requests.
     * @return
     */
    private boolean populateAccessCredentials() {
        if( mAuthenticator.populateCredentials() ) {
            mSparkDeviceId = mAuthenticator.getDeviceId();
            mSparkAccessToken = mAuthenticator.getAccessToken();
            return true;
        }
        return false;
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

    public static enum CONNECTION_STATE {
        DISCONNECTED,
        CONNECTING,
        CONNECTED,
        INVALID_CREDENTIALS,
        TIMEOUT
    }

    static public class WiBeanAlarmPackV1 {
        public static final int MINUTES_IN_DAY = 24 * 60;

        private int mOnTimeAsMinutesAfterMidnight;
        private boolean mAlarmArmed;
        private int mUtcOffset = 0;

        /**
         * Copy constructor.
         */
        public WiBeanAlarmPackV1(WiBeanAlarmPackV1 pack) {
            this.setOnTimeAsMinutesAfterMidnight(pack.mOnTimeAsMinutesAfterMidnight);
            this.mUtcOffset = pack.mUtcOffset;
        }

        public WiBeanAlarmPackV1() {
            setOnTimeAsMinutesAfterMidnight(480);
        }

        /**
         * Equality overrides
         */
        public boolean equals(WiBeanAlarmPackV1 another) {
            return (another instanceof WiBeanAlarmPackV1)
                    && (another.mOnTimeAsMinutesAfterMidnight == this.mOnTimeAsMinutesAfterMidnight)
                    && (another.mUtcOffset == this.mUtcOffset)
                    && (another.mAlarmArmed == this.mAlarmArmed);
        }

        public int hashCode() {
            // you pick a hard-coded, randomly chosen, non-zero, odd number
            // ideally different for each class
            return new HashCodeBuilder(17, 37).
                    append(mUtcOffset).
                    append(mOnTimeAsMinutesAfterMidnight).
                    append(mAlarmArmed).
                    toHashCode();
        }

        public int getOnTimeAsMinutesAfterMidnight() {
            return mOnTimeAsMinutesAfterMidnight;
        }

        public void setOnTimeAsMinutesAfterMidnight(int mOnTimeAsMinutesAfterMidnight) {
            this.mOnTimeAsMinutesAfterMidnight = mOnTimeAsMinutesAfterMidnight;
            mAlarmArmed = (this.mOnTimeAsMinutesAfterMidnight < MINUTES_IN_DAY);
        }

        public boolean setUtcOffset(int utcOffset) {
            if (Math.abs(utcOffset) > 12) {
                return false;
            } else {
                mUtcOffset = utcOffset;
                return true;
            }
        }

        public int getUtcOffset() {
            return mUtcOffset;
        }

        public boolean getAlarmArmed() {
            return mAlarmArmed;
        }


    }
}
