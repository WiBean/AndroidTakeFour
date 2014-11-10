package com.wibean.android.wibean.wibean;


import com.squareup.okhttp.Authenticator;
import com.squareup.okhttp.Credentials;
import com.squareup.okhttp.FormEncodingBuilder;
import com.squareup.okhttp.OkHttpClient;
import com.squareup.okhttp.Request;
import com.squareup.okhttp.RequestBody;
import com.squareup.okhttp.Response;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.IOException;
import java.net.Proxy;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;

/**
 * Created by John-Michael on 11/9/2014.
 */
public class SparkAuthenticator {
    private static final String URL_SPARK_BASE = "https://api.spark.io/";
    private static final String URL_GENERATE_TOKEN = "oauth/token/";
    private static final String URL_LIST_TOKENS = "v1/access_tokens/";
    private static final String URL_LIST_DEVICES = "v1/devices/";
    /*
    // ERROR CODES
    200 OK - API call successfully delivered to the Core and executed.
    400 Bad Request - Your request is not understood by the Core,
    or the requested subresource (variable/function) has not been exposed.
    401 Unauthorized - Your access token is not valid.
    403 Forbidden - Your access token is not authorized to interface with this Core.
    404 Not Found - The Core you requested is not currently connected to the cloud.
    408 Timed Out - The cloud experienced a significant delay when trying to reach the Core.
    500 Server errors - Fail whale. Something's wrong on our end.
    */

    private String mShortCode = "";
    private String mUsername = "";
    private String mPassword = "";
    private String mDeviceId = "";
    private String mAccessToken = "";
    // httpClients
    private final OkHttpClient mHttpClient = new OkHttpClient();
    private final OkHttpClient mHttpClientWithBasic = new OkHttpClient();
    private final OkHttpClient mHttpClientWithBasicForGeneration = new OkHttpClient();
    // used for date conversion
    private final DateFormat sDateFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSZ");
    private static final String TOKEN_EXPIRES_AT_FIELD = "expires_at";
    private static final String TOKEN_LIST_TOKEN_FIELD = "token";
    private static final String TOKEN_CREATED_TOKEN_FIELD = "access_token";
    private static final String DEVICE_ID_FIELD = "id";


    SparkAuthenticator(String shortCode) {
        setShortCode(shortCode);
    };
    SparkAuthenticator(String username, String password) {
        setUsernameAndPassword(username,password);
    };

    // First, you need a username and password
    public boolean setUsernameAndPassword(String username, String password) {
        boolean success = true;
        success &= setUsername(username);
        success &= setPassword(password);
        return success;
    };
    public boolean setUsername(String username) {
        if( username.isEmpty() ) {
            return false;
        }
        mUsername = username;
        updateRequestAuthenticator();
        return true;
    };
    public boolean setPassword(String password) {
        if( password.isEmpty() ) {
            return false;
        }
        mPassword = password;
        updateRequestAuthenticator();
        return true;
    }
    // Or a short code
    public boolean setShortCode(String shortcode) {
        if( !shortcode.contains("::") ) {
            return false;
        }
        mShortCode = shortcode;
        int sepIndex = mShortCode.lastIndexOf("::");
        // TODO: DEBuG THIS
        String username = mShortCode.substring(0,sepIndex) + ".silvia@wibean.de";
        String password = "JMF" + mShortCode.substring(sepIndex,mShortCode.length()) + "SF";
        return setUsernameAndPassword(username, password);
    };
    private void updateRequestAuthenticator() {
        mHttpClientWithBasic.setAuthenticator( new Authenticator() {
            @Override
            public Request authenticate(Proxy proxy, Response response) throws IOException {
                String credential = Credentials.basic(mUsername, mPassword);
                return response.request().newBuilder().header("Authorization", credential).build();
            }
            @Override
            public Request authenticateProxy(Proxy proxy, Response response) throws IOException {
                return null;
            }
        });
        mHttpClientWithBasicForGeneration.setAuthenticator( new Authenticator() {
            @Override
            public Request authenticate(Proxy proxy, Response response) throws IOException {
                String credential = Credentials.basic("spark", "spark");
                return response.request().newBuilder().header("Authorization", credential).build();
            }
            @Override
            public Request authenticateProxy(Proxy proxy, Response response) throws IOException {
                return null;
            }
        });
    };

    private boolean hasUsefulCredentials() {
        return !mUsername.isEmpty() && !mPassword.isEmpty();
    };

    // Then, you need a valid access token
    private boolean getValidAccessToken() {
        if( mAccessToken.isEmpty() ) {
            if( hasUsefulCredentials() ) {
                return false;
            }
            else {
                if( !findExistingToken() ) {
                    return createNewToken();
                }
                else {
                    return true;
                }
            }
        }
        else {
            return true;
        }
    };

    private boolean findExistingToken() {
        if( !hasUsefulCredentials() ) {
            return false;
        }
        boolean success = false;
        try {
            StringBuilder targetURL = new StringBuilder();
            targetURL.append(URL_SPARK_BASE).append(URL_LIST_TOKENS);
            Request.Builder builder = new Request.Builder().url(targetURL.toString());
            Request request = builder.build();
            Response response = mHttpClientWithBasic.newCall(request).execute();
            final JSONArray bodyAsObject = new JSONArray(response.body().string().trim().replace("\n", ""));
            switch( response.code() ) {
                case 200:
                    // ok, loop through all tokens to see if we have a valid one
                    long nowAsTime = Calendar.getInstance().getTime().getTime();
                    int bestTokenIndex = -1;
                    long longestDiff = 0;
                    String bestAccessToken = "";
                    for(int k=0;k<bodyAsObject.length();k++) {
                        final JSONObject obj = bodyAsObject.getJSONObject(k);
                        if( !obj.has(TOKEN_EXPIRES_AT_FIELD) ) {
                            continue;
                        }
                        Date expiresAt = sDateFormat.parse(obj.getString(TOKEN_EXPIRES_AT_FIELD));
                        long timeDiff = expiresAt.getTime() - nowAsTime;
                        if( timeDiff > longestDiff ) {
                            longestDiff = timeDiff;
                            bestTokenIndex = k;
                            bestAccessToken = obj.getString(TOKEN_LIST_TOKEN_FIELD);
                        }
                    }
                    if( bestTokenIndex != -1 ) {
                        mAccessToken = bestAccessToken;
                        success = true;
                    }
                    else {
                        // if no valid tokens, fail
                    }
                    break;
                case 400:
                case 401:
                case 403:
                case 404:
                    // shouldn't be here
                case 408:
                    // TODO: throw a timeout?
                case 500:
                    // TODO: indicate server failure?
                    System.out.println("findExistingToken: code: " + response.code());
                    break;

            }
        } catch (Exception e) {
            System.out.println("findExistingToken failed: " + e.getMessage() + ' ' + e.getClass());
        }
        return success;
    };

    private boolean createNewToken() {
        if( !hasUsefulCredentials() ) {
            return false;
        }
        boolean success = false;
        try {
            StringBuilder targetURL = new StringBuilder();
            targetURL.append(URL_SPARK_BASE).append(URL_GENERATE_TOKEN);
            Request.Builder builder = new Request.Builder().url(targetURL.toString());
            RequestBody formBody = new FormEncodingBuilder()
                    .add("grant_type", "password")
                    .add("username", mUsername)
                    .add("password", mPassword)
                    .build();
            builder.post(formBody);
            Request request = builder.build();
            Response response = mHttpClientWithBasicForGeneration.newCall(request).execute();
            final JSONObject bodyAsObject = new JSONObject(response.body().string().trim().replace("\n", ""));
            switch( response.code() ) {
                case 200:
                    // pull off the token
                    if( !bodyAsObject.has(TOKEN_CREATED_TOKEN_FIELD) ) {
                        mAccessToken = bodyAsObject.getString(TOKEN_CREATED_TOKEN_FIELD);
                        success = true;
                    }
                    else {
                        // SHOULDN'T HAPPEN
                    }
                    break;
                case 400:
                case 401:
                case 403:
                case 404:
                    // shouldn't be here
                case 408:
                    // TODO: throw a timeout?
                case 500:
                    // TODO: indicate server failure?
                    System.out.println("createNewToken: code: " + response.code());
                    break;

            }
        } catch (Exception e) {
            System.out.println("createNewToken failed: " + e.getMessage() + ' ' + e.getClass());
        }
        return success;
    };

    // And finally, you need a valid device ID
    private boolean fetchDeviceId() {
        return fetchDeviceId(false);
    }
    private boolean fetchDeviceId(boolean fastFail) {
        if( !getValidAccessToken() ) {
            return false;
        }
        boolean success = false;
        try {
            StringBuilder targetURL = new StringBuilder();
            targetURL.append(URL_SPARK_BASE).append(URL_LIST_DEVICES);
            targetURL.append("?").append(mAccessToken);
            Request request =  new Request.Builder().url(targetURL.toString()).build();
            Response response = mHttpClient.newCall(request).execute();
            final JSONArray bodyAsObject = new JSONArray(response.body().string().trim().replace("\n", ""));
            switch( response.code() ) {
                case 200:
                    // pull off the first device
                    for(int k=0;k<bodyAsObject.length();k++) {
                        final JSONObject obj = bodyAsObject.getJSONObject(k);
                        if( !obj.has(DEVICE_ID_FIELD) ) {
                            continue;
                        }
                        mDeviceId = obj.getString(DEVICE_ID_FIELD);
                        success = true;
                    }
                    break;
                case 401:
                case 403:
                    // generate new token if allowed
                    if( !fastFail ) {
                        createNewToken();
                        fetchDeviceId(true);
                    }
                    break;
                case 400:
                case 404:
                    // shouldn't be here
                case 408:
                    // TODO: throw a timeout?
                case 500:
                    // TODO: indicate server failure?
                    System.out.println("fetchDeviceId: code: " + response.code());
                    break;
            }
        } catch (Exception e) {
            //responseText.setText("Err chk heat: " + e.getMessage() + ' ' + e.getClass());
            System.out.println("fetchDeviceId failed: " + e.getMessage() + ' ' + e.getClass());
        }
        return success;
    };


    // Now, you can use it!
    public boolean populateCredentials() {
        if( getValidAccessToken() ) {
            if( fetchDeviceId() ) {
                return true;
            }
        }
        return false;
    }

    public String getDeviceId() {
        return mDeviceId;
    }
    public String getAccessToken() {
        return mAccessToken;
    }


}
