package com.wibean.android.wibean.data;

import android.net.Uri;

import com.squareup.okhttp.MediaType;
import com.squareup.okhttp.OkHttpClient;
import com.squareup.okhttp.Request;
import com.squareup.okhttp.RequestBody;
import com.squareup.okhttp.Response;

import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.apache.http.NameValuePair;
import org.apache.http.client.utils.URLEncodedUtils;
import org.json.JSONObject;

import java.net.URI;
import java.util.List;

/**
 * Represents a single brewing program.
 */

public class BrewingProgram {
    public static final Integer NUMONOFFTIMES = 5;
    private Integer[] mOnTimes = new Integer[NUMONOFFTIMES];
    private Float[] mOnTimesAsSeconds = new Float[NUMONOFFTIMES];
    private Integer[] mOffTimes = new Integer[NUMONOFFTIMES];
    private Float[] mOffTimesAsSeconds = new Float[NUMONOFFTIMES];
    public static final Integer MIN_TIME_UNITS = 0;
    public static final Integer MAX_TIME_UNITS = 100;
    public static final String GOOGLE_SHORTEN_URL = "https://www.googleapis.com/urlshortener/v1/url";
    public static final MediaType JSON
            = MediaType.parse("application/json; charset=utf-8");
    // httpClient, make one to save resources
    private final OkHttpClient mHttpClient = new OkHttpClient();
    private String mId = "";
    private String mName = "";
    private String mDescription = "";
    private String mCreatedAt = "";
    private String mModifiedAt = "";
    private String mShortUrl = "";

    // CALCULATED FIELDS
    private long mTotalDurationInMilliseconds = 0;

    /**
     * Constructor
     *
     * @param id
     * @param name
     */
    public BrewingProgram(CharSequence id, CharSequence name) {
        zeroFields();
        setId(id.toString());
        setName(name.toString());
        setDescription("");
    }

    /**
     * Constructor
     * @param id
     * @param name
     * @param description
     * @param onTimes
     * @param offTimes
     */
    public BrewingProgram(CharSequence id, CharSequence name, CharSequence description, Integer[] onTimes, Integer[] offTimes) {
        zeroFields();
        setId(id.toString());
        setName(name.toString());
        setDescription(description.toString());
        setOnTimes(onTimes);
        setOffTimes(offTimes);
        calculateFields();
    }

    /**
     * Copy constructor.
     */
    public BrewingProgram(BrewingProgram copyFrom) {
        zeroFields();
        mId = new String(copyFrom.mId);
        mName = new String(copyFrom.mName);
        mDescription = new String(copyFrom.mDescription);
        mOnTimes = copyFrom.mOnTimes.clone();
        mOnTimesAsSeconds = copyFrom.mOnTimesAsSeconds.clone();
        mOffTimes = copyFrom.mOffTimes.clone();
        mOffTimesAsSeconds = copyFrom.mOffTimesAsSeconds.clone();
        mCreatedAt = new String(copyFrom.mCreatedAt);
        mModifiedAt = new String(copyFrom.mModifiedAt);
        mShortUrl = new String(copyFrom.mShortUrl);
        calculateFields();
    }

    public static BrewingProgram fromUri(Uri androidUri) {
        BrewingProgram newGuy = new BrewingProgram("", "");
        try {
            List<NameValuePair> params = URLEncodedUtils.parse(new java.net.URI(androidUri.toString()), "UTF-8");
            for (int k = 0; k < params.size(); ++k) {
                newGuy.parseNameValuePair(params.get(k));
                System.out.println("key: " + params.get(k).getName() + " value: " + params.get(k).getValue());
            }
            newGuy.calculateFields();
        } catch (Exception e) {
            // crap
        }
        return newGuy;
    }

    private void zeroFields() {
        for (int k = 0; k < NUMONOFFTIMES; ++k) {
            mOnTimes[k] = 0;
            mOffTimes[k] = 0;
            mOnTimesAsSeconds[k] = 0.f;
            mOffTimesAsSeconds[k] = 0.f;
        }
    }

    /**
     * Equality overrides
     */
    public boolean equals(BrewingProgram another) {
        return (another instanceof BrewingProgram)
                && mId.equals(another.mId)
                && mName.equals(another.mName)
                && mDescription.equals(another.mDescription)
                && mOnTimes.equals(another.mOnTimes)
                && mOffTimes.equals(another.mOffTimes)
                && mCreatedAt.equals(another.mCreatedAt)
                && mModifiedAt.equals(another.mModifiedAt)
                && mShortUrl.equals(another.mShortUrl);
    }

    public int hashCode() {
        // you pick a hard-coded, randomly chosen, non-zero, odd number
        // ideally different for each class
        return new HashCodeBuilder(17, 37).
                append(mId).
                append(mName).
                append(mDescription).
                append(mOnTimes).
                append(mOffTimes).
                append(mCreatedAt).
                append(mModifiedAt).
                append(mShortUrl).
                toHashCode();
    }

    public final String getCreatedAt() {
        return mCreatedAt;
    }

    public void setCreatedAt(String createdAt) {
        mCreatedAt = new String(createdAt);
    }

    public final String getModifiedAt() {
        return mModifiedAt;
    }

    public void setModifiedAt(String modifiedAt) {
        mModifiedAt = new String(modifiedAt);
    }

    public final String getId() {
        return mId;
    }

    public final String getName() {
        return mName;
    }

    public final String getDescription() {
        return mDescription;
    }

    public final Integer[] getOnTimes() {
        return mOnTimes;
    }

    public final Float[] getOnTimesAsSeconds() {
        return mOnTimesAsSeconds;
    }
    public final Integer[] getOffTimes() {
        return mOffTimes;
    }

    public final Float[] getOffTimesAsSeconds() {
        return mOffTimesAsSeconds;
    }

    public boolean setId(String id) {
        mId = new String(id);
        return true;
    }

    public boolean setName(CharSequence name) {
        mName = new String(name.toString());
        return true;
    }

    public boolean setDescription(CharSequence description) {
        mDescription = new String(description.toString());
        return true;
    }

    public boolean setOnTimes(Integer[] onTimes) {
        if (onTimes.length > BrewingProgram.NUMONOFFTIMES) {
            return false;
        }
        int k = 0; //counter
        // make sure the times they gave are good
        for (; k < onTimes.length; k++) {
            if (onTimes[k] < 0) {
                return false;
            }
        }
        // fill the rest
        for (; k < BrewingProgram.NUMONOFFTIMES; k++) {
            onTimes[k] = 0;
        }
        mOnTimes = onTimes.clone();
        for (int m = 0; m < mOnTimes.length; ++m) {
            mOnTimesAsSeconds[m] = mOnTimes[m].floatValue() / 10.f;
        }
        calculateFields();
        return true;
    }

    public boolean setOffTimes(Integer[] offTimes) {
        if (offTimes.length > BrewingProgram.NUMONOFFTIMES) {
            return false;
        }
        int k = 0; //counter
        // make sure the times they gave are good
        for (; k < offTimes.length; k++) {
            if (offTimes[k] < 0) {
                return false;
            }
        }
        // fill the rest
        for (; k < BrewingProgram.NUMONOFFTIMES; k++) {
            offTimes[k] = 0;
        }
        mOffTimes = offTimes.clone();
        for (int m = 0; m < mOffTimes.length; ++m) {
            mOffTimesAsSeconds[m] = mOffTimes[m].floatValue() / 10.f;
        }
        calculateFields();
        return true;
    }

    public final String getShortUrl() {
        return mShortUrl;
    }

    public void setShortUrl(String shortUrl) {
        mShortUrl = new String(shortUrl);
    }

    public boolean shortenUrl() {
        final String bodyString = "{\"longUrl\": \"" + this.toUri().toString() + "\"}";
        RequestBody body = RequestBody.create(JSON, bodyString);
        Request request = new Request.Builder()
                .url(GOOGLE_SHORTEN_URL)
                .post(body)
                .build();
        try {
            Response response = mHttpClient.newCall(request).execute();
            // remove the newlines because there won't be any in this response and it messes up
            // the Java JSONObject parser
            final JSONObject bodyAsObject = new JSONObject(response.body().string().trim().replace("\n", ""));
            if ((response.code() == 200) &&
                    bodyAsObject.has("kind") &&
                    bodyAsObject.getString("kind").startsWith("urlshortener#url")) {
                setShortUrl(bodyAsObject.getString("id"));
                return true;
            }
            // if we get here, something was wrong
            System.out.println("bad response: " + response.body().string());
        } catch (Exception e) {
            System.out.println("getShortUrl Failed: " + e.getMessage() + ' ' + e.getClass());
        }
        return false;
    }

    public long getTotalDurationInMilliseconds() {
        return mTotalDurationInMilliseconds;
    }

    @Override
    public String toString() {
        return mName + mDescription;
    }

    public URI toUri() {
        StringBuilder queryString = new StringBuilder();
        queryString.append("name=").append(mName).append("&");
        queryString.append("description=").append(mDescription).append("&");
        queryString.append("modified_at=").append(mModifiedAt).append("&");
        queryString.append("created_at=").append(mCreatedAt).append("&");
        for (int k = 0; k < NUMONOFFTIMES; ++k) {
            queryString.append("onF[").append(k).append("]=").append(mOnTimes[k]).append("&");
            queryString.append("offF[").append(k).append("]=").append(mOffTimes[k]).append("&");
        }
        try {
            return new URI("http", "www.wibean.com", "/brewingProgram/v1", queryString.toString(), null);
        } catch (Exception e) {
            System.out.println("BrewingProgram::toUri failed: " + e.getLocalizedMessage());
            return null;
        }
    }

    public URI toSparkUri(String deviceId, String accessToken) {
        StringBuilder queryString = new StringBuilder();
        for (int k = 0; k < NUMONOFFTIMES; ++k) {
            queryString.append("onF[").append(k).append("]=").append(mOnTimes[k]).append("&");
            queryString.append("offF[").append(k).append("]=").append(mOffTimes[k]).append("&");
        }
        try {
            return new URI("http", "www.wibean.com", "/brewingProgram/v1", queryString.toString(), null);
        } catch (Exception e) {
            System.out.println("BrewingProgram::toUri failed: " + e.getLocalizedMessage());
            return null;
        }
    }

    private void parseNameValuePair(NameValuePair thePair) {
        final String name = thePair.getName();
        switch (name) {
            case "name":
                setName(thePair.getValue());
                break;
            case "description":
                setDescription(thePair.getValue());
                break;
            case "created_at":
                setCreatedAt(thePair.getValue());
                break;
            default:
                // this version of the program only supports max 5 times, so multi-digit indecies are bad
                if (name.startsWith("onF[") && (name.length() == 6)) {
                    Integer index = Integer.valueOf(name.substring(4, 5));
                    if ((index > NUMONOFFTIMES) || (index < 0)) {
                        break;
                    }
                    Integer value = Integer.valueOf(thePair.getValue());
                    if ((value < MIN_TIME_UNITS) || (value > MAX_TIME_UNITS)) {
                        break;
                    }
                    mOnTimes[index] = value;
                } else if (name.startsWith("offF[") && (name.length() == 7)) {
                    Integer index = Integer.valueOf(name.substring(5, 6));
                    if ((index > NUMONOFFTIMES) || (index < 0)) {
                        break;
                    }
                    Integer value = Integer.valueOf(thePair.getValue());
                    if ((value < MIN_TIME_UNITS) || (value > MAX_TIME_UNITS)) {
                        break;
                    }
                    mOffTimes[index] = value;
                }
        }

    }

    private void calculateFields() {
        long totalTimeInMilliseconds = 0;
        for (int time : mOnTimes) {
            totalTimeInMilliseconds += time;
        }
        for (int time : mOffTimes) {
            totalTimeInMilliseconds += time;
        }
        mTotalDurationInMilliseconds = totalTimeInMilliseconds * 100; // each tick is 100ms
    }
}
