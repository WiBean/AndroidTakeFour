package com.wibean.android.wibean.util;

/**
 * Created by John-Michael on 8/4/2014.
 */
public class AveragingBuffer {

    private final int LENGTH = 5;
    private final float LENGTH_AS_FLOAT = LENGTH;
    Float[] mData = {0.f, 0.f, 0.f, 0.f, 0.f};
    private int mInsertPointer = 0;
    private float mSum = 0;
    private float mAverage = 0;

    public void add(float val) {
        mSum -= mData[mInsertPointer];
        mData[mInsertPointer++] = val;
        mInsertPointer = mInsertPointer % LENGTH;
        mSum += val;
        mAverage = mSum / LENGTH_AS_FLOAT;

    }

    public float average() {
        return mAverage;
    }
}
