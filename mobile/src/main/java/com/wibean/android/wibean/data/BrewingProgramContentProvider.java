package com.wibean.android.wibean.data;

import android.content.ContentProvider;
import android.content.ContentResolver;
import android.content.ContentValues;
import android.content.UriMatcher;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteQueryBuilder;
import android.net.Uri;
import android.text.TextUtils;

import java.util.Arrays;
import java.util.HashSet;

/**
 * Created by John-Michael on 7/10/2014.
 */
public class BrewingProgramContentProvider extends ContentProvider {
    public static final String CONTENT_TYPE = ContentResolver.CURSOR_DIR_BASE_TYPE
            + "/brewing_programs";
    public static final String CONTENT_ITEM_TYPE = ContentResolver.CURSOR_ITEM_BASE_TYPE
            + "/brewing_program";
    // used for the UriMacher
    private static final int BREWINGPROGRAMS = 10;
    private static final int BREWINGPROGRAMS_ID = 20;
    private static final String AUTHORITY = "com.wibean.android.wibean.data.contentprovider";
    private static final String BASE_PATH = "brewing_programs";
    public static final Uri CONTENT_URI = Uri.parse("content://" + AUTHORITY
            + "/" + BASE_PATH);
    private static final UriMatcher sURIMatcher = new UriMatcher(UriMatcher.NO_MATCH);

    static {
        sURIMatcher.addURI(AUTHORITY, BASE_PATH, BREWINGPROGRAMS);
        sURIMatcher.addURI(AUTHORITY, BASE_PATH + "/#", BREWINGPROGRAMS_ID);
    }

    // database
    private BrewingProgramHelper database;

    @Override
    public boolean onCreate() {
        database = new BrewingProgramHelper(getContext());
        return false;
    }

    @Override
    public Cursor query(Uri uri, String[] projection, String selection,
                        String[] selectionArgs, String sortOrder) {
        // Using SQLiteQueryBuilder instead of query() method
        SQLiteQueryBuilder queryBuilder = new SQLiteQueryBuilder();
        // check if the caller has requested a column which does not exists
        checkColumns(projection);
        // Set the table
        queryBuilder.setTables(BrewingProgramHelper.DATABASE_NAME);
        int uriType = sURIMatcher.match(uri);
        switch (uriType) {
            case BREWINGPROGRAMS:
                break;
            case BREWINGPROGRAMS_ID:
                // adding the ID to the original query
                // add in an rowID alias here, so it works with the Android things which expect
                // an ID column in the format '_ID'
                queryBuilder.appendWhere(BrewingProgramHelper.COLUMN_ID + "="
                        + uri.getLastPathSegment());
                break;
            default:
                throw new IllegalArgumentException("Unknown URI: " + uri);
        }
        SQLiteDatabase db = database.getWritableDatabase();
        Cursor cursor = queryBuilder.query(db, projection, selection,
                selectionArgs, null, null, sortOrder);
        // make sure that potential listeners are getting notified
        cursor.setNotificationUri(getContext().getContentResolver(), uri);
        return cursor;
    }

    @Override
    public String getType(Uri uri) {
        return null;
    }

    @Override
    public Uri insert(Uri uri, ContentValues values) {
        int uriType = sURIMatcher.match(uri);
        SQLiteDatabase sqlDB = database.getWritableDatabase();
        int rowsDeleted = 0;
        long id = 0;
        switch (uriType) {
            case BREWINGPROGRAMS:
                id = sqlDB.insert(BrewingProgramHelper.DATABASE_NAME, null, values);
                break;
            default:
                throw new IllegalArgumentException("Unknown URI: " + uri);
        }
        getContext().getContentResolver().notifyChange(uri, null);
        return Uri.parse(BASE_PATH + "/" + id);
    }

    @Override
    public int delete(Uri uri, String selection, String[] selectionArgs) {
        int uriType = sURIMatcher.match(uri);
        SQLiteDatabase sqlDB = database.getWritableDatabase();
        int rowsDeleted = 0;
        switch (uriType) {
            case BREWINGPROGRAMS:
                rowsDeleted = sqlDB.delete(BrewingProgramHelper.DATABASE_NAME, selection,
                        selectionArgs);
                break;
            case BREWINGPROGRAMS_ID:
                String id = uri.getLastPathSegment();
                if (TextUtils.isEmpty(selection)) {
                    rowsDeleted = sqlDB.delete(BrewingProgramHelper.DATABASE_NAME,
                            BrewingProgramHelper.COLUMN_ID + "=" + id,
                            null);
                } else {
                    rowsDeleted = sqlDB.delete(BrewingProgramHelper.DATABASE_NAME,
                            BrewingProgramHelper.COLUMN_ID + "=" + id
                                    + " and " + selection,
                            selectionArgs
                    );
                }
                break;
            default:
                throw new IllegalArgumentException("Unknown URI: " + uri);
        }
        getContext().getContentResolver().notifyChange(uri, null);
        return rowsDeleted;
    }

    @Override
    public int update(Uri uri, ContentValues values, String selection,
                      String[] selectionArgs) {

        int uriType = sURIMatcher.match(uri);
        SQLiteDatabase sqlDB = database.getWritableDatabase();
        int rowsUpdated = 0;
        switch (uriType) {
            case BREWINGPROGRAMS:
                rowsUpdated = sqlDB.update(BrewingProgramHelper.DATABASE_NAME,
                        values,
                        selection,
                        selectionArgs);
                break;
            case BREWINGPROGRAMS_ID:
                String id = uri.getLastPathSegment();
                if (TextUtils.isEmpty(selection)) {
                    rowsUpdated = sqlDB.update(BrewingProgramHelper.DATABASE_NAME,
                            values,
                            BrewingProgramHelper.COLUMN_ID + "=" + id,
                            null);
                } else {
                    rowsUpdated = sqlDB.update(BrewingProgramHelper.DATABASE_NAME,
                            values,
                            BrewingProgramHelper.COLUMN_ID + "=" + id
                                    + " and "
                                    + selection,
                            selectionArgs
                    );
                }
                break;
            default:
                throw new IllegalArgumentException("Unknown URI: " + uri);
        }
        getContext().getContentResolver().notifyChange(uri, null);
        return rowsUpdated;
    }

    private void checkColumns(String[] projection) {
        String[] available = {
                BrewingProgramHelper.COLUMN_ID, BrewingProgramHelper.COLUMN_ID_ALIASED_SELECT,

                BrewingProgramHelper.COLUMN_NAME, BrewingProgramHelper.COLUMN_DESCRIPTION,
                BrewingProgramHelper.COLUMN_ON_ONE, BrewingProgramHelper.COLUMN_OFF_ONE,
                BrewingProgramHelper.COLUMN_ON_TWO, BrewingProgramHelper.COLUMN_OFF_TWO,
                BrewingProgramHelper.COLUMN_ON_THREE, BrewingProgramHelper.COLUMN_OFF_THREE,
                BrewingProgramHelper.COLUMN_ON_FOUR, BrewingProgramHelper.COLUMN_OFF_FOUR,
                BrewingProgramHelper.COLUMN_ON_FIVE, BrewingProgramHelper.COLUMN_OFF_FIVE,
                BrewingProgramHelper.COLUMN_ORIGINAL_AUTHOR, BrewingProgramHelper.COLUMN_SHORT_URL,
                BrewingProgramHelper.COLUMN_CREATED_AT, BrewingProgramHelper.COLUMN_MODIFIED_AT,
                BrewingProgramHelper.COLUMN_IMAGE_THUMBNAIL_NAME};
        if (projection != null) {
            HashSet<String> requestedColumns = new HashSet<String>(Arrays.asList(projection));
            HashSet<String> availableColumns = new HashSet<String>(Arrays.asList(available));
            // check if all columns which are requested are available
            if (!availableColumns.containsAll(requestedColumns)) {
                throw new IllegalArgumentException("Unknown columns in projection");
            }
        }
    }
}
