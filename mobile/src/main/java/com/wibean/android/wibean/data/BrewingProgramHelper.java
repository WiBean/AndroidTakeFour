package com.wibean.android.wibean.data;

import android.content.ContentValues;
import android.content.Context;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;

/**
 * Created by John-Michael on 7/10/2014.
 * This class describes
 * - The SQLite database which contains the brewing programs
 * - A convenience method for seeding the database with programs
 */
public class BrewingProgramHelper extends SQLiteOpenHelper {

    // DB NAME
    public static final String DATABASE_NAME = "brewing_programs";
    public static final String COLUMN_ID = "_rowid_";
    public static final String COLUMN_ID_ALIASED_SELECT = "_rowid_ AS _id";
    public static final String COLUMN_ID_ALIASED = "_id";
    public static final String COLUMN_NAME = "name";
    public static final String COLUMN_DESCRIPTION = "description";
    public static final String COLUMN_ON_ONE = "on_one";
    public static final String COLUMN_OFF_ONE = "off_one";
    public static final String COLUMN_ON_TWO = "on_two";
    public static final String COLUMN_OFF_TWO = "off_two";
    public static final String COLUMN_ON_THREE = "on_three";
    public static final String COLUMN_OFF_THREE = "off_three";
    public static final String COLUMN_ON_FOUR = "on_four";
    public static final String COLUMN_OFF_FOUR = "off_four";
    public static final String COLUMN_ON_FIVE = "on_five";
    public static final String COLUMN_OFF_FIVE = "off_five";
    public static final String COLUMN_ORIGINAL_AUTHOR = "original_author";
    public static final String COLUMN_SHORT_URL = "short_url";
    public static final String COLUMN_CREATED_AT = "created_at";
    public static final String COLUMN_MODIFIED_AT = "modified_at";
    public static final String[] PROJECTION_DATA_COLUMNS_WITH_ID = {
            COLUMN_ID_ALIASED_SELECT,
            COLUMN_NAME,
            COLUMN_DESCRIPTION,
            COLUMN_ON_ONE, COLUMN_OFF_ONE,
            COLUMN_ON_TWO, COLUMN_OFF_TWO,
            COLUMN_ON_THREE, COLUMN_OFF_THREE,
            COLUMN_ON_FOUR, COLUMN_OFF_FOUR,
            COLUMN_ON_FIVE, COLUMN_OFF_FIVE,
            COLUMN_SHORT_URL,
            COLUMN_CREATED_AT, COLUMN_MODIFIED_AT
    };
    public static final String COLUMN_IMAGE_THUMBNAIL_NAME = "image_thumbnail_name";
    // DB Version
    private static final int DATABASE_VERSION = 2;

    public BrewingProgramHelper(Context context) {
        super(context, DATABASE_NAME, null, DATABASE_VERSION);
    }

    @Override
    public void onCreate(SQLiteDatabase db) {
        // SQL for creating table
        // WE LEAVE OFF AN ID COLUMN AND USE THE SQLITE FEATURE
        // _rowid_ for this purpose!!
        String CREATE_BREWINGPROGRAM_TABLE = "CREATE TABLE " + DATABASE_NAME + " ( " +
                COLUMN_NAME + " TEXT, " +
                COLUMN_DESCRIPTION + " TEXT, " +
                COLUMN_ON_ONE + " INTEGER, " +
                COLUMN_OFF_ONE + " INTEGER, " +
                COLUMN_ON_TWO + " INTEGER, " +
                COLUMN_OFF_TWO + " INTEGER, " +
                COLUMN_ON_THREE + " INTEGER, " +
                COLUMN_OFF_THREE + " INTEGER, " +
                COLUMN_ON_FOUR + " INTEGER, " +
                COLUMN_OFF_FOUR + " INTEGER, " +
                COLUMN_ON_FIVE + " INTEGER, " +
                COLUMN_OFF_FIVE + " INTEGER, " +
                COLUMN_ORIGINAL_AUTHOR + " TEXT DEFAULT \"\", " +
                COLUMN_SHORT_URL + " TEXT DEFAULT \"\", " +
                COLUMN_CREATED_AT + " TEXT DEFAULT current_timestamp, " +
                COLUMN_MODIFIED_AT + " TEXT DEFAULT current_timestamp, " +
                COLUMN_IMAGE_THUMBNAIL_NAME + " TEXT DEFAULT \"basic_espresso\" ) ";


        // create brewing programs table
        db.execSQL(CREATE_BREWINGPROGRAM_TABLE);
        // add in some data
        createHelper(db, "Starter Program", "A basic program", 300, 0, 0, 0);
        createHelper(db, "Level One", "Some customization", 100, 30, 200, 20);
        createHelper(db, "Heavy Delay", "Allows a great steep time", 30, 50, 250, 0);
    }

    @Override
    public void onUpgrade(SQLiteDatabase db, int oldVersion, int newVersion) {
        // simple upgrade script which destroys old schema and initializes
        // new schema.
        // TODO: Make non-destructive upgrade script.
        // drop old if exists
        db.execSQL("DROP TABLE IF EXISTS " + DATABASE_NAME);
        // create the new version
        this.onCreate(db);
    }

    private void createHelper(SQLiteDatabase db, String name, String description, int onOne, int offOne, int onTwo, int offTwo) {
        ContentValues values = new ContentValues();
        values.put(COLUMN_NAME, name);
        values.put(COLUMN_DESCRIPTION, description);
        values.put(COLUMN_ON_ONE, onOne);
        values.put(COLUMN_OFF_ONE, offOne);
        values.put(COLUMN_ON_TWO, onTwo);
        values.put(COLUMN_OFF_TWO, offTwo);
        db.insert(DATABASE_NAME, null, values);
    }
}
