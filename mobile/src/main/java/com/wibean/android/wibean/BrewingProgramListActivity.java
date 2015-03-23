package com.wibean.android.wibean;

import android.app.ActionBar;
import android.app.Activity;
import android.app.AlertDialog;
import android.app.Fragment;
import android.app.FragmentManager;
import android.app.LoaderManager;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.ProgressDialog;
import android.app.TaskStackBuilder;
import android.content.ContentUris;
import android.content.ContentValues;
import android.content.Context;
import android.content.CursorLoader;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.Loader;
import android.content.SharedPreferences;
import android.database.Cursor;
import android.net.Uri;
import android.os.AsyncTask;
import android.os.Bundle;
import android.os.Handler;
import android.support.annotation.IdRes;
import android.support.v4.app.NotificationCompat;
import android.support.v4.widget.DrawerLayout;
import android.view.Menu;
import android.view.MenuItem;
import android.widget.EditText;
import android.widget.ProgressBar;
import android.widget.TextView;
import android.widget.Toast;

import com.google.android.gms.analytics.GoogleAnalytics;
import com.google.android.gms.analytics.Tracker;
import com.google.zxing.integration.android.IntentIntegrator;
import com.google.zxing.integration.android.IntentResult;
import com.wibean.android.wibean.data.BrewingProgram;
import com.wibean.android.wibean.data.BrewingProgramContentProvider;
import com.wibean.android.wibean.data.BrewingProgramHelper;
import com.wibean.android.wibean.wibean.WiBeanSparkState;
import com.squareup.okhttp.OkHttpClient;

import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.concurrent.Semaphore;

/**
 * An activity representing a list of BrewingPrograms. This activity
 * has different presentations for handset and tablet-size devices. On
 * handsets, the activity presents a list of items, which when touched,
 * lead to a {@link BrewingProgramDetailFragment} representing
 * item details. On tablets, the activity presents the list of items and
 * item details side-by-side using two vertical panes.
 * <p/>
 * The activity makes heavy use of fragments. The list of items is a
 * {@link BrewingProgramListFragment} and the item details
 * (if present) is a {@link BrewingProgramDetailFragment}.
 * <p/>
 * This activity also implements the required
 * {@link BrewingProgramListFragment.Callbacks} interface
 * to listen for item selections.
 */
public class BrewingProgramListActivity extends Activity
        implements BrewingProgramListFragment.Callbacks,
        NavigationDrawerFragment.NavigationDrawerCallbacks,
        TakeControlFragment.TakeControlFragmentListener,
        AlarmFragment.WiBeanAlarmFragmentInteractionListener,
        BrewingProgramDetailFragment.BrewingProgramDetailCallbacks,
        SmartConfigFragment.SmartConfigFragmentListener {

    /**
     * FRAGMENT IDENTIFIERS
     */
    private static final String TAG_TAKECONTROL = "fragment_takeControl";
    private static final String TAG_BREWINGPROGRAMLIST = "fragment_brewingProgramList";
    private static final String TAG_ALARM = "fragment_alarm";
    private static final String TAG_BREWINGPROGRAMDETAIL = "fragment_brewingProgramDetail";
    private static final String TAG_SMARTCONFIG = "fragment_smartConfig";
    /**
     * NOTIFICATION IDENTIFIERS
     */
    private static final int NOTIFICATION_HOT = 100;
    private static final String PROPERTY_ID = "UA-42606656-1";
    private static final int PROGRAM_DETAIL_LOADER = 1;
    // and a related listener to use when we can to cancel a brew in progress
    final DialogInterface.OnCancelListener sBrewCanceler = new DialogInterface.OnCancelListener() {
        @Override
        public void onCancel(DialogInterface dialog) {
            // first, cancel the old program
            mBrewingTask.cancel(true);
        }
    };
    // httpClient, make one to save resources
    OkHttpClient mHttpClient;
    // used so we can cancel a brew in progress
    AsyncTask<BrewingProgram, Integer, Integer> mBrewingTask;
    HashMap<TrackerName, Tracker> mTrackers = new HashMap<TrackerName, Tracker>();
    /**
     * Fragment managing the behaviors, interactions and presentation of the navigation drawer.
     */
    private NavigationDrawerFragment mNavigationDrawerFragment;
    /**
     * Whether or not the activity is in two-pane mode, i.e. running on a tablet
     * device.
     */
    private boolean mTwoPane;
    // Handler allows us to run actions on the GUI thread, and post delayed events
    private Handler mHandler = new Handler();
    // two progress dialogs used by the fragments
    private ProgressDialog mIndefiniteProgress;
    private ProgressBar mIndefiniteProgressLow;
    private ProgressDialog mDefiniteProgress;
    // keep track of our status label  (assigned in onViewCreated)
    private TextView mStatusBarStateText;
    private TextView mAlarmTimeText;
    private TextView mMachineTimeText;
    // handles the state and communication with the WiBean
    private WiBeanSparkState mWibean = new WiBeanSparkState();
    // this variable is used to allow fragments to point at a control which we will fill when
    // barcode scans come back
    private
    @IdRes
    int mRequestedViewId = -1;
    // keep track of whether we have valid credentials
    private boolean mCredentialsValid = false;
    // keep track of the context
    private Context mContext;
    // mutex for keeping track of temperature HTTP calls
    private Semaphore mTempLoopMutex = new Semaphore(1);
    // used to trigger notifications for heating
    private boolean mNotifyWhenHot = false;
    private float mGoalTemperature = 92;
    // keep track of foreground/background state and stop the polling loop
    private boolean mPausePolling = false;
    private boolean mFollowupStatus = false;
    // END GOOGLE ANALYTICS TRACKING METHODS AND RESOURCES

    synchronized Tracker getTracker(TrackerName trackerId) {
        if (!mTrackers.containsKey(trackerId)) {
            GoogleAnalytics analytics = GoogleAnalytics.getInstance(this);
            Tracker t = (trackerId == TrackerName.APP_TRACKER) ? analytics.newTracker(PROPERTY_ID)
                    : analytics.newTracker(R.xml.global_tracker);
            mTrackers.put(trackerId, t);

        }
        return mTrackers.get(trackerId);
    }

    //*******************
    //* LIFECYCLE METHODS
    //******************
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        mContext = this;
        // Google Analytics override
        if (!BuildConfig.REPORT_ANALYTICS) {
            // When dry run is set, hits will not be dispatched, but will still be logged as
            // though they were dispatched.
            GoogleAnalytics.getInstance(this).setDryRun(true);
        }

        setContentView(R.layout.activity_brewingprogram_list);
        // hook up convenience members
        mStatusBarStateText = (TextView) findViewById(R.id.tv_inControlLabel);
        mIndefiniteProgressLow = (ProgressBar) findViewById(R.id.pb_indeterminateLow);
        mAlarmTimeText = (TextView) findViewById(R.id.tv_alarmSetFor);
        mMachineTimeText = (TextView) findViewById(R.id.tv_deviceTime);
        /*
        if (findViewById(R.id.brewingprogram_detail_container) != null) {
            // The detail container view will be present only in the
            // large-screen layouts (res/values-large and
            // res/values-sw600dp). If this view is present, then the
            // activity should be in two-pane mode.
            mTwoPane = true;
            // In two-pane mode, list items should be given the
            // 'activated' state when touched.
            ((BrewingProgramListFragment) getFragmentManager()
                    .findFragmentById(R.id.brewingprogram_list))
                    .setActivateOnItemClick(true);
        }
        */
        mNavigationDrawerFragment = (NavigationDrawerFragment)
                getFragmentManager().findFragmentById(R.id.navigation_drawer);
        // Set up the drawer.
        mNavigationDrawerFragment.setUp(
                R.id.navigation_drawer,
                (DrawerLayout) findViewById(R.id.drawer_layout));
        mHttpClient = new OkHttpClient();
        // Intent parsing goes here for deep links
        Intent intent = getIntent();
        if (!parseIntent(intent)) {
            mNavigationDrawerFragment.selectItem(2);
        }
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        boolean success = super.onCreateOptionsMenu(menu);
        // always load the global menu
        getMenuInflater().inflate(R.menu.global, menu);
        if (!mNavigationDrawerFragment.isDrawerOpen()) {
            restoreActionBar();
        }
        try {
            MenuItem item = menu.findItem(R.id.menu_toggle_heating);
            if (mWibean.isHeatingLocal()) {
                item.setTitle(R.string.action_toggle_heating_off);
            } else {
                item.setTitle(R.string.action_toggle_heating_on);
            }
        } catch (Exception e) {
            System.out.println(e.toString());
        }


        return success;
    }

    /**
     * For the Detail fragment, when the user pressed back, we should see if need to save changes
     * they have made.
     */
    @Override
    public void onBackPressed() {
        // clear focus on all the fields so the filters run
        final BrewingProgramDetailFragment fragment = (BrewingProgramDetailFragment) getFragmentManager().findFragmentByTag(TAG_BREWINGPROGRAMDETAIL);
        if (fragment != null) {
            fragment.saveIfNecessary();
        }
        super.onBackPressed();
    }

    @Override
    public void onActivityResult(int requestCode, int resultCode, Intent intent) {
        IntentResult result = IntentIntegrator.parseActivityResult(requestCode, resultCode, intent);
        if (result != null) {
            String contents = result.getContents();
            if (contents != null) {
                // load the string
                EditText et = (EditText) findViewById(mRequestedViewId);
                if (et != null) {
                    et.setText(contents);
                }
            }
            // else do nothing and fail
        }
        // reset requested control
        mRequestedViewId = -1;
    }

    @Override
    public void onPause() {
        super.onPause();
        mPausePolling = true;
    }

    @Override
    public void onResume() {
        super.onResume();
        mPausePolling = false;
        statusPollLoop();
    }

    // returns true if action taken
    private boolean parseIntent(Intent intent) {
        String action = intent.getAction();
        Uri data = intent.getData();
        if ((action == null) || (action.isEmpty())) {
            return false;
        } else if (data == null) {
            return false;
        } else if (action.equals("android.intent.action.VIEW")) {
            // parse appropriately different versions
            if (data.getScheme().equalsIgnoreCase("http")) {
                if (data.getHost().equalsIgnoreCase("www.wibean.com")) {
                    if (data.getPath().startsWith("/brewingProgram/v1")) {
                        // parse the program.
                        System.out.println(data.getQuery());
                        BrewingProgram newProg = BrewingProgram.fromUri(data);
                        if (insertOrUpdateBrewingProgram(newProg)) {
                            // navigate to the program list so the backstack works
                            mNavigationDrawerFragment.selectItem(0);
                            // load the item
                            onItemSelected(newProg.getId());
                            return true;
                        }
                    }
                }
            }
        }
        return false;
    }

    public void restoreActionBar() {
        ActionBar actionBar = getActionBar();
        actionBar.setNavigationMode(ActionBar.NAVIGATION_MODE_STANDARD);
        actionBar.setDisplayShowTitleEnabled(true);
    }

    //*************
    //* INTERFACES
    //*************

    /**
     * INTERFACE FOR testCredentials fragment
     */

    public boolean refreshPrefs() {
        SharedPreferences prefs = getPreferences(Context.MODE_PRIVATE);
        String accessCode = prefs.getString(WiBeanSparkState.PREF_KEY_ACCESS_CODE, "");
        mGoalTemperature = Float.valueOf(prefs.getString(WiBeanSparkState.PREF_KEY_BREW_TEMP, "92"));
        final int utcOffset = prefs.getInt(WiBeanSparkState.PREF_KEY_DEVICE_TIMEZONE, 0);
        if (accessCode.isEmpty()) {
            return false;
        }
        boolean success = true;
        success &= mWibean.setAccessCode(accessCode);
        success &= updateTimeZone(utcOffset);
        success &= mWibean.setTemperature(mGoalTemperature);
        return success;
    }

    /**
     * Allows fragment to request alert dialogues which the host activity can appropriately
     * display.
     *
     * @param title   Title of the Alert Dialog.
     * @param message Message displayed in the Alert Dialog.
     */
    public void alertUser(String title, String message) {
        // alert the user and stop
        AlertDialog.Builder builder = new AlertDialog.Builder(this);
        builder.setMessage(message)
                .setPositiveButton("OK", null);
        if (!title.isEmpty()) {
            builder.setTitle(title);
        }
        AlertDialog dialog = builder.create();
        dialog.show();
    }

    public void setTargetControl(@IdRes int controlId) {
        mRequestedViewId = controlId;
    }

    public void toggleHeating() {
        mWibean.setHeating(!mWibean.isHeatingLocal());
        mNotifyWhenHot = mWibean.isHeatingLocal();
        invalidateOptionsMenu();
        statusPollLoop();
    }

    /**
     * Runs the indefinite progress bar along the bottom with no text
     */
    public void makeBusy() {
        mIndefiniteProgressLow.setVisibility(mIndefiniteProgressLow.VISIBLE);
    }

    /**
     * Allows user to use the progress bar for the whole activity.
     * Designed to be called in the GUI thread, most likely via an AsyncTask pre/post trigger
     */
    public void makeBusy(final CharSequence title, final CharSequence message) {
        if (mIndefiniteProgress == null) {
            mIndefiniteProgress = new ProgressDialog(BrewingProgramListActivity.this);
        }
        mIndefiniteProgress.setProgressStyle(mIndefiniteProgress.STYLE_SPINNER);
        mIndefiniteProgress.setTitle(title);
        mIndefiniteProgress.setMessage(message);
        mIndefiniteProgress.setIndeterminate(true);
        mIndefiniteProgress.setCancelable(false);
        mIndefiniteProgress.show();
    }

    public void makeBusyWithProgress(final CharSequence title, final CharSequence message) {
        if (mDefiniteProgress == null) {
            mDefiniteProgress = new ProgressDialog(BrewingProgramListActivity.this, R.style.ProgressDialogRedBackground);
            mDefiniteProgress.setProgressStyle(ProgressDialog.STYLE_HORIZONTAL);
            mDefiniteProgress.setMax(100);
            mDefiniteProgress.setCancelable(true);
            mDefiniteProgress.setOnCancelListener(sBrewCanceler);
            //mDefiniteProgress.getWindow().setBackgroundDrawableResource(android.R.color.holo_red_dark);
        }
        mDefiniteProgress.setTitle(title);
        mDefiniteProgress.setMessage(message);
        mDefiniteProgress.setProgress(0);
        mDefiniteProgress.show();
    }

    public void updateBusyProgress(int value) {
        if (mDefiniteProgress != null) {
            mDefiniteProgress.setProgress(value);
            mDefiniteProgress.show();
        }
    }

    public void makeNotBusy() {
        if (mIndefiniteProgress != null) {
            mIndefiniteProgress.dismiss();
        }
        if (mDefiniteProgress != null) {
            mDefiniteProgress.setProgress(0);
            mDefiniteProgress.dismiss();
        }
        mIndefiniteProgressLow.setVisibility(mIndefiniteProgressLow.GONE);
    }

    public void statusPollLoop() {
        // only allow one poll at a time
        if (!mPausePolling && mTempLoopMutex.tryAcquire()) {
            // make the request
            AsyncTask<Void, Boolean, WiBeanSparkState.CONNECTION_STATE> task = new QueryStatusTask().execute();
        } else {
            mFollowupStatus = true;
        }
    }
    // ********************
    // INTERFACES
    // ********************

    public boolean insertOrUpdateBrewingProgram(BrewingProgram theProgram) {
        // Defines an object to contain the updated values
        ContentValues updateValues = new ContentValues();
        // Sets the updated value and updates the selected words.
        updateValues.put(BrewingProgramHelper.COLUMN_NAME, theProgram.getName());
        updateValues.put(BrewingProgramHelper.COLUMN_DESCRIPTION, theProgram.getDescription());
        // we can't use the SQLite datetime() function via the ContentValues object, so construct
        // the string ourselves
        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        Date date = new Date();
        updateValues.put(BrewingProgramHelper.COLUMN_MODIFIED_AT, dateFormat.format(date));

        Integer[] onTimes = theProgram.getOnTimes();
        Integer[] offTimes = theProgram.getOffTimes();
        updateValues.put(BrewingProgramHelper.COLUMN_ON_ONE, onTimes[0]);
        updateValues.put(BrewingProgramHelper.COLUMN_OFF_ONE, offTimes[0]);
        updateValues.put(BrewingProgramHelper.COLUMN_ON_TWO, onTimes[1]);
        updateValues.put(BrewingProgramHelper.COLUMN_OFF_TWO, offTimes[1]);
        updateValues.put(BrewingProgramHelper.COLUMN_ON_THREE, onTimes[2]);
        updateValues.put(BrewingProgramHelper.COLUMN_OFF_THREE, offTimes[2]);
        updateValues.put(BrewingProgramHelper.COLUMN_ON_FOUR, onTimes[3]);
        updateValues.put(BrewingProgramHelper.COLUMN_OFF_FOUR, offTimes[3]);
        updateValues.put(BrewingProgramHelper.COLUMN_ON_FIVE, onTimes[4]);
        updateValues.put(BrewingProgramHelper.COLUMN_OFF_FIVE, offTimes[4]);
        updateValues.put(BrewingProgramHelper.COLUMN_SHORT_URL, theProgram.getShortUrl());

        // catch results
        int rowsUpdated = 0;
        Uri newRow;
        if (theProgram.getId().isEmpty()) {
            // insert
            newRow = this.getContentResolver().insert(
                    BrewingProgramContentProvider.CONTENT_URI,  // the user dictionary content URI
                    updateValues); // the columns to update
            String resultAsString = newRow.toString();
            if (!resultAsString.contains("-1")) {
                // success!
                theProgram.setId(resultAsString.substring(resultAsString.lastIndexOf("/") + 1));
                return true;
            } else {
                return false;
            }
        } else {
            // update
            rowsUpdated = this.getContentResolver().update(
                    ContentUris.withAppendedId(BrewingProgramContentProvider.CONTENT_URI, Long.parseLong(theProgram.getId())),  // the user dictionary content URI
                    updateValues,                       // the columns to update
                    null, // the column to select on
                    null// the value to compare to
            );
            return (rowsUpdated > 0);
        }
    }

    /**
     * INTERFACE FOR NavigationDrawer fragment
     * add support for the navigation drawer
     */
    @Override
    public void onNavigationDrawerItemSelected(int position) {
        // update the main content by replacing fragments
        Fragment fragment = null;
        // figure out which was to place
        String tag = "";
        switch (position) {
            default:
            case 0:
                fragment = new BrewingProgramListFragment();
                tag = TAG_BREWINGPROGRAMLIST;
                break;
            case 1:
                fragment = AlarmFragment.newInstance(mWibean.getAlarm());
                tag = TAG_ALARM;
                break;
            case 2:
                fragment = TakeControlFragment.newInstance(mCredentialsValid);
                tag = TAG_TAKECONTROL;
                break;
            case 3:
                fragment = SmartConfigFragment.newInstance();
                tag = TAG_SMARTCONFIG;
                break;

        }
        if (fragment != null) {
            FragmentManager fm = getFragmentManager();
            // clean  up the back stack
            fm.popBackStack("menu_item_create_new", FragmentManager.POP_BACK_STACK_INCLUSIVE);
            // do the swap
            fm.beginTransaction()
                    .replace(R.id.list_content_container, fragment, tag)
                    .commit();
        }
    }

    public boolean isHeating() {
        return mWibean.isHeating();
    }

    public void onHeatToggleSelected() {
        toggleHeating();
    }

    /**
     * When the brewing temperature is reached and the user has requested a notification, deliver
     * them here
     */
    public void deliverHotNotifications() {
        // if shared pref
        NotificationCompat.Builder nb = new NotificationCompat.Builder(this);
        nb.setContentTitle(getString(R.string.notify_goalTemperatureAchieved));
        nb.setContentText(getString(R.string.notify_goalTemperatureAchieved_prefix)
                + String.valueOf(mWibean.getHeadTemperature())
                + getString(R.string.notify_goalTemperatureAchieved_suffix));
        nb.setSmallIcon(R.drawable.ic_whats_hot);
        // The stack builder object will contain an artificial back stack for the started Activity.
        // This ensures that navigating backward from the Activity leads out of your application to the Home screen.
        TaskStackBuilder stackBuilder = TaskStackBuilder.create(this);
        // Adds the back stack for the Intent (but not the Intent itself)
        stackBuilder.addParentStack(BrewingProgramListActivity.class);
        // Adds the Intent that starts the Activity to the top of the stack
        // Creates an explicit intent for an Activity in your app
        Intent resultIntent = new Intent(this, BrewingProgramListActivity.class);
        stackBuilder.addNextIntent(resultIntent);
        PendingIntent resultPendingIntent =
                stackBuilder.getPendingIntent(
                        0,
                        PendingIntent.FLAG_UPDATE_CURRENT
                );
        nb.setContentIntent(resultPendingIntent);
        nb.setAutoCancel(true);
        NotificationManager notificationManager = (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);
        notificationManager.notify(NOTIFICATION_HOT, nb.build());
    }


    /**
     * UTILITY
     */

    /**
     * INTERFACE FOR BrewingProgramListFragment
     * takes action when the user clicks an item
     */
    public void onItemSelected(String id) {
        FragmentManager fragmentManager = getFragmentManager();
        BrewingProgramDetailFragment frag = new BrewingProgramDetailFragment();
        Bundle args = new Bundle();
        args.putString(BrewingProgramDetailFragment.ARG_ITEM_ID, id);
        frag.setArguments(args);
        fragmentManager.beginTransaction()
                .replace(R.id.list_content_container, frag, TAG_BREWINGPROGRAMDETAIL)
                .addToBackStack("brew_program_detail_show")
                .commit();
    }

    /**
     * Turns the input into a human readable 24-hour style clock string HH:MM
     *
     * @param minutesAfterMidnight
     * @return
     */
    String minutesAfterMidnightToString(int minutesAfterMidnight) {
        StringBuilder builder = new StringBuilder();
        builder.append(minutesAfterMidnight / 60);
        builder.append(":");
        builder.append(String.format("%02d", minutesAfterMidnight % 60));
        return builder.toString();
    }

    /**
     * Set the appropriate status text when connecting or updating
     */
    public void setUpdatingStatusText() {
        if (mWibean.getConnectionState() == WiBeanSparkState.CONNECTION_STATE.CONNECTED) {
            mStatusBarStateText.setText(R.string.heading_control_status_updating);
        } else {
            mStatusBarStateText.setText(R.string.label_control_status_connecting);
        }
    }

    /**
     * INTERFACE FOR AlarmFragment
     * tries communication when user sets alarm
     */
    public boolean sendAlarmRequest(WiBeanSparkState.WiBeanAlarmPackV1 requestedAlarm) {
        if (mWibean.setAlarm(requestedAlarm)) {
            statusPollLoop();
            return true;
        }
        return false;
    }

    /**
     * INTERFACE FOR BrewingProgramDetailFragment
     * when the user wants to brew!
     */
    public void brewProgram(BrewingProgram theProgram) {
        Boolean success = false;
        try {
            mBrewingTask = new BrewProgramTask().execute(theProgram);
        } catch (Exception e) {
            System.out.println("brewProgram was interrupted: " + e.getLocalizedMessage());
            success = false;
        }
    }

    public void buildProgramFromId(final long id, final BrewingProgramAcceptor acceptor) {
        getLoaderManager().restartLoader(PROGRAM_DETAIL_LOADER, null, new LoaderManager.LoaderCallbacks<Cursor>() {
            @Override
            public Loader<Cursor> onCreateLoader(int loaderID, Bundle bundle) {
                return new CursorLoader(
                        mContext,   // Parent activity context
                        ContentUris.withAppendedId(BrewingProgramContentProvider.CONTENT_URI, id),// Table to query
                        BrewingProgramHelper.PROJECTION_DATA_COLUMNS_WITH_ID,           // null, return every column
                        null,            // No selection clause because the URI handles it!!!
                        null,            // No selection arguments
                        null             // Default sort order
                );
            }

            @Override
            public void onLoadFinished(Loader<Cursor> loader, Cursor cursor) {
                /**
                 * Move the results into the view
                 */
                if (cursor.getCount() <= 0) {
                    return;
                }
                cursor.moveToFirst();
                BrewingProgram bp = new BrewingProgram("-1", "noname");
                try {
                    int k = 0;
                    String idAsString = String.valueOf(cursor.getLong(k++));
                    String name = cursor.getString(k++);
                    bp.setId(idAsString);
                    bp.setName(name);
                    bp.setDescription(cursor.getString(k++));
                    Integer[] onTimes = new Integer[5];
                    Integer[] offTimes = new Integer[5];
                    onTimes[0] = cursor.getInt((k++));
                    offTimes[0] = cursor.getInt((k++));
                    onTimes[1] = cursor.getInt((k++));
                    offTimes[1] = cursor.getInt((k++));
                    onTimes[2] = cursor.getInt((k++));
                    offTimes[2] = cursor.getInt((k++));
                    onTimes[3] = cursor.getInt((k++));
                    offTimes[3] = cursor.getInt((k++));
                    onTimes[4] = cursor.getInt((k++));
                    offTimes[4] = cursor.getInt((k++));
                    bp.setOnTimes(onTimes);
                    bp.setOffTimes(offTimes);
                    bp.setShortUrl(cursor.getString(k++));
                    bp.setCreatedAt(cursor.getString(k++));
                    bp.setModifiedAt(cursor.getString(k++));
                } catch (Exception e) {
                    System.out.println("CURSOR ERROR: " + e.getLocalizedMessage());
                    e.printStackTrace();
                }
                try {
                    if (acceptor != null) {
                        acceptor.useBrewingProgram(bp);
                    }
                } catch (Exception e) {
                    System.out.println("Acceptor threw exception: " + e.getLocalizedMessage());
                    e.printStackTrace();
                }
                // it has done its job - terminate
                getLoaderManager().destroyLoader(PROGRAM_DETAIL_LOADER);
            }

            @Override
            public void onLoaderReset(Loader<Cursor> loader) {
            }
        });
    }

    /**
     * Allow the user to brew a program simply by ID as well
     *
     * @param programId
     */
    public void brewProgram(long programId) {
        buildProgramFromId(programId, new BrewingProgramAcceptor() {
            @Override
            public void useBrewingProgram(BrewingProgram bp) {
                brewProgram(bp);
            }
        });
    }

    ;

    public boolean saveOrCreateItem(BrewingProgram aProgram) {
        return insertOrUpdateBrewingProgram(aProgram);
    }

    /**
     * INTERFACE FOR TakeControlFragment
     */
    public boolean updateTimeZone(int newOffset) {
        WiBeanSparkState.WiBeanAlarmPackV1 pack = mWibean.getAlarm();
        if (pack.getUtcOffset() != newOffset) {
            if (pack.setUtcOffset(newOffset) && mWibean.setAlarm(pack)) {
                statusPollLoop();
                return true;
            }
        } else {
            return true;
        }
        return false;
    }

    /**
     * Google Analytics Tracking
     * Enum used to identify the tracker that needs to be used for tracking.
     * <p/>
     * A single tracker is usually enough for most purposes. In case you do need multiple trackers,
     * storing them all in Application object helps ensure that they are created only once per
     * application instance.
     */
    public enum TrackerName {
        APP_TRACKER, // Tracker used only in this app.
        GLOBAL_TRACKER, // Tracker used by all the apps from a company. eg: roll-up tracking.
    }

    /**
     * The LOADER instance used here must be identified, whatever you want
     */
    public interface BrewingProgramAcceptor {
        void useBrewingProgram(BrewingProgram bp);
    }

    private class BrewProgramTask extends AsyncTask<BrewingProgram, Integer, Integer> {
        protected void onPreExecute() {
            Context c = getApplicationContext();
            makeBusyWithProgress(c.getString(R.string.action_brewing), c.getString(R.string.action_brewing_description));
            //set the status label
            mStatusBarStateText.setText(R.string.label_control_status_brewing);
            refreshPrefs();
        }

        protected Integer doInBackground(BrewingProgram... programs) {
            int lastRet = -1;
            for (int k = 0; k < programs.length; ++k) {
                lastRet = mWibean.runBrewProgram(programs[k]);
                // now spin a progress bar for the length of the program
                // spin at ~10fps
                final int sleepTimeInMs = 1000 / 10;
                final long totalDuration = programs[k].getTotalDurationInMilliseconds();
                Calendar c = Calendar.getInstance();
                final long startTime = c.getTimeInMillis();
                final long endTime = startTime + totalDuration;
                // only spin if the brew actually started well
                while ((lastRet == 1) && (c.getTimeInMillis() < endTime)) {
                    if (isCancelled()) {
                        // dispatch a cancel request
                        BrewingProgram p = new BrewingProgram("0", "empty");
                        final Integer[] arr = new Integer[]{0, 0, 0, 0, 0};
                        p.setOnTimes(arr);
                        p.setOffTimes(arr);
                        publishProgress(100);
                        return mWibean.runBrewProgram(p);
                    }
                    try {
                        Thread.sleep(sleepTimeInMs);
                    } catch (Exception e) {
                    }
                    ;
                    // update the calendar object with the new time
                    c = Calendar.getInstance();
                    publishProgress((int) ((c.getTimeInMillis() - startTime) * 100 / totalDuration));
                }
                publishProgress(100);
            }
            return lastRet;
        }

        protected void onProgressUpdate(Integer... progress) {
            updateBusyProgress(progress[0]);
        }

        protected void onPostExecute(Integer result) {
            resultSwitch(result);
        }

        protected void onCancelled(Integer result) {
            resultSwitch(result);
        }

        // ONLY CALL THIS FROM A UI-THREAD
        private void resultSwitch(Integer result) {
            switch (result) {
                case WiBeanSparkState.RETURN_CODE_PUMP_SUCCESS:
                    Toast.makeText(BrewingProgramListActivity.this, mContext.getString(R.string.notify_brewSuccess), Toast.LENGTH_LONG).show();
                    break;
                case WiBeanSparkState.RETURN_CODE_PUMP_INVALID_PROGRAM:
                    alertUser(getString(R.string.notify_brewingFailure_title), getString(R.string.notify_brewingFailure_message_error));
                    break;
                case WiBeanSparkState.RETURN_CODE_PUMP_BUSY:
                    alertUser(getString(R.string.notify_brewingFailure_title), getString(R.string.notify_brewingFailure_message_busy));
                    break;
                case WiBeanSparkState.RETURN_CODE_PUMP_CANCELLED:
                    Toast.makeText(BrewingProgramListActivity.this, mContext.getString(R.string.notify_brewCancelled), Toast.LENGTH_LONG).show();
                    break;
                case WiBeanSparkState.RETURN_CODE_BAD_CREDENTIALS:
                    Toast.makeText(BrewingProgramListActivity.this, mContext.getString(R.string.notify_brewingFailure_message_error), Toast.LENGTH_LONG).show();
                    break;
            }
            // TODO: pre-emptive strike the status text, have a method which properly the status text no matter what
            makeNotBusy();
        }
    }

    private class QueryStatusTask extends AsyncTask<Void, Boolean, WiBeanSparkState.CONNECTION_STATE> {
        protected void onPreExecute() {
            refreshPrefs();
            if (!mCredentialsValid || !mWibean.isSynchronized()) {
                makeBusy();
                setUpdatingStatusText();
            }
        };
        protected WiBeanSparkState.CONNECTION_STATE doInBackground(Void... voids) {
            if (mWibean.isSynchronized()) {
                return mWibean.queryStatus();
            } else {
                mWibean.synchronizeWithRemote();
                WiBeanSparkState.CONNECTION_STATE st = mWibean.queryStatus();
                return st;
            }
        };
        protected void onPostExecute(WiBeanSparkState.CONNECTION_STATE result) {
            try {
                boolean tryAgain = true;
                String newStatusBarText = new String("");
                switch (result) {
                    case INVALID_CREDENTIALS:
                        // bad credentials
                        mCredentialsValid = false;
                        // update Control status text
                        mStatusBarStateText.setText(R.string.label_control_status_bad_credentials);
                        tryAgain = false;
                        break;
                    case TIMEOUT:
                        // update Control status text
                        mStatusBarStateText.setText(R.string.label_control_status_bad);
                        // but keep polling
                        tryAgain = true;
                        break;
                    case CONNECTED:
                        // if success and we just connected
                        if ((mHandler != null) && !mCredentialsValid) {
                            // notify user
                            mHandler.post(() -> {
                                Toast.makeText(BrewingProgramListActivity.this, mContext.getString(R.string.notify_wibeanConnectionSuccess), Toast.LENGTH_SHORT).show();
                            });
                            // and flip to the brewing programs
                            mHandler.post(new Runnable() {
                                @Override
                                public void run() {
                                    mNavigationDrawerFragment.selectItem(0);
                                }
                            });
                        }
                        mCredentialsValid = true;
                        // update Control status text
                        if (mWibean.isBrewing()) {
                            newStatusBarText = getString(R.string.label_control_status_brewing);
                        } else if (mWibean.isHeating()) {
                            newStatusBarText = getString(R.string.label_control_status_heating);
                        } else {
                            newStatusBarText = getString(R.string.label_control_status_cooling);
                        }
                        // and update the heat/sleep button by forcing a rebuild of the menus
                        invalidateOptionsMenu();
                        // update head temp display
                        TextView v = (TextView) findViewById(R.id.tv_headTemperature);
                        v.setText(new StringBuilder().append(mWibean.getHeadTemperature()).toString());
                        // if we have an Alarm fragment, update the remote UI state
                        WiBeanSparkState.WiBeanAlarmPackV1 alarmPack = mWibean.getAlarm();
                        AlarmFragment f = (AlarmFragment) getFragmentManager().findFragmentByTag(TAG_ALARM);
                        if (mWibean.isSynchronized() && (f != null)) {
                            f.updateRemoteAlarm(alarmPack);
                        }
                        // update the alarm time show on screen
                        if (alarmPack.getAlarmArmed()) {
                            mAlarmTimeText.setText(minutesAfterMidnightToString(alarmPack.getOnTimeAsMinutesAfterMidnight()));
                        } else {
                            mAlarmTimeText.setText(getString(R.string.alarm_status_off));
                        }
                        // update the machine time shown on screen
                        final int minutesAfterMidnight = mWibean.getMachineTimeAsMinutesAfterMidnight();
                        mMachineTimeText.setText(minutesAfterMidnightToString(minutesAfterMidnight));
                        // Only update the new status bar if we don't have any further pending updates
                        // This prevents the status text from flashing through several states quickly
                        // when the user makes a lot of change quickly
                        if (mWibean.isSynchronized() && !newStatusBarText.isEmpty()) {
                            mStatusBarStateText.setText(newStatusBarText);
                        }
                        break;
                }
                // if we have a TakeControl fragment, update the UI for proper consistency
                TakeControlFragment f = (TakeControlFragment) getFragmentManager().findFragmentByTag(TAG_TAKECONTROL);
                if (f != null) {
                    if (mCredentialsValid) {
                        f.setCredentialsValid();
                    } else {
                        f.setCredentialsInvalid();
                    }
                }
                if (mNotifyWhenHot && (mWibean.getHeadTemperature() >= mGoalTemperature)) {
                    deliverHotNotifications();
                    mNotifyWhenHot = false;
                }
                // RELEASE BEFORE TRYING AGAIN
                mTempLoopMutex.release();
                if (tryAgain) {
                    // query every 4 seconds when cold
                    int queryInterval = 4000;
                    // if someone has requested an immediate refresh
                    if (mFollowupStatus) {
                        mFollowupStatus = false;
                        queryInterval = 1;
                    } else if (mWibean.isHeating()) {
                        // 2 seconds when heating
                        queryInterval = 2000;
                    } else if (mWibean.isBrewing()) {
                        // and 1 second when  brewing
                        queryInterval = 1000;
                    }
                    mHandler.postDelayed(new Runnable() {
                        @Override
                        public void run() {
                            statusPollLoop();
                        }
                    }, queryInterval);
                }
            } catch (Exception e) {
                // if it fails, no worries
            }
            // if we have nothing left to sync/do, be not busy!
            if (mWibean.isSynchronized() || !mCredentialsValid) {
                makeNotBusy();
            }
        }
    }
}
