package com.wibean.android.wibean;

import android.app.ActionBar;
import android.app.Activity;
import android.app.Fragment;
import android.content.Intent;
import android.os.AsyncTask;
import android.os.Bundle;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.LayoutInflater;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ShareActionProvider;
import android.widget.TextView;
import android.widget.Toast;

import com.wibean.android.wibean.data.BrewingProgram;

/**
 * A fragment representing a single BrewingProgram detail screen.
 * This fragment is contained in a {@link BrewingProgramListActivity}
 */
public class BrewingProgramDetailFragment extends Fragment implements
        View.OnClickListener {
    /**
     * The fragment argument representing the item ID that this fragment
     * represents.
     */
    public static final String ARG_ITEM_ID = "item_id";
    /**
     * The LOADER instance used here must be identified, whatever you want
     */
    private static final int PROGRAMS_LOADER = 0;
    // Event listener
    BrewingProgramDetailCallbacks mListener;
    private TextWatcher mDifferenceToggle = new TextWatcher() {
        @Override
        public void beforeTextChanged(CharSequence s, int start, int count, int after) {
        }

        @Override
        public void onTextChanged(CharSequence s, int start, int before, int count) {

        }

        @Override
        public void afterTextChanged(Editable s) {
            // remove prefixed decimal points
            while ((s.length() > 0) && (s.charAt(0) == '.')) {
                s.delete(0, 1);
            }
            updateUiOnChange();
        }
    };
    private View.OnFocusChangeListener mDecimalPlaceChecker = new View.OnFocusChangeListener() {
        @Override
        public void onFocusChange(View v, boolean hasFocus) {
            if (hasFocus) {
                return;
            }
            Editable s = ((TextView) v).getEditableText();
            if (s.length() == 0) {
                s.append("0.0");
                return;
            }

            int decMark = -1;
            int k = 0;
            // find the decimal
            while (k < s.length()) {
                if (s.charAt(k) == '.') {
                    decMark = k;
                    ++k;
                    break;
                }
                // prevent more than 2 characters before the decimal
                if (k >= 2) {
                    s.delete(k, k + 1);
                    continue;
                }
                ++k;
            }
            // remove dupilcate decimal places
            while (k < s.length()) {
                if (s.charAt(k) == '.') {
                    s.delete(k, k + 1);
                    continue;
                }
                ++k;
            }
            // if they omitted a trailing .0, give them one
            if (decMark == -1) {
                s.append(".0");
            }
            // if they omitted a trailing 0, give them one
            else if (decMark == (s.length() - 1)) {
                s.append('0');
            }
            // check for points after decimal
            else if (s.length() >= decMark + 2) {
                s.delete(decMark + 2, s.length());
            }

        }
    };
    // Do we have unsaved changes?
    private boolean mUnsavedChanges = false;
    //for the share button
    private ShareActionProvider mShareActionProvider;
    // keep track of the numeric input fields
    private EditText[] mNumericInputFields = new EditText[10];
    /**
     * The content this fragment is presenting.
     */
    private BrewingProgram mItem = new BrewingProgram("-1", "", "",
            new Integer[]{0, 0, 0, 0, 0}, new Integer[]{0, 0, 0, 0, 0});

    /**
     * Mandatory empty constructor for the fragment manager to instantiate the
     * fragment (e.g. upon screen orientation changes).
     */
    public BrewingProgramDetailFragment() {
    }

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setHasOptionsMenu(true);
        if (getArguments().containsKey(ARG_ITEM_ID)) {
            // Load the dummy content specified by the fragment
            // arguments. In a real-world scenario, use a Loader
            // to load content from a content provider.
            mItem.setId(getArguments().getString(ARG_ITEM_ID));
        }
    }

    @Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container,
                             Bundle savedInstanceState) {
        super.onCreateView(inflater, container, savedInstanceState);
        View rootView = inflater.inflate(R.layout.fragment_brewingprogram_detail, container, false);
        if (mItem.getId().isEmpty()) {
            //we are creating a fresh one
            ((Button) rootView.findViewById(R.id.btn_programDiscardChanges)).setText(R.string.action_createProgram);
        } else {

        }
        // hookup the button here in the Fragment
        // (onClicks generated from buttons in Fragments get sent to their Activity
        // removing modularity)
        ((Button) rootView.findViewById(R.id.btn_brew)).setOnClickListener(this);
        ((Button) rootView.findViewById(R.id.btn_programDiscardChanges)).setOnClickListener(this);

        // populate the list of controls
        mNumericInputFields[0] = (EditText) rootView.findViewById(R.id.et_onForOne);
        mNumericInputFields[1] = (EditText) rootView.findViewById(R.id.et_offForOne);
        mNumericInputFields[2] = (EditText) rootView.findViewById(R.id.et_onForTwo);
        mNumericInputFields[3] = (EditText) rootView.findViewById(R.id.et_offForTwo);
        mNumericInputFields[4] = (EditText) rootView.findViewById(R.id.et_onForThree);
        mNumericInputFields[5] = (EditText) rootView.findViewById(R.id.et_offForThree);
        mNumericInputFields[6] = (EditText) rootView.findViewById(R.id.et_onForFour);
        mNumericInputFields[7] = (EditText) rootView.findViewById(R.id.et_offForFour);
        mNumericInputFields[8] = (EditText) rootView.findViewById(R.id.et_onForFive);
        mNumericInputFields[9] = (EditText) rootView.findViewById(R.id.et_offForFive);

        // setup difference checker to enable/disable save button
        ((EditText) rootView.findViewById(R.id.et_program_name)).addTextChangedListener(mDifferenceToggle);
        ((EditText) rootView.findViewById(R.id.et_program_description)).addTextChangedListener(mDifferenceToggle);
        for (final EditText et : mNumericInputFields) {
            et.addTextChangedListener(mDifferenceToggle);
        }
        // setup decimal place checker
        for (final EditText et : mNumericInputFields) {
            et.setOnFocusChangeListener(mDecimalPlaceChecker);
        }

        return rootView;
    }

    @Override
    public void onViewCreated(View view, Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);

        if (!mItem.getId().isEmpty()) {
            mListener.makeBusy("Loading", "Loading program from database...");
            // call the loader
            mListener.buildProgramFromId(Long.valueOf(mItem.getId()), new BrewingProgramListActivity.BrewingProgramAcceptor() {
                @Override
                public void useBrewingProgram(BrewingProgram bp) {
                    setBrewProgram(bp);
                }
            });
        } else {
            // item is blank, init with default values
            mItem.setName("Untitled Program");
            mItem.setDescription("Best coffee ever.");
            Integer onTimes[] = new Integer[]{50, 50, 0, 0, 0};
            Integer offTimes[] = new Integer[]{20, 0, 0, 0, 0};
            mItem.setOnTimes(onTimes);
            mItem.setOffTimes(offTimes);
            updateUiFromItem();
            ((Button) getView().findViewById(R.id.btn_brew)).setEnabled(true);
        }
    }

    @Override
    public void onCreateOptionsMenu(Menu menu, MenuInflater inflater) {
        super.onCreateOptionsMenu(menu, inflater);
        inflater.inflate(R.menu.brewing_program, menu);
        ActionBar actionBar = getActivity().getActionBar();
        actionBar.setNavigationMode(ActionBar.NAVIGATION_MODE_STANDARD);
        actionBar.setDisplayShowTitleEnabled(true);
        actionBar.setTitle("Brew");
        // Locate MenuItem with ShareActionProvider
        MenuItem item = menu.findItem(R.id.menu_item_share);
        // Fetch and store ShareActionProvider
        mShareActionProvider = (ShareActionProvider) item.getActionProvider();
    }

    @Override
    public void onAttach(Activity activity) {
        super.onAttach(activity);
        try {
            mListener = (BrewingProgramDetailCallbacks) activity;
        } catch (ClassCastException e) {
            throw new ClassCastException(activity.toString()
                    + " must implement BrewingProgramDetailCallbacks");
        }
    }

    @Override
    public void onDetach() {
        super.onDetach();
        mListener = null;
    }

    // Call to update the share intent
    private void setShareIntent() {
        if (mShareActionProvider != null) {
            Intent shareIntent = new Intent();
            shareIntent.setAction(Intent.ACTION_SEND);
            shareIntent.putExtra(Intent.EXTRA_TEXT, mItem.getName() + " " + mItem.getShortUrl());
            shareIntent.setType("text/plain");
            mShareActionProvider.setShareIntent(shareIntent);
        }
    }

    private void updateUiOnChange() {
        mUnsavedChanges = isItemDifferentThanUi();
        Button b = (Button) getView().findViewById(R.id.btn_programDiscardChanges);
        if (b != null) {
            b.setEnabled(mUnsavedChanges);
        }

    }

    private void updateUiFromItem() {
        // do stuff;
        EditText et;
        TextView tv;
        et = (EditText) getView().findViewById(R.id.et_program_name);
        et.setText(mItem.getName());
        et = (EditText) getView().findViewById(R.id.et_program_description);
        et.setText(mItem.getDescription());

        // convert from 100ms (units of coffee machine) to seconds (for user display)
        final Float[] onTimesAsFloat = mItem.getOnTimesAsSeconds();
        final Float[] offTimesAsFloat = mItem.getOffTimesAsSeconds();
        et = (EditText) getView().findViewById(R.id.et_onForOne);
        et.setText(onTimesAsFloat[0].toString());
        et = (EditText) getView().findViewById(R.id.et_offForOne);
        et.setText(offTimesAsFloat[0].toString());
        et = (EditText) getView().findViewById(R.id.et_onForTwo);
        et.setText(onTimesAsFloat[1].toString());
        et = (EditText) getView().findViewById(R.id.et_offForTwo);
        et.setText(offTimesAsFloat[1].toString());
        et = (EditText) getView().findViewById(R.id.et_onForThree);
        et.setText(onTimesAsFloat[2].toString());
        et = (EditText) getView().findViewById(R.id.et_offForThree);
        et.setText(offTimesAsFloat[2].toString());
        et = (EditText) getView().findViewById(R.id.et_onForFour);
        et.setText(onTimesAsFloat[3].toString());
        et = (EditText) getView().findViewById(R.id.et_offForFour);
        et.setText(offTimesAsFloat[3].toString());
        et = (EditText) getView().findViewById(R.id.et_onForFive);
        et.setText(onTimesAsFloat[4].toString());
        et = (EditText) getView().findViewById(R.id.et_offForFive);
        et.setText(offTimesAsFloat[4].toString());

        tv = (TextView) getView().findViewById(R.id.tv_createdAt);
        tv.setText(mItem.getCreatedAt());
        tv = (TextView) getView().findViewById(R.id.tv_modifiedAt);
        tv.setText(mItem.getModifiedAt());

        mListener.makeNotBusy();
        if (mItem.getShortUrl().isEmpty()) {
            try {
                AsyncTask<BrewingProgram, Integer, Boolean> task = new ShortenUrlTask().execute(mItem);
            } catch (Exception e) {
                System.out.println("ShortenUrlTask was interrupted: " + e.getLocalizedMessage());
            }
        } else {
            setShareIntent();
        }

    }

    private void updateItemFromUi() {
        // do stuff;
        EditText v;
        v = (EditText) getView().findViewById(R.id.et_program_name);
        mItem.setName(v.getText());
        v = (EditText) getView().findViewById(R.id.et_program_description);
        mItem.setDescription(v.getText());

        Integer[] onTimes = mItem.getOnTimes();
        Integer[] offTimes = mItem.getOffTimes();
        v = (EditText) getView().findViewById(R.id.et_onForOne);
        ifEmptySetZero(v);
        // convert from seconds (user displayed format) to 100ms units (machine time units)
        // as we limit to one decimal point above, do this by just removing the decimal point and
        // cast to Integer
        onTimes[0] = Integer.valueOf(v.getText().toString().replace(".", ""));
        v = (EditText) getView().findViewById(R.id.et_offForOne);
        ifEmptySetZero(v);
        offTimes[0] = Integer.valueOf(v.getText().toString().replace(".", ""));
        v = (EditText) getView().findViewById(R.id.et_onForTwo);
        ifEmptySetZero(v);
        onTimes[1] = Integer.valueOf(v.getText().toString().replace(".", ""));
        v = (EditText) getView().findViewById(R.id.et_offForTwo);
        ifEmptySetZero(v);
        offTimes[1] = Integer.valueOf(v.getText().toString().replace(".", ""));
        v = (EditText) getView().findViewById(R.id.et_onForThree);
        ifEmptySetZero(v);
        onTimes[2] = Integer.valueOf(v.getText().toString().replace(".", ""));
        v = (EditText) getView().findViewById(R.id.et_offForThree);
        ifEmptySetZero(v);
        offTimes[2] = Integer.valueOf(v.getText().toString().replace(".", ""));
        v = (EditText) getView().findViewById(R.id.et_onForFour);
        ifEmptySetZero(v);
        onTimes[3] = Integer.valueOf(v.getText().toString().replace(".", ""));
        v = (EditText) getView().findViewById(R.id.et_offForFour);
        ifEmptySetZero(v);
        offTimes[3] = Integer.valueOf(v.getText().toString().replace(".", ""));
        v = (EditText) getView().findViewById(R.id.et_onForFive);
        ifEmptySetZero(v);
        onTimes[4] = Integer.valueOf(v.getText().toString().replace(".", ""));
        v = (EditText) getView().findViewById(R.id.et_offForFive);
        ifEmptySetZero(v);
        offTimes[4] = Integer.valueOf(v.getText().toString().replace(".", ""));

        mItem.setOnTimes(onTimes);
        mItem.setOffTimes(offTimes);
    }

    private boolean isItemDifferentThanUi() {
        // do stuff;
        EditText v;
        v = (EditText) getView().findViewById(R.id.et_program_name);
        if (!v.getText().toString().contentEquals(mItem.getName())) {
            return true;
        }
        v = (EditText) getView().findViewById(R.id.et_program_description);
        if (!v.getText().toString().contentEquals(mItem.getDescription())) {
            return true;
        }
        Float[] onTimesAsFloat = mItem.getOnTimesAsSeconds();
        Float[] offTimesAsFloat = mItem.getOffTimesAsSeconds();
        v = (EditText) getView().findViewById(R.id.et_onForOne);
        if (v.getText().toString().isEmpty() || !Float.valueOf(v.getText().toString()).equals(onTimesAsFloat[0])) {
            return true;
        }
        v = (EditText) getView().findViewById(R.id.et_offForOne);
        if (v.getText().toString().isEmpty() || !Float.valueOf(v.getText().toString()).equals(offTimesAsFloat[0])) {
            return true;
        }
        v = (EditText) getView().findViewById(R.id.et_onForTwo);
        if (v.getText().toString().isEmpty() || !Float.valueOf(v.getText().toString()).equals(onTimesAsFloat[1])) {
            return true;
        }
        v = (EditText) getView().findViewById(R.id.et_offForTwo);
        if (v.getText().toString().isEmpty() || !Float.valueOf(v.getText().toString()).equals(offTimesAsFloat[1])) {
            return true;
        }
        v = (EditText) getView().findViewById(R.id.et_onForThree);
        if (v.getText().toString().isEmpty() || !Float.valueOf(v.getText().toString()).equals(onTimesAsFloat[2])) {
            return true;
        }
        v = (EditText) getView().findViewById(R.id.et_offForThree);
        if (v.getText().toString().isEmpty() || !Float.valueOf(v.getText().toString()).equals(offTimesAsFloat[2])) {
            return true;
        }
        v = (EditText) getView().findViewById(R.id.et_onForFour);
        if (v.getText().toString().isEmpty() || !Float.valueOf(v.getText().toString()).equals(onTimesAsFloat[3])) {
            return true;
        }
        v = (EditText) getView().findViewById(R.id.et_offForFour);
        if (v.getText().toString().isEmpty() || !Float.valueOf(v.getText().toString()).equals(offTimesAsFloat[3])) {
            return true;
        }
        v = (EditText) getView().findViewById(R.id.et_onForFive);
        if (v.getText().toString().isEmpty() || !Float.valueOf(v.getText().toString()).equals(onTimesAsFloat[4])) {
            return true;
        }
        v = (EditText) getView().findViewById(R.id.et_offForFive);
        if (v.getText().toString().isEmpty() || !Float.valueOf(v.getText().toString()).equals(offTimesAsFloat[4])) {
            return true;
        }
        return false;
    }

    private void ifEmptySetZero(EditText v) {
        if (v.getText().toString().isEmpty()) {
            v.setText("0");
        }
    }

    private void on_brewButtonClicked(View v) {
        if (mListener != null) {
            updateItemFromUi();
            mListener.brewProgram(mItem);
        }
    }

    private void on_discardChangesClicked(View v) {
        // discard
        updateUiFromItem();
    }

    private void saveOrUpdateRecord(View v) {
        if (mListener.saveOrCreateItem(mItem)) {
            Toast.makeText(getActivity(), getString(R.string.notify_changesSavedSuccess), Toast.LENGTH_SHORT);
        } else {
            Toast.makeText(getActivity(), getString(R.string.notify_changesSavedFailure), Toast.LENGTH_SHORT);
        }
        updateUiOnChange();
    }


    /**
     * ***********
     * INTERFACES
     * ************
     */

    // for View.onClickListener interface
    // handle onClick in the fragment, yay Android Fragments
    @Override
    public void onClick(View v) {
        switch (v.getId()) {
            case R.id.btn_brew:
                on_brewButtonClicked(v);
                break;
            case R.id.btn_programDiscardChanges:
                on_discardChangesClicked(v);
                break;
        }
    }

    public void saveIfNecessary() {
        if (mUnsavedChanges) {
            // clear focus so the onFocusLost listeners can run and prune inputs
            for (final EditText et : mNumericInputFields) {
                et.clearFocus();
            }
            updateItemFromUi();
            try {
                AsyncTask<BrewingProgram, Integer, Boolean> task = new ShortenUrlTask().execute(mItem);
                task.get(); //block on task to keep this alive
            } catch (Exception e) {
                System.out.println("ShortenUrlTask was interrupted: " + e.getLocalizedMessage());
            }
            // the save commands in the Async task will fail here if called from the activity itself
            // (as happens when the back button is intercepted and this is called)
            mListener.saveOrCreateItem(mItem);
            mListener.makeNotBusy(); // kill the busy spinner
        }
    }

    public void setBrewProgram(BrewingProgram theProgram) {
        mItem = new BrewingProgram(theProgram);
        ((Button) getView().findViewById(R.id.btn_brew)).setEnabled(true);
        updateUiFromItem();
    }

    public interface BrewingProgramDetailCallbacks {
        void brewProgram(BrewingProgram theProgram);

        void makeBusy(final CharSequence title, final CharSequence message);

        void makeNotBusy();

        boolean saveOrCreateItem(BrewingProgram aProgram);

        void buildProgramFromId(final long id, final BrewingProgramListActivity.BrewingProgramAcceptor acceptor);
    }

    private class ShortenUrlTask extends AsyncTask<BrewingProgram, Integer, Boolean> {
        protected Boolean doInBackground(BrewingProgram... programs) {
            Boolean success = true;
            for (int k = 0; k < programs.length; ++k) {
                success &= programs[k].shortenUrl();
            }
            return success;
        }

        protected void onPreExecute() {
            mListener.makeBusy("Please wait", "Shortening URL...");
        }

        protected void onPostExecute(Boolean result) {
            setShareIntent();
            // since we have a new URL, save if we can
            if (mListener != null) {
                mListener.saveOrCreateItem(mItem);
                mListener.makeNotBusy();
            }
        }
    }
}
