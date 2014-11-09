package com.wibean.android.wibean.data;

import android.content.Context;
import android.database.Cursor;
import android.view.View;
import android.widget.ImageButton;
import android.widget.ImageView;
import android.widget.ResourceCursorAdapter;
import android.widget.TextView;

import com.wibean.android.wibean.R;

/**
 * Created by John-Michael on 9/24/2014.
 * This creates a list of brewing programs with an image, title, description, and an edit button
 */
public class BrewProgramListAdapter extends ResourceCursorAdapter {

    private EditButtonReceiver mEditButtonReceiver = null;

    public BrewProgramListAdapter(Context context, int layout, Cursor cursor, int flags) {
        super(context, layout, cursor, flags);
        mEditButtonReceiver = null;
    }

    public void setEditButtonReceiver(EditButtonReceiver callback) {
        mEditButtonReceiver = callback;
    }

    @Override
    public void bindView(View view, Context context, Cursor cursor) {
        TextView bpt = (TextView) view.findViewById(R.id.tv_listRow_brewProgram_title);
        TextView bpd = (TextView) view.findViewById(R.id.tv_listRow_brewProgram_description);
        ImageView bpthumb = (ImageView) view.findViewById(R.id.iv_brew_program_graphic);
        ImageButton bpEdit = (ImageButton) view.findViewById(R.id.ib_editBrewProgram);

        bpt.setText(cursor.getString(cursor.getColumnIndex(BrewingProgramHelper.COLUMN_NAME)));
        bpd.setText(cursor.getString(cursor.getColumnIndex(BrewingProgramHelper.COLUMN_DESCRIPTION)));
        bpthumb.setImageDrawable(
                context.getResources().getDrawable(
                        context.getResources().getIdentifier(
                                cursor.getString(
                                        cursor.getColumnIndex(BrewingProgramHelper.COLUMN_IMAGE_THUMBNAIL_NAME)
                                ), "drawable", context.getPackageName()))
        );
        final long itemId = cursor.getLong(cursor.getColumnIndex(BrewingProgramHelper.COLUMN_ID_ALIASED));
        if (mEditButtonReceiver != null) {
            bpEdit.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    mEditButtonReceiver.launchEditor(itemId);
                }
            });
        }
    }

    public interface EditButtonReceiver {
        void launchEditor(long itemId);
    }

}
