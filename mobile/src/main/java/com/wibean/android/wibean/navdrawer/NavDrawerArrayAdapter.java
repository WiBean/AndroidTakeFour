package com.wibean.android.wibean.navdrawer;

/**
 * Created by John-Michael on 7/18/2014.
 */

import android.content.Context;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ArrayAdapter;
import android.widget.ImageView;
import android.widget.TextView;

import com.wibean.android.wibean.R;

import java.util.ArrayList;


public class NavDrawerArrayAdapter extends ArrayAdapter<NavDrawerItem> {

    private Context context;

    public NavDrawerArrayAdapter(Context context, int textViewResourceId, ArrayList<NavDrawerItem> items) {
        super(context, textViewResourceId, items);
        this.context = context;
    }

    @Override
    public View getView(int position, View convertView, ViewGroup parent) {
        if (convertView == null) {
            LayoutInflater inflater = (LayoutInflater) context.getSystemService(Context.LAYOUT_INFLATER_SERVICE);
            convertView = inflater.inflate(R.layout.nav_drawer_list_item, null);
        }
        ImageView imgIcon = (ImageView) convertView.findViewById(R.id.icon);
        TextView txtTitle = (TextView) convertView.findViewById(R.id.title);
        TextView txtCount = (TextView) convertView.findViewById(R.id.counter);

        NavDrawerItem anItem = getItem(position);
        imgIcon.setImageResource(anItem.getIcon());
        txtTitle.setText(anItem.getTitle());
        // displaying count
        // check whether it set visible or not
        if (anItem.getCounterVisibility()) {
            txtCount.setText(anItem.getCount());
        } else {
            // hide the counter view
            txtCount.setVisibility(View.GONE);
        }

        return convertView;
    }
}
