package com.linkedin.android.atrace;

import android.app.Activity;
import android.os.Bundle;
import android.os.Trace;
import android.widget.Toast;

public class MainActivity extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        findViewById(R.id.button).setOnClickListener(v -> {
            Atrace.enableSystrace();
            Toast.makeText(MainActivity.this, "开启成功", Toast.LENGTH_SHORT).show();
        });
        findViewById(R.id.closeButton).setOnClickListener(v -> {
            Atrace.restoreSystrace();
            Toast.makeText(MainActivity.this, "关闭成功", Toast.LENGTH_SHORT).show();
        });

        findViewById(R.id.layout).setOnClickListener(v -> {
            Trace.beginSection("test");
            try {
                Thread.sleep(10);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
            Trace.endSection();
        });
    }
}
