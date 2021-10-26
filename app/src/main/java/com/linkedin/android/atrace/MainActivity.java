package com.linkedin.android.atrace;

import android.app.Activity;
import android.os.Bundle;
import android.os.Trace;
import android.util.Log;
import android.widget.Toast;
import java.io.File;
import java.io.IOException;

public class MainActivity extends Activity {
    File dir;
    File traceFile;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        dir = this.getExternalCacheDir();

        findViewById(R.id.button).setOnClickListener(v -> {
            traceFile = new File(dir, System.currentTimeMillis() + ".trace");
            try {
                traceFile.createNewFile();
                Atrace.enableSystrace(traceFile.getAbsolutePath());
                Log.e("hjw", traceFile.getAbsolutePath());
                Toast.makeText(MainActivity.this, "开启成功: " + traceFile.getAbsolutePath(), Toast.LENGTH_SHORT).show();
            } catch (IOException e) {
                e.printStackTrace();
            }
        });
        findViewById(R.id.closeButton).setOnClickListener(v -> {
            Atrace.restoreSystrace();
            Log.e("hjw", "run:\nadb pull " + traceFile.getAbsolutePath());
            Toast.makeText(MainActivity.this, "关闭成功", Toast.LENGTH_SHORT).show();
        });

        findViewById(R.id.layout).setOnClickListener(v -> {
            Trace.beginSection("test");
            int fib = fib(1000000000);
            Trace.endSection();
            Log.e("hjw", "fib=" + fib);
        });

        Log.e("hjw", this.getFilesDir().getAbsolutePath());
    }

    public int fib(int n) {
        if (n < 0) {
            return 0;
        } else if (n == 0 || n == 1) {
            return n;
        }
        int f1 = 0, f2 = 1;
        for (int i = 1; i < n; i++) {
            int temp = (f2 + f1) % 1000000007;
            f1 = f2;
            f2 = temp;
        }
        return f2;
    }
}
