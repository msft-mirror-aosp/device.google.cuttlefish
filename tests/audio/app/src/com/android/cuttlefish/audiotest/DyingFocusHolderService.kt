/*
 * Copyright (C) 2026 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.android.cuttlefish.audiotest

import android.app.Service
import android.content.Context
import android.content.Intent
import android.media.AudioAttributes
import android.media.AudioFocusRequest
import android.media.AudioManager
import android.os.Bundle
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.Process
import android.os.ResultReceiver
import android.util.Log

/**
 * Helper [Service] running in a dedicated `:dying_focus_client` child process.
 *
 * Requests and holds an [AudioFocusRequest] until the process is abruptly terminated via `SIGKILL`
 * (`Process.killProcess`), exercising `MediaFocusControl`'s `AudioFocusDeathHandler.binderDied()`
 * cleanup path.
 *
 * **Warning**: Never abandon audio focus in [onDestroy]; if [onDestroy] is reached without a prior
 * `SIGKILL`, self-terminate so focus is still only ever released via
 * `AudioFocusDeathHandler.binderDied()`.
 */
class DyingFocusHolderService : Service() {
    private val mainHandler by lazy { Handler(mainLooper) }

    // Retained on the Service instance so any second onStartCommand() in the same process can
    // cleanly abandon the prior request before registering a new one. (Not required for GC
    // pinning; AudioManager.mAudioFocusIdListenerMap and mICallBack already hold strong refs.)
    private var activeRequest: AudioFocusRequest? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent == null) {
            return START_NOT_STICKY
        }

        val usage = intent.getIntExtra(EXTRA_USAGE, AudioAttributes.USAGE_ALARM)
        val contentType =
            intent.getIntExtra(EXTRA_CONTENT_TYPE, AudioAttributes.CONTENT_TYPE_SONIFICATION)
        val focusGain =
            intent.getIntExtra(EXTRA_FOCUS_GAIN, AudioManager.AUDIOFOCUS_GAIN_TRANSIENT)
        val receiver = intent.getParcelableExtra(EXTRA_RESULT_RECEIVER, ResultReceiver::class.java)

        val audioManager = getSystemService(Context.AUDIO_SERVICE) as AudioManager
        activeRequest?.let { previous ->
            audioManager.abandonAudioFocusRequest(previous)
            activeRequest = null
        }

        val attributes =
            AudioAttributes.Builder()
                .setUsage(usage)
                .setContentType(contentType)
                .build()

        val listener =
            TaggedFocusListener(CLIENT_TAG_DYING_CHILD) { focusChange ->
                Log.d(TAG, "Child onAudioFocusChange: focusChange=$focusChange")
            }

        val request =
            AudioFocusRequest.Builder(focusGain)
                .setAudioAttributes(attributes)
                .setOnAudioFocusChangeListener(listener, mainHandler)
                .build()
        activeRequest = request

        val result = audioManager.requestAudioFocus(request)
        val pid = Process.myPid()
        Log.d(
            TAG,
            "Child process pid=$pid requested AudioFocus (usage=$usage, focusGain=$focusGain): " +
                "result=$result",
        )

        val resultData = Bundle().apply { putInt(KEY_PID, pid) }
        receiver?.send(result, resultData)

        return START_NOT_STICKY
    }

    /**
     * If the service is ever stopped without a prior `SIGKILL` (e.g. `killChildProcess()` raced a
     * still-attaching child), terminate the process instead of abandoning focus so that focus is
     * still only ever released via `AudioFocusDeathHandler.binderDied()`.
     */
    override fun onDestroy() {
        super.onDestroy()
        Log.w(TAG, "onDestroy() without prior SIGKILL; self-terminating pid=${Process.myPid()}")
        Process.killProcess(Process.myPid())
    }

    /** Start-only service; avoids ServiceConnection death/unbind races when SIGKILLed. */
    override fun onBind(intent: Intent?): IBinder? = null

    companion object {
        private const val TAG = "AudioFocusChildSvc"
        const val CLIENT_TAG_DYING_CHILD = "dying_child"
        const val EXTRA_USAGE = "extra_usage"
        const val EXTRA_CONTENT_TYPE = "extra_content_type"
        const val EXTRA_FOCUS_GAIN = "extra_focus_gain"
        const val EXTRA_RESULT_RECEIVER = "extra_result_receiver"
        const val KEY_PID = "pid"
    }
}
