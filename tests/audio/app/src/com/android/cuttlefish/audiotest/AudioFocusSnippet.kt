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

import android.app.ActivityManager
import android.content.Context
import android.content.Intent
import android.media.AudioAttributes
import android.media.AudioFocusRequest
import android.media.AudioManager
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.Process
import android.os.ResultReceiver
import android.util.Log
import androidx.annotation.GuardedBy
import androidx.test.platform.app.InstrumentationRegistry
import com.google.android.mobly.snippet.Snippet
import com.google.android.mobly.snippet.event.EventCache
import com.google.android.mobly.snippet.event.SnippetEvent
import com.google.android.mobly.snippet.rpc.AsyncRpc
import com.google.android.mobly.snippet.rpc.Rpc
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

/**
 * [AudioManager.OnAudioFocusChangeListener] whose [toString] produces a deterministic,
 * per-instance `CfAudioTest[<tag>]#<seq>` token inside `MediaFocusControl`'s
 * `FocusRequester.mClientId` dump, avoiding reliance on synthetic Kotlin/R8 lambda class names
 * while keeping repeated requests on the same [tag] distinct.
 */
internal class TaggedFocusListener(
    private val tag: String,
    private val onChange: (Int) -> Unit,
) : AudioManager.OnAudioFocusChangeListener {
    private val seq = NEXT_SEQ.incrementAndGet()

    override fun onAudioFocusChange(focusChange: Int) = onChange(focusChange)

    // Unique per instance: AudioManager/MediaFocusControl key focus clients on
    // AudioManager.toString() + listener.toString().
    override fun toString(): String = "CfAudioTest[$tag]#$seq"

    private companion object {
        val NEXT_SEQ = AtomicInteger(0)
    }
}

/**
 * Mobly Snippet exposing Android AudioFocus operations over JSON-RPC.
 *
 * Keyed by [clientId] so multiple independent focus clients can be created,
 * observed, and abandoned concurrently within the same test session.
 */
class AudioFocusSnippet : Snippet {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context: Context = instrumentation.targetContext
    private val audioManager = context.getSystemService(Context.AUDIO_SERVICE) as AudioManager
    private val mainHandler = Handler(Looper.getMainLooper())
    private val lock = Any()
    private val lastChildPid = AtomicInteger(-1)
    private val childStartPending = AtomicBoolean(false)

    @GuardedBy("lock")
    private val activeRequests = mutableMapOf<String, MutableList<AudioFocusRequest>>()

    @GuardedBy("lock")
    private val callbackIds = mutableMapOf<String, String>()

    init {
        instrumentation.uiAutomation.adoptShellPermissionIdentity()
    }

    /**
     * Requests audio focus for [clientId] with the specified [usage], [contentType], and
     * [focusGain].
     */
    @Rpc(description = "Requests audio focus for clientId with given attributes and gain type")
    fun requestAudioFocus(
        clientId: String,
        usage: Int,
        contentType: Int,
        focusGain: Int,
    ): Int {
        val attributes =
            AudioAttributes.Builder()
                .setUsage(usage)
                .setContentType(contentType)
                .build()

        val listener =
            TaggedFocusListener(clientId) { focusChange ->
                Log.d(TAG, "onAudioFocusChange: clientId=$clientId focusChange=$focusChange")
                val callbackId = synchronized(lock) { callbackIds[clientId] }
                if (callbackId != null) {
                    val event =
                        SnippetEvent(callbackId, EVENT_ON_AUDIO_FOCUS_CHANGE).apply {
                            data.putString(FIELD_CLIENT_ID, clientId)
                            data.putInt(FIELD_FOCUS_CHANGE, focusChange)
                        }
                    EventCache.getInstance().postEvent(event)
                }
            }

        val request =
            AudioFocusRequest.Builder(focusGain)
                .setAudioAttributes(attributes)
                .setAcceptsDelayedFocusGain(true)
                .setOnAudioFocusChangeListener(listener, mainHandler)
                .build()

        val result = audioManager.requestAudioFocus(request)
        Log.d(
            TAG,
            "requestAudioFocus: clientId=$clientId usage=$usage contentType=$contentType " +
                "focusGain=$focusGain result=$result",
        )
        if (result == AudioManager.AUDIOFOCUS_REQUEST_GRANTED ||
            result == AudioManager.AUDIOFOCUS_REQUEST_DELAYED
        ) {
            synchronized(lock) {
                activeRequests.getOrPut(clientId) { mutableListOf() }.add(request)
            }
        }
        return result
    }

    /**
     * Starts [DyingFocusHolderService] in a dedicated `:dying_focus_client` child process,
     * requests audio focus there, and returns the child process PID (or `-1` if the focus request
     * failed or timed out).
     */
    @Rpc(
        description =
            "Requests audio focus in :dying_focus_client child process; returns positive PID on " +
                "AUDIOFOCUS_REQUEST_GRANTED or -1 on failure/timeout"
    )
    fun requestAudioFocusInChildProcess(
        usage: Int,
        contentType: Int,
        focusGain: Int,
    ): Int {
        lastChildPid.set(-1)
        val latch = CountDownLatch(1)
        val childPid = AtomicInteger(-1)
        val focusResult = AtomicInteger(AudioManager.AUDIOFOCUS_REQUEST_FAILED)

        val receiver =
            object : ResultReceiver(mainHandler) {
                override fun onReceiveResult(resultCode: Int, resultData: Bundle?) {
                    val reportedPid = resultData?.getInt(DyingFocusHolderService.KEY_PID, -1) ?: -1
                    if (reportedPid > 0) {
                        lastChildPid.set(reportedPid)
                    }
                    childPid.set(reportedPid)
                    focusResult.set(resultCode)
                    latch.countDown()
                }
            }

        val intent =
            Intent(context, DyingFocusHolderService::class.java).apply {
                putExtra(DyingFocusHolderService.EXTRA_USAGE, usage)
                putExtra(DyingFocusHolderService.EXTRA_CONTENT_TYPE, contentType)
                putExtra(DyingFocusHolderService.EXTRA_FOCUS_GAIN, focusGain)
                putExtra(DyingFocusHolderService.EXTRA_RESULT_RECEIVER, receiver)
            }
        childStartPending.set(true)
        context.startService(intent)

        if (!latch.await(CHILD_START_TIMEOUT_SEC, TimeUnit.SECONDS)) {
            Log.e(
                TAG,
                "Timed out after ${CHILD_START_TIMEOUT_SEC}s waiting for " +
                    "$CHILD_PROCESS_NAME to acquire audio focus",
            )
            return -1
        }
        if (focusResult.get() != AudioManager.AUDIOFOCUS_REQUEST_GRANTED) {
            Log.e(
                TAG,
                "Child process pid=${childPid.get()} failed to acquire audio focus: " +
                    "result=${focusResult.get()}",
            )
            return -1
        }
        return childPid.get()
    }

    /**
     * Sends `SIGKILL` (`Process.killProcess`) to the `:dying_focus_client` process if running and
     * stops [DyingFocusHolderService].
     *
     * Because the child process shares this snippet's UID, `Process.killProcess` requires no root
     * or shell privileges. Returns the killed PID, or `-1` if no child process was active.
     */
    @Rpc(
        description =
            "SIGKILLs the :dying_focus_client process if running; returns killed PID or -1"
    )
    fun killChildProcess(): Int {
        val wasPending = childStartPending.getAndSet(false)
        val recordedPid = lastChildPid.getAndSet(-1)
        val am = context.getSystemService(ActivityManager::class.java)
        val runningPid =
            am?.runningAppProcesses
                ?.firstOrNull { it.processName == CHILD_PROCESS_NAME }
                ?.pid ?: -1
        val targetPid = if (runningPid > 0) runningPid else recordedPid

        // Send SIGKILL before stopService() so the child dies immediately without running
        // Service.onDestroy(), then clear the ServiceRecord in ActivityManagerService.
        if (targetPid > 0) {
            Log.d(TAG, "killChildProcess: sending SIGKILL to $CHILD_PROCESS_NAME pid=$targetPid")
            Process.killProcess(targetPid)
        } else if (wasPending) {
            Log.w(
                TAG,
                "killChildProcess: start pending but $CHILD_PROCESS_NAME not attached; " +
                    "relying on DyingFocusHolderService.onDestroy() self-termination",
            )
        }
        context.stopService(Intent(context, DyingFocusHolderService::class.java))
        return targetPid
    }

    /** Abandons all active [AudioFocusRequest]s associated with [clientId]. */
    @Rpc(description = "Abandons audio focus for clientId")
    fun abandonAudioFocus(clientId: String): Int {
        val requests =
            synchronized(lock) {
                callbackIds.remove(clientId)
                activeRequests.remove(clientId)
            }
        if (requests.isNullOrEmpty()) {
            Log.w(TAG, "abandonAudioFocus: no active request for clientId=$clientId")
            return AudioManager.AUDIOFOCUS_REQUEST_FAILED
        }
        var lastResult = AudioManager.AUDIOFOCUS_REQUEST_GRANTED
        for (request in requests) {
            lastResult = audioManager.abandonAudioFocusRequest(request)
            Log.d(TAG, "abandonAudioFocus: clientId=$clientId result=$lastResult")
        }
        return lastResult
    }

    /** Abandons all active audio focus requests to ensure test isolation. */
    @Rpc(description = "Abandons all active audio focus requests")
    fun abandonAllAudioFocus() {
        val requestsByClient =
            synchronized(lock) {
                val copy = activeRequests.mapValues { it.value.toList() }
                activeRequests.clear()
                callbackIds.clear()
                copy
            }
        for ((clientId, requests) in requestsByClient) {
            for (request in requests) {
                val result = audioManager.abandonAudioFocusRequest(request)
                Log.d(TAG, "abandonAllAudioFocus: clientId=$clientId result=$result")
            }
        }
    }

    /** Registers an asynchronous callback for focus change events on [clientId]. */
    @AsyncRpc(description = "Registers an audio focus change listener for clientId")
    fun registerFocusChangeListener(callbackId: String, clientId: String) {
        Log.d(TAG, "registerFocusChangeListener: clientId=$clientId callbackId=$callbackId")
        synchronized(lock) {
            callbackIds[clientId] = callbackId
        }
    }

    /** Unregisters any asynchronous focus change listener associated with [clientId]. */
    @Rpc(description = "Unregisters an audio focus change listener for clientId")
    fun unregisterFocusChangeListener(clientId: String) {
        Log.d(TAG, "unregisterFocusChangeListener: clientId=$clientId")
        synchronized(lock) {
            callbackIds.remove(clientId)
        }
    }

    override fun shutdown() {
        killChildProcess()
        abandonAllAudioFocus()
        instrumentation.uiAutomation.dropShellPermissionIdentity()
    }

    private companion object {
        const val TAG = "AudioFocusSnippet"
        const val CHILD_PROCESS_NAME = "com.android.cuttlefish.audiotest:dying_focus_client"
        const val EVENT_ON_AUDIO_FOCUS_CHANGE = "onAudioFocusChange"
        const val FIELD_CLIENT_ID = "clientId"
        const val FIELD_FOCUS_CHANGE = "focusChange"
        const val CHILD_START_TIMEOUT_SEC = 15L
    }
}
