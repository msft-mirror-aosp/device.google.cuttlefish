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

import android.content.Context
import android.media.AudioAttributes
import android.media.AudioFormat
import android.media.AudioManager
import android.media.AudioModeSession
import android.media.AudioTrack
import android.media.audio.Flags
import android.os.SystemClock
import android.util.Log
import androidx.annotation.GuardedBy
import androidx.test.platform.app.InstrumentationRegistry
import com.google.android.mobly.snippet.Snippet
import com.google.android.mobly.snippet.rpc.Rpc
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import kotlin.math.PI
import kotlin.math.sin

/**
 * Mobly Snippet exposing [AudioModeSession] VoIP/Call session management and [AudioTrack] streaming
 * over JSON-RPC.
 *
 * Uses [AudioModeSession] in lieu of direct `AudioManager.setMode()`,
 * `AudioManager.setCommunicationDevice()`, and manual `requestAudioFocus()` calls for VoIP and
 * call mode owners.
 */
class AudioModeSessionSnippet : Snippet {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context: Context = instrumentation.targetContext
    private val audioManager = context.getSystemService(Context.AUDIO_SERVICE) as AudioManager
    private val callbackExecutor = Executors.newSingleThreadExecutor()
    private val lock = Any()

    @GuardedBy("lock")
    private val activeSessions = mutableMapOf<String, ManagedModeSession>()

    @GuardedBy("lock")
    private val activeStreams = mutableMapOf<String, ActivePlaybackStream>()

    init {
        SnippetShellPermissions.ensureAdopted()
    }

    /** Returns true if the [Flags.FLAG_FUSED_TELECOM_ROUTE_API] flag is enabled. */
    @Rpc(description = "Returns true if AudioModeSession (fusedTelecomRouteApi) is enabled")
    fun isModeSessionSupported(): Boolean = Flags.fusedTelecomRouteApi()

    /** Returns the list of connected output device types from [AudioManager.getDevices]. */
    @Rpc(description = "Returns connected output device types from AudioManager")
    fun getOutputDeviceTypes(): List<Int> =
        audioManager.getDevices(AudioManager.GET_DEVICES_OUTPUTS).map { it.type }

    /**
     * Creates an [AudioModeSession] identified by [sessionId] with [initialMode] and
     * [isDisplayActiveUseCase], waits for initial session activation and default routing, and
     * returns the default routed `primaryDevice.type`.
     */
    @Rpc(
        description =
            "Creates an AudioModeSession, waits for initial routing, and returns the routed " +
                "device type"
    )
    fun createModeSession(
        sessionId: String,
        initialMode: Int,
        isDisplayActiveUseCase: Boolean,
    ): Int {
        closeModeSession(sessionId)

        val callback = SessionCallback(sessionId)
        val request =
            AudioModeSession.Request.Builder()
                .setInitialMode(initialMode)
                .setDisplayActiveUseCase(isDisplayActiveUseCase)
                .setClientAttribution(context.attributionSource)
                .build()

        val session = audioManager.createAudioModeSession(request, callbackExecutor, callback)
        val managed = ManagedModeSession(sessionId, session, callback)
        synchronized(lock) {
            activeSessions[sessionId] = managed
        }

        try {
            callback.awaitInitialRoutes()
            val resumedReqId = callback.awaitResumed()
            val result = callback.awaitRoutingResult(resumedReqId)
            check(result.status == AudioModeSession.ROUTING_RESULT_SUCCESSFUL) {
                "Initial routing failed for sessionId=$sessionId: " +
                    "status=${result.status} route=${result.route}"
            }
            val routedType = result.route?.primaryDevice?.type ?: -1
            Log.d(
                TAG,
                "createModeSession: sessionId=$sessionId mode=$initialMode " +
                    "displayActive=$isDisplayActiveUseCase routedType=$routedType",
            )
            return routedType
        } catch (e: Throwable) {
            closeModeSession(sessionId)
            throw e
        }
    }

    /**
     * Returns the list of `primaryDevice.type` values from [AudioModeSession.getAvailableRoutes]
     * for [sessionId].
     */
    @Rpc(description = "Returns available route primary device types for sessionId")
    fun getSessionAvailableRouteTypes(sessionId: String): List<Int> {
        val managed = getManagedSession(sessionId)
        return managed.session.availableRoutes.map { it.primaryDevice.type }
    }

    /**
     * Requests routing on [sessionId] to the [AudioModeSession.AudioRoute] whose
     * `primaryDevice.type == deviceType`, waits for `onRoutingResult`, and returns the applied
     * device type.
     */
    @Rpc(
        description =
            "Requests routing to deviceType on sessionId and returns the applied device type"
    )
    fun requestSessionRouteByType(sessionId: String, deviceType: Int): Int {
        val managed = getManagedSession(sessionId)
        val targetRoute =
            managed.session.availableRoutes.firstOrNull { it.primaryDevice.type == deviceType }
                ?: throw IllegalArgumentException(
                    "Device type $deviceType not found in availableRoutes for " +
                        "sessionId=$sessionId: ${managed.session.availableRoutes}"
                )

        val requestId = managed.session.setRequestedRoute(targetRoute)
        val result = managed.callback.awaitRoutingResult(requestId)
        check(result.status == AudioModeSession.ROUTING_RESULT_SUCCESSFUL) {
            "requestSessionRouteByType failed for sessionId=$sessionId deviceType=$deviceType: " +
                "reqId=$requestId status=${result.status} route=${result.route}"
        }
        val appliedType = result.route?.primaryDevice?.type ?: -1
        Log.d(
            TAG,
            "requestSessionRouteByType: sessionId=$sessionId reqId=$requestId " +
                "appliedType=$appliedType",
        )
        return appliedType
    }

    /**
     * Updates [AudioModeSession.setDisplayActiveUseCase] on [sessionId], waits for the resulting
     * default route update callback, and returns the newly routed `primaryDevice.type`.
     *
     * Precondition: [sessionId] must still be using default routing (no explicit route set via
     * [requestSessionRouteByType]) and changing [isDisplayActiveUseCase] must alter the computed
     * default route so that `AudioService` dispatches `onRoutingResult`.
     */
    @Rpc(
        description =
            "Updates isDisplayActiveUseCase on sessionId and returns the updated default " +
                "routed device type"
    )
    fun setSessionDisplayActiveUseCase(
        sessionId: String,
        isDisplayActiveUseCase: Boolean,
    ): Int {
        val managed = getManagedSession(sessionId)
        managed.callback.clearRoutingResults()
        managed.session.setDisplayActiveUseCase(isDisplayActiveUseCase)
        val result = managed.callback.awaitRoutingResult(expectedRequestId = null)
        check(result.status == AudioModeSession.ROUTING_RESULT_SUCCESSFUL) {
            "setSessionDisplayActiveUseCase routing failed for sessionId=$sessionId: " +
                "status=${result.status} route=${result.route}"
        }
        val appliedType = result.route?.primaryDevice?.type ?: -1
        Log.d(
            TAG,
            "setSessionDisplayActiveUseCase: sessionId=$sessionId " +
                "displayActive=$isDisplayActiveUseCase appliedType=$appliedType",
        )
        return appliedType
    }

    /**
     * Waits for [AudioModeSession.Callback.onPaused] on [sessionId] (triggered when preempted by a
     * newer or higher-priority session).
     */
    @Rpc(description = "Waits for onPaused() callback on sessionId")
    fun awaitSessionPaused(sessionId: String): Boolean {
        val managed = getManagedSession(sessionId)
        managed.callback.awaitPaused()
        return true
    }

    /**
     * Waits for [AudioModeSession.Callback.onResumed] and its matching `onRoutingResult` on
     * [sessionId] after a preempting session closes, returning the restored `primaryDevice.type`.
     */
    @Rpc(
        description =
            "Waits for onResumed() and restored onRoutingResult() on sessionId, returning the " +
                "routed device type"
    )
    fun awaitSessionResumedAndRouted(sessionId: String): Int {
        val managed = getManagedSession(sessionId)
        val resumedReqId = managed.callback.awaitResumed()
        val result = managed.callback.awaitRoutingResult(resumedReqId)
        check(result.status == AudioModeSession.ROUTING_RESULT_SUCCESSFUL) {
            "Restored routing failed on resume for sessionId=$sessionId: " +
                "reqId=$resumedReqId status=${result.status} route=${result.route}"
        }
        return result.route?.primaryDevice?.type ?: -1
    }

    /** Closes the [AudioModeSession] associated with [sessionId] and waits for `onClosed()`. */
    @Rpc(description = "Closes the AudioModeSession for sessionId")
    fun closeModeSession(sessionId: String) {
        val managed =
            synchronized(lock) {
                activeSessions.remove(sessionId)
            } ?: return
        managed.session.close()
        managed.callback.awaitClosed()
        Log.d(TAG, "closeModeSession: sessionId=$sessionId closed")
    }

    /** Closes all active [AudioModeSession] instances. */
    @Rpc(description = "Closes all active AudioModeSessions")
    fun closeAllModeSessions() {
        val sessions =
            synchronized(lock) {
                val copy = activeSessions.values.toList()
                activeSessions.clear()
                copy
            }
        for (managed in sessions) {
            runCatching {
                managed.session.close()
                managed.callback.awaitClosed()
            }.onFailure { e ->
                Log.w(TAG, "closeAllModeSessions: failed closing ${managed.sessionId}", e)
            }
        }
    }

    /**
     * Starts continuous 48 kHz sine-wave [AudioTrack] playback keyed by [streamId] with the given
     * [usage] and [contentType].
     */
    @Rpc(description = "Starts continuous sine-wave AudioTrack playback for streamId")
    fun startPlayback(streamId: String, usage: Int, contentType: Int) {
        stopPlayback(streamId)

        val attributes =
            AudioAttributes.Builder()
                .setUsage(usage)
                .setContentType(contentType)
                .build()
        val format =
            AudioFormat.Builder()
                .setSampleRate(SAMPLE_RATE_HZ)
                .setEncoding(AudioFormat.ENCODING_PCM_16BIT)
                .setChannelMask(AudioFormat.CHANNEL_OUT_MONO)
                .build()
        val rawMinBufBytes =
            AudioTrack.getMinBufferSize(
                SAMPLE_RATE_HZ,
                AudioFormat.CHANNEL_OUT_MONO,
                AudioFormat.ENCODING_PCM_16BIT,
            )
        check(rawMinBufBytes > 0) {
            "AudioTrack.getMinBufferSize failed for streamId=$streamId: $rawMinBufBytes"
        }
        val minBufBytes = rawMinBufBytes.coerceAtLeast(FRAMES_PER_BUFFER * 2)

        val track =
            AudioTrack.Builder()
                .setAudioAttributes(attributes)
                .setAudioFormat(format)
                .setBufferSizeInBytes(minBufBytes * 2)
                .setTransferMode(AudioTrack.MODE_STREAM)
                .build()

        val running = AtomicBoolean(true)
        val firstWriteLatch = CountDownLatch(1)
        val firstWriteError = AtomicReference<String?>(null)
        val pcmBuffer = buildSineWaveBuffer(FRAMES_PER_BUFFER, SAMPLE_RATE_HZ, TONE_FREQ_HZ)

        val writerThread =
            Thread(
                    {
                        try {
                            track.play()
                            while (running.get()) {
                                val written =
                                    track.write(
                                        pcmBuffer,
                                        0,
                                        pcmBuffer.size,
                                        AudioTrack.WRITE_BLOCKING,
                                    )
                                if (written < 0) {
                                    firstWriteError.compareAndSet(
                                        null,
                                        "AudioTrack.write returned error $written on " +
                                            "streamId=$streamId",
                                    )
                                    firstWriteLatch.countDown()
                                    Log.w(TAG, "AudioTrack write error for $streamId: $written")
                                    break
                                }
                                firstWriteLatch.countDown()
                            }
                        } catch (e: Exception) {
                            firstWriteError.compareAndSet(
                                null,
                                "AudioTrack playback startup exception on " +
                                    "streamId=$streamId: ${e.message}",
                            )
                            Log.w(TAG, "AudioTrack playback thread exception for $streamId", e)
                        } finally {
                            firstWriteLatch.countDown()
                        }
                    },
                    "CfAudioPlay-$streamId",
                )
                .apply { isDaemon = true }

        val activeStream = ActivePlaybackStream(streamId, track, running, writerThread)
        synchronized(lock) {
            activeStreams[streamId] = activeStream
        }
        writerThread.start()
        val started = firstWriteLatch.await(CALLBACK_TIMEOUT_MS, TimeUnit.MILLISECONDS)
        val startupErr = firstWriteError.get()
        if (!started || startupErr != null) {
            stopPlayback(streamId)
            error(
                startupErr
                    ?: "Timed out waiting for initial AudioTrack write on streamId=$streamId"
            )
        }
        Log.d(TAG, "startPlayback: streamId=$streamId usage=$usage contentType=$contentType")
    }

    /** Stops and releases the [AudioTrack] playback stream identified by [streamId]. */
    @Rpc(description = "Stops and releases AudioTrack playback for streamId")
    fun stopPlayback(streamId: String) {
        val stream =
            synchronized(lock) {
                activeStreams.remove(streamId)
            } ?: return
        stream.stopAndRelease()
        Log.d(TAG, "stopPlayback: streamId=$streamId stopped")
    }

    /** Stops and releases all active [AudioTrack] playback streams. */
    @Rpc(description = "Stops and releases all active AudioTrack playback streams")
    fun stopAllPlayback() {
        val streams =
            synchronized(lock) {
                val copy = activeStreams.values.toList()
                activeStreams.clear()
                copy
            }
        for (stream in streams) {
            stream.stopAndRelease()
        }
    }

    override fun shutdown() {
        stopAllPlayback()
        closeAllModeSessions()
        callbackExecutor.shutdownNow()
    }

    private fun getManagedSession(sessionId: String): ManagedModeSession =
        synchronized(lock) { activeSessions[sessionId] }
            ?: throw IllegalArgumentException("No active AudioModeSession for sessionId=$sessionId")

    private data class RoutingResultEvent(
        val requestId: Int,
        val route: AudioModeSession.AudioRoute?,
        val status: Int,
    )

    private class SessionCallback(private val sessionId: String) : AudioModeSession.Callback {
        private val routesQueue = LinkedBlockingQueue<List<AudioModeSession.AudioRoute>>()
        private val resumedQueue = LinkedBlockingQueue<Int>()
        private val pausedQueue = LinkedBlockingQueue<Boolean>()
        private val closedQueue = LinkedBlockingQueue<Boolean>()
        private val routingResultsQueue = LinkedBlockingQueue<RoutingResultEvent>()

        override fun onAvailableRoutesChanged(availableRoutes: List<AudioModeSession.AudioRoute>) {
            Log.d(TAG, "[$sessionId] onAvailableRoutesChanged: $availableRoutes")
            routesQueue.offer(availableRoutes)
        }

        override fun onExternalRequestedRouteChanged(
            newRoute: AudioModeSession.AudioRoute?,
            requestId: Int,
        ) {
            Log.d(
                TAG,
                "[$sessionId] onExternalRequestedRouteChanged: reqId=$requestId route=$newRoute",
            )
        }

        override fun onPaused() {
            Log.d(TAG, "[$sessionId] onPaused")
            pausedQueue.offer(true)
        }

        override fun onResumed(requestId: Int) {
            Log.d(TAG, "[$sessionId] onResumed: reqId=$requestId")
            resumedQueue.offer(requestId)
        }

        override fun onClosed() {
            Log.d(TAG, "[$sessionId] onClosed")
            closedQueue.offer(true)
        }

        override fun onRoutingResult(
            requestId: Int,
            route: AudioModeSession.AudioRoute?,
            status: Int,
        ) {
            Log.d(
                TAG,
                "[$sessionId] onRoutingResult: reqId=$requestId status=$status route=$route",
            )
            routingResultsQueue.offer(RoutingResultEvent(requestId, route, status))
        }

        fun clearRoutingResults() {
            routingResultsQueue.clear()
        }

        fun awaitInitialRoutes(): List<AudioModeSession.AudioRoute> =
            routesQueue.poll(CALLBACK_TIMEOUT_MS, TimeUnit.MILLISECONDS)
                ?: error("Timed out waiting for onAvailableRoutesChanged on sessionId=$sessionId")

        fun awaitResumed(): Int =
            resumedQueue.poll(CALLBACK_TIMEOUT_MS, TimeUnit.MILLISECONDS)
                ?: error("Timed out waiting for onResumed on sessionId=$sessionId")

        fun awaitPaused() {
            pausedQueue.poll(CALLBACK_TIMEOUT_MS, TimeUnit.MILLISECONDS)
                ?: error("Timed out waiting for onPaused on sessionId=$sessionId")
        }

        fun awaitClosed() {
            closedQueue.poll(CALLBACK_TIMEOUT_MS, TimeUnit.MILLISECONDS)
                ?: error("Timed out waiting for onClosed on sessionId=$sessionId")
        }

        fun awaitRoutingResult(expectedRequestId: Int?): RoutingResultEvent {
            val deadlineMs = SystemClock.elapsedRealtime() + CALLBACK_TIMEOUT_MS
            while (true) {
                val remainingMs = deadlineMs - SystemClock.elapsedRealtime()
                if (remainingMs <= 0L) {
                    error(
                        "Timed out waiting for onRoutingResult(" +
                            "expectedReqId=$expectedRequestId) on sessionId=$sessionId"
                    )
                }
                val event =
                    routingResultsQueue.poll(remainingMs, TimeUnit.MILLISECONDS)
                        ?: error(
                            "Timed out waiting for onRoutingResult(" +
                                "expectedReqId=$expectedRequestId) on sessionId=$sessionId"
                        )
                if (expectedRequestId == null || event.requestId == expectedRequestId) {
                    return event
                }
            }
        }
    }

    private data class ManagedModeSession(
        val sessionId: String,
        val session: AudioModeSession,
        val callback: SessionCallback,
    )

    private class ActivePlaybackStream(
        val streamId: String,
        private val track: AudioTrack,
        private val running: AtomicBoolean,
        private val writerThread: Thread,
    ) {
        fun stopAndRelease() {
            running.set(false)
            runCatching {
                if (track.playState == AudioTrack.PLAYSTATE_PLAYING) {
                    track.stop()
                }
            }
            runCatching { writerThread.join(STREAM_STOP_JOIN_MS) }
            runCatching { track.release() }
        }
    }

    private companion object {
        const val TAG = "AudioModeSessionSnippet"
        const val CALLBACK_TIMEOUT_MS = DEFAULT_CALLBACK_TIMEOUT_MS
        const val STREAM_STOP_JOIN_MS = 1000L
        const val SAMPLE_RATE_HZ = 48000
        const val FRAMES_PER_BUFFER = 960 // 20 ms at 48 kHz
        const val TONE_FREQ_HZ = 400.0 // Exact 8 cycles per 960-frame buffer at 48 kHz
        const val SINE_AMPLITUDE = 12000

        fun buildSineWaveBuffer(frames: Int, sampleRateHz: Int, freqHz: Double): ShortArray {
            return ShortArray(frames) { idx ->
                val angle = 2.0 * PI * freqHz * idx / sampleRateHz
                (sin(angle) * SINE_AMPLITUDE).toInt().toShort()
            }
        }
    }
}
