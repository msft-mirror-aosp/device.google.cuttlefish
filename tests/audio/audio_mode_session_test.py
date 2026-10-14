#!/usr/bin/env python3
# Copyright (C) 2026 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Cuttlefish VoIP AudioModeSession Routing & Preemption E2E Test Suite."""

import os

import audio_stack_inspector
from mobly import asserts
from mobly import base_test
from mobly import test_runner
from mobly.controllers import android_device
from mobly.controllers.android_device_lib.services import logcat

SNIPPET_PACKAGE = 'com.android.cuttlefish.audiotest'
AUDIO_MODE_SESSION_LOGCAT_TAGS = ' '.join((
    'AudioFocusSnippet:V',
    'AudioModeSessionSnippet:V',
    'AudioSvc:V',
    'AudioSvc.FocusCtrl:V',
    'AudioSvc.FocusReq:V',
    'AudioSvc.ModeSession:V',
    'AudioSvc.DeviceBroker:V',
    'APM::AudioPolicyEngine:V',
    'APM_AudioPolicyManager:V',
))
DEFAULT_TIMEOUT_SEC = audio_stack_inspector.DEFAULT_TIMEOUT_SEC
FOCUS_CALLBACK_TIMEOUT_SEC = int(DEFAULT_TIMEOUT_SEC)
ROUTE_CONVERGENCE_TIMEOUT_SEC = DEFAULT_TIMEOUT_SEC
FRAMES_ADVANCING_TIMEOUT_SEC = DEFAULT_TIMEOUT_SEC
ON_AUDIO_FOCUS_CHANGE_EVENT = 'onAudioFocusChange'

MEDIA_CLIENT_ID = 'media_client'
VOIP_SESSION_ID = 'whatsapp_voip'
CELLULAR_SESSION_ID = 'cellular_call'
VOIP_STREAM_ID = 'voip_stream'
MEDIA_STREAM_ID = 'media_stream'

# Mirrors android.media.AudioAttributes / AudioManager / AudioDeviceInfo constants.
USAGE_MEDIA = 1
USAGE_VOICE_COMMUNICATION = 2

CONTENT_TYPE_SPEECH = 1
CONTENT_TYPE_MUSIC = 2

AUDIOFOCUS_GAIN = 1
AUDIOFOCUS_LOSS_TRANSIENT = -2

AUDIOFOCUS_REQUEST_GRANTED = 1

MODE_NORMAL = 0
MODE_IN_CALL = 2
MODE_IN_COMMUNICATION = 3

TYPE_BUILTIN_EARPIECE = 1
TYPE_BUILTIN_SPEAKER = 2

SPEAKER_DEVICE_TOKEN = 'AUDIO_DEVICE_OUT_SPEAKER'
EARPIECE_DEVICE_TOKEN = 'AUDIO_DEVICE_OUT_EARPIECE'
SPEAKER_ADDRESS = 'CARD_0_DEV_0'
EARPIECE_ADDRESS = 'CARD_0_DEV_1'
SPEAKER_ALSA_DEV = 0
EARPIECE_ALSA_DEV = 1


class CuttlefishVoipModeSessionTest(base_test.BaseTestClass):
  """E2E VoIP call routing and preemption tests using AudioModeSession."""

  DUMPSYS_TARGETS = {
      'dumpsys_audio': 'dumpsys audio',
      'dumpsys_audio_policy': 'dumpsys media.audio_policy',
      'dumpsys_audio_flinger': 'dumpsys media.audio_flinger',
      'alsa_pcm_status': (
          'head -n 20 /proc/asound/card0/pcm*/sub0/status 2>/dev/null || true'
      ),
  }

  def setup_class(self):
    self.ads = self.register_controller(android_device)
    self.dut = self.ads[0]
    self.inspector = audio_stack_inspector.AudioStackInspector(self.dut)

    features = self.dut.adb.shell('pm list features').decode(
        'utf-8', errors='replace'
    )
    for non_phone_feature in (
        'feature:android.hardware.type.automotive',
        'feature:android.hardware.type.watch',
        'feature:android.hardware.type.television',
        'feature:android.hardware.type.pc',
    ):
      asserts.abort_class_if(
          non_phone_feature in features,
          f'Non-phone target ({non_phone_feature}); built-in Earpiece/Speaker'
          ' VoIP routing suite only targets phone configurations.',
      )

    asserts.abort_class_if(
        not self.inspector.has_alsa_playback_device(SPEAKER_ALSA_DEV)
        or not self.inspector.has_alsa_playback_device(EARPIECE_ALSA_DEV),
        'Multi-stream ALSA playback substreams (pcm0p and pcm1p) not present;'
        ' requires phone config with output_audio_streams_count=2.',
    )

    dumpsys_audio = self.dut.adb.shell('dumpsys audio').decode(
        'utf-8', errors='replace'
    )
    asserts.abort_class_if(
        'has focus policy:true' in dumpsys_audio,
        'External AudioFocusPolicy is active; standard AudioModeSession focus'
        ' rules do not apply.',
    )
    asserts.abort_class_if(
        'Multi Audio Focus enabled :true' in dumpsys_audio,
        'Multi Audio Focus is enabled; standard single-focus preemption rules'
        ' do not apply.',
    )

    self.dut.services.register(
        'audio_mode_session_logcat',
        logcat.Logcat,
        configs=logcat.Config(
            logcat_params=f'-s {AUDIO_MODE_SESSION_LOGCAT_TAGS}'
        ),
    )
    self.dut.load_snippet('audio', SNIPPET_PACKAGE)

    asserts.abort_class_if(
        not self.dut.audio.isModeSessionSupported(),
        'AudioModeSession (Flags.fusedTelecomRouteApi) is disabled on device.',
    )

    output_types = self.dut.audio.getOutputDeviceTypes()
    asserts.abort_class_if(
        TYPE_BUILTIN_EARPIECE not in output_types
        or TYPE_BUILTIN_SPEAKER not in output_types,
        f'Both TYPE_BUILTIN_EARPIECE ({TYPE_BUILTIN_EARPIECE}) and'
        f' TYPE_BUILTIN_SPEAKER ({TYPE_BUILTIN_SPEAKER}) are required, got'
        f' output device types: {output_types}',
    )

  def _cleanup_audio_state(self):
    if not hasattr(self.dut, 'audio'):
      return
    for action in (
        self.dut.audio.stopAllPlayback,
        self.dut.audio.closeAllModeSessions,
        self.dut.audio.killChildProcess,
        self.dut.audio.abandonAllAudioFocus,
    ):
      try:
        action()
      except Exception:  # pylint: disable=broad-except
        pass

  def setup_test(self):
    self._cleanup_audio_state()

  def teardown_test(self):
    self._cleanup_audio_state()

  def on_fail(self, record):
    del record
    self.dut.services.create_output_excerpts_all(self.current_test_info)
    for file_type, cmd in self.DUMPSYS_TARGETS.items():
      filename = self.dut.generate_filename(
          file_type, self.current_test_info, 'txt'
      )
      output_file = os.path.join(self.current_test_info.output_path, filename)
      content = self.dut.adb.shell(cmd).decode('utf-8', errors='replace')
      with open(output_file, 'w', encoding='utf-8') as f:
        f.write(content)

  def teardown_class(self):
    if hasattr(self.dut, 'audio'):
      self.dut.unload_snippet('audio')
    self.dut.services.stop_all()

  def _assert_5_layer_route(
      self,
      strategy_name: str,
      expected_device_token: str,
      expected_address: str,
      expected_alsa_dev: int,
      inactive_alsa_dev: int,
      expected_mode: str,
  ) -> audio_stack_inspector.AudioStackSnapshot:
    """Verifies routing and active streaming across all 5 guest audio layers."""
    converged, snap = self.inspector.wait_for_route(
        strategy_name=strategy_name,
        expected_device_token=expected_device_token,
        expected_address=expected_address,
        expected_alsa_dev=expected_alsa_dev,
        inactive_alsa_devs=(inactive_alsa_dev,),
        expected_mode=expected_mode,
        timeout_sec=ROUTE_CONVERGENCE_TIMEOUT_SEC,
    )
    asserts.assert_true(
        converged,
        '5-layer route did not converge: '
        + '; '.join(
            self.inspector.find_route_mismatches(
                snap,
                strategy_name=strategy_name,
                expected_device_token=expected_device_token,
                expected_address=expected_address,
                expected_alsa_dev=expected_alsa_dev,
                inactive_alsa_devs=(inactive_alsa_dev,),
                expected_mode=expected_mode,
            )
        ),
    )

    base_frames, latest_frames = self.inspector.wait_for_frames_advancing(
        expected_device_token,
        timeout_sec=FRAMES_ADVANCING_TIMEOUT_SEC,
    )
    asserts.assert_greater(
        latest_frames,
        base_frames,
        f'Layer 4 (AudioFlinger): expected Frames written to advance on'
        f' {expected_device_token} (base={base_frames}, latest={latest_frames})',
    )
    return snap

  def test_voip_mode_session_default_voice_vs_video_routing(self):
    """Verifies AudioModeSession default routing for voice (Earpiece) vs video (Speaker)."""
    # 1. Voice-only VoIP session (isDisplayActiveUseCase=False) -> defaults to Earpiece
    routed_type = self.dut.audio.createModeSession(
        VOIP_SESSION_ID, MODE_IN_COMMUNICATION, False
    )
    asserts.assert_equal(
        routed_type,
        TYPE_BUILTIN_EARPIECE,
        'Expected voice VoIP AudioModeSession (isDisplayActiveUseCase=False) to'
        f' default to TYPE_BUILTIN_EARPIECE ({TYPE_BUILTIN_EARPIECE}), got'
        f' {routed_type}',
    )

    self.dut.audio.startPlayback(
        VOIP_STREAM_ID, USAGE_VOICE_COMMUNICATION, CONTENT_TYPE_SPEECH
    )
    self._assert_5_layer_route(
        strategy_name='STRATEGY_PHONE',
        expected_device_token=EARPIECE_DEVICE_TOKEN,
        expected_address=EARPIECE_ADDRESS,
        expected_alsa_dev=EARPIECE_ALSA_DEV,
        inactive_alsa_dev=SPEAKER_ALSA_DEV,
        expected_mode='MODE_IN_COMMUNICATION',
    )

    # 2. Switch session to video/display-active use case (isDisplayActiveUseCase=True)
    # -> default route transitions from Earpiece to Speaker.
    updated_type = self.dut.audio.setSessionDisplayActiveUseCase(
        VOIP_SESSION_ID, True
    )
    asserts.assert_equal(
        updated_type,
        TYPE_BUILTIN_SPEAKER,
        'Expected video VoIP AudioModeSession (isDisplayActiveUseCase=True) to'
        f' route to TYPE_BUILTIN_SPEAKER ({TYPE_BUILTIN_SPEAKER}), got'
        f' {updated_type}',
    )
    self._assert_5_layer_route(
        strategy_name='STRATEGY_PHONE',
        expected_device_token=SPEAKER_DEVICE_TOKEN,
        expected_address=SPEAKER_ADDRESS,
        expected_alsa_dev=SPEAKER_ALSA_DEV,
        inactive_alsa_dev=EARPIECE_ALSA_DEV,
        expected_mode='MODE_IN_COMMUNICATION',
    )

  def test_voip_mode_session_mid_call_route_switching(self):
    """Verifies mid-call Earpiece <-> Speaker switching via AudioModeSession.setRequestedRoute."""
    routed_type = self.dut.audio.createModeSession(
        VOIP_SESSION_ID, MODE_IN_COMMUNICATION, False
    )
    asserts.assert_equal(routed_type, TYPE_BUILTIN_EARPIECE)

    available_types = self.dut.audio.getSessionAvailableRouteTypes(
        VOIP_SESSION_ID
    )
    asserts.assert_in(TYPE_BUILTIN_EARPIECE, available_types)
    asserts.assert_in(TYPE_BUILTIN_SPEAKER, available_types)

    self.dut.audio.startPlayback(
        VOIP_STREAM_ID, USAGE_VOICE_COMMUNICATION, CONTENT_TYPE_SPEECH
    )

    # Initial state: Earpiece (CARD_0_DEV_1 / pcm1p)
    self._assert_5_layer_route(
        strategy_name='STRATEGY_PHONE',
        expected_device_token=EARPIECE_DEVICE_TOKEN,
        expected_address=EARPIECE_ADDRESS,
        expected_alsa_dev=EARPIECE_ALSA_DEV,
        inactive_alsa_dev=SPEAKER_ALSA_DEV,
        expected_mode='MODE_IN_COMMUNICATION',
    )

    # Switch mid-call to Speaker (CARD_0_DEV_0 / pcm0p)
    speaker_type = self.dut.audio.requestSessionRouteByType(
        VOIP_SESSION_ID, TYPE_BUILTIN_SPEAKER
    )
    asserts.assert_equal(speaker_type, TYPE_BUILTIN_SPEAKER)
    self._assert_5_layer_route(
        strategy_name='STRATEGY_PHONE',
        expected_device_token=SPEAKER_DEVICE_TOKEN,
        expected_address=SPEAKER_ADDRESS,
        expected_alsa_dev=SPEAKER_ALSA_DEV,
        inactive_alsa_dev=EARPIECE_ALSA_DEV,
        expected_mode='MODE_IN_COMMUNICATION',
    )

    # Switch mid-call back to Earpiece (CARD_0_DEV_1 / pcm1p)
    earpiece_type = self.dut.audio.requestSessionRouteByType(
        VOIP_SESSION_ID, TYPE_BUILTIN_EARPIECE
    )
    asserts.assert_equal(earpiece_type, TYPE_BUILTIN_EARPIECE)
    self._assert_5_layer_route(
        strategy_name='STRATEGY_PHONE',
        expected_device_token=EARPIECE_DEVICE_TOKEN,
        expected_address=EARPIECE_ADDRESS,
        expected_alsa_dev=EARPIECE_ALSA_DEV,
        inactive_alsa_dev=SPEAKER_ALSA_DEV,
        expected_mode='MODE_IN_COMMUNICATION',
    )

  def test_voip_mode_session_preempts_and_restores_media_playback(self):
    """Verifies AudioModeSession preempts media focus/routing and restores it on close."""
    media_handler = self.dut.audio.registerFocusChangeListener(MEDIA_CLIENT_ID)

    # 1. Start Media playback with AUDIOFOCUS_GAIN on Speaker (CARD_0_DEV_0 / pcm0p)
    focus_res = self.dut.audio.requestAudioFocus(
        MEDIA_CLIENT_ID, USAGE_MEDIA, CONTENT_TYPE_MUSIC, AUDIOFOCUS_GAIN
    )
    asserts.assert_equal(focus_res, AUDIOFOCUS_REQUEST_GRANTED)

    self.dut.audio.startPlayback(
        MEDIA_STREAM_ID, USAGE_MEDIA, CONTENT_TYPE_MUSIC
    )
    self._assert_5_layer_route(
        strategy_name='STRATEGY_MEDIA',
        expected_device_token=SPEAKER_DEVICE_TOKEN,
        expected_address=SPEAKER_ADDRESS,
        expected_alsa_dev=SPEAKER_ALSA_DEV,
        inactive_alsa_dev=EARPIECE_ALSA_DEV,
        expected_mode='MODE_NORMAL',
    )

    # 2. Start VoIP AudioModeSession -> automatically acquires call focus and locks focus
    routed_type = self.dut.audio.createModeSession(
        VOIP_SESSION_ID, MODE_IN_COMMUNICATION, False
    )
    asserts.assert_equal(routed_type, TYPE_BUILTIN_EARPIECE)

    loss_event = media_handler.waitAndGet(
        ON_AUDIO_FOCUS_CHANGE_EVENT, timeout=FOCUS_CALLBACK_TIMEOUT_SEC
    )
    asserts.assert_equal(loss_event.data['clientId'], MEDIA_CLIENT_ID)
    asserts.assert_equal(
        loss_event.data['focusChange'], AUDIOFOCUS_LOSS_TRANSIENT
    )

    # Media app pauses on AUDIOFOCUS_LOSS_TRANSIENT while VoIP streams on Earpiece
    self.dut.audio.stopPlayback(MEDIA_STREAM_ID)
    self.dut.audio.startPlayback(
        VOIP_STREAM_ID, USAGE_VOICE_COMMUNICATION, CONTENT_TYPE_SPEECH
    )
    voip_snap = self._assert_5_layer_route(
        strategy_name='STRATEGY_PHONE',
        expected_device_token=EARPIECE_DEVICE_TOKEN,
        expected_address=EARPIECE_ADDRESS,
        expected_alsa_dev=EARPIECE_ALSA_DEV,
        inactive_alsa_dev=SPEAKER_ALSA_DEV,
        expected_mode='MODE_IN_COMMUNICATION',
    )
    asserts.assert_true(
        any(s.is_live and s.has_focus for s in voip_snap.mode_sessions),
        f'Expected live AudioModeSession to hold audio focus, got'
        f' {voip_snap.mode_sessions}',
    )

    # 3. End VoIP AudioModeSession -> Media automatically receives AUDIOFOCUS_GAIN & resumes Speaker
    self.dut.audio.stopPlayback(VOIP_STREAM_ID)
    self.dut.audio.closeModeSession(VOIP_SESSION_ID)

    gain_event = media_handler.waitAndGet(
        ON_AUDIO_FOCUS_CHANGE_EVENT, timeout=FOCUS_CALLBACK_TIMEOUT_SEC
    )
    asserts.assert_equal(gain_event.data['clientId'], MEDIA_CLIENT_ID)
    asserts.assert_equal(gain_event.data['focusChange'], AUDIOFOCUS_GAIN)

    self.dut.audio.startPlayback(
        MEDIA_STREAM_ID, USAGE_MEDIA, CONTENT_TYPE_MUSIC
    )
    self._assert_5_layer_route(
        strategy_name='STRATEGY_MEDIA',
        expected_device_token=SPEAKER_DEVICE_TOKEN,
        expected_address=SPEAKER_ADDRESS,
        expected_alsa_dev=SPEAKER_ALSA_DEV,
        inactive_alsa_dev=EARPIECE_ALSA_DEV,
        expected_mode='MODE_NORMAL',
    )

  def test_voip_mode_session_preempted_by_cellular_call_and_restored(self):
    """Verifies MODE_IN_CALL preempts a MODE_IN_COMMUNICATION session and restores on close."""
    # 1. Start WhatsApp-style VoIP session (MODE_IN_COMMUNICATION) and explicitly set
    # requestedRoute=Earpiece so AudioService persists and restores this route across preemption.
    init_voip_type = self.dut.audio.createModeSession(
        VOIP_SESSION_ID, MODE_IN_COMMUNICATION, False
    )
    asserts.assert_equal(init_voip_type, TYPE_BUILTIN_EARPIECE)
    asserts.assert_equal(
        self.dut.audio.requestSessionRouteByType(
            VOIP_SESSION_ID, TYPE_BUILTIN_EARPIECE
        ),
        TYPE_BUILTIN_EARPIECE,
    )

    self.dut.audio.startPlayback(
        VOIP_STREAM_ID, USAGE_VOICE_COMMUNICATION, CONTENT_TYPE_SPEECH
    )
    self._assert_5_layer_route(
        strategy_name='STRATEGY_PHONE',
        expected_device_token=EARPIECE_DEVICE_TOKEN,
        expected_address=EARPIECE_ADDRESS,
        expected_alsa_dev=EARPIECE_ALSA_DEV,
        inactive_alsa_dev=SPEAKER_ALSA_DEV,
        expected_mode='MODE_IN_COMMUNICATION',
    )

    # 2. Incoming/active cellular call session (MODE_IN_CALL) starts and routes to Speaker.
    # Keep VOIP_STREAM_ID (USAGE_VOICE_COMMUNICATION -> STRATEGY_PHONE) playing to exercise
    # live AudioFlinger/HAL re-routing while MODE_IN_CALL owns STRATEGY_PHONE routing.
    init_call_type = self.dut.audio.createModeSession(
        CELLULAR_SESSION_ID, MODE_IN_CALL, True
    )
    asserts.assert_equal(init_call_type, TYPE_BUILTIN_SPEAKER)
    asserts.assert_true(
        self.dut.audio.awaitSessionPaused(VOIP_SESSION_ID),
        'Expected VoIP AudioModeSession to pause when preempted by MODE_IN_CALL session',
    )

    self._assert_5_layer_route(
        strategy_name='STRATEGY_PHONE',
        expected_device_token=SPEAKER_DEVICE_TOKEN,
        expected_address=SPEAKER_ADDRESS,
        expected_alsa_dev=SPEAKER_ALSA_DEV,
        inactive_alsa_dev=EARPIECE_ALSA_DEV,
        expected_mode='MODE_IN_CALL',
    )

    # 3. Close cellular call session -> VoIP session automatically resumes and restores Earpiece
    self.dut.audio.closeModeSession(CELLULAR_SESSION_ID)
    restored_type = self.dut.audio.awaitSessionResumedAndRouted(VOIP_SESSION_ID)
    asserts.assert_equal(
        restored_type,
        TYPE_BUILTIN_EARPIECE,
        'Expected resumed VoIP AudioModeSession to restore'
        f' TYPE_BUILTIN_EARPIECE ({TYPE_BUILTIN_EARPIECE}), got {restored_type}',
    )

    self._assert_5_layer_route(
        strategy_name='STRATEGY_PHONE',
        expected_device_token=EARPIECE_DEVICE_TOKEN,
        expected_address=EARPIECE_ADDRESS,
        expected_alsa_dev=EARPIECE_ALSA_DEV,
        inactive_alsa_dev=SPEAKER_ALSA_DEV,
        expected_mode='MODE_IN_COMMUNICATION',
    )


if __name__ == '__main__':
  test_runner.main()
