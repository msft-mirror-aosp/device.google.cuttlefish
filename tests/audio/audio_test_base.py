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
"""Shared base class and constants for Cuttlefish 5-layer E2E audio tests."""

from collections.abc import Sequence
import os

import audio_stack_inspector
from mobly import asserts
from mobly import base_test
from mobly.controllers import android_device
from mobly.controllers.android_device_lib.services import logcat

SNIPPET_PACKAGE = 'com.android.cuttlefish.audiotest'
DEFAULT_LOGCAT_TAGS = ' '.join((
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


class CuttlefishAudioTestBase(base_test.BaseTestClass):
  """Base class for Cuttlefish 5-layer E2E audio routing and streaming tests."""

  LOGCAT_SERVICE_NAME = 'cf_audio_logcat'
  LOGCAT_TAGS = DEFAULT_LOGCAT_TAGS
  REQUIRE_EARPIECE_AND_DUAL_ALSA = True

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
    if self.REQUIRE_EARPIECE_AND_DUAL_ALSA:
      for non_phone_feature in (
          'feature:android.hardware.type.automotive',
          'feature:android.hardware.type.watch',
          'feature:android.hardware.type.television',
          'feature:android.hardware.type.pc',
      ):
        asserts.abort_class_if(
            non_phone_feature in features,
            f'Non-phone target ({non_phone_feature}); built-in Earpiece/Speaker'
            ' routing suite only targets phone configurations.',
        )

      asserts.abort_class_if(
          not self.inspector.has_alsa_playback_device(SPEAKER_ALSA_DEV)
          or not self.inspector.has_alsa_playback_device(EARPIECE_ALSA_DEV),
          'Multi-stream ALSA playback substreams (pcm0p and pcm1p) not present;'
          ' requires phone config with output_audio_streams_count=2.',
      )
    else:
      asserts.abort_class_if(
          'feature:android.hardware.type.automotive' in features,
          'Automotive targets use CarAudioFocus (external focus policy) with'
          ' zone-specific focus semantics.',
      )

    focus_config = self.inspector.get_focus_config()
    asserts.abort_class_if(
        focus_config.has_focus_policy,
        'External AudioFocusPolicy is active; standard focus and routing'
        ' rules do not apply.',
    )
    asserts.abort_class_if(
        focus_config.multi_audio_focus_enabled,
        'Multi Audio Focus is enabled; standard single-focus preemption rules'
        ' do not apply.',
    )

    self.dut.services.register(
        self.LOGCAT_SERVICE_NAME,
        logcat.Logcat,
        configs=logcat.Config(logcat_params=f'-s {self.LOGCAT_TAGS}'),
    )
    self.dut.load_snippet('audio', SNIPPET_PACKAGE)

    if self.REQUIRE_EARPIECE_AND_DUAL_ALSA:
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
      expected_alsa_dev: int | None = None,
      inactive_alsa_dev: int | None = None,
      inactive_alsa_devs: Sequence[int] = (),
      expected_mode: str = 'MODE_NORMAL',
  ) -> audio_stack_inspector.AudioStackSnapshot:
    """Verifies routing and active streaming across all 5 guest audio layers."""
    resolved_inactive_devs = (
        tuple(inactive_alsa_devs)
        if inactive_alsa_devs
        else ((inactive_alsa_dev,) if inactive_alsa_dev is not None else ())
    )
    converged, snap = self.inspector.wait_for_route(
        strategy_name=strategy_name,
        expected_device_token=expected_device_token,
        expected_address=expected_address,
        expected_alsa_dev=expected_alsa_dev,
        inactive_alsa_devs=resolved_inactive_devs,
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
                inactive_alsa_devs=resolved_inactive_devs,
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
