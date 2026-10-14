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
"""Unit tests for the 5-layer Cuttlefish audio stack inspector."""

import unittest
from unittest import mock

import audio_stack_inspector


SAMPLE_DUMPSYS_AUDIO = """\
Audio Focus stack entries (last is top of stack):
  source:android.os.BinderProxy@1234 -- pack: com.android.cuttlefish.audiotest

## Audio mode:
  - Requested mode = MODE_IN_COMMUNICATION
  - Actual mode = MODE_IN_COMMUNICATION

  Computed Preferred communication device: AudioDeviceAttributes: role:output type:builtin_earpiece addr:CARD_0_DEV_1
  Applied Preferred communication device: AudioDeviceAttributes: role:output type:builtin_earpiece addr:CARD_0_DEV_1
  Active communication device: AudioDeviceAttributes: role:output type:builtin_earpiece addr:CARD_0_DEV_1

  AudioModeSession [7f3a1b]:
    package: com.android.cuttlefish.audiotest uid: 10142 pid: 4120
    mode: MODE_IN_COMMUNICATION (3)
    isDisplayActiveUseCase: false
    lifecycle: clientPaused=false serverPaused=false closed=false hasFocus=true isLive=true
    requestedRoute: Device(type: builtin_earpiece, addr: CARD_0_DEV_1)
    appliedRoute: Device(type: builtin_earpiece, addr: CARD_0_DEV_1)

players:
  AudioPlaybackConfiguration piid:15 deviceIds:[4] type:android.media.AudioTrack u/pid:10142/4120 state:started attr:AudioAttributes: usage=USAGE_VOICE_COMMUNICATION content=CONTENT_TYPE_SPEECH
"""

SAMPLE_DUMPSYS_AUDIO_POLICY = """\
Product Strategies:
  -STRATEGY_PHONE (id: 14)
   Selected Device: {AUDIO_DEVICE_OUT_EARPIECE, @:CARD_0_DEV_1}
  -STRATEGY_MEDIA (id: 15)
   Selected Device: {AUDIO_DEVICE_OUT_SPEAKER, @:CARD_0_DEV_0}

Audio Patches:
  Audio patch 0:
   owner uid 1041; handle 18; HAL handle 7
    [src 1] Mix Port ID: 21; I/O handle: 13;
    [sink 1] Device Port ID: 4; {AUDIO_DEVICE_OUT_EARPIECE, @:CARD_0_DEV_1}
"""

SAMPLE_DUMPSYS_AUDIO_FLINGER = """\
Output thread 0xb400007a10, name AudioOut_D, tid 512, type 0 (MIXER):
  I/O handle: 13
  Standby: no
  Sample rate: 48000 Hz
  Output devices: 0x1 (AUDIO_DEVICE_OUT_EARPIECE)
  Frames written: 24960
  1 Tracks of which 1 are active

Input thread 0xb400007b20, name AudioIn_15, tid 619, type 3 (RECORD):
  I/O handle: 21
  Standby: no
  Sample rate: 48000 Hz
  Input device: 0x80000004 (AUDIO_DEVICE_IN_BUILTIN_MIC)
  Audio source: 7 (AUDIO_SOURCE_VOICE_COMMUNICATION)

Historical Thread Log:
Output thread 0xb400007a00, name AudioOut_OLD, tid 400, type 0 (MIXER):
  I/O handle: 99
  Standby: no
  Output devices: 0x2 (AUDIO_DEVICE_OUT_SPEAKER)
  Frames written: 999999
  1 Tracks of which 1 are active
"""


class AudioStackInspectorTest(unittest.TestCase):
  """Tests for dumpsys parsers and 5-layer route convergence checks."""

  def test_parse_dumpsys_audio_happy_path_extracts_mode_and_session(self):
    parsed = audio_stack_inspector.parse_dumpsys_audio(SAMPLE_DUMPSYS_AUDIO)

    self.assertEqual(parsed['requested_mode'], 'MODE_IN_COMMUNICATION')
    self.assertEqual(parsed['actual_mode'], 'MODE_IN_COMMUNICATION')
    self.assertIn(
        'type:builtin_earpiece', str(parsed['active_comm_device'])
    )
    self.assertEqual(
        parsed['started_playback_usages'], ('USAGE_VOICE_COMMUNICATION',)
    )
    sessions = parsed['mode_sessions']
    self.assertEqual(len(sessions), 1)
    self.assertEqual(
        sessions[0],
        audio_stack_inspector.AudioModeSessionInfo(
            short_id='7f3a1b',
            mode='MODE_IN_COMMUNICATION',
            is_display_active_use_case=False,
            client_paused=False,
            server_paused=False,
            closed=False,
            has_focus=True,
            is_live=True,
            requested_route='Device(type: builtin_earpiece, addr: CARD_0_DEV_1)',
            applied_route='Device(type: builtin_earpiece, addr: CARD_0_DEV_1)',
        ),
    )

  def test_parse_dumpsys_audio_missing_anchor_raises_value_error(self):
    with self.assertRaisesRegex(
        ValueError, r"Missing section anchor '## Audio mode'.*unexpected dump"
    ):
      audio_stack_inspector.parse_dumpsys_audio('unexpected dump header')

  def test_parse_dumpsys_audio_policy_happy_path_extracts_strategies_and_patches(
      self,
  ):
    strategies, patches = audio_stack_inspector.parse_dumpsys_audio_policy(
        SAMPLE_DUMPSYS_AUDIO_POLICY
    )

    self.assertEqual(
        strategies['STRATEGY_PHONE'],
        audio_stack_inspector.StrategyRoute(
            name='STRATEGY_PHONE',
            device_types='AUDIO_DEVICE_OUT_EARPIECE',
            address='CARD_0_DEV_1',
        ),
    )
    self.assertEqual(
        strategies['STRATEGY_MEDIA'],
        audio_stack_inspector.StrategyRoute(
            name='STRATEGY_MEDIA',
            device_types='AUDIO_DEVICE_OUT_SPEAKER',
            address='CARD_0_DEV_0',
        ),
    )
    self.assertEqual(
        patches,
        (
            audio_stack_inspector.AudioPatchInfo(
                handle=18,
                src_mix_port_id=21,
                io_handle=13,
                sink_device_port_id=4,
                sink_device='AUDIO_DEVICE_OUT_EARPIECE, @:CARD_0_DEV_1',
            ),
        ),
    )

  def test_parse_dumpsys_audio_policy_missing_anchor_raises_value_error(self):
    with self.assertRaisesRegex(
        ValueError, r"Missing section anchor 'owner uid'.*no patches section"
    ):
      audio_stack_inspector.parse_dumpsys_audio_policy('no patches section')

  def test_parse_dumpsys_audio_flinger_happy_path_ignores_historical_log(self):
    output_threads, input_threads = (
        audio_stack_inspector.parse_dumpsys_audio_flinger(
            SAMPLE_DUMPSYS_AUDIO_FLINGER
        )
    )

    self.assertEqual(
        output_threads,
        {
            13: audio_stack_inspector.OutputThreadInfo(
                io_handle=13,
                standby=False,
                output_devices='0x1 (AUDIO_DEVICE_OUT_EARPIECE)',
                frames_written=24960,
                active_tracks=1,
            ),
        },
    )
    self.assertNotIn(99, output_threads)
    self.assertEqual(
        input_threads,
        {
            21: audio_stack_inspector.InputThreadInfo(
                io_handle=21,
                standby=False,
                input_device='0x80000004 (AUDIO_DEVICE_IN_BUILTIN_MIC)',
                audio_source='7 (AUDIO_SOURCE_VOICE_COMMUNICATION)',
            ),
        },
    )

  def test_parse_dumpsys_audio_flinger_missing_anchor_raises_value_error(self):
    with self.assertRaisesRegex(
        ValueError, r"Missing section anchor 'Output thread'.*empty flinger"
    ):
      audio_stack_inspector.parse_dumpsys_audio_flinger('empty flinger dump')

  def test_wait_for_route_converges_and_reports_failing_layers_on_timeout(self):
    dut = mock.MagicMock()
    inspector = audio_stack_inspector.AudioStackInspector(dut)
    layer1 = audio_stack_inspector.parse_dumpsys_audio(SAMPLE_DUMPSYS_AUDIO)
    strategies, patches = audio_stack_inspector.parse_dumpsys_audio_policy(
        SAMPLE_DUMPSYS_AUDIO_POLICY
    )
    out_threads, in_threads = audio_stack_inspector.parse_dumpsys_audio_flinger(
        SAMPLE_DUMPSYS_AUDIO_FLINGER
    )
    snap = audio_stack_inspector.AudioStackSnapshot(
        requested_mode=str(layer1['requested_mode']),
        actual_mode=str(layer1['actual_mode']),
        computed_preferred_comm_device=str(
            layer1['computed_preferred_comm_device']
        ),
        applied_preferred_comm_device=str(
            layer1['applied_preferred_comm_device']
        ),
        active_comm_device=str(layer1['active_comm_device']),
        started_playback_usages=tuple(layer1['started_playback_usages']),
        mode_sessions=tuple(layer1['mode_sessions']),
        strategies=strategies,
        patches=patches,
        output_threads=out_threads,
        input_threads=in_threads,
        alsa_playback_running={0: False, 1: True},
        alsa_capture_running={0: True},
    )
    inspector.snapshot = mock.MagicMock(return_value=snap)

    converged, returned_snap = inspector.wait_for_route(
        strategy_name='STRATEGY_PHONE',
        expected_device_token='AUDIO_DEVICE_OUT_EARPIECE',
        expected_address='CARD_0_DEV_1',
        expected_alsa_dev=1,
        inactive_alsa_devs=(0,),
        expected_mode='MODE_IN_COMMUNICATION',
        timeout_sec=0.0,
    )

    self.assertTrue(converged)
    self.assertEqual(returned_snap, snap)

    timed_out_converged, timed_out_snap = inspector.wait_for_route(
        strategy_name='STRATEGY_PHONE',
        expected_device_token='AUDIO_DEVICE_OUT_EARPIECE',
        expected_address='CARD_0_DEV_1',
        expected_alsa_dev=0,
        inactive_alsa_devs=(1,),
        expected_mode='MODE_IN_COMMUNICATION',
        timeout_sec=0.0,
    )
    mismatches = inspector.find_route_mismatches(
        timed_out_snap,
        strategy_name='STRATEGY_PHONE',
        expected_device_token='AUDIO_DEVICE_OUT_EARPIECE',
        expected_address='CARD_0_DEV_1',
        expected_alsa_dev=0,
        inactive_alsa_devs=(1,),
        expected_mode='MODE_IN_COMMUNICATION',
    )

    self.assertFalse(timed_out_converged)
    self.assertTrue(all('Layer 5 (ALSA)' in m for m in mismatches))

  def test_read_alsa_running_states_batches_probe_in_single_shell_call(self):
    dut = mock.MagicMock()
    dut.adb.shell.return_value = (
        b'===HAL_FDS===\n'
        b'lrwx------ 1audioserver 10 -> /dev/snd/pcmC0D1p\n'
        b'===PLAY_0===\n'
        b'closed\n'
        b'===PLAY_1===\n'
        b'state: RUNNING\n'
        b'===CAP_0===\n'
        b'state: RUNNING\n'
    )
    inspector = audio_stack_inspector.AudioStackInspector(dut)

    playback_running, capture_running = inspector.read_alsa_running_states()

    dut.adb.shell.assert_called_once()
    self.assertEqual(playback_running, {0: False, 1: True})
    self.assertEqual(capture_running, {0: True})


if __name__ == '__main__':
  unittest.main(verbosity=2)
