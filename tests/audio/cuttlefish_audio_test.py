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
"""Cuttlefish Audio Focus and E2E Test Suite."""

import os
import time

import audio_stack_inspector
from mobly import asserts
from mobly import base_test
from mobly import test_runner
from mobly.controllers import android_device
from mobly.controllers.android_device_lib.services import logcat

SNIPPET_PACKAGE = 'com.android.cuttlefish.audiotest'
AUDIO_FOCUS_LOGCAT_TAGS = ' '.join((
    'AudioFocusSnippet:V',
    'AudioFocusChildSvc:V',
    'AudioSvc:V',
    'AudioSvc.FocusCtrl:V',
    'AudioSvc.FocusReq:V',
    'ActivityManager:I',
))
DEFAULT_TIMEOUT_SEC = audio_stack_inspector.DEFAULT_TIMEOUT_SEC
FOCUS_CALLBACK_TIMEOUT_SEC = int(DEFAULT_TIMEOUT_SEC)
BINDER_DEATH_TIMEOUT_SEC = int(DEFAULT_TIMEOUT_SEC)
ON_AUDIO_FOCUS_CHANGE_EVENT = 'onAudioFocusChange'
MEDIA_CLIENT_ID = 'media_client'
ALARM_CLIENT_ID = 'alarm_client'
MEDIA_CLIENT_TAG = 'CfAudioTest[media_client]'
DYING_CHILD_CLIENT_TAG = 'CfAudioTest[dying_child]'

# Mirrors android.media.AudioAttributes / AudioManager constants; keep in sync.
# AudioAttributes.Usage constants
USAGE_MEDIA = 1
USAGE_VOICE_COMMUNICATION = 2
USAGE_ALARM = 4
USAGE_NOTIFICATION = 5
USAGE_ASSISTANCE_NAVIGATION_GUIDANCE = 12
USAGE_GAME = 14

# AudioAttributes.ContentType constants
CONTENT_TYPE_SPEECH = 1
CONTENT_TYPE_MUSIC = 2
CONTENT_TYPE_SONIFICATION = 4

# AudioManager focus gain / loss constants
AUDIOFOCUS_GAIN = 1
AUDIOFOCUS_GAIN_TRANSIENT = 2
AUDIOFOCUS_GAIN_TRANSIENT_MAY_DUCK = 3
AUDIOFOCUS_LOSS_TRANSIENT = -2

# AudioManager focus request result constants
AUDIOFOCUS_REQUEST_FAILED = 0
AUDIOFOCUS_REQUEST_GRANTED = 1
AUDIOFOCUS_REQUEST_DELAYED = 2

_STACK_HEADER = 'Audio Focus stack entries (last is top of stack):'
_STACK_TERMINATORS = (
    'No external focus policy',
    'External focus policy:',
    ' Notify on duck:',
)

# Declarative Audio Focus use-case matrix:
# (use_case_name, usage, content_type, focus_gain, expected_result)
AUDIO_FOCUS_USE_CASES = [
    (
        'media',
        USAGE_MEDIA,
        CONTENT_TYPE_MUSIC,
        AUDIOFOCUS_GAIN,
        AUDIOFOCUS_REQUEST_GRANTED,
    ),
    (
        'voice_communication',
        USAGE_VOICE_COMMUNICATION,
        CONTENT_TYPE_SPEECH,
        AUDIOFOCUS_GAIN_TRANSIENT,
        AUDIOFOCUS_REQUEST_GRANTED,
    ),
    (
        'navigation',
        USAGE_ASSISTANCE_NAVIGATION_GUIDANCE,
        CONTENT_TYPE_SPEECH,
        AUDIOFOCUS_GAIN_TRANSIENT_MAY_DUCK,
        AUDIOFOCUS_REQUEST_GRANTED,
    ),
    (
        'alarm',
        USAGE_ALARM,
        CONTENT_TYPE_SONIFICATION,
        AUDIOFOCUS_GAIN_TRANSIENT,
        AUDIOFOCUS_REQUEST_GRANTED,
    ),
    (
        'notification',
        USAGE_NOTIFICATION,
        CONTENT_TYPE_SONIFICATION,
        AUDIOFOCUS_GAIN_TRANSIENT_MAY_DUCK,
        AUDIOFOCUS_REQUEST_GRANTED,
    ),
    (
        'game',
        USAGE_GAME,
        CONTENT_TYPE_SONIFICATION,
        AUDIOFOCUS_GAIN,
        AUDIOFOCUS_REQUEST_GRANTED,
    ),
]


class CuttlefishAudioFocusTest(base_test.BaseTestClass):
  """Data-driven Audio Focus validation suite for Cuttlefish."""

  # Focus tests only require `dumpsys audio` + filtered focus logcat.
  # Future streaming/routing test classes can extend this map with:
  #   'dumpsys_audio_flinger': 'dumpsys media.audio_flinger',
  #   'dumpsys_audio_policy': 'dumpsys media.audio_policy',
  DUMPSYS_TARGETS = {
      'dumpsys_audio': 'dumpsys audio',
  }

  def setup_class(self):
    self.ads = self.register_controller(android_device)
    self.dut = self.ads[0]

    features = self.dut.adb.shell('pm list features').decode(
        'utf-8', errors='replace'
    )
    asserts.abort_class_if(
        'feature:android.hardware.type.automotive' in features,
        'Automotive targets use CarAudioFocus (external focus policy) with'
        ' zone-specific focus semantics.',
    )
    dump = self._dumpsys_audio()
    asserts.abort_class_if(
        'has focus policy:true' in dump,
        'External focus policy installed; standard MediaFocusControl stack'
        ' semantics do not apply.',
    )
    asserts.abort_class_if(
        'Multi Audio Focus enabled :true' in dump,
        'Multi-audio-focus enabled; standard single-focus LIFO stack'
        ' semantics do not apply.',
    )

    self.dut.services.register(
        'audio_focus_logcat',
        logcat.Logcat,
        configs=logcat.Config(logcat_params=f'-s {AUDIO_FOCUS_LOGCAT_TAGS}'),
    )
    self.dut.load_snippet('audio', SNIPPET_PACKAGE)

  def setup_test(self):
    self.dut.audio.killChildProcess()
    self.dut.audio.abandonAllAudioFocus()
    active_stack = self._wait_for_stack_without(SNIPPET_PACKAGE)
    asserts.assert_not_in(
        SNIPPET_PACKAGE,
        active_stack,
        f'Expected clean focus stack before test start, found stale'
        f' {SNIPPET_PACKAGE} entry in: {active_stack}',
    )

  def teardown_test(self):
    self.dut.audio.killChildProcess()
    self.dut.audio.abandonAllAudioFocus()

  def on_fail(self, record):
    del record  # Unused; self.current_test_info scopes output files.
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

  def pre_run(self):
    self.generate_tests(
        test_logic=self._verify_audio_focus_use_case,
        name_func=lambda use_case, *_: f'test_audio_focus_{use_case}',
        arg_sets=AUDIO_FOCUS_USE_CASES,
    )

  def _dumpsys_audio(self) -> str:
    """Returns the full decoded output of `adb shell dumpsys audio`."""
    return self.dut.adb.shell('dumpsys audio').decode('utf-8', errors='replace')

  def _get_active_focus_stack(self) -> str:
    """Returns the MediaFocusControl stack lines from `dumpsys audio`."""
    dumpsys_audio = self._dumpsys_audio()
    _, sep, tail = dumpsys_audio.partition(_STACK_HEADER)
    asserts.assert_true(
        bool(sep),
        f'Could not find {_STACK_HEADER!r} section in dumpsys audio',
    )
    stack_lines = []
    for line in tail.splitlines():
      if line.startswith(_STACK_TERMINATORS):
        break
      stack_lines.append(line)
    return '\n'.join(stack_lines)

  def _wait_for_stack_without(
      self,
      token: str,
      timeout_sec: float = DEFAULT_TIMEOUT_SEC,
      poll_interval_sec: float = audio_stack_inspector.DEFAULT_POLL_INTERVAL_SEC,
  ) -> str:
    """Polls the live focus stack until `token` is absent or deadline expires."""
    deadline = time.monotonic() + timeout_sec
    while True:
      stack = self._get_active_focus_stack()
      if token not in stack or time.monotonic() >= deadline:
        return stack
      time.sleep(poll_interval_sec)

  def _verify_audio_focus_use_case(
      self,
      use_case: str,
      usage: int,
      content_type: int,
      focus_gain: int,
      expected_result: int,
  ):
    """Verifies focus grant, stack registration, and abandon for a use case."""
    self.dut.log.info(
        'Requesting AudioFocus for use_case=%s (usage=%d, content_type=%d,'
        ' focus_gain=%d)',
        use_case,
        usage,
        content_type,
        focus_gain,
    )
    result = self.dut.audio.requestAudioFocus(
        use_case, usage, content_type, focus_gain
    )
    asserts.assert_equal(
        result,
        expected_result,
        f'Expected focus result {expected_result} for {use_case}, got {result}',
    )

    client_tag = f'CfAudioTest[{use_case}]'
    active_stack = self._get_active_focus_stack()
    asserts.assert_in(
        client_tag,
        active_stack,
        f'Expected {client_tag} in active focus stack for {use_case}, got:'
        f' {active_stack}',
    )

    abandon_result = self.dut.audio.abandonAudioFocus(use_case)
    asserts.assert_equal(
        abandon_result,
        AUDIOFOCUS_REQUEST_GRANTED,
        f'Expected abandonAudioFocus to succeed for {use_case}, got'
        f' {abandon_result}',
    )

    post_abandon_stack = self._get_active_focus_stack()
    asserts.assert_not_in(
        client_tag,
        post_abandon_stack,
        f'Expected {client_tag} to be removed from active focus stack'
        f' after abandon for {use_case}, got: {post_abandon_stack}',
    )

  def test_audio_focus_change_listener_callback(self):
    handler = self.dut.audio.registerFocusChangeListener(MEDIA_CLIENT_ID)

    media_res = self.dut.audio.requestAudioFocus(
        MEDIA_CLIENT_ID, USAGE_MEDIA, CONTENT_TYPE_MUSIC, AUDIOFOCUS_GAIN
    )
    asserts.assert_equal(media_res, AUDIOFOCUS_REQUEST_GRANTED)

    alarm_res = self.dut.audio.requestAudioFocus(
        ALARM_CLIENT_ID,
        USAGE_ALARM,
        CONTENT_TYPE_SONIFICATION,
        AUDIOFOCUS_GAIN_TRANSIENT,
    )
    asserts.assert_equal(alarm_res, AUDIOFOCUS_REQUEST_GRANTED)

    loss_event = handler.waitAndGet(
        ON_AUDIO_FOCUS_CHANGE_EVENT, timeout=FOCUS_CALLBACK_TIMEOUT_SEC
    )
    asserts.assert_equal(loss_event.data['clientId'], MEDIA_CLIENT_ID)
    asserts.assert_equal(
        loss_event.data['focusChange'], AUDIOFOCUS_LOSS_TRANSIENT
    )

    abandon_res = self.dut.audio.abandonAudioFocus(ALARM_CLIENT_ID)
    asserts.assert_equal(abandon_res, AUDIOFOCUS_REQUEST_GRANTED)

    regain_event = handler.waitAndGet(
        ON_AUDIO_FOCUS_CHANGE_EVENT, timeout=FOCUS_CALLBACK_TIMEOUT_SEC
    )
    asserts.assert_equal(regain_event.data['clientId'], MEDIA_CLIENT_ID)
    asserts.assert_equal(regain_event.data['focusChange'], AUDIOFOCUS_GAIN)

    self.dut.audio.unregisterFocusChangeListener(MEDIA_CLIENT_ID)
    self.dut.audio.abandonAudioFocus(MEDIA_CLIENT_ID)

  def test_audio_focus_same_client_multiple_requests(self):
    """Verifies repeated requests on one clientId stay distinct and all abandon."""
    for focus_gain in (AUDIOFOCUS_GAIN, AUDIOFOCUS_GAIN_TRANSIENT):
      asserts.assert_equal(
          self.dut.audio.requestAudioFocus(
              MEDIA_CLIENT_ID,
              USAGE_MEDIA,
              CONTENT_TYPE_MUSIC,
              focus_gain,
          ),
          AUDIOFOCUS_REQUEST_GRANTED,
          f'Expected media_client request (gain={focus_gain}) to be granted',
      )
    stack = self._get_active_focus_stack()
    asserts.assert_equal(
        stack.count(MEDIA_CLIENT_TAG),
        2,
        f'Expected 2 distinct {MEDIA_CLIENT_TAG} entries, got: {stack}',
    )
    asserts.assert_equal(
        self.dut.audio.abandonAudioFocus(MEDIA_CLIENT_ID),
        AUDIOFOCUS_REQUEST_GRANTED,
        'Expected abandon of all media_client requests to succeed',
    )
    stack = self._get_active_focus_stack()
    asserts.assert_not_in(
        MEDIA_CLIENT_TAG,
        stack,
        f'Expected no {MEDIA_CLIENT_TAG} left after abandon, got: {stack}',
    )

  def test_audio_focus_cleanup_on_client_death(self):
    """Verifies Binder death of a focus-holding child purges its stack entry."""
    handler = self.dut.audio.registerFocusChangeListener(MEDIA_CLIENT_ID)

    media_res = self.dut.audio.requestAudioFocus(
        MEDIA_CLIENT_ID, USAGE_MEDIA, CONTENT_TYPE_MUSIC, AUDIOFOCUS_GAIN
    )
    asserts.assert_equal(
        media_res,
        AUDIOFOCUS_REQUEST_GRANTED,
        'Expected initial media_client focus request to be granted',
    )

    child_pid = self.dut.audio.requestAudioFocusInChildProcess(
        USAGE_ALARM, CONTENT_TYPE_SONIFICATION, AUDIOFOCUS_GAIN_TRANSIENT
    )
    asserts.assert_true(
        child_pid > 0,
        f'Expected positive child process PID, got {child_pid}',
    )

    loss_event = handler.waitAndGet(
        ON_AUDIO_FOCUS_CHANGE_EVENT, timeout=FOCUS_CALLBACK_TIMEOUT_SEC
    )
    asserts.assert_equal(
        loss_event.data['clientId'],
        MEDIA_CLIENT_ID,
        'Expected focus loss callback for media_client',
    )
    asserts.assert_equal(
        loss_event.data['focusChange'],
        AUDIOFOCUS_LOSS_TRANSIENT,
        'Expected AUDIOFOCUS_LOSS_TRANSIENT when child process acquires focus',
    )

    stack_before_death = self._get_active_focus_stack()
    asserts.assert_in(
        MEDIA_CLIENT_TAG,
        stack_before_death,
        f'Expected {MEDIA_CLIENT_TAG} in stack before child death,'
        f' got: {stack_before_death}',
    )
    asserts.assert_in(
        DYING_CHILD_CLIENT_TAG,
        stack_before_death,
        f'Expected {DYING_CHILD_CLIENT_TAG} in stack before child'
        f' death, got: {stack_before_death}',
    )
    asserts.assert_greater(
        stack_before_death.index(DYING_CHILD_CLIENT_TAG),
        stack_before_death.index(MEDIA_CLIENT_TAG),
        f'Expected {DYING_CHILD_CLIENT_TAG} above {MEDIA_CLIENT_TAG}'
        f' (top of stack) before kill, got: {stack_before_death}',
    )

    premature_events = handler.getAll(ON_AUDIO_FOCUS_CHANGE_EVENT)
    asserts.assert_false(
        premature_events,
        f'Unexpected focus callbacks before child process kill:'
        f' {[e.data for e in premature_events]}',
    )

    self.dut.log.info(
        'Killing child focus holder process (expected pid=%d) without'
        ' abandonAudioFocus()',
        child_pid,
    )
    killed_pid = self.dut.audio.killChildProcess()
    asserts.assert_equal(
        killed_pid,
        child_pid,
        f'Expected killChildProcess() to kill child_pid={child_pid},'
        f' got killed_pid={killed_pid}',
    )

    regain_event = handler.waitAndGet(
        ON_AUDIO_FOCUS_CHANGE_EVENT, timeout=BINDER_DEATH_TIMEOUT_SEC
    )
    asserts.assert_equal(
        regain_event.data['clientId'],
        MEDIA_CLIENT_ID,
        'Expected focus regain callback for media_client after child death',
    )
    asserts.assert_equal(
        regain_event.data['focusChange'],
        AUDIOFOCUS_GAIN,
        'Expected AUDIOFOCUS_GAIN after child process Binder death cleanup',
    )

    extra_events = handler.getAll(ON_AUDIO_FOCUS_CHANGE_EVENT)
    asserts.assert_false(
        extra_events,
        f'Unexpected extra focus callbacks after child death:'
        f' {[e.data for e in extra_events]}',
    )

    stack_after_death = self._get_active_focus_stack()
    asserts.assert_not_in(
        DYING_CHILD_CLIENT_TAG,
        stack_after_death,
        f'Expected dead {DYING_CHILD_CLIENT_TAG} entry to be purged on Binder'
        f' death, got: {stack_after_death}',
    )
    asserts.assert_in(
        MEDIA_CLIENT_TAG,
        stack_after_death,
        f'Expected surviving {MEDIA_CLIENT_TAG} entry to remain in stack after'
        f' child death, got: {stack_after_death}',
    )

    abandon_res = self.dut.audio.abandonAudioFocus(MEDIA_CLIENT_ID)
    asserts.assert_equal(
        abandon_res,
        AUDIOFOCUS_REQUEST_GRANTED,
        'Expected surviving media_client abandonAudioFocus to succeed',
    )

    stack_after_cleanup = self._get_active_focus_stack()
    asserts.assert_not_in(
        SNIPPET_PACKAGE,
        stack_after_cleanup,
        f'Expected all {SNIPPET_PACKAGE} entries to be purged after death'
        f' cleanup and abandon, got: {stack_after_cleanup}',
    )


if __name__ == '__main__':
  test_runner.main()
