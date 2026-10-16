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
"""5-Layer Audio Stack Inspector for Cuttlefish E2E Audio Tests.

Inspects and correlates routing and streaming state across:
  Layer 1: AudioService (`dumpsys audio`)
  Layer 2: AudioPolicyManager Product Strategies (`dumpsys media.audio_policy`)
  Layer 3: AudioPolicyManager Audio Patches (`dumpsys media.audio_policy`)
  Layer 4: AudioFlinger Mixer & Record Threads (`dumpsys media.audio_flinger`)
  Layer 5: ALSA / VirtIO-Snd Kernel PCM State (`/proc/asound/card0/pcm*/sub0/status`)
"""

import dataclasses
import re
import time
from typing import Mapping, Sequence

DEFAULT_TIMEOUT_SEC = 10.0
DEFAULT_POLL_INTERVAL_SEC = 0.25
_DUMP_EXCERPT_MAX_CHARS = 240


def _require_section_anchor(dump: str, anchor: str, service_name: str) -> None:
  """Raises ValueError with a dump excerpt if `anchor` is absent from `dump`."""
  if anchor not in dump:
    excerpt = dump[:_DUMP_EXCERPT_MAX_CHARS].replace('\n', '\\n')
    raise ValueError(
        f'Missing section anchor {anchor!r} in {service_name} dump;'
        f' excerpt={excerpt!r}'
    )


@dataclasses.dataclass(frozen=True)
class StrategyRoute:
  """Selected routing state for a ProductStrategy in `dumpsys media.audio_policy`."""

  name: str
  device_types: str
  address: str


@dataclasses.dataclass(frozen=True)
class AudioPatchInfo:
  """Active audio patch entry in `dumpsys media.audio_policy`."""

  handle: int
  src_mix_port_id: int
  io_handle: int
  sink_device_port_id: int
  sink_device: str


@dataclasses.dataclass(frozen=True)
class OutputThreadInfo:
  """AudioFlinger PlaybackThread snapshot from `dumpsys media.audio_flinger`."""

  io_handle: int
  standby: bool
  output_devices: str
  frames_written: int
  active_tracks: int


@dataclasses.dataclass(frozen=True)
class InputThreadInfo:
  """AudioFlinger RecordThread snapshot from `dumpsys media.audio_flinger`."""

  io_handle: int
  standby: bool
  input_device: str
  audio_source: str


@dataclasses.dataclass(frozen=True)
class AudioModeSessionInfo:
  """AudioModeSession snapshot from `dumpsys audio`."""

  short_id: str
  mode: str
  is_display_active_use_case: bool
  client_paused: bool
  server_paused: bool
  closed: bool
  has_focus: bool
  is_live: bool
  requested_route: str
  applied_route: str


@dataclasses.dataclass(frozen=True)
class AudioStackSnapshot:
  """Correlated 5-layer snapshot of the Android guest audio stack."""

  # Layer 1: AudioService
  requested_mode: str
  actual_mode: str
  computed_preferred_comm_device: str
  applied_preferred_comm_device: str
  active_comm_device: str
  started_playback_usages: tuple[str, ...]
  mode_sessions: tuple[AudioModeSessionInfo, ...]

  # Layer 2 & 3: AudioPolicyManager
  strategies: Mapping[str, StrategyRoute]
  patches: tuple[AudioPatchInfo, ...]

  # Layer 4: AudioFlinger
  output_threads: Mapping[int, OutputThreadInfo]
  input_threads: Mapping[int, InputThreadInfo]

  # Layer 5: ALSA / VirtIO-Snd (/proc/asound/card0)
  alsa_playback_running: Mapping[int, bool]
  alsa_capture_running: Mapping[int, bool]


_REQ_MODE_RE = re.compile(r'^\s*-\s*Requested mode\s*=\s*(\S+)', re.MULTILINE)
_ACT_MODE_RE = re.compile(r'^\s*-\s*Actual mode\s*=\s*(\S+)', re.MULTILINE)
_COMP_COMM_RE = re.compile(
    r'^\s*Computed Preferred communication device:\s*(.+)$', re.MULTILINE
)
_APPL_COMM_RE = re.compile(
    r'^\s*Applied Preferred communication device:\s*(.+)$', re.MULTILINE
)
_ACT_COMM_RE = re.compile(
    r'^\s*Active communication device:\s*(.+)$', re.MULTILINE
)
_PLAYBACK_STARTED_RE = re.compile(
    r'AudioPlaybackConfiguration\s+piid:\d+.*?\bstate:started\b.*?\busage=(\S+)',
    re.MULTILINE,
)
_MODE_SESSION_RE = re.compile(
    r'AudioModeSession\s+\[([^\]]+)\]:\s*\n'
    r'(?:[ \t]+(?!AudioModeSession\b).*\n)*?'
    r'\s+mode:\s*(\S+)\s*\(-?\d+\)\s*\n'
    r'\s+isDisplayActiveUseCase:\s*(true|false)\s*\n'
    r'\s+lifecycle:\s*clientPaused=(true|false)\s+serverPaused=(true|false)'
    r'\s+closed=(true|false)\s+hasFocus=(true|false)\s+isLive=(true|false)\s*\n'
    r'\s+requestedRoute:\s*(.+)\n'
    r'\s+appliedRoute:\s*(.+)',
    re.MULTILINE,
)

_STRATEGY_RE = re.compile(
    r'^\s*-(STRATEGY_\S+)\s+\(id:\s*\d+\)\s*(?:\(ZoneId:\s*\d+\))?\s*\n'
    r'\s*Selected Device:\s*\{([^}]*),\s*@:([^}]*)\}',
    re.MULTILINE,
)

_PATCH_RE = re.compile(
    r'owner uid\s+\d+;\s*handle\s+(\d+);\s*HAL handle\s+\d+\s*\n'
    r'(?:\s*\[src\s+\d+\]\s*Device Port ID:[^\n]*\n)*'
    r'\s*\[src\s+\d+\]\s*Mix Port ID:\s*(\d+);\s*I/O handle:\s*(\d+);\s*\n'
    r'\s*\[sink\s+1\]\s*Device Port ID:\s*(\d+);\s*\{([^}]*)\}',
    re.MULTILINE,
)

_THREAD_HEADER_RE = re.compile(
    r'^(Output|Input) thread 0x[0-9a-fA-F]+,\s*name\s+\S+,\s*tid\s+\d+,'
    r'\s*type\s+\d+\s*\(([^)]+)\):',
    re.MULTILINE,
)
_FLINGER_THREAD_END_RE = re.compile(
    r'\n(?:Historical Thread Log|\s*## BEGIN (?!thread dump))'
)
_IO_HANDLE_RE = re.compile(r'^\s*I/O handle:\s*(\d+)', re.MULTILINE)
_STANDBY_RE = re.compile(r'^\s*Standby:\s*(\S+)', re.MULTILINE)
_OUT_DEVICES_RE = re.compile(r'^\s*Output devices:\s*(.+)$', re.MULTILINE)
_IN_DEVICE_RE = re.compile(r'^\s*Input device:\s*(.+)$', re.MULTILINE)
_AUDIO_SOURCE_RE = re.compile(r'^\s*Audio source:\s*(.+)$', re.MULTILINE)
_FRAMES_WRITTEN_RE = re.compile(r'^\s*Frames written:\s*(\d+)', re.MULTILINE)
_ACTIVE_TRACKS_RE = re.compile(
    r'^\s*\d+\s+Tracks(?:\s+of which\s+(\d+)\s+are active)?', re.MULTILINE
)


def parse_dumpsys_audio(dump: str) -> dict[str, object]:
  """Parses Layer 1 fields from `dumpsys audio`."""
  _require_section_anchor(dump, '## Audio mode', 'audio')
  req_match = _REQ_MODE_RE.search(dump)
  act_match = _ACT_MODE_RE.search(dump)
  comp_match = _COMP_COMM_RE.search(dump)
  appl_match = _APPL_COMM_RE.search(dump)
  act_comm_match = _ACT_COMM_RE.search(dump)
  started_usages = tuple(_PLAYBACK_STARTED_RE.findall(dump))
  mode_sessions: list[AudioModeSessionInfo] = []
  for match in _MODE_SESSION_RE.finditer(dump):
    mode_sessions.append(
        AudioModeSessionInfo(
            short_id=match.group(1).strip(),
            mode=match.group(2).strip(),
            is_display_active_use_case=match.group(3) == 'true',
            client_paused=match.group(4) == 'true',
            server_paused=match.group(5) == 'true',
            closed=match.group(6) == 'true',
            has_focus=match.group(7) == 'true',
            is_live=match.group(8) == 'true',
            requested_route=match.group(9).strip(),
            applied_route=match.group(10).strip(),
        )
    )
  return {
      'requested_mode': req_match.group(1).strip() if req_match else '',
      'actual_mode': act_match.group(1).strip() if act_match else '',
      'computed_preferred_comm_device': (
          comp_match.group(1).strip() if comp_match else ''
      ),
      'applied_preferred_comm_device': (
          appl_match.group(1).strip() if appl_match else ''
      ),
      'active_comm_device': (
          act_comm_match.group(1).strip() if act_comm_match else ''
      ),
      'started_playback_usages': started_usages,
      'mode_sessions': tuple(mode_sessions),
  }


def parse_dumpsys_audio_policy(
    dump: str,
) -> tuple[dict[str, StrategyRoute], tuple[AudioPatchInfo, ...]]:
  """Parses Layer 2 (ProductStrategies) and Layer 3 (AudioPatches) from APM."""
  _require_section_anchor(dump, 'owner uid', 'media.audio_policy')
  strategies: dict[str, StrategyRoute] = {}
  for match in _STRATEGY_RE.finditer(dump):
    name = match.group(1).strip()
    dev_types = match.group(2).strip()
    addr = match.group(3).strip()
    strategies[name] = StrategyRoute(
        name=name,
        device_types=dev_types,
        address=addr,
    )

  patches: list[AudioPatchInfo] = []
  for match in _PATCH_RE.finditer(dump):
    patches.append(
        AudioPatchInfo(
            handle=int(match.group(1)),
            src_mix_port_id=int(match.group(2)),
            io_handle=int(match.group(3)),
            sink_device_port_id=int(match.group(4)),
            sink_device=match.group(5).strip(),
        )
    )
  return strategies, tuple(patches)


def parse_dumpsys_audio_flinger(
    dump: str,
) -> tuple[dict[int, OutputThreadInfo], dict[int, InputThreadInfo]]:
  """Parses Layer 4 (Output and Input threads) from `dumpsys media.audio_flinger`."""
  _require_section_anchor(dump, 'Output thread', 'media.audio_flinger')
  output_threads: dict[int, OutputThreadInfo] = {}
  input_threads: dict[int, InputThreadInfo] = {}

  end_match = _FLINGER_THREAD_END_RE.search(dump)
  active_dump = dump[: end_match.start()] if end_match else dump

  matches = list(_THREAD_HEADER_RE.finditer(active_dump))
  for idx, match in enumerate(matches):
    direction = match.group(1)
    start = match.end()
    end = (
        matches[idx + 1].start() if idx + 1 < len(matches) else len(active_dump)
    )
    block = active_dump[start:end]

    io_match = _IO_HANDLE_RE.search(block)
    if not io_match:
      continue
    io_handle = int(io_match.group(1))
    standby_match = _STANDBY_RE.search(block)
    standby = (
        standby_match.group(1).strip().lower() == 'yes'
        if standby_match
        else True
    )

    if direction == 'Output':
      out_dev_match = _OUT_DEVICES_RE.search(block)
      frames_match = _FRAMES_WRITTEN_RE.search(block)
      tracks_match = _ACTIVE_TRACKS_RE.search(block)
      active_tracks = (
          int(tracks_match.group(1))
          if (tracks_match and tracks_match.group(1))
          else 0
      )
      output_threads[io_handle] = OutputThreadInfo(
          io_handle=io_handle,
          standby=standby,
          output_devices=(
              out_dev_match.group(1).strip() if out_dev_match else ''
          ),
          frames_written=int(frames_match.group(1)) if frames_match else 0,
          active_tracks=active_tracks,
      )
    else:
      in_dev_match = _IN_DEVICE_RE.search(block)
      source_match = _AUDIO_SOURCE_RE.search(block)
      input_threads[io_handle] = InputThreadInfo(
          io_handle=io_handle,
          standby=standby,
          input_device=in_dev_match.group(1).strip() if in_dev_match else '',
          audio_source=source_match.group(1).strip() if source_match else '',
      )

  return output_threads, input_threads


class AudioStackInspector:
  """Captures and verifies 5-layer audio stack snapshots on an AndroidDevice."""

  def __init__(self, dut):
    self._dut = dut

  def _shell(self, cmd: str) -> str:
    return self._dut.adb.shell(cmd).decode('utf-8', errors='replace')

  def has_alsa_playback_device(self, device_id: int, card_id: int = 0) -> bool:
    """Returns True if `/dev/snd/pcmC<card_id>D<device_id>p` exists."""
    dev_path = f'/dev/snd/pcmC{card_id}D{device_id}p'
    proc_path = f'/proc/asound/card{card_id}/pcm{device_id}p/sub0/status'
    out = self._shell(
        f'(test -e {dev_path} || test -e {proc_path}) && echo 1 || echo 0'
    ).strip()
    return out == '1'

  def read_alsa_running_states(
      self,
      playback_devices: Sequence[int] = (0, 1),
      capture_devices: Sequence[int] = (0,),
      card_id: int = 0,
  ) -> tuple[dict[int, bool], dict[int, bool]]:
    """Reads ALSA active state for playback and capture substreams in one shell call."""
    # Check both `/proc/asound/.../status` (`state: RUNNING`) and open `/dev/snd/pcm*`
    # file descriptors in the AIDL Audio HAL (`StreamAlsa` opens the TinyALSA PCM
    # proxy only while active and closes it in `standby()`).
    script_parts = [
        'echo "===HAL_FDS==="',
        (
            'for p in $(pidof android.hardware.audio.service-aidl.example);'
            ' do ls -l "/proc/$p/fd" 2>/dev/null; done'
        ),
    ]
    for dev_id in playback_devices:
      proc_path = f'/proc/asound/card{card_id}/pcm{dev_id}p/sub0/status'
      script_parts.append(f'echo "===PLAY_{dev_id}==="')
      script_parts.append(f'cat {proc_path} 2>/dev/null || true')
    for dev_id in capture_devices:
      proc_path = f'/proc/asound/card{card_id}/pcm{dev_id}c/sub0/status'
      script_parts.append(f'echo "===CAP_{dev_id}==="')
      script_parts.append(f'cat {proc_path} 2>/dev/null || true')

    combined_out = self._shell(
        f"su 0 sh -c '{'; '.join(script_parts)}' || true"
    )
    sections: dict[str, list[str]] = {}
    current_key = ''
    for line in combined_out.splitlines():
      stripped = line.strip()
      if stripped.startswith('===') and stripped.endswith('==='):
        current_key = stripped[3:-3]
        sections[current_key] = []
      elif current_key:
        sections[current_key].append(line)

    hal_fds = '\n'.join(sections.get('HAL_FDS', ()))
    playback_running: dict[int, bool] = {}
    for dev_id in playback_devices:
      dev_node = f'/dev/snd/pcmC{card_id}D{dev_id}p'
      status = '\n'.join(sections.get(f'PLAY_{dev_id}', ()))
      playback_running[dev_id] = (
          'state: RUNNING' in status or dev_node in hal_fds
      )

    capture_running: dict[int, bool] = {}
    for dev_id in capture_devices:
      dev_node = f'/dev/snd/pcmC{card_id}D{dev_id}c'
      status = '\n'.join(sections.get(f'CAP_{dev_id}', ()))
      capture_running[dev_id] = (
          'state: RUNNING' in status or dev_node in hal_fds
      )

    return playback_running, capture_running

  def snapshot(
      self,
      playback_devices: Sequence[int] = (0, 1),
      capture_devices: Sequence[int] = (0,),
  ) -> AudioStackSnapshot:
    """Captures a correlated 5-layer snapshot across AudioService, APM, AF, and ALSA."""
    audio_dump = self._shell('dumpsys audio')
    policy_dump = self._shell('dumpsys media.audio_policy')
    flinger_dump = self._shell('dumpsys media.audio_flinger')
    alsa_play, alsa_cap = self.read_alsa_running_states(
        playback_devices=playback_devices,
        capture_devices=capture_devices,
    )

    layer1 = parse_dumpsys_audio(audio_dump)
    strategies, patches = parse_dumpsys_audio_policy(policy_dump)
    output_threads, input_threads = parse_dumpsys_audio_flinger(flinger_dump)

    return AudioStackSnapshot(
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
        output_threads=output_threads,
        input_threads=input_threads,
        alsa_playback_running=alsa_play,
        alsa_capture_running=alsa_cap,
    )

  def find_route_mismatches(
      self,
      snap: AudioStackSnapshot,
      strategy_name: str,
      expected_device_token: str,
      expected_address: str,
      expected_alsa_dev: int,
      inactive_alsa_devs: Sequence[int] = (),
      expected_mode: str | None = None,
  ) -> list[str]:
    """Returns descriptions of any layers that do not match the expected route."""
    mismatches: list[str] = []
    if expected_mode is not None:
      if snap.actual_mode != expected_mode:
        mismatches.append(
            f'Layer 1 (AudioService): expected Actual mode={expected_mode},'
            f' got {snap.actual_mode!r}'
        )
      if expected_mode != 'MODE_NORMAL' and not any(
          s.is_live and s.mode == expected_mode for s in snap.mode_sessions
      ):
        mismatches.append(
            f'Layer 1 (AudioService): expected live AudioModeSession in'
            f' {expected_mode}, got {snap.mode_sessions}'
        )

    strat = snap.strategies.get(strategy_name)
    if strat is None:
      mismatches.append(
          f'Layer 2 (AudioPolicy): missing {strategy_name} in'
          f' {list(snap.strategies.keys())}'
      )
    else:
      if expected_device_token not in strat.device_types:
        mismatches.append(
            f'Layer 2 (AudioPolicy): expected {expected_device_token} in'
            f' {strategy_name} device_types, got {strat}'
        )
      if strat.address != expected_address:
        mismatches.append(
            f'Layer 2 (AudioPolicy): expected {strategy_name} address'
            f' {expected_address!r}, got {strat.address!r}'
        )

    if not any(expected_address in p.sink_device for p in snap.patches):
      mismatches.append(
          f'Layer 3 (AudioPatches): expected active patch to sink'
          f' {expected_address}, got patches={snap.patches}'
      )

    if not any(
        not t.standby and expected_device_token in t.output_devices
        for t in snap.output_threads.values()
    ):
      mismatches.append(
          f'Layer 4 (AudioFlinger): expected non-standby output thread on'
          f' {expected_device_token}, got threads={snap.output_threads}'
      )

    if not snap.alsa_playback_running.get(expected_alsa_dev, False):
      mismatches.append(
          f'Layer 5 (ALSA): expected pcm{expected_alsa_dev}p to be RUNNING,'
          f' got {snap.alsa_playback_running}'
      )
    for dev in inactive_alsa_devs:
      if snap.alsa_playback_running.get(dev, True):
        mismatches.append(
            f'Layer 5 (ALSA): expected pcm{dev}p to be closed/inactive, got'
            f' {snap.alsa_playback_running}'
        )
    return mismatches

  def wait_for_route(
      self,
      strategy_name: str,
      expected_device_token: str,
      expected_address: str,
      expected_alsa_dev: int,
      inactive_alsa_devs: Sequence[int] = (),
      expected_mode: str | None = None,
      timeout_sec: float = DEFAULT_TIMEOUT_SEC,
      poll_interval_sec: float = DEFAULT_POLL_INTERVAL_SEC,
  ) -> tuple[bool, AudioStackSnapshot]:
    """Polls until all 5 layers converge on the expected device route and ALSA stream."""
    deadline = time.monotonic() + timeout_sec
    while True:
      last_snap = self.snapshot()
      if not self.find_route_mismatches(
          last_snap,
          strategy_name=strategy_name,
          expected_device_token=expected_device_token,
          expected_address=expected_address,
          expected_alsa_dev=expected_alsa_dev,
          inactive_alsa_devs=inactive_alsa_devs,
          expected_mode=expected_mode,
      ):
        return True, last_snap
      if time.monotonic() >= deadline:
        return False, last_snap
      time.sleep(poll_interval_sec)

  def wait_for_frames_advancing(
      self,
      expected_device_token: str,
      timeout_sec: float = DEFAULT_TIMEOUT_SEC,
      poll_interval_sec: float = DEFAULT_POLL_INTERVAL_SEC,
  ) -> tuple[int, int]:
    """Polls AudioFlinger until `Frames written` advances on the routed output thread."""
    baseline_snap = self.snapshot()
    baseline_frames = 0
    target_io_handle = None
    for io_handle, thread in baseline_snap.output_threads.items():
      if not thread.standby and expected_device_token in thread.output_devices:
        target_io_handle = io_handle
        baseline_frames = thread.frames_written
        break

    deadline = time.monotonic() + timeout_sec
    latest_frames = baseline_frames
    while time.monotonic() < deadline:
      time.sleep(poll_interval_sec)
      snap = self.snapshot()
      tracked = (
          snap.output_threads.get(target_io_handle)
          if target_io_handle is not None
          else None
      )
      if (
          tracked is not None
          and not tracked.standby
          and expected_device_token in tracked.output_devices
      ):
        latest_frames = tracked.frames_written
        if latest_frames > baseline_frames:
          return baseline_frames, latest_frames
      else:
        target_io_handle = None
        for io_handle, thread in snap.output_threads.items():
          if (
              not thread.standby
              and expected_device_token in thread.output_devices
          ):
            target_io_handle = io_handle
            baseline_frames = thread.frames_written
            latest_frames = baseline_frames
            break
    return baseline_frames, latest_frames
