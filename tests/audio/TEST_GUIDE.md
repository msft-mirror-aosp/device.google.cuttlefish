# Test Execution & Live Observation Guide (`cuttlefish-audio-test`)

This guide is written for testers and engineers running, observing, and triaging the `cuttlefish-audio-test` end-to-end Audio Focus validation suite on Cuttlefish (or physical Android devices).

---

## 1. Pre-Flight Checklist & Live Observation Setup

Before launching the test suite, open **two terminal windows** so you can watch the host test runner and the live on-device audio focus state side by side.

### Terminal 1 — Live Device Logcat Observer
Start a filtered logcat stream watching both the test snippet (`AudioFocusSnippet`) and the Android system audio focus arbitrator (`MediaFocusControl` / `AudioService`):

```bash
export ANDROID_SERIAL=<device_ip>:<port>
adb -s $ANDROID_SERIAL logcat -c
adb -s $ANDROID_SERIAL logcat -v time -s AudioFocusSnippet:V AudioFocusChildSvc:V AudioSvc:V AudioSvc.FocusCtrl:V AudioSvc.FocusReq:V ActivityManager:I
```

### Terminal 2 — Test Execution
Verify the device is online and run the test suite with AnTS result uploading enabled:

```bash
export ANDROID_SERIAL=<device_ip>:<port>
adb -s $ANDROID_SERIAL get-state   # Must print: device
atest cuttlefish-audio-test --request-upload-result
```

---

## 2. What the Test Suite Does (Step-by-Step Observation Guide)

When `atest cuttlefish-audio-test` runs, Tradefed installs `CuttlefishAudioSnippet.apk` (`com.android.cuttlefish.audiotest`), starts the Mobly JSON-RPC snippet server on the device, and executes **9 test cases** inside `CuttlefishAudioFocusTest`.

Every single test case is bracketed by automatic isolation hooks:
- **Before every test (`setup_test`)**: Calls `killChildProcess()`, `abandonAllAudioFocus()`, and polls `_wait_for_stack_without()` to guarantee the device's Audio Focus stack is completely clean before the test begins.
- **After every test (`teardown_test`)**: Calls `killChildProcess()` and `abandonAllAudioFocus()` again so even if a test fails mid-execution, no orphaned child processes or focus requests pollute subsequent tests.

---

### Test 1: `test_audio_focus_change_listener_callback`
**Goal**: Verifies asynchronous two-client Audio Focus arbitration and callback delivery (`@AsyncRpc`).

#### Step-by-Step Sequence of Events:
1. **Register Listener**: Host registers an async focus change listener for `clientId="media_client"`.
2. **Acquire Background Media Focus**: `media_client` requests permanent focus (`USAGE_MEDIA = 1`, `CONTENT_TYPE_MUSIC = 2`, `AUDIOFOCUS_GAIN = 1`).
   - **Expected Return**: `AUDIOFOCUS_REQUEST_GRANTED (1)`.
3. **Interrupt with Transient Alarm**: A second client (`alarm_client`) requests transient focus (`USAGE_ALARM = 4`, `CONTENT_TYPE_SONIFICATION = 4`, `AUDIOFOCUS_GAIN_TRANSIENT = 2`).
   - **Expected Return**: `AUDIOFOCUS_REQUEST_GRANTED (1)`.
4. **Verify Transient Focus Loss Callback**: `AudioService` dispatches `onAudioFocusChange(-2)` (`AUDIOFOCUS_LOSS_TRANSIENT`) to `media_client` on the main looper. The snippet posts a `SnippetEvent("onAudioFocusChange")` back to Mobly.
   - **Assertion**: Event received within 10s with `clientId == "media_client"` and `focusChange == -2`.
5. **Abandon Transient Alarm**: `alarm_client` abandons its focus request.
6. **Verify Focus Regain Callback**: `AudioService` automatically restores focus to `media_client` and dispatches `onAudioFocusChange(1)` (`AUDIOFOCUS_GAIN`).
   - **Assertion**: Event received within 10s with `clientId == "media_client"` and `focusChange == 1`.
7. **Cleanup**: Unregisters `media_client` listener and abandons `media_client` focus.

#### What to Look For in Terminal 1 (`adb logcat`):
```text
D/AudioFocusSnippet: registerFocusChangeListener: clientId=media_client callbackId=...
D/AudioFocusSnippet: requestAudioFocus: clientId=media_client usage=1 contentType=2 focusGain=1 result=1
D/AudioFocusSnippet: requestAudioFocus: clientId=alarm_client usage=4 contentType=4 focusGain=2 result=1
D/AudioFocusSnippet: onAudioFocusChange: clientId=media_client focusChange=-2
D/AudioFocusSnippet: abandonAudioFocus: clientId=alarm_client result=1
D/AudioFocusSnippet: onAudioFocusChange: clientId=media_client focusChange=1
D/AudioFocusSnippet: unregisterFocusChangeListener: clientId=media_client
D/AudioFocusSnippet: abandonAudioFocus: clientId=media_client result=1
```

---

### Test 2: `test_audio_focus_same_client_multiple_requests`
**Goal**: Verifies that repeated `requestAudioFocus()` calls with the same `clientId` use distinct per-instance `TaggedFocusListener` identities (`CfAudioTest[<tag>]#<seq>`) and are all removed when `abandonAudioFocus(clientId)` is called.

---

### Test 3: `test_audio_focus_cleanup_on_client_death`
**Goal**: Verifies `MediaFocusControl`'s Binder death cleanup (`AudioFocusDeathHandler.binderDied()` $\rightarrow$ `removeFocusStackEntryOnDeath()`) when a focus-holding client process dies abruptly without calling `abandonAudioFocus()`.

#### Step-by-Step Sequence of Events:
1. **Acquire Background Media Focus**: `media_client` in the main snippet process requests `AUDIOFOCUS_GAIN` (`USAGE_MEDIA = 1`, `CONTENT_TYPE_MUSIC = 2`).
2. **Acquire Transient Focus in Dedicated Child Process**: Calls `requestAudioFocusInChildProcess(USAGE_ALARM, CONTENT_TYPE_SONIFICATION, AUDIOFOCUS_GAIN_TRANSIENT)` which starts `DyingFocusHolderService` in `:dying_focus_client` and returns its OS process PID (`child_pid`).
3. **Verify Pre-Death Focus Stack & Loss Callback**:
   - `media_client` receives `AUDIOFOCUS_LOSS_TRANSIENT` (`-2`).
   - `dumpsys audio` active focus stack contains both `CfAudioTest[media_client]` and `CfAudioTest[dying_child]` (with `CfAudioTest[dying_child]` at the top of the stack).
4. **Abrupt Process Termination (`killChildProcess()`)**: Sends same-UID `SIGKILL` (`Process.killProcess`) to `:dying_focus_client` directly without calling `abandonAudioFocus()`.
5. **Verify Automatic Death Cleanup & Regain Callback**:
   - `media_client` receives `AUDIOFOCUS_GAIN` (`1`) within 10s.
   - `dumpsys audio` active focus stack confirms `CfAudioTest[dying_child]` was automatically purged while `CfAudioTest[media_client]` remains active.
6. **Cleanup**: Abandons `media_client` and verifies the focus stack is completely clean.

---

### Tests 4–9: Data-Driven Audio Focus Use-Case Matrix
**Goal**: Validates that every primary Android audio use case can acquire focus, appears in the **live** `MediaFocusControl` focus stack, and cleanly exits the live stack when abandoned.

Each of these 6 tests executes the exact same 4-stage verification loop:
1. **Request Focus**: Calls `requestAudioFocus(use_case, usage, content_type, focus_gain)` $\rightarrow$ must return `1` (`GRANTED`).
2. **Inspect Active Focus Stack (`dumpsys audio`)**: Runs `adb shell dumpsys audio`, extracts **only** the live section between `Audio Focus stack entries (last is top of stack):` and the stack terminator (`No external focus policy` / `External focus policy:` / ` Notify on duck:`), and verifies `CfAudioTest[<use_case>]` is actively holding focus.
   - *Why this matters*: `dumpsys audio` also contains a historical `focus commands as seen by MediaFocusControl` event log. Checking only the live stack ensures the test catches bugs where a focus request was logged historically but dropped from the active stack.
3. **Abandon Focus**: Calls `abandonAudioFocus(use_case)` $\rightarrow$ must return `1` (`GRANTED`).
4. **Verify Active Stack Removal**: Re-reads the live `dumpsys audio` focus stack section and asserts `CfAudioTest[<use_case>]` is **no longer present**.

| # | Test Name | Use Case Simulated | `Usage` Constant | `ContentType` Constant | `FocusGain` Constant | Expected Logcat Signature |
| :-: | :--- | :--- | :--- | :--- | :--- | :--- |
| **4** | `test_audio_focus_media` | Music / Video playback | `USAGE_MEDIA` (`1`) | `CONTENT_TYPE_MUSIC` (`2`) | `AUDIOFOCUS_GAIN` (`1`) | `clientId=media usage=1 contentType=2 focusGain=1 result=1` |
| **5** | `test_audio_focus_voice_communication` | VoIP / Carrier voice call | `USAGE_VOICE_COMMUNICATION` (`2`) | `CONTENT_TYPE_SPEECH` (`1`) | `AUDIOFOCUS_GAIN_TRANSIENT` (`2`) | `clientId=voice_communication usage=2 contentType=1 focusGain=2 result=1` |
| **6** | `test_audio_focus_navigation` | Turn-by-turn GPS prompt | `USAGE_ASSISTANCE_NAVIGATION_GUIDANCE` (`12`) | `CONTENT_TYPE_SPEECH` (`1`) | `AUDIOFOCUS_GAIN_TRANSIENT_MAY_DUCK` (`3`) | `clientId=navigation usage=12 contentType=1 focusGain=3 result=1` |
| **7** | `test_audio_focus_alarm` | Clock / Timer alarm | `USAGE_ALARM` (`4`) | `CONTENT_TYPE_SONIFICATION` (`4`) | `AUDIOFOCUS_GAIN_TRANSIENT` (`2`) | `clientId=alarm usage=4 contentType=4 focusGain=2 result=1` |
| **8** | `test_audio_focus_notification` | Incoming message chime | `USAGE_NOTIFICATION` (`5`) | `CONTENT_TYPE_SONIFICATION` (`4`) | `AUDIOFOCUS_GAIN_TRANSIENT_MAY_DUCK` (`3`) | `clientId=notification usage=5 contentType=4 focusGain=3 result=1` |
| **9** | `test_audio_focus_game` | Interactive game audio | `USAGE_GAME` (`14`) | `CONTENT_TYPE_SONIFICATION` (`4`) | `AUDIOFOCUS_GAIN` (`1`) | `clientId=game usage=14 contentType=4 focusGain=1 result=1` |

---

## 3. Healthy Run Output & Expected Timings (4 Cores vs. 1 Core)

### 3.1 `cuttlefish-audio-test` (9 Audio Focus Tests)
A healthy execution on Cuttlefish completes all 9 tests in **~1.5 seconds total on 4 cores** ($70\text{ ms} - 310\text{ ms}$ per test) and **~2.2 seconds total on 1 core**:

```text
x86_64 cuttlefish-audio-test
----------------------------
x86_64 cuttlefish-audio-test (9 Tests)
[1/9] CuttlefishAudioFocusTest#test_audio_focus_change_listener_callback: PASSED (72ms)
[2/9] CuttlefishAudioFocusTest#test_audio_focus_cleanup_on_client_death: PASSED (264ms)
[3/9] CuttlefishAudioFocusTest#test_audio_focus_same_client_multiple_requests: PASSED (95ms)
[4/9] CuttlefishAudioFocusTest#test_audio_focus_media: PASSED (131ms)
[5/9] CuttlefishAudioFocusTest#test_audio_focus_voice_communication: PASSED (155ms)
[6/9] CuttlefishAudioFocusTest#test_audio_focus_navigation: PASSED (134ms)
[7/9] CuttlefishAudioFocusTest#test_audio_focus_alarm: PASSED (111ms)
[8/9] CuttlefishAudioFocusTest#test_audio_focus_notification: PASSED (147ms)
[9/9] CuttlefishAudioFocusTest#test_audio_focus_game: PASSED (150ms)
```

### 3.2 `cuttlefish-audio-mode-session-test` (4 VoIP `AudioModeSession` 5-Layer Routing Tests)
A healthy execution completes all 4 tests in **~12.8 seconds total on 4 cores** and **~15.6 seconds total on 1 core**:

```text
x86_64 cuttlefish-audio-mode-session-test
-----------------------------------------
x86_64 cuttlefish-audio-mode-session-test (4 Tests)
[1/4] CuttlefishVoipModeSessionTest#test_voip_mode_session_default_voice_vs_video_routing: PASSED (2.110s)
[2/4] CuttlefishVoipModeSessionTest#test_voip_mode_session_mid_call_route_switching: PASSED (3.186s)
[3/4] CuttlefishVoipModeSessionTest#test_voip_mode_session_preempted_by_cellular_call_and_restored: PASSED (3.410s)
[4/4] CuttlefishVoipModeSessionTest#test_voip_mode_session_preempts_and_restores_media_playback: PASSED (4.048s)
```

---

## 4. Standard Procedure: Running Time-Sensitive Load Tests with Simulated Suppressed Performance (`1 Core`)

Non-premium or heavily contended cloud presubmit hosts can experience severe vCPU throttling. To proactively uncover timing assumptions, race conditions, or tight polling timeouts before submitting changes, always validate time-sensitive audio tests with the guest constrained to **a single online CPU core (`cpu0`)**.

### Step 1 — Clean Up Stale Background `logcat` Processes
If previous test runs were interrupted (`Ctrl+C` or killed Tradefed invocations), orphaned `logcat` processes may still be running inside the guest and consuming `cpu0` cycles:
```bash
export ANDROID_SERIAL=<device_ip>:<port>
adb -s $ANDROID_SERIAL shell 'su 0 killall logcat 2>/dev/null || true'
```

### Step 2 — Constrain Cuttlefish Guest to 1 CPU Core (`nproc=1`)
Use Linux CPU hotplug in sysfs to take `cpu1..cpuN` offline while keeping `cpu0` active:
```bash
adb -s $ANDROID_SERIAL shell 'su 0 sh -c "for f in /sys/devices/system/cpu/cpu[1-9]*/online; do [ -e \$f ] && echo 0 > \$f; done; cat /sys/devices/system/cpu/online; nproc"'
```
Verify that `cat /sys/devices/system/cpu/online` outputs `0` and `nproc` outputs `1`.

### Step 3 — Run Multi-Iteration Stress Test (`--iterations 100`)
Execute both test suites back-to-back or for 100 iterations to characterize the tail latency distribution:
```bash
# Single verification pass under 1-core constraint:
ANDROID_SERIAL=$ANDROID_SERIAL atest -it cuttlefish-audio-mode-session-test cuttlefish-audio-test --request-upload-result

# Full 100-iteration endurance & statistical benchmark:
ANDROID_SERIAL=$ANDROID_SERIAL atest -it cuttlefish-audio-mode-session-test cuttlefish-audio-test --iterations 100 --request-upload-result
```

### Step 4 — Restore All Guest CPU Cores Online
Always bring all vCPUs back online when finished:
```bash
adb -s $ANDROID_SERIAL shell 'su 0 sh -c "for f in /sys/devices/system/cpu/cpu[1-9]*/online; do [ -e \$f ] && echo 1 > \$f; done; cat /sys/devices/system/cpu/online; nproc"'
```

### Step 5 — Timeout & Polling Interval Sizing Rule
- On a 1-core guest (`nproc=1`), real-time 48 kHz audio mixer threads (`AudioFlinger`), `system_server` (`AudioService`), `CuttlefishAudioSnippet`, and `adbd` (`dumpsys` inspection) contend for `cpu0` (verified across 100-iteration runs on 4-core `http://ab/I05100010640673808` and 1-core `http://ab/I35400010640768731`).
- **Timeout Sizing Rule**: Polling helpers and asynchronous callback waits in time-sensitive audio tests (`DEFAULT_TIMEOUT_SEC`, `ROUTE_CONVERGENCE_TIMEOUT_SEC`, `FRAMES_ADVANCING_TIMEOUT_SEC`, `FOCUS_CALLBACK_TIMEOUT_SEC`, `DEFAULT_CALLBACK_TIMEOUT_MS`) must use at least a **`10.0s` timeout ceiling** and a **`>= 250ms` polling interval** (`DEFAULT_POLL_INTERVAL_SEC`) so `dumpsys` polling does not overload `cpu0` and single-core scheduling spikes do not cause false failures in presubmit.

---

## 5. Failure Triage Matrix (What to Look For When a Test Fails)

If any test fails or hangs, match the failure message against the table below:

| Observed Failure / Symptom | Likely Root Cause | What to Inspect / Verify |
| :--- | :--- | :--- |
| **`Expected focus result 1 for <use_case>, got 0`** | Another high-priority exclusive focus owner (e.g. an active phone call, emergency alert, or external `AudioPolicy` focus lock) rejected the request. | Run `adb shell dumpsys audio` and inspect `Audio Focus stack entries` and `has focus policy:`. Check if another app or system service holds `AUDIOFOCUS_GAIN_TRANSIENT_EXCLUSIVE`. |
| **`Expected CfAudioTest[<use_case>] in active focus stack`** | `requestAudioFocus` returned `1` (`GRANTED`), but the entry was immediately evicted or `MediaFocusControl` dump formatting changed. | Run `adb shell dumpsys audio \| grep -A 15 "Audio Focus stack entries"` to check whether the entry was preempted between the RPC return and `dumpsys`. |
| **`Expected CfAudioTest[<use_case>] to be removed from active focus stack after abandon`** | `abandonAudioFocusRequest` failed to remove all focus entries for the package (orphaned `AudioFocusRequest`). | Check logcat for `abandonAudioFocus: clientId=... result=...` and verify no duplicate un-abandoned requests exist. |
| **`CallbackHandlerTimeoutError: Timed out after waiting 10.0s for event 'onAudioFocusChange'`** | Main looper blocked on device, or interrupting client did not cause a focus change for `media_client`. | Check `adb logcat -s AudioFocusSnippet:V AudioSvc.FocusCtrl:V`. Confirm both `requestAudioFocus` calls returned `result=1` and check whether `onAudioFocusChange` fired on device. |
| **`Layer 2 (AudioPolicy) / Layer 5 (ALSA): expected AUDIO_DEVICE_OUT_EARPIECE / pcm1p to be RUNNING`** | Target device is not configured with `use_phone_audio_policy=true` and `output_audio_streams_count=2`. | Check `adb shell ls -l /proc/asound/card0/` for both `pcm0p` and `pcm1p`, and inspect `dumpsys media.audio_policy` for `Attached Devices: Speaker, Earpiece`. |
| **Test fails during `setup_class` / `load_snippet`** | `CuttlefishAudioSnippet.apk` failed to install or `SnippetRunner` instrumentation crashed on startup. | Check `adb shell pm list instrumentation` for `com.android.cuttlefish.audiotest/com.google.android.mobly.snippet.SnippetRunner` and inspect crash logs in logcat (`AndroidRuntime:E`). |

---

## 6. Collecting Logs & Artifacts for Bug Reports

Whenever filing a bug for a failure in `cuttlefish-audio-test` or `cuttlefish-audio-mode-session-test`, attach:
1. **The AnTS Invocation URL** printed at the bottom of the `atest` run (`http://ab/I...`).
2. **Local Mobly & Tradefed Logs** located at:
   ```bash
   /tmp/atest_result_$USER/CURRENT/log/
   ```
   Key files inside that directory:
   - `test_summary.yaml`: Full Mobly test records, stack traces, and timestamps.
   - Device logcat & `dumpsys` artifacts (`dumpsys_audio`, `dumpsys_audio_policy`, `dumpsys_audio_flinger`, `alsa_pcm_status`) captured automatically on failure.
