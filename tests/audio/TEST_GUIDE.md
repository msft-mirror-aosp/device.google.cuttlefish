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
   - **Assertion**: Event received within 5s with `clientId == "media_client"` and `focusChange == -2`.
5. **Abandon Transient Alarm**: `alarm_client` abandons its focus request.
6. **Verify Focus Regain Callback**: `AudioService` automatically restores focus to `media_client` and dispatches `onAudioFocusChange(1)` (`AUDIOFOCUS_GAIN`).
   - **Assertion**: Event received within 5s with `clientId == "media_client"` and `focusChange == 1`.
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

## 3. Healthy Run Output & Expected Timings

A healthy execution on Cuttlefish completes all 9 tests in **~1.3 seconds total** ($70\text{ ms} - 270\text{ ms}$ per test):

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
Summary (Test executed with 1 device.)

-------
x86_64 cuttlefish-audio-test: Passed: 9, Failed: 0, Ignored: 0, Assumption Failed: 0

All tests passed!
Test Result uploaded to http://ab/I...
```

---

## 4. Failure Triage Matrix (What to Look For When a Test Fails)

If any test fails or hangs, match the failure message against the table below:

| Observed Failure / Symptom | Likely Root Cause | What to Inspect / Verify |
| :--- | :--- | :--- |
| **`Expected focus result 1 for <use_case>, got 0`** | Another high-priority exclusive focus owner (e.g. an active phone call, emergency alert, or external `AudioPolicy` focus lock) rejected the request. | Run `adb shell dumpsys audio` and inspect `Audio Focus stack entries` and `has focus policy:`. Check if another app or system service holds `AUDIOFOCUS_GAIN_TRANSIENT_EXCLUSIVE`. |
| **`Expected CfAudioTest[<use_case>] in active focus stack`** | `requestAudioFocus` returned `1` (`GRANTED`), but the entry was immediately evicted or `MediaFocusControl` dump formatting changed. | Run `adb shell dumpsys audio \| grep -A 15 "Audio Focus stack entries"` to check whether the entry was preempted between the RPC return and `dumpsys`. |
| **`Expected CfAudioTest[<use_case>] to be removed from active focus stack after abandon`** | `abandonAudioFocusRequest` failed to remove all focus entries for the package (orphaned `AudioFocusRequest`). | Check logcat for `abandonAudioFocus: clientId=... result=...` and verify no duplicate un-abandoned requests exist. |
| **`CallbackHandlerTimeoutError: Timed out after waiting 5.0s for event 'onAudioFocusChange'`** in Test 1 | Main looper blocked on device, or `alarm_client` did not cause a focus change for `media_client`. | Check `adb logcat -s AudioFocusSnippet:V AudioSvc.FocusCtrl:V`. Confirm both `requestAudioFocus` calls returned `result=1` and check whether `onAudioFocusChange` fired on device. |
| **Test fails during `setup_class` / `load_snippet`** | `CuttlefishAudioSnippet.apk` failed to install or `SnippetRunner` instrumentation crashed on startup. | Check `adb shell pm list instrumentation` for `com.android.cuttlefish.audiotest/com.google.android.mobly.snippet.SnippetRunner` and inspect crash logs in logcat (`AndroidRuntime:E`). |

---

## 5. Collecting Logs & Artifacts for Bug Reports

Whenever filing a bug for a failure in `cuttlefish-audio-test`, attach:
1. **The AnTS Invocation URL** printed at the bottom of the `atest` run (`http://ab/I...`).
2. **Local Mobly & Tradefed Logs** located at:
   ```bash
   /tmp/atest_result_$USER/CURRENT/log/
   ```
   Key files inside that directory:
   - `test_summary.yaml`: Full Mobly test records, stack traces, and timestamps.
   - Device logcat & `dumpsys` artifacts captured automatically by Tradefed.
