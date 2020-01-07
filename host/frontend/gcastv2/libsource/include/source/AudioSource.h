/*
 * Copyright 2018, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include <media/stagefright/foundation/ABuffer.h>
#include <source/StreamingSource.h>

#include <memory>
#include <thread>

#define SIMULATE_AUDIO          0

namespace vsoc {
    class RegionWorker;
    namespace audio_data {
        class AudioDataRegionView;
    }
}

namespace android {

struct AudioSource : public StreamingSource {
    using AudioDataRegionView = vsoc::audio_data::AudioDataRegionView;

    enum class Format {
        AAC,
        OPUS,
        G711_ALAW,
        G711_ULAW,
    };
    // ADTS framing is only supported for Format::AAC.
    explicit AudioSource(Format format, bool useADTSFraming = false);

    AudioSource(const AudioSource &) = delete;
    AudioSource &operator=(const AudioSource &) = delete;

    ~AudioSource() override;

    status_t initCheck() const override;

    sp<AMessage> getFormat() const override;

    status_t start() override;
    status_t stop() override;

    status_t requestIDRFrame() override;

    void inject(const void *data, size_t size);

private:
    enum State {
        STOPPING,
        STOPPED,
        RUNNING,
        PAUSED
    };

    struct Encoder;
    struct AACEncoder;
    struct OPUSEncoder;
    struct G711Encoder;

    status_t mInitCheck;
    State mState;
    std::unique_ptr<Encoder> mEncoder;

    sp<AMessage> mFormat;

    std::mutex mLock;
    std::unique_ptr<std::thread> mThread;

#if SIMULATE_AUDIO
    static constexpr int32_t kSampleRate = 44100;
    static constexpr int32_t kNumChannels = 2;
    static constexpr size_t kNumFramesPerBuffer = 400;
    static constexpr int32_t kFrequency = 500;
    size_t mPhase;
#endif
};

}  // namespace android


