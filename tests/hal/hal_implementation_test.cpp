/*
 * Copyright (C) 2019 The Android Open Source Project
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
#include <aidl/metadata.h>
#include <android-base/logging.h>
#include <android-base/strings.h>
#include <gtest/gtest.h>
#include <hidl-util/FQName.h>
#include <hidl/metadata.h>
#include <vintf/VintfObject.h>

using namespace android;

// clang-format off
static const std::set<std::string> kKnownMissingHidl = {
    "android.frameworks.cameraservice.device@2.1",
    "android.frameworks.cameraservice.service@2.2", // converted to AIDL, see b/205764761
    "android.frameworks.displayservice@1.0", // deprecated, see b/141930622
    "android.frameworks.schedulerservice@1.0", // deprecated, see b/37226359
    "android.frameworks.vr.composer@1.0",
    "android.frameworks.vr.composer@2.0",
    "android.frameworks.automotive.display@1.0",
    "android.frameworks.stats@1.0",  // converted to AIDL, see b/177667419
    "android.hardware.atrace@1.0", // deprecated, see b/204935495
    "android.hardware.audio@2.0",
    "android.hardware.audio@4.0",
    "android.hardware.audio@5.0",
    "android.hardware.audio@6.0",
    "android.hardware.audio.effect@2.0",
    "android.hardware.audio.effect@4.0",
    "android.hardware.audio.effect@5.0",
    "android.hardware.audio.effect@6.0",
    "android.hardware.authsecret@1.0", // converted to AIDL, see b/182976659
    "android.hardware.automotive.audiocontrol@1.0",
    "android.hardware.automotive.audiocontrol@2.0",
    "android.hardware.automotive.can@1.0",  // converted to AIDL, see b/170405615
    "android.hardware.automotive.evs@1.1",
    "android.hardware.automotive.sv@1.0",
    "android.hardware.automotive.vehicle@2.0",
    "android.hardware.biometrics.fingerprint@2.3", // converted to AIDL, see b/152416783
    "android.hardware.biometrics.face@1.0", // converted to AIDL, see b/168730443
    "android.hardware.bluetooth.a2dp@1.0",
    "android.hardware.bluetooth.audio@2.1", // converted to AIDL, see b/203490261
    "android.hardware.bluetooth@1.1", // converted to AIDL, see b/205758693
    "android.hardware.boot@1.2", // converted to AIDL, see b/227536004
    "android.hardware.broadcastradio@1.1",
    "android.hardware.broadcastradio@2.0",
    "android.hardware.camera.provider@2.7", // Camera converted to AIDL, b/196432585
    "android.hardware.cas@1.2", // converted to AIDL, see b/227673974
    "android.hardware.cas.native@1.0",
    "android.hardware.configstore@1.1", // deprecated, see b/149050985, b/149050733
    "android.hardware.confirmationui@1.0", // converted to AIDL, see b/205760172
    "android.hardware.contexthub@1.2",
    "android.hardware.drm@1.4", // converted to AIDL, b/200055138
    "android.hardware.fastboot@1.1",
    "android.hardware.dumpstate@1.1", // deprecated, see b/205760700
    "android.hardware.gatekeeper@1.0", // converted to AIDL, b/205760843
    "android.hardware.gnss@1.1", // GNSS converted to AIDL, b/206670536
    "android.hardware.gnss@2.1", // GNSS converted to AIDL, b/206670536
    "android.hardware.gnss.measurement_corrections@1.1", // is sub-interface of gnss
    "android.hardware.gnss.visibility_control@1.0",
    "android.hardware.graphics.allocator@2.0",
    "android.hardware.graphics.allocator@3.0",
    "android.hardware.graphics.allocator@4.0", // converted to AIDL, see b/205761012
    "android.hardware.graphics.bufferqueue@1.0",
    "android.hardware.graphics.bufferqueue@2.0",
    "android.hardware.graphics.composer@2.4", // converted to AIDL, see b/193240715
    "android.hardware.graphics.mapper@2.1",
    "android.hardware.graphics.mapper@3.0",
    "android.hardware.health.storage@1.0", // converted to AIDL, see b/177470478
    "android.hardware.health@2.1", // converted to AIDL, see b/177269435
    "android.hardware.input.classifier@1.0", // converted to AIDL, see b/205761620
    "android.hardware.ir@1.0", // converted to AIDL, see b/205000342
    "android.hardware.keymaster@3.0",
    "android.hardware.keymaster@4.1", // Replaced by AIDL KeyMint, see b/111446262
    "android.hardware.light@2.0",
    "android.hardware.media.bufferpool@1.0",
    "android.hardware.media.bufferpool@2.0",
    "android.hardware.media.omx@1.0", // deprecated b/205761766
    "android.hardware.memtrack@1.0",
    "android.hardware.neuralnetworks@1.3", // converted to AIDL, see b/161428342
    "android.hardware.nfc@1.2",
    "android.hardware.oemlock@1.0",
    "android.hardware.power@1.3",
    "android.hardware.power.stats@1.0",
    "android.hardware.radio@1.6", // converted to AIDL
    "android.hardware.radio.config@1.3", // converted to AIDL
    "android.hardware.radio.deprecated@1.0",
    "android.hardware.renderscript@1.0",
    "android.hardware.soundtrigger@2.3",
    "android.hardware.secure_element@1.2",
    "android.hardware.sensors@1.0",
    "android.hardware.sensors@2.1",
    "android.hardware.tetheroffload.config@1.0",
    "android.hardware.tetheroffload.control@1.1", // see b/170699770
    "android.hardware.thermal@1.1",
    "android.hardware.thermal@2.0", // Converted to AIDL (see b/205762943)
    "android.hardware.tv.cec@1.1",
    "android.hardware.tv.input@1.0",
    "android.hardware.tv.tuner@1.1",
    "android.hardware.usb@1.3", // migrated to AIDL see b/200993386
    "android.hardware.usb.gadget@1.2",
    "android.hardware.vibrator@1.3",
    "android.hardware.vr@1.0",
    "android.hardware.weaver@1.0",
    "android.hardware.wifi@1.6", // Converted to AIDL (see b/205044134)
    "android.hardware.wifi.hostapd@1.3", // Converted to AIDL (see b/194806512)
    "android.hardware.wifi.supplicant@1.4", // Converted to AIDL (see b/196235436)
    "android.hardware.wifi.offload@1.0",
    "android.hidl.base@1.0",
    "android.hidl.memory.token@1.0",
    "android.system.net.netd@1.1", // Converted to AIDL (see b/205764585)
    "android.system.suspend@1.0", // Converted to AIDL (see b/170260236)
    "android.system.wifi.keystore@1.0", // Converted to AIDL (see b/205764502)
};
// clang-format on

struct VersionedAidlPackage {
  std::string name;
  size_t version;
  int bugNum;
  bool operator<(const VersionedAidlPackage& rhs) const {
    return (name < rhs.name || (name == rhs.name && version < rhs.version));
  }
};

/*
 * Always missing AIDL packages that are not served on Cuttlefish.
 * These are typically types-only packages.
 */
static const std::set<std::string> kAlwaysMissingAidl = {

    // android.frameworks.cameraservice.common is a type only package use by
    // android.frameworks.cameraservice.device.
    // android.frameworks.cameraservice.device is an interface returnd by
    // android.frameworks.cameraservice.service.
    "android.frameworks.cameraservice.common.",
    "android.frameworks.cameraservice.device.",

    // types-only packages, which never expect a default implementation
    "android.hardware.audio.common.",
    "android.hardware.audio.core.sounddose.",
    "android.hardware.biometrics.common.",
    "android.hardware.common.",
    "android.hardware.common.fmq.",
    "android.hardware.graphics.common.",
    "android.hardware.input.common.",
    "android.media.audio.common.",
    "android.hardware.radio.",
    "android.hardware.uwb.fira_android.",
    "android.hardware.keymaster.",

    // android.hardware.camera.device is an interface returned by
    // android.hardware.camera.provider.
    // android.hardware.camera.common and android.hardware.camera.metadata are
    // types used by android.hardware.camera.provider and
    // android.hardware.camera.device.
    "android.hardware.camera.common.",
    "android.hardware.camera.device.",
    "android.hardware.camera.metadata.",

    // android.hardware.media.bufferpool2 is a HAL-less interface.
    // It could be used for buffer recycling and caching by using the interface.
    "android.hardware.media.bufferpool2.",

    /**
     * These types are only used in Android TV, so don't expect them on phones.
     * TODO(b/266868403) This test should run on TV devices to enforce the same
     * requirements
     */
    "android.hardware.tv.hdmi.cec.",
    "android.hardware.tv.hdmi.earc.",
    "android.hardware.tv.hdmi.connection.",
    "android.hardware.tv.tuner.",
    "android.hardware.tv.input.",

    /**
     * These types are only used in Android Automotive, so don't expect them
     * on phones.
     * TODO(b/266868868) This test should run on Automotive devices to enforce
     * the same requirements
     */
    "android.hardware.automotive.vehicle.",
    "android.automotive.computepipe.registry.",
    "android.automotive.computepipe.runner.",
    "android.automotive.watchdog.",
    "android.frameworks.automotive.display.",
    "android.frameworks.automotive.powerpolicy.",
    "android.frameworks.automotive.powerpolicy.internal.",
    "android.frameworks.automotive.telemetry.",
    "android.hardware.automotive.audiocontrol.",
    "android.hardware.automotive.can.",
    "android.hardware.automotive.evs.",
    "android.hardware.broadcastradio.",
    "android.hardware.automotive.occupant_awareness.",
    "android.hardware.automotive.remoteaccess.",
    "android.hardware.automotive.ivn.",

    /**
     * No implementation on cuttlefish for fastboot AIDL hal because it doesn't
     * run during normal boot, only in recovery/fastboot mode.
     */
    "android.hardware.fastboot.",
};

/*
 * These packages should have implementations but currently do not.
 * These must be accompanied by a bug and expected to be here temporarily.
 */
static const std::vector<VersionedAidlPackage> kKnownMissingAidl = {
    // Cuttlefish Identity Credential HAL implementation is currently
    // stuck at version 3 while RKP support is being added. Will be
    // updated soon.
    {"android.hardware.identity.", 4, 266869317},
    {"android.hardware.identity.", 5, 266869317},

    {"android.se.omapi.", 1, 266870904},
    {"android.hardware.secure_element.", 1, 123254068},
    {"android.hardware.soundtrigger3.", 1, 266941225},
    {"android.media.soundtrigger.", 1, 266941225},
    {"android.hardware.weaver.", 2, 262418065},
};

// AOSP packages which are never considered
static bool isHidlPackageConsidered(const FQName& name) {
  static std::vector<std::string> gAospExclude = {
      // packages not implemented now that we never expect to be implemented
      "android.hardware.tests",
      // packages not registered with hwservicemanager, usually sub-interfaces
      "android.hardware.camera.device",
  };
  for (const std::string& package : gAospExclude) {
    if (name.inPackage(package)) {
      return false;
    }
  }
  return true;
}

// android.hardware.foo.IFoo -> android.hardware.foo.
std::string getAidlPackage(const std::string& aidlType) {
  size_t lastDot = aidlType.rfind('.');
  CHECK(lastDot != std::string::npos);
  return aidlType.substr(0, lastDot + 1);
}

static bool isAospHidlInterface(const FQName& name) {
  static const std::vector<std::string> kAospPackages = {
      "android.hidl",
      "android.hardware",
      "android.frameworks",
      "android.system",
  };
  for (const std::string& package : kAospPackages) {
    if (name.inPackage(package)) {
      return true;
    }
  }
  return false;
}

static std::set<FQName> allTreeHidlInterfaces() {
  std::set<FQName> ret;
  for (const auto& iface : HidlInterfaceMetadata::all()) {
    FQName f;
    CHECK(f.setTo(iface.name)) << iface.name;
    ret.insert(f);
  }
  return ret;
}

static std::set<FQName> allHidlManifestInterfaces() {
  std::set<FQName> ret;
  auto setInserter = [&](const vintf::ManifestInstance& i) -> bool {
    if (i.format() != vintf::HalFormat::HIDL) {
      return true;  // continue
    }
    FQName fqName;
    CHECK(fqName.setTo(i.getFqInstance().getFqNameString()));
    ret.insert(fqName);
    return true;  // continue
  };
  vintf::VintfObject::GetDeviceHalManifest()->forEachInstance(setInserter);
  vintf::VintfObject::GetFrameworkHalManifest()->forEachInstance(setInserter);
  return ret;
}

static bool isAospAidlInterface(const std::string& name) {
  return base::StartsWith(name, "android.") &&
         !base::StartsWith(name, "android.hardware.tests.") &&
         !base::StartsWith(name, "android.aidl.tests");
}

static bool isAlwaysMissingAidl(const std::string& name) {
  return kAlwaysMissingAidl.find(getAidlPackage(name)) !=
         kAlwaysMissingAidl.end();
}

static std::vector<VersionedAidlPackage> allAidlManifestInterfaces() {
  std::vector<VersionedAidlPackage> ret;
  auto setInserter = [&](const vintf::ManifestInstance& i) -> bool {
    if (i.format() != vintf::HalFormat::AIDL) {
      return true;  // continue
    }
    ret.push_back({i.package() + "." + i.interface(), i.version().minorVer, 0});
    return true;  // continue
  };
  vintf::VintfObject::GetDeviceHalManifest()->forEachInstance(setInserter);
  vintf::VintfObject::GetFrameworkHalManifest()->forEachInstance(setInserter);
  return ret;
}

TEST(Hal, AllHidlInterfacesAreInAosp) {
  for (const FQName& name : allHidlManifestInterfaces()) {
    EXPECT_TRUE(isAospHidlInterface(name))
        << "This device should only have AOSP interfaces, not: "
        << name.string();
  }
}

TEST(Hal, HidlInterfacesImplemented) {
  // instances -> major version -> minor versions
  std::map<std::string, std::map<size_t, std::set<size_t>>> unimplemented;

  for (const FQName& f : allTreeHidlInterfaces()) {
    if (!isAospHidlInterface(f)) continue;
    if (!isHidlPackageConsidered(f)) continue;

    unimplemented[f.package()][f.getPackageMajorVersion()].insert(
        f.getPackageMinorVersion());
  }

  // we'll be removing items from this which we know are missing
  // in order to be left with those elements which we thought we
  // knew were missing but are actually present
  std::set<std::string> thoughtMissing = kKnownMissingHidl;

  for (const FQName& f : allHidlManifestInterfaces()) {
    if (thoughtMissing.erase(f.getPackageAndVersion().string()) > 0) {
      ADD_FAILURE() << "Instance in missing list, but available: "
                    << f.string();
    }

    std::set<size_t>& minors =
        unimplemented[f.package()][f.getPackageMajorVersion()];
    size_t minor = f.getPackageMinorVersion();

    auto it = minors.find(minor);
    if (it == minors.end()) continue;

    // if 1.2 is implemented, also considere 1.0, 1.1 implemented
    minors.erase(minors.begin(), std::next(it));
  }

  for (const auto& [package, minorsPerMajor] : unimplemented) {
    for (const auto& [major, minors] : minorsPerMajor) {
      if (minors.empty()) continue;

      size_t maxMinor = *minors.rbegin();

      FQName missing;
      ASSERT_TRUE(missing.setTo(package, major, maxMinor));

      if (thoughtMissing.erase(missing.string()) > 0) continue;

      ADD_FAILURE() << "Missing implementation from " << missing.string();
    }
  }

  for (const std::string& missing : thoughtMissing) {
    ADD_FAILURE() << "Instance in missing list and cannot find it anywhere: "
                  << missing << " (multiple versions in missing list?)";
  }
}

TEST(Hal, AllAidlInterfacesAreInAosp) {
  for (const auto& package : allAidlManifestInterfaces()) {
    EXPECT_TRUE(isAospAidlInterface(package.name))
        << "This device should only have AOSP interfaces, not: "
        << package.name;
  }
}

struct AidlPackageCheck {
  bool hasRegistration;
  bool knownMissing;
};

TEST(Hal, AidlInterfacesImplemented) {
  std::vector<VersionedAidlPackage> manifest = allAidlManifestInterfaces();
  std::vector<VersionedAidlPackage> thoughtMissing = kKnownMissingAidl;

  for (const auto& treePackage : AidlInterfaceMetadata::all()) {
    ASSERT_FALSE(treePackage.types.empty()) << treePackage.name;
    if (std::none_of(treePackage.types.begin(), treePackage.types.end(),
                     isAospAidlInterface) ||
        std::any_of(treePackage.types.begin(), treePackage.types.end(),
                    isAlwaysMissingAidl))
      continue;
    if (treePackage.stability != "vintf") continue;

    // expect versions from 1 to latest version. If the package has development
    // the latest version is the latest known version + 1. Each of these need
    // to be checked for registration and knownMissing.
    std::map<size_t, AidlPackageCheck> expectedVersions;
    for (const auto version : treePackage.versions) {
      expectedVersions[version] = {false, false};
    }
    if (treePackage.has_development) {
      size_t version =
          treePackage.versions.empty() ? 1 : *treePackage.versions.rbegin() + 1;
      expectedVersions[version] = {false, false};
    }

    // Check all types and versions defined by the package for registration.
    // The package version is considered registered if any of those types are
    // present in the manifest with the same version.
    // The package version is considered known missing if it is found in
    // thoughtMissing.
    bool latestRegistered = false;
    for (const std::string& type : treePackage.types) {
      for (auto& [version, check] : expectedVersions) {
        auto it = std::remove_if(
            manifest.begin(), manifest.end(),
            [&type, &ver = version](const VersionedAidlPackage& package) {
              return package.name == type && package.version == ver;
            });
        if (it != manifest.end()) {
          manifest.erase(it, manifest.end());
          if (version == expectedVersions.rbegin()->first) {
            latestRegistered = true;
          }
          check.hasRegistration = true;
        }
        it = std::remove_if(
            thoughtMissing.begin(), thoughtMissing.end(),
            [&type, &ver = version](const VersionedAidlPackage& package) {
              return package.name == getAidlPackage(type) &&
                     package.version == ver;
            });
        if (it != thoughtMissing.end()) {
          thoughtMissing.erase(it, thoughtMissing.end());
          check.knownMissing = true;
        }
      }
    }

    if (!latestRegistered && !expectedVersions.rbegin()->second.knownMissing) {
      ADD_FAILURE() << "The latest version ("
                    << expectedVersions.rbegin()->first
                    << ") of the module is not implemented: "
                    << treePackage.name
                    << " which declares the following types:\n    "
                    << base::Join(treePackage.types, "\n    ");
    }

    for (const auto& [version, check] : expectedVersions) {
      if (check.knownMissing) {
        if (check.hasRegistration) {
          ADD_FAILURE() << "Package in missing list, but available: "
                        << treePackage.name << " V" << version
                        << " which declares the following types:\n    "
                        << base::Join(treePackage.types, "\n    ");
        }

        continue;
      }
    }
  }

  for (const auto& package : thoughtMissing) {
    ADD_FAILURE() << "Interface in missing list and cannot find it anywhere: "
                  << package.name << " V" << package.version;
  }

  for (const auto& package : manifest) {
    ADD_FAILURE() << "Can't find manifest entry in tree: " << package.name
                  << " version: " << package.version;
  }
}
