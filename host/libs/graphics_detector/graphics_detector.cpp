/*
 * Copyright (C) 2020 The Android Open Source Project
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

#include "host/libs/graphics_detector/graphics_detector.h"

#include <sstream>
#include <vector>

#include <EGL/egl.h>
#include <EGL/eglext.h>
#include <android-base/logging.h>
#include <android-base/strings.h>
#include <dlfcn.h>
#include <sys/wait.h>
#include <vulkan/vulkan.h>

namespace cuttlefish {
namespace {

constexpr const char kEglLib[] = "libEGL.so.1";
constexpr const char kGlLib[] = "libOpenGL.so.0";
constexpr const char kGles1Lib[] = "libGLESv1_CM.so.1";
constexpr const char kGles2Lib[] = "libGLESv2.so.2";
constexpr const char kVulkanLib[] = "libvulkan.so.1";

constexpr const char kSurfacelessContextExt[] = "EGL_KHR_surfaceless_context";

class Closer {
public:
  Closer(std::function<void()> on_close) : on_close_(on_close) {}
  ~Closer() { on_close_(); }

private:
  std::function<void()> on_close_;
};

struct LibraryCloser {
 public:
  void operator()(void* library) { dlclose(library); }
};

using ManagedLibrary = std::unique_ptr<void, LibraryCloser>;

void PopulateGlAvailability(GraphicsAvailability* availability) {
  ManagedLibrary gl_lib(dlopen(kGlLib, RTLD_NOW | RTLD_LOCAL));
  if (!gl_lib) {
    LOG(VERBOSE) << "Failed to dlopen " << kGlLib << ".";
    return;
  }
  LOG(VERBOSE) << "Loaded " << kGlLib << ".";
  availability->has_gl = true;
}

void PopulateGles1Availability(GraphicsAvailability* availability) {
  ManagedLibrary gles1_lib(dlopen(kGles1Lib, RTLD_NOW | RTLD_LOCAL));
  if (!gles1_lib) {
    LOG(VERBOSE) << "Failed to dlopen " << kGles1Lib << ".";
    return;
  }
  LOG(VERBOSE) << "Loaded " << kGles1Lib << ".";
  availability->has_gles1 = true;
}

void PopulateGles2Availability(GraphicsAvailability* availability) {
  ManagedLibrary gles2_lib(dlopen(kGles2Lib, RTLD_NOW | RTLD_LOCAL));
  if (!gles2_lib) {
    LOG(VERBOSE) << "Failed to dlopen " << kGles2Lib << ".";
    return;
  }
  LOG(VERBOSE) << "Loaded " << kGles2Lib << ".";
  availability->has_gles2 = true;
}

void PopulateEglAvailability(GraphicsAvailability* availability) {
  ManagedLibrary egllib(dlopen(kEglLib, RTLD_NOW | RTLD_LOCAL));
  if (!egllib) {
    LOG(VERBOSE) << "Failed to dlopen " << kEglLib << ".";
    return;
  }
  LOG(VERBOSE) << "Loaded " << kEglLib << ".";
  availability->has_egl = true;

  PFNEGLGETPROCADDRESSPROC eglGetProcAddress =
      reinterpret_cast<PFNEGLGETPROCADDRESSPROC>(
          dlsym(egllib.get(), "eglGetProcAddress"));
  if (eglGetProcAddress == nullptr) {
    LOG(VERBOSE) << "Failed to find function eglGetProcAddress.";
    return;
  }
  LOG(VERBOSE) << "Loaded eglGetProcAddress.";

  // Some implementations have it so that eglGetProcAddress is only for
  // loading EXT functions.
  auto EglLoadFunction = [&](const char* name) {
    void* func = dlsym(egllib.get(), name);
    if (func == NULL) {
      func = reinterpret_cast<void*>(eglGetProcAddress(name));
    }
    return func;
  };

  PFNEGLGETERRORPROC eglGetError =
    reinterpret_cast<PFNEGLGETERRORPROC>(EglLoadFunction("eglGetError"));
  if (eglGetError == nullptr) {
    LOG(VERBOSE) << "Failed to find function eglGetError.";
    return;
  }
  LOG(VERBOSE) << "Loaded eglGetError.";

  PFNEGLGETDISPLAYPROC eglGetDisplay =
    reinterpret_cast<PFNEGLGETDISPLAYPROC>(EglLoadFunction("eglGetDisplay"));
  if (eglGetDisplay == nullptr) {
    LOG(VERBOSE) << "Failed to find function eglGetDisplay.";
    return;
  }
  LOG(VERBOSE) << "Loaded eglGetDisplay.";

  EGLDisplay default_display = eglGetDisplay(EGL_DEFAULT_DISPLAY);
  if (default_display == EGL_NO_DISPLAY) {
    LOG(VERBOSE) << "Failed to get default display. " << eglGetError();
    return;
  }
  LOG(VERBOSE) << "Found default display.";
  availability->has_egl_default_display = true;

  PFNEGLINITIALIZEPROC eglInitialize =
    reinterpret_cast<PFNEGLINITIALIZEPROC>(EglLoadFunction("eglInitialize"));
  if (eglInitialize == nullptr) {
    LOG(VERBOSE) << "Failed to find function eglQueryString";
    return;
  }

  EGLint client_version_major = 0;
  EGLint client_version_minor = 0;
  if (eglInitialize(default_display,
                    &client_version_major,
                    &client_version_minor) != EGL_TRUE) {
    LOG(VERBOSE) << "Failed to initialize default display.";
    return;
  }
  LOG(VERBOSE) << "Initialized default display.";

  PFNEGLQUERYSTRINGPROC eglQueryString =
    reinterpret_cast<PFNEGLQUERYSTRINGPROC>(EglLoadFunction("eglQueryString"));
  if (eglQueryString == nullptr) {
    LOG(VERBOSE) << "Failed to find function eglQueryString";
    return;
  }
  LOG(VERBOSE) << "Loaded eglQueryString.";

  std::string client_extensions;
  if (client_version_major >= 1 && client_version_minor >= 5) {
    client_extensions = eglQueryString(EGL_NO_DISPLAY, EGL_EXTENSIONS);
  }
  availability->egl_client_extensions = client_extensions;

  EGLDisplay display = EGL_NO_DISPLAY;

  if (client_extensions.find("EGL_EXT_platform_base") != std::string::npos) {
    LOG(VERBOSE) << "Client extension EGL_EXT_platform_base is supported.";

    PFNEGLGETPLATFORMDISPLAYEXTPROC eglGetPlatformDisplayEXT =
      reinterpret_cast<PFNEGLGETPLATFORMDISPLAYEXTPROC>(
        EglLoadFunction("eglGetPlatformDisplayEXT"));
    if (eglGetPlatformDisplayEXT == nullptr) {
      LOG(VERBOSE) << "Failed to find function eglGetPlatformDisplayEXT";
      return;
    }

    display =
      eglGetPlatformDisplayEXT(EGL_PLATFORM_SURFACELESS_MESA,
                               EGL_DEFAULT_DISPLAY,
                               NULL);
  } else {
    LOG(VERBOSE) << "Failed to find client extension EGL_EXT_platform_base.";
  }
  if (display == EGL_NO_DISPLAY) {
    LOG(VERBOSE) << "Failed to get EGL_PLATFORM_SURFACELESS_MESA display..."
                 << "failing back to EGL_DEFAULT_DISPLAY display.";
    display = default_display;
  }
  if (display == EGL_NO_DISPLAY) {
    LOG(VERBOSE) << "Failed to find display.";
    return;
  }

  if (eglInitialize(display,
                    &client_version_major,
                    &client_version_minor) != EGL_TRUE) {
    LOG(VERBOSE) << "Failed to initialize surfaceless display.";
    return;
  }
  LOG(VERBOSE) << "Initialized surfaceless display.";

  const std::string version_string = eglQueryString(display, EGL_VERSION);
  if (version_string.empty()) {
    LOG(VERBOSE) << "Failed to query client version.";
    return;
  }
  LOG(VERBOSE) << "Found version: " << version_string;
  availability->egl_version = version_string;

  const std::string vendor_string = eglQueryString(display, EGL_VENDOR);
  if (vendor_string.empty()) {
    LOG(VERBOSE) << "Failed to query vendor.";
    return;
  }
  LOG(VERBOSE) << "Found vendor: " << vendor_string;
  availability->egl_vendor = vendor_string;

  const std::string extensions_string = eglQueryString(display, EGL_EXTENSIONS);
  if (extensions_string.empty()) {
    LOG(VERBOSE) << "Failed to query extensions.";
    return;
  }
  LOG(VERBOSE) << "Found extensions: " << extensions_string;
  availability->egl_extensions = extensions_string;

  if (extensions_string.find(kSurfacelessContextExt) == std::string::npos) {
    LOG(VERBOSE) << "Failed to find extension EGL_KHR_surfaceless_context.";
    return;
  }

  const std::string display_apis_string = eglQueryString(display,
                                                         EGL_CLIENT_APIS);
  if (display_apis_string.empty()) {
    LOG(VERBOSE) << "Failed to query display apis.";
    return;
  }
  LOG(VERBOSE) << "Found display apis: " << display_apis_string;

  PFNEGLBINDAPIPROC eglBindAPI =
    reinterpret_cast<PFNEGLBINDAPIPROC>(EglLoadFunction("eglBindAPI"));
  if (eglBindAPI == nullptr) {
    LOG(VERBOSE) << "Failed to find function eglBindAPI";
    return;
  }
  LOG(VERBOSE) << "Loaded eglBindAPI.";

  if (eglBindAPI(EGL_OPENGL_ES_API) == EGL_FALSE) {
    LOG(VERBOSE) << "Failed to bind GLES API.";
    return;
  }
  LOG(VERBOSE) << "Bound GLES API.";

  PFNEGLCHOOSECONFIGPROC eglChooseConfig =
    reinterpret_cast<PFNEGLCHOOSECONFIGPROC>(
      EglLoadFunction("eglChooseConfig"));
  if (eglChooseConfig == nullptr) {
    LOG(VERBOSE) << "Failed to find function eglChooseConfig";
    return;
  }
  LOG(VERBOSE) << "Loaded eglChooseConfig.";

  const EGLint framebuffer_config_attributes[] = {
    EGL_SURFACE_TYPE, EGL_PBUFFER_BIT,
    EGL_RENDERABLE_TYPE, EGL_OPENGL_ES2_BIT,
    EGL_RED_SIZE, 1,
    EGL_GREEN_SIZE, 1,
    EGL_BLUE_SIZE, 1,
    EGL_ALPHA_SIZE, 0,
    EGL_NONE,
  };

  EGLConfig framebuffer_config;
  EGLint num_framebuffer_configs = 0;
  if (eglChooseConfig(display,
                      framebuffer_config_attributes,
                      &framebuffer_config,
                      1,
                      &num_framebuffer_configs) != EGL_TRUE) {
    LOG(VERBOSE) << "Failed to find matching framebuffer config.";
    return;
  }
  LOG(VERBOSE) << "Found matching framebuffer config.";

  PFNEGLCREATECONTEXTPROC eglCreateContext =
    reinterpret_cast<PFNEGLCREATECONTEXTPROC>(
      EglLoadFunction("eglCreateContext"));
  if (eglCreateContext == nullptr) {
    LOG(VERBOSE) << "Failed to find function eglCreateContext";
    return;
  }
  LOG(VERBOSE) << "Loaded eglCreateContext.";

  PFNEGLDESTROYCONTEXTPROC eglDestroyContext =
    reinterpret_cast<PFNEGLDESTROYCONTEXTPROC>(
      EglLoadFunction("eglDestroyContext"));
  if (eglDestroyContext == nullptr) {
    LOG(VERBOSE) << "Failed to find function eglDestroyContext";
    return;
  }
  LOG(VERBOSE) << "Loaded eglDestroyContext.";

  const EGLint context_attributes[] = {
    EGL_CONTEXT_CLIENT_VERSION, 2,
    EGL_NONE
  };

  EGLContext context = eglCreateContext(display,
                                        framebuffer_config,
                                        EGL_NO_CONTEXT,
                                        context_attributes);
  if (context == EGL_NO_CONTEXT) {
    LOG(VERBOSE) << "Failed to create EGL context.";
    return;
  }
  LOG(VERBOSE) << "Created EGL context.";
  Closer context_closer([&]() { eglDestroyContext(display, context); });

  PFNEGLMAKECURRENTPROC eglMakeCurrent =
    reinterpret_cast<PFNEGLMAKECURRENTPROC>(EglLoadFunction("eglMakeCurrent"));
  if (eglMakeCurrent == nullptr) {
    LOG(VERBOSE) << "Failed to find function eglMakeCurrent";
    return;
  }
  LOG(VERBOSE) << "Loaded eglMakeCurrent.";

  if (eglMakeCurrent(display,
                     EGL_NO_SURFACE,
                     EGL_NO_SURFACE,
                     context) != EGL_TRUE) {
    LOG(VERBOSE) << "Failed to make EGL context current.";
    return;
  }
  LOG(VERBOSE) << "Make EGL context current.";
  availability->has_egl_surfaceless_with_gles = true;
}

void PopulateVulkanAvailability(GraphicsAvailability* availability) {
  ManagedLibrary vklib(dlopen(kVulkanLib, RTLD_NOW | RTLD_LOCAL));
  if (!vklib) {
    LOG(VERBOSE) << "Failed to dlopen " << kVulkanLib << ".";
    return;
  }
  LOG(VERBOSE) << "Loaded " << kVulkanLib << ".";
  availability->has_vulkan = true;

  uint32_t instance_version = 0;

  PFN_vkGetInstanceProcAddr vkGetInstanceProcAddr =
      reinterpret_cast<PFN_vkGetInstanceProcAddr>(
          dlsym(vklib.get(), "vkGetInstanceProcAddr"));
  if (vkGetInstanceProcAddr == nullptr) {
    LOG(VERBOSE) << "Failed to find symbol vkGetInstanceProcAddr.";
    return;
  }

  PFN_vkEnumerateInstanceVersion vkEnumerateInstanceVersion =
      reinterpret_cast<PFN_vkEnumerateInstanceVersion>(
          dlsym(vklib.get(), "vkEnumerateInstanceVersion"));
  if (vkEnumerateInstanceVersion == nullptr ||
      vkEnumerateInstanceVersion(&instance_version) != VK_SUCCESS) {
    instance_version = VK_API_VERSION_1_0;
  }

  PFN_vkCreateInstance vkCreateInstance =
    reinterpret_cast<PFN_vkCreateInstance>(
      vkGetInstanceProcAddr(VK_NULL_HANDLE, "vkCreateInstance"));
  if (vkCreateInstance == nullptr) {
    LOG(VERBOSE) << "Failed to get function vkCreateInstance.";
    return;
  }

  VkApplicationInfo application_info;
  application_info.sType = VK_STRUCTURE_TYPE_APPLICATION_INFO;
  application_info.pNext = nullptr;
  application_info.pApplicationName = "";
  application_info.applicationVersion = 1;
  application_info.pEngineName = "";
  application_info.engineVersion = 1;
  application_info.apiVersion = instance_version;

  VkInstanceCreateInfo instance_create_info = {};
  instance_create_info.sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO;
  instance_create_info.pNext = nullptr;
  instance_create_info.flags = 0;
  instance_create_info.pApplicationInfo = &application_info;
  instance_create_info.enabledLayerCount = 0;
  instance_create_info.ppEnabledLayerNames = nullptr;
  instance_create_info.enabledExtensionCount = 0;
  instance_create_info.ppEnabledExtensionNames = nullptr;

  VkInstance instance = VK_NULL_HANDLE;
  VkResult result = vkCreateInstance(&instance_create_info, nullptr, &instance);
  if (result != VK_SUCCESS) {
    if (result == VK_ERROR_OUT_OF_HOST_MEMORY) {
      LOG(VERBOSE) << "Failed to create Vulkan instance: "
                   << "VK_ERROR_OUT_OF_HOST_MEMORY.";
    } else if (result == VK_ERROR_OUT_OF_DEVICE_MEMORY) {
      LOG(VERBOSE) << "Failed to create Vulkan instance: "
                   << "VK_ERROR_OUT_OF_DEVICE_MEMORY.";
    } else if (result == VK_ERROR_INITIALIZATION_FAILED) {
      LOG(VERBOSE) << "Failed to create Vulkan instance: "
                   << "VK_ERROR_INITIALIZATION_FAILED.";
    } else if (result == VK_ERROR_LAYER_NOT_PRESENT) {
      LOG(VERBOSE) << "Failed to create Vulkan instance: "
                   << "VK_ERROR_LAYER_NOT_PRESENT.";
    } else if (result == VK_ERROR_EXTENSION_NOT_PRESENT) {
      LOG(VERBOSE) << "Failed to create Vulkan instance: "
                   << "VK_ERROR_EXTENSION_NOT_PRESENT.";
    } else if (result == VK_ERROR_INCOMPATIBLE_DRIVER) {
      LOG(VERBOSE) << "Failed to create Vulkan instance: "
                   << "VK_ERROR_INCOMPATIBLE_DRIVER.";
    } else {
      LOG(VERBOSE) << "Failed to create Vulkan instance.";
    }
    return;
  }

  PFN_vkDestroyInstance vkDestroyInstance =
    reinterpret_cast<PFN_vkDestroyInstance>(
      vkGetInstanceProcAddr(instance, "vkDestroyInstance"));
  if (vkDestroyInstance == nullptr) {
    LOG(VERBOSE) << "Failed to get function vkDestroyInstance.";
    return;
  }

  Closer instancecloser([&]() {vkDestroyInstance(instance, nullptr); });

  PFN_vkEnumeratePhysicalDevices vkEnumeratePhysicalDevices =
    reinterpret_cast<PFN_vkEnumeratePhysicalDevices>(
      vkGetInstanceProcAddr(instance, "vkEnumeratePhysicalDevices"));
  if (vkEnumeratePhysicalDevices == nullptr) {
    LOG(VERBOSE) << "Failed to "
                 << "vkGetInstanceProcAddr(vkEnumeratePhysicalDevices).";
    return;
  }

  PFN_vkGetPhysicalDeviceProperties vkGetPhysicalDeviceProperties =
    reinterpret_cast<PFN_vkGetPhysicalDeviceProperties>(
      vkGetInstanceProcAddr(instance, "vkGetPhysicalDeviceProperties"));
  if (vkGetPhysicalDeviceProperties == nullptr) {
    LOG(VERBOSE) << "Failed to "
                 << "vkGetInstanceProcAddr(vkGetPhysicalDeviceProperties).";
    return;
  }

  auto vkEnumerateDeviceExtensionProperties =
    reinterpret_cast<PFN_vkEnumerateDeviceExtensionProperties>(
      vkGetInstanceProcAddr(instance, "vkEnumerateDeviceExtensionProperties"));
  if (vkEnumerateDeviceExtensionProperties == nullptr) {
    LOG(VERBOSE) << "Failed to "
                 << "vkGetInstanceProcAddr("
                 << "vkEnumerateDeviceExtensionProperties"
                 << ").";
    return;
  }

  uint32_t device_count = 0;
  result = vkEnumeratePhysicalDevices(instance, &device_count, nullptr);
  if (result != VK_SUCCESS) {
    if (result == VK_INCOMPLETE) {
      LOG(VERBOSE) << "Failed to enumerate physical device count: "
                   << "VK_INCOMPLETE";
    } else if (result == VK_ERROR_OUT_OF_HOST_MEMORY) {
      LOG(VERBOSE) << "Failed to enumerate physical device count: "
                   << "VK_ERROR_OUT_OF_HOST_MEMORY";
    } else if (result == VK_ERROR_OUT_OF_DEVICE_MEMORY) {
      LOG(VERBOSE) << "Failed to enumerate physical device count: "
                   << "VK_ERROR_OUT_OF_DEVICE_MEMORY";
    } else if (result == VK_ERROR_INITIALIZATION_FAILED) {
      LOG(VERBOSE) << "Failed to enumerate physical device count: "
                   << "VK_ERROR_INITIALIZATION_FAILED";
    } else {
      LOG(VERBOSE) << "Failed to enumerate physical device count.";
    }
    return;
  }

  if (device_count == 0) {
    LOG(VERBOSE) << "No physical devices present.";
    return;
  }

  std::vector<VkPhysicalDevice> devices(device_count, VK_NULL_HANDLE);
  result = vkEnumeratePhysicalDevices(instance, &device_count, devices.data());
  if (result != VK_SUCCESS) {
    LOG(VERBOSE) << "Failed to enumerate physical devices.";
    return;
  }

  for (VkPhysicalDevice device : devices) {
    VkPhysicalDeviceProperties device_properties = {};
    vkGetPhysicalDeviceProperties(device, &device_properties);

    uint32_t device_extensions_count = 0;
    vkEnumerateDeviceExtensionProperties(device,
                                         nullptr,
                                         &device_extensions_count,
                                         nullptr);

    std::vector<VkExtensionProperties> device_extensions;
    device_extensions.resize(device_extensions_count);

    vkEnumerateDeviceExtensionProperties(device,
                                         nullptr,
                                         &device_extensions_count,
                                         device_extensions.data());

    std::vector<const char*> device_extensions_strings;
    for (const VkExtensionProperties& device_extension : device_extensions) {
      device_extensions_strings.push_back(device_extension.extensionName);
    }

    std::string device_extensions_string =
      android::base::Join(device_extensions_strings, ' ');

    if (device_properties.deviceType == VK_PHYSICAL_DEVICE_TYPE_DISCRETE_GPU) {
      availability->has_discrete_gpu = true;
      availability->discrete_gpu_device_name = device_properties.deviceName;
      availability->discrete_gpu_device_extensions = device_extensions_string;
      break;
    }
  }
}

GraphicsAvailability GetGraphicsAvailability() {
  GraphicsAvailability availability;

  PopulateEglAvailability(&availability);
  PopulateGlAvailability(&availability);
  PopulateGles1Availability(&availability);
  PopulateGles2Availability(&availability);
  PopulateVulkanAvailability(&availability);

  return availability;
}

}  // namespace

bool ShouldEnableAcceleratedRendering(
    const GraphicsAvailability& availability) {
  return availability.has_egl && availability.has_egl_surfaceless_with_gles &&
         availability.has_discrete_gpu;
}

// Runs GetGraphicsAvailability() inside of a subprocess first to ensure that
// GetGraphicsAvailability() can complete successfully without crashing
// assemble_cvd. Configurations such as GCE instances without a GPU but with GPU
// drivers for example have seen crashes.
GraphicsAvailability GetGraphicsAvailabilityWithSubprocessCheck() {
  pid_t pid = fork();
  if (pid == 0) {
    GetGraphicsAvailability();
    std::exit(0);
  }
  int status;
  if (waitpid(pid, &status, 0) != pid) {
    PLOG(ERROR) << "Failed to wait for graphics check subprocess";
    return GraphicsAvailability{};
  }
  if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
    return GetGraphicsAvailability();
  }
  LOG(VERBOSE) << "Subprocess for detect_graphics failed with " << status;
  return GraphicsAvailability{};
}

std::ostream& operator<<(std::ostream& stream,
                         const GraphicsAvailability& availability) {
  std::ios_base::fmtflags flags_backup(stream.flags());
  stream << std::boolalpha;
  stream << "Graphics Availability:\n";
  stream << "OpenGL available: " << availability.has_gl << "\n";
  stream << "OpenGL ES1 available: " << availability.has_gles1 << "\n";
  stream << "OpenGL ES2 available: " << availability.has_gles2 << "\n";
  stream << "EGL available: " << availability.has_egl << "\n";
  stream << "EGL client extensions: " << availability.egl_client_extensions
         << "\n";
  stream << "EGL default display available: "
         << availability.has_egl_default_display << "\n";
  stream << "EGL display vendor: " << availability.egl_vendor << "\n";
  stream << "EGL display version: " << availability.egl_version << "\n";
  stream << "EGL display extensions: " << availability.egl_extensions << "\n";
  stream << "EGL surfaceless display with GLES: "
         << availability.has_egl_surfaceless_with_gles << "\n";
  stream << "Vulkan available: " << availability.has_vulkan << "\n";
  stream << "Vulkan discrete GPU detected: " << availability.has_discrete_gpu
         << "\n";
  if (availability.has_discrete_gpu) {
    stream << "Vulkan discrete GPU device name: "
           << availability.discrete_gpu_device_name << "\n";
    stream << "Vulkan discrete GPU device extensions: "
           << availability.discrete_gpu_device_extensions << "\n";
  }
  stream.flags(flags_backup);
  return stream;
}

} // namespace cuttlefish
