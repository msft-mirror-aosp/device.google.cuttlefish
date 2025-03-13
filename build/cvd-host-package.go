// Copyright (C) 2020 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cuttlefish

import (
	"fmt"
	"strings"

	"github.com/google/blueprint"
	"github.com/google/blueprint/proptools"

	"android/soong/android"
)

func init() {
	android.RegisterModuleType("cvd_host_package", cvdHostPackageFactory)
	android.RegisterParallelSingletonType("cvd_host_package_singleton", cvdHostPackageSingletonFactory)
}

type cvdHostPackage struct {
	android.ModuleBase
	android.PackagingBase
	tarballFile android.InstallPath
	stampFile   android.InstallPath
}

func cvdHostPackageFactory() android.Module {
	module := &cvdHostPackage{}
	android.InitPackageModule(module)
	android.InitAndroidArchModule(module, android.HostSupported, android.MultilibFirst)
	module.IgnoreMissingDependencies = true
	return module
}

type cvdHostPackageSingleton struct {
	tarballPaths android.Paths
}

func cvdHostPackageSingletonFactory() android.Singleton {
	return &cvdHostPackageSingleton{}
}

type dependencyTag struct {
	blueprint.BaseDependencyTag
	android.InstallAlwaysNeededDependencyTag // to force installation of both "deps" and manually added dependencies
	android.PackagingItemAlwaysDepTag        // to force packaging of both "deps" and manually added dependencies
}

var cvdHostPackageDependencyTag = dependencyTag{}

func (c *cvdHostPackage) DepsMutator(ctx android.BottomUpMutatorContext) {
	c.AddDeps(ctx, cvdHostPackageDependencyTag)

	variations := []blueprint.Variation{
		{Mutator: "os", Variation: ctx.Target().Os.String()},
		{Mutator: "arch", Variation: android.Common.String()},
	}
	for _, dep := range strings.Split(
		ctx.Config().VendorConfig("cvd").String("grub_config"), " ") {
		if ctx.OtherModuleExists(dep) {
			ctx.AddVariationDependencies(variations, cvdHostPackageDependencyTag, dep)
		}
	}
	for _, dep := range strings.Split(
		ctx.Config().VendorConfig("cvd").String("launch_configs"), " ") {
		if ctx.OtherModuleExists(dep) {
			ctx.AddVariationDependencies(variations, cvdHostPackageDependencyTag, dep)
		}
	}

	for _, dep := range strings.Split(
		ctx.Config().VendorConfig("cvd").String("binary"), " ") {
		if ctx.OtherModuleExists(dep) {
			ctx.AddVariationDependencies(ctx.Target().Variations(), cvdHostPackageDependencyTag, dep)
		}
	}

	// If cvd_custom_action_config is set, include custom action servers in the
	// host package as specified by cvd_custom_action_servers.
	customActionConfig := ctx.Config().VendorConfig("cvd").String("custom_action_config")
	if customActionConfig != "" && ctx.OtherModuleExists(customActionConfig) {
		ctx.AddVariationDependencies(variations, cvdHostPackageDependencyTag,
			customActionConfig)
		for _, dep := range strings.Split(
			ctx.Config().VendorConfig("cvd").String("custom_action_servers"), " ") {
			if ctx.OtherModuleExists(dep) {
				ctx.AddVariationDependencies(nil, cvdHostPackageDependencyTag, dep)
			}
		}
	}

	// Include custom CSS file in host package if custom_style is set
	custom_style := ctx.Config().VendorConfig("cvd").String("custom_style")
	if custom_style == "" || !ctx.OtherModuleExists(custom_style) {
		custom_style = "webrtc_custom_blank.css"
	}
	ctx.AddVariationDependencies(variations, cvdHostPackageDependencyTag, custom_style)
}

var pctx = android.NewPackageContext("android/soong/cuttlefish")

func (c *cvdHostPackage) GenerateAndroidBuildActions(ctx android.ModuleContext) {
	packageDir := android.PathForModuleInstall(ctx, c.BaseModuleName())

	stamp := android.PathForModuleOut(ctx, "package.stamp")
	dirBuilder := android.NewRuleBuilder(pctx, ctx)
	dirBuilder.Command().Text("rm").Flag("-rf").Text(packageDir.String())
	dirBuilder.Command().Text("mkdir").Flag("-p").Text(packageDir.String())
	c.CopySpecsToDir(ctx, dirBuilder, c.GatherPackagingSpecs(ctx), packageDir)
	dirBuilder.Command().Text("touch").Output(stamp)
	dirBuilder.Build("cvd_host_package", fmt.Sprintf("Packaging %s", c.BaseModuleName()))
	ctx.InstallFile(android.PathForModuleInstall(ctx), c.BaseModuleName()+".stamp", stamp)
	c.stampFile = android.PathForModuleInPartitionInstall(ctx, c.BaseModuleName()+".stamp")

	tarball := android.PathForModuleOut(ctx, "package.tar.gz")
	tarballBuilder := android.NewRuleBuilder(pctx, ctx)
	tarballBuilder.Command().Text("tar Scfz").
		Output(tarball).
		Flag("-C").
		Text(packageDir.String()).
		Implicit(stamp).
		Flag("--mtime='2020-01-01'"). // to have reproducible builds
		Text(".")
	tarballBuilder.Build("cvd_host_tarball", fmt.Sprintf("Creating tarball for %s", c.BaseModuleName()))
	ctx.InstallFile(android.PathForModuleInstall(ctx), c.BaseModuleName()+".tar.gz", tarball)
	c.tarballFile = android.PathForModuleInstall(ctx, c.BaseModuleName()+".tar.gz")

	android.SetProvider(ctx, CvdHostPackageMetadataInfoProvider, CvdHostPackageMetadataInfo{
		TarballMetadata: c.tarballFile,
		StampMetadata:   c.stampFile,
	})
}

type CvdHostPackageMetadataInfo struct {
	TarballMetadata android.Path
	StampMetadata   android.Path
}
var CvdHostPackageMetadataInfoProvider = blueprint.NewProvider[CvdHostPackageMetadataInfo]()

// Create "hosttar" phony target with "cvd-host_package.tar.gz" path.
// Add stamp files into "droidcore" dependency.
func (p *cvdHostPackageSingleton) GenerateBuildActions(ctx android.SingletonContext) {
	var cvdHostPackageTarball android.Paths
	var cvdHostPackageStamp android.Paths

	ctx.VisitAllModuleProxies(func(module android.ModuleProxy) {
		if !android.OtherModulePointerProviderOrDefault(ctx, module, android.CommonModuleInfoProvider).Enabled {
			return
		}
		if c, ok := android.OtherModuleProvider(ctx, module, CvdHostPackageMetadataInfoProvider); ok {
			if !android.IsModulePreferredProxy(ctx, module) {
				return
			}
			cvdHostPackageTarball = append(cvdHostPackageTarball, c.TarballMetadata)
			cvdHostPackageStamp = append(cvdHostPackageStamp, c.StampMetadata)
		}
	})

	if cvdHostPackageTarball == nil {
		// nothing to do.
		return
	}

	board_platform := proptools.String(ctx.Config().ProductVariables().BoardPlatform)
	if (board_platform == "vsoc_arm") || (board_platform == "vsoc_arm64") || (board_platform == "vsoc_riscv64") || (board_platform == "vsoc_x86") || (board_platform == "vsoc_x86_64") {
		p.tarballPaths = cvdHostPackageTarball
		ctx.Phony("hosttar", cvdHostPackageTarball...)
		ctx.Phony("droidcore", cvdHostPackageStamp...)
	}

	if p.tarballPaths != nil {
		for _, path := range p.tarballPaths {
			// The riscv64 cuttlefish builds can be run on qemu on an x86_64 or arm64 host. Dist both sets of host packages.
			if len(p.tarballPaths) > 1 && strings.Contains(path.String(), "linux-x86") {
				ctx.DistForGoalWithFilename("dist_files", path, "cvd-host_package-x86_64.tar.gz")
			} else {
				ctx.DistForGoal("dist_files", path)
			}
		}
	}
}
