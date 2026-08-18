/*
 * Copyright (C) 2025 The Android Open Source Project
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

package com.android.cuttlefish.tests;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.android.tradefed.log.LogUtil.CLog;
import com.android.tradefed.testtype.DeviceJUnit4ClassRunner;
import com.android.tradefed.testtype.junit4.BaseHostJUnit4Test;
import com.android.tradefed.util.CommandResult;
import com.android.tradefed.util.CommandStatus;
import com.android.tradefed.util.StreamUtil;

import java.awt.image.BufferedImage;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.util.Collections;
import java.util.List;
import javax.imageio.ImageIO;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

/**
 * Tests for VKMS writeback functionality in Cuttlefish.
 *
 * This test uses CfVkmsTester to set up a virtual display with writeback enabled
 * and reads it back using the `screencap` command to process it.
 */
@RunWith(DeviceJUnit4ClassRunner.class)
public class CfWritebackTest extends BaseHostJUnit4Test {
    private CfVkmsTester mVkmsTester;

    @Before
    public void setUp() throws Exception {
        List<CfVkmsTester.VkmsConnectorSetup> connectorConfigs =
                Collections.singletonList(
                        CfVkmsTester.VkmsConnectorSetup.builder()
                                .setMonitor(CfVkmsTester.Monitor.REDRIX)
                                .setEnabledAtStart(true)
                                .build());

        mVkmsTester = CfVkmsTester.createWithConfig(getDevice(), connectorConfigs);
        assertNotNull("Failed to initialize VKMS tester", mVkmsTester);

        mVkmsTester.waitForDisplaysToBeOn(1, CfVkmsTester.DISPLAY_BRINGUP_TIMEOUT_MS);
        // After the display is on, wait for the login screen to find a colored image to read back.
        Thread.sleep(10000);
    }

    @After
    public void tearDown() throws Exception {
        if (mVkmsTester != null) {
            mVkmsTester.close();
            mVkmsTester = null;
        }
    }

    @Test
    public void testUiIsntBlackReadback() throws Exception {
        final String imagePath = "/data/local/tmp/cf_writeback/writeback_test.png";
        File localFile = null;
        try {
            getDevice().executeShellV2Command("mkdir -p /data/local/tmp/cf_writeback");

            // Capture the screen content. Because we have configured the device with VKMS and
            // enabled writeback, this will exercise the desired HWC readback path.
            CommandResult screencapResult =
                    getDevice().executeShellV2Command("screencap -p " + imagePath);
            assertTrue(
                    "Failed to take screencap. Stderr: " + screencapResult.getStderr(),
                    screencapResult.getStatus() == CommandStatus.SUCCESS);

            localFile = getDevice().pullFile(imagePath);
            assertNotNull("Failed to pull screenshot file from device", localFile);

            try (InputStream is = new FileInputStream(localFile)) {
                BufferedImage image = ImageIO.read(is);
                assertNotNull("Failed to read screenshot image from file", image);

                verifyImageIsNotBlack(image, 10 /* tolerance */);
            }
        } catch (Exception e) {
            CLog.e("Exception during test execution: %s", e.getMessage());
            throw e;
        }
    }

    /**
     * Verifies that the maximum color component of a BufferedImage is not black.
     *
     * @param image The image to check.
     * @param tolerance The acceptable value for an RGB component to be considered not black.
     */
    private void verifyImageIsNotBlack(BufferedImage image, int tolerance) {
        int width = image.getWidth();
        int height = image.getHeight();
        int maxRed = 0;
        int maxGreen = 0;
        int maxBlue = 0;

        for (int y = 0; y < height; y++) {
            for (int x = 0; x < width; x++) {
                int rgb = image.getRGB(x, y);
                int red = (rgb >> 16) & 0xFF;
                int green = (rgb >> 8) & 0xFF;
                int blue = rgb & 0xFF;

                if (red > tolerance || green > tolerance || blue > tolerance) {
                    // Short-circuit immediately once any component is sufficiently bright
                    return;
                }

                maxRed = Math.max(maxRed, red);
                maxGreen = Math.max(maxGreen, green);
                maxBlue = Math.max(maxBlue, blue);
            }
        }

        // If we didn't short-circuit, we scanned everything and it's practically black.
        fail(String.format("Image is largely black. Max color: R=%d, G=%d, B=%d. Tolerance: %d",
                                 maxRed, maxGreen, maxBlue, tolerance));
    }
}