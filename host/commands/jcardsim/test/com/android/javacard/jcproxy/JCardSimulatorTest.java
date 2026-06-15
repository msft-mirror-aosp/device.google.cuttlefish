/*
 * Copyright (C) 2026 The Android Open Source Project
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

package com.android.javacard.jcproxy;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import javacard.framework.ISO7816;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.io.IOException;
import java.util.HexFormat;

@RunWith(JUnit4.class)
public class JCardSimulatorTest {

    private JCardSimulator mSimulator;

    @Before
    public void setUp() throws Exception {
        mSimulator = new JCardSimulator();
        mSimulator.initializeSimulator();
    }

    @After
    public void tearDown() throws Exception {
        if (mSimulator != null) {
            mSimulator.disconnectSimulator();
        }
    }

    /**
     * Verifies basic logical channel management.
     *
     * <p>Validation:
     *
     * <ul>
     *   <li>Sends a MANAGE CHANNEL open command.
     *   <li>Sends a MANAGE CHANNEL close command for the opened channel.
     * </ul>
     *
     * <p>Expectation:
     *
     * <ul>
     *   <li>Opening returns channel 1 with SW_NO_ERROR (9000).
     *   <li>Closing returns SW_NO_ERROR (9000).
     * </ul>
     */
    @Test
    public void testManageChannelOpenClose() throws Exception {
        // Manage Channel Open
        // CLA: 00, INS: 70, P1: 00, P2: 00, Le: 01
        byte[] openChannelApdu = new byte[] {0x00, 0x70, 0x00, 0x00, 0x01};
        byte[] response = mSimulator.executeApdu(openChannelApdu);

        // Expected response: [channel_number, 0x90, 0x00]
        // Since it's the first channel, it should be 1 (0 is basic)
        byte[] expectedOpenResponse = new byte[] {0x01, (byte) 0x90, 0x00};
        assertArrayEquals(expectedOpenResponse, response);

        // Manage Channel Close
        // CLA: 00, INS: 70, P1: 80, P2: 01 (channel to close)
        byte[] closeChannelApdu = new byte[] {0x00, 0x70, (byte) 0x80, 0x01};
        response = mSimulator.executeApdu(closeChannelApdu);
        assertEquals(ISO7816.SW_NO_ERROR, getStatusWord(response));
    }

    /**
     * Verifies that selecting a non-existent applet fails.
     *
     * <p>Validation: Sends a SELECT command for a random AID not in the configuration registry.
     *
     * <p>Expectation: Returns SW_FILE_NOT_FOUND (6A82).
     */
    @Test
    public void testSelectInvalidApplet() throws Exception {
        // Select APDU for a non-existent applet
        // CLA: 00, INS: A4, P1: 04, P2: 00, Lc: 05, Data: 0102030405
        byte[] selectApdu =
                new byte[] {0x00, (byte) 0xA4, 0x04, 0x00, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05};
        byte[] response = mSimulator.executeApdu(selectApdu);

        // Expected response: SW_FILE_NOT_FOUND (0x6A82)
        assertEquals(ISO7816.SW_FILE_NOT_FOUND, getStatusWord(response));
    }

    /**
     * Verifies successful applet selection after simulator setup.
     *
     * <p>Validation:
     *
     * <ul>
     *   <li>Sets up the simulator (installs and provisions applets).
     *   <li>Sends a SELECT command for the KeyMint applet.
     * </ul>
     *
     * <p>Expectation:
     *
     * <ul>
     *   <li>Setup completes without error.
     *   <li>Selection succeeds and returns SW_NO_ERROR (9000) at the end of the response.
     * </ul>
     */
    @Test
    public void testSelectWithSetup() throws Exception {
        mSimulator.setupSimulator();

        byte[] aidBytes = HexFormat.of().parseHex(JCardSimulator.KEYMINT_AID);
        byte[] selectApdu = new byte[5 + aidBytes.length];
        selectApdu[0] = 0x00;
        selectApdu[1] = (byte) 0xA4;
        selectApdu[2] = 0x04;
        selectApdu[3] = 0x00;
        selectApdu[4] = (byte) aidBytes.length;
        System.arraycopy(aidBytes, 0, selectApdu, 5, aidBytes.length);

        byte[] response = mSimulator.executeApdu(selectApdu);

        // Expected response: SW_NO_ERROR (0x9000) at the end.
        assertEquals(ISO7816.SW_NO_ERROR, getStatusWord(response));
    }

    /**
     * Verifies that selecting an applet on an unsupported channel number fails.
     *
     * <p>Validation:
     *
     * <ul>
     *   <li>Sets up the simulator.
     *   <li>Sends a SELECT command for KeyMint on {@code MAX_LOGICAL_CHANNEL} + 1.
     * </ul>
     *
     * <p>Expectation: Throws an IOException containing "Unsupported channel".
     */
    @Test
    public void testSelectOnUnsupportedChannel() throws Exception {
        // Setup simulator to ensure applet can be selected
        mSimulator.setupSimulator();

        // SELECT on channel MAX_LOGICAL_CHANNEL + 1 (which is unsupported)
        byte testChannel = (byte) (JCardSimulator.MAX_LOGICAL_CHANNEL + 1);
        byte[] aidBytes = HexFormat.of().parseHex(JCardSimulator.KEYMINT_AID);
        byte[] selectApdu = new byte[5 + aidBytes.length];
        // For extended range (4-19), the CLA byte is 0x40 + (channel minus 4)
        selectApdu[0] = (byte) (0x40 + (testChannel - 4));
        selectApdu[1] = (byte) 0xA4; // INS: SELECT
        selectApdu[2] = 0x04;
        selectApdu[3] = 0x00;
        selectApdu[4] = (byte) aidBytes.length;
        System.arraycopy(aidBytes, 0, selectApdu, 5, aidBytes.length);

        IOException exception =
                assertThrows(IOException.class, () -> mSimulator.executeApdu(selectApdu));
        assertTrue(exception.getMessage().contains("Unsupported channel"));
    }

    /**
     * Verifies that non-select commands on unsupported channels are rejected early.
     *
     * <p>Validation: Sends a dummy command on an unsupported channel (MAX_LOGICAL_CHANNEL + 1).
     *
     * <p>Expectation: Throws an IOException containing "Unsupported channel" before transmitting to
     * the simulator.
     */
    @Test
    public void testNonSelectOnUnsupportedChannel() throws Exception {
        // Some dummy APDU on channel MAX_LOGICAL_CHANNEL + 1 (which is unsupported)
        byte testChannel = (byte) (JCardSimulator.MAX_LOGICAL_CHANNEL + 1);
        // For extended range (4-19), the CLA byte is 0x40 + (channel minus 4)
        byte cla = (byte) (0x40 + (testChannel - 4));
        byte[] apdu = new byte[] {cla, 0x00, 0x00, 0x00};

        IOException exception = assertThrows(IOException.class, () -> mSimulator.executeApdu(apdu));
        assertTrue(exception.getMessage().contains("Unsupported channel"));
    }

    /**
     * Verifies that closing invalid logical channels is rejected.
     *
     * <p>Validation:
     *
     * <ul>
     *   <li>Attempts to close channel 0 (basic channel).
     *   <li>Attempts to close channel 4 (out of bounds).
     *   <li>Attempts to close channel 5 (out of bounds).
     * </ul>
     *
     * <p>Expectation: All attempts are rejected with SW_WRONG_P1P2 (6B00).
     */
    @Test
    public void testCloseInvalidChannel() throws Exception {
        // Try to close channel 0 (basic channel, not allowed to close via MANAGE CHANNEL)
        // CLA: 00, INS: 70, P1: 80 (Close), P2: 00 (Channel 0)
        byte[] closeChannel0Apdu = new byte[] {0x00, 0x70, (byte) 0x80, 0x00};
        byte[] response = mSimulator.executeApdu(closeChannel0Apdu);
        assertEquals(ISO7816.SW_WRONG_P1P2, getStatusWord(response));

        // Try to close channel 4 (greater than or equal to MAX_LOGICAL_CHANNEL)
        // CLA: 00, INS: 70, P1: 80 (Close), P2: 04 (Channel 4)
        byte[] closeChannel4Apdu = new byte[] {0x00, 0x70, (byte) 0x80, 0x04};
        response = mSimulator.executeApdu(closeChannel4Apdu);
        assertEquals(ISO7816.SW_WRONG_P1P2, getStatusWord(response));

        // Try to close channel 5
        // CLA: 00, INS: 70, P1: 80 (Close), P2: 05 (Channel 5)
        byte[] closeChannel5Apdu = new byte[] {0x00, 0x70, (byte) 0x80, 0x05};
        response = mSimulator.executeApdu(closeChannel5Apdu);
        assertEquals(ISO7816.SW_WRONG_P1P2, getStatusWord(response));
    }

    /**
     * Verifies that closing a valid but unopened logical channel is handled gracefully.
     *
     * <p>Validation: Attempts to close channel 1 (never opened).
     *
     * <p>Expectation: Succeeds and returns SW_NO_ERROR (9000).
     */
    @Test
    public void testCloseUnopenedValidChannel() throws Exception {
        // Try to close channel 1 which is not open (null in channelAid)
        // CLA: 00, INS: 70, P1: 80 (Close), P2: 01 (Channel 1)
        byte[] closeChannel1Apdu = new byte[] {0x00, 0x70, (byte) 0x80, 0x01};
        byte[] response = mSimulator.executeApdu(closeChannel1Apdu);
        // Expected response: SW_NO_ERROR (0x9000)
        assertEquals(ISO7816.SW_NO_ERROR, getStatusWord(response));
    }

    /**
     * Verifies correct implicit channel and applet switching.
     *
     * <p>Validation:
     *
     * <ul>
     *   <li>Selects KeyMint on channel 0.
     *   <li>Opens channel 1 and selects OMAPI applet on it.
     *   <li>Sends a dummy command on channel 0 (expects implicit switch to KeyMint).
     *   <li>Sends a dummy command on channel 1 (expects implicit switch to OMAPI).
     * </ul>
     *
     * <p>Expectation:
     *
     * <ul>
     *   <li>Dummy command on channel 0 is routed to KeyMint, which returns SW_NO_ERROR (9000) with
     *       CBOR error UNKNOWN_ERROR (1000) in data (due to incomplete provisioning).
     *   <li>Dummy command on channel 1 is routed to OMAPI, which returns standard
     *       SW_INS_NOT_SUPPORTED (6D00).
     * </ul>
     */
    @Test
    public void testChannelSwitching() throws Exception {
        mSimulator.setupSimulator();

        // 1. Select KeyMint on channel 0
        byte[] aidBytesKeyMint = HexFormat.of().parseHex(JCardSimulator.KEYMINT_AID);
        byte[] selectKeyMintApdu = new byte[5 + aidBytesKeyMint.length];
        selectKeyMintApdu[0] = 0x00; // CLA: Channel 0
        selectKeyMintApdu[1] = (byte) 0xA4;
        selectKeyMintApdu[2] = 0x04;
        selectKeyMintApdu[3] = 0x00;
        selectKeyMintApdu[4] = (byte) aidBytesKeyMint.length;
        System.arraycopy(aidBytesKeyMint, 0, selectKeyMintApdu, 5, aidBytesKeyMint.length);
        byte[] response = mSimulator.executeApdu(selectKeyMintApdu);
        assertEquals(ISO7816.SW_NO_ERROR, getStatusWord(response));

        // 2. Open channel 1
        byte[] openChannelApdu = new byte[] {0x00, 0x70, 0x00, 0x00, 0x01};
        response = mSimulator.executeApdu(openChannelApdu);
        assertArrayEquals(new byte[] {0x01, (byte) 0x90, 0x00}, response);

        // 3. Select OMAPI Test Applet 1 on channel 1
        byte[] aidBytesOmapi = HexFormat.of().parseHex(JCardSimulator.OMAPI_TEST_APPLET_AID_1);
        byte[] selectOmapiApdu = new byte[5 + aidBytesOmapi.length];
        selectOmapiApdu[0] = 0x01; // CLA: Channel 1
        selectOmapiApdu[1] = (byte) 0xA4;
        selectOmapiApdu[2] = 0x04;
        selectOmapiApdu[3] = 0x00;
        selectOmapiApdu[4] = (byte) aidBytesOmapi.length;
        System.arraycopy(aidBytesOmapi, 0, selectOmapiApdu, 5, aidBytesOmapi.length);
        response = mSimulator.executeApdu(selectOmapiApdu);
        assertEquals(ISO7816.SW_NO_ERROR, getStatusWord(response));

        // Now currentChannel should be 1.

        // 4. Send dummy command on channel 0 (KeyMint) with valid P1P2 (from simulator)
        short p1p2 = JCardSimulator.getKeyMintP1P2();
        byte p1 = (byte) ((p1p2 >> 8) & 0xFF);
        byte p2 = (byte) (p1p2 & 0xFF);
        byte[] dummyCmdChan0 = new byte[] {0x00, (byte) 0xFF, p1, p2};
        response = mSimulator.executeApdu(dummyCmdChan0);
        // KeyMint returns 9000 with CBOR error code [1000] (UNKNOWN_ERROR) in data
        // because provisioning is not complete (pre-shared secret and attest IDs are missing).
        // Expected response bytes: [0x81, 0x19, 0x03, 0xE8, 0x90, 0x00], which is UNKNOWN_ERROR.
        byte[] expectedKeyMintResponse =
                new byte[] {(byte) 0x81, (byte) 0x19, (byte) 0x03, (byte) 0xE8, (byte) 0x90, 0x00};
        assertArrayEquals(expectedKeyMintResponse, response);

        // Now currentChannel should be 0.

        // 5. Send correct command on channel 1 (OMAPI) and expect 9000
        // INS 0x06 (NO_DATA_INS_1) returns SW_NO_ERROR (9000)
        byte[] cmdChan1 = new byte[] {0x01, 0x06, 0x00, 0x00};
        response = mSimulator.executeApdu(cmdChan1);
        assertEquals(ISO7816.SW_NO_ERROR, getStatusWord(response));
    }

    /**
     * Verifies that the simulator is configured with the expected maximum logical channels.
     *
     * <p>We assert it is exactly 4 because the underlying jcardsim library only supports basic
     * logical channels (0-3) for applet selection.
     */
    @Test
    public void testMaxLogicalChannelLimit() {
        assertEquals(4, JCardSimulator.MAX_LOGICAL_CHANNEL);
    }

    private short getStatusWord(byte[] response) {
        int len = response.length;
        assertTrue("Response too short to contain status word: " + len, len >= 2);
        return (short) (((response[len - 2] & 0xFF) << 8) | (response[len - 1] & 0xFF));
    }
}
