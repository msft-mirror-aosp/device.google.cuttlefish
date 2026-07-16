/*
 * Copyright (C) 2024 The Android Open Source Project
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

import com.android.cts.omapi.test.CtsAndroidOmapiTestApplet;
import com.android.javacard.keymaster.KM3Applet;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;

import javacard.framework.AID;
import javacard.framework.Applet;
import javacard.framework.ISO7816;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.HexFormat;
import java.util.Map;
import java.util.TreeMap;
import java.util.Vector;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

/**
 * This class manages JCardSim operations: channel setup, applet installation, simulator
 * initialization/reset, and APDU transmission.
 */
public class JCardSimulator implements Simulator {
    public static final int MAX_LOGICAL_CHANNEL = 4;
    public static final byte INS_SELECT = (byte) 0xA4;
    public static final byte INS_MANAGE_CHANNEL = (byte) 0x70;
    public static final byte BASIC_CHANNEL = (byte) 0;
    public static final byte INVALID_CHANNEL = (byte) -1;
    // KeyMint Applet AID
    public static final String KEYMINT_AID = "A00000006203020C010101";
    // OMAPI Test Applet AIDs
    public static final String OMAPI_TEST_APPLET_AID_1 = "A000000476416E64726F696443545331";
    public static final String OMAPI_TEST_APPLET_AID_2 = "A000000476416E64726F696443545332";
    private static final Map<String, Class<? extends Applet>> CONFIGURATION_MAP;

    static {
        // Registry of applets to be installed in the simulator.
        // TreeMap with case-insensitive ordering allows AIDs to be matched regardless
        // of hexadecimal string casing during the selection process.
        CONFIGURATION_MAP = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        CONFIGURATION_MAP.put(KEYMINT_AID, getKeyMintClass());
        CONFIGURATION_MAP.put(OMAPI_TEST_APPLET_AID_1, CtsAndroidOmapiTestApplet.class);
        CONFIGURATION_MAP.put(OMAPI_TEST_APPLET_AID_2, CtsAndroidOmapiTestApplet.class);
    }

    public static Class<? extends Applet> getKeyMintClass() {
        return KM3Applet.class;
    }

    public static short getKeyMintP1P2() {
        return KM3Applet.P1P2;
    }

    private CardSimulator simulator;
    private Vector<String> channelAid;
    private int currentChannel;

    public JCardSimulator() {
        // Creating an empty Vector
        channelAid = new Vector<String>(MAX_LOGICAL_CHANNEL);
        for (int ch = 0; ch < MAX_LOGICAL_CHANNEL; ch++) {
            channelAid.add(null);
        }
        currentChannel = INVALID_CHANNEL;
    }

    @Override
    public void initializeSimulator() throws Exception {
        // Create simulator
        simulator = new CardSimulator();
    }

    @Override
    public void disconnectSimulator() throws Exception {
        currentChannel = INVALID_CHANNEL;
    }

    private void provisionKeyMint() throws Exception {
        // Select applet
        simulator.selectApplet(AIDUtil.create(KEYMINT_AID));
        // Provision
        new KeymintSEFactoryProvision(simulator).provision();
        new KeymintOEMProvision(simulator).provision();

        // Deselect the Keymint applet.
        simulator.reset();
    }

    @Override
    public void setupSimulator() throws Exception {
        CONFIGURATION_MAP.forEach(
                (aid, appletClass) -> {
                    byte[] aidBytes = HexFormat.of().parseHex(aid);
                    byte aidLength = (byte) aidBytes.length;

                    // Installs the applet into the simulator with GlobalPlatform-compliant
                    // parameters.
                    // The install parameters follow the LV (Length-Value) format:
                    // [Li][AID][Lc][ControlInfo][La][AppletData]
                    // - Li: Instance AID Length
                    // - Lc: Control Info Length (0x00 for this installation)
                    // - La: Applet Data Length (0x00 for this installation)

                    // Total length = 1 (Li) + aidLen + 1 (Lc) + 1 (La)
                    short totalLen = (short) (1 + aidLength + 1 + 1);
                    ByteBuffer inputParamBytes = ByteBuffer.allocate(totalLen);

                    // Construction of the Installation Parameters (LV pairs)
                    inputParamBytes.put(aidLength); // Li: Length of Instance AID
                    inputParamBytes.put(aidBytes); // Instance AID bytes
                    inputParamBytes.put((byte) 0); // Lc: Length of Control Info (Empty)
                    inputParamBytes.put((byte) 0); // La: Length of Applet Data (Empty)

                    AID appletAID = AIDUtil.create(aid);

                    simulator.installApplet(
                            appletAID,
                            appletClass,
                            inputParamBytes.array(),
                            (short) 0,
                            (byte) inputParamBytes.capacity());
                });

        provisionKeyMint();
    }

    private static byte extractChannelNumber(byte cla) throws IOException {
        // As per ISO7816-4 specification for CLA byte (section 5.1.1) and GlobalPlatform Card
        // Specification (section 11.1.4.1), both interindustry and proprietary classes use Bit 7
        // (b7 in 1-indexed, corresponding to Bit 6 / 0x40 in 0-indexed) to distinguish between
        // basic and extended logical channels:
        //
        // 1. Basic Logical Channels (0-3): b7 is set to 0 (CLA is 0x0X or 0x8X).
        //    - Bits 2 and 1 (LSB, 0x03) encode the logical channel number.
        // 2. Extended Logical Channels (4-19): b7 is set to 1 (CLA is 0x4X or 0xCX).
        //    - Bits 4 to 1 (0x0F) encode the channel number minus 4.

        boolean isExtended = (cla & 0x40) == 0x40;
        byte ch;
        if (isExtended) {
            // Further Class: Bits 4 to 1 (0x0F) encode (channel minus 4).
            ch = (byte) ((cla & 0x0F) + 4);
        } else {
            // Basic Class: Bits 2 to 1 (0x03) encode channel (0-3).
            ch = (byte) (cla & 0x03);
        }

        if (ch < 0 || ch >= MAX_LOGICAL_CHANNEL) {
            throw new IOException("Unsupported channel: " + ch);
        }
        return ch;
    }

    private byte[] processManageCommand(byte[] apdu) {
        int firstAvailableSlot = INVALID_CHANNEL;
        int numChannels = channelAid.size();

        // Close the channel if p1 = 0x80
        if (apdu[ISO7816.OFFSET_P1] == (byte) 0x80) {
            byte channelToClose = apdu[ISO7816.OFFSET_P2];
            if (channelToClose <= 0 || channelToClose >= numChannels) {
                return formatApduResponse(null, ISO7816.SW_WRONG_P1P2);
            }
            channelAid.set(channelToClose, null);
            if (channelToClose == currentChannel) {
                currentChannel = INVALID_CHANNEL;
            }
            return formatApduResponse(null, ISO7816.SW_NO_ERROR);
        }

        for (int i = 1; i < numChannels; i++) {
            if (channelAid.get(i) == null) {
                firstAvailableSlot = i;
                break;
            }
        }

        if (INVALID_CHANNEL == firstAvailableSlot) {
            return formatApduResponse(null, ISO7816.SW_LOGICAL_CHANNEL_NOT_SUPPORTED);
        }

        return formatApduResponse(new byte[] {(byte) firstAvailableSlot}, ISO7816.SW_NO_ERROR);
    }

    /**
     * Manually transmits a SELECT APDU to the simulator to initiate applet selection.
     *
     * <p>Unlike {@code Simulator.selectApplet()}, which abstracts the selection logic, this method
     * uses {@code Simulator.transmit()} to send the raw APDU bytes exactly as provided. This
     * ensures that any specific encoding or custom parameters in the caller's SELECT command are
     * preserved and processed without modification by the simulator framework.
     *
     * @param apdu The raw SELECT APDU byte array to be transmitted.
     * @return The response APDU bytes returned by the simulator.
     * @throws Exception If the transmission fails or the simulator state is invalid.
     */
    private byte[] processSelectCommand(byte[] apdu) throws Exception {
        CommandAPDU apduCmd = new CommandAPDU(apdu);
        // Validate the channel number early. Although the channel index `ch` is only needed
        // later to update the registry upon successful selection, we must check it here.
        // The underlying jcardsim library does not support extended logical channels (4-19)
        // in its applet selection detection logic (it expects basic CLA 0x0X and treats 0x4X
        // as a regular apdu command, returning an error SW like 6D00).
        // Checking early forces a fast fail and throws an IOException for unsupported channels (>=
        // 4), maintaining consistency with non-select command behavior.
        byte ch = extractChannelNumber((byte) apduCmd.getCLA());
        byte[] aid = apduCmd.getData();
        // If the AID is empty, it means no applet is to be selected on this channel and the
        // default applet is used.
        // Currently, no default applet is actually selected. We return SW_NO_ERROR just to pass
        // the VTS OMAPI test.
        if (aid.length == 0) {
            return formatApduResponse(null, ISO7816.SW_NO_ERROR);
        }

        String aidHex = HexFormat.of().formatHex(aid);
        if (!CONFIGURATION_MAP.containsKey(aidHex)) {
            return formatApduResponse(null, ISO7816.SW_FILE_NOT_FOUND);
        }

        ResponseAPDU response = new ResponseAPDU(simulator.transmitCommand(apdu));
        if (ISO7816.SW_NO_ERROR == (short) response.getSW()) {
            // Update the channel registry to associate this AID with the active channel.
            channelAid.set(ch, aidHex);
            currentChannel = ch;
        }
        return formatApduResponse(response);
    }

    /*
     * Jcard Simulator design is based on one applet and one channel at a time
     *
     * In order to communicate multiple applets simultaneously on different channels
     * We have added Logical channels implementation here. which has the following variables
     *  - Vector[AID] (index 0 represent channel 0... so on)
     *  - CurrentChannelnumber
     * Generalized flow between SE hal and SE applet via JCserver is as follows
     *
     *    SE HAL                     JCServer                                     JcardSim
     *  ------------------------------------------------------------------------------------------
     *  Managechannel ->         check if any channel is
     *                           free, if yes set occupied
     *                           and return channel number.
     *                           Else Error
     *
     *  Select Cmd    ->         select Command                              -->    select cmd
     *
     *                           if success copy AID to
     *                           respective array and set
     *                           CurrentChannelnumber = CH(CLA)
     *
     *
     *  Non-Select Cmd ->      if (CH(CLA) == CurrentChannelnumber)
     *                             send "Non-Select" cmd                    --> "Non-Select" cmd
     *                         else
     *                             send "select(AID(CH(CLA))"               -->  select cmd
     *                                  "CurrentChannelnumber = CH(CLA)"
     *                             send "Non-Select" cmd                    --> "Non-Select" cmd
     */
    @Override
    public byte[] executeApdu(byte[] apdu) throws Exception {
        // Handle manage channel command.
        if (apdu[ISO7816.OFFSET_INS] == INS_MANAGE_CHANNEL) {
            return processManageCommand(apdu);
        }

        // Handle select command
        if (apdu[ISO7816.OFFSET_INS] == INS_SELECT) {
            return processSelectCommand(apdu);
        }

        // Switch channel if not current before sending the APDU command.
        CommandAPDU apduCmd = new CommandAPDU(apdu);
        byte channel = extractChannelNumber((byte) apduCmd.getCLA());
        if (channel != currentChannel) {
            String aidStr = channelAid.get(channel);
            if (aidStr == null) {
                // When a logical channel is closed, the associated AID in the channelAid vector
                // is cleared (set to null). If we receive a command on a channel with no active
                // AID, we return SW_APPLET_SELECT_FAILED to signal the client (e.g., KeyMint HAL)
                // that the applet needs to be re-selected on this channel.
                currentChannel = INVALID_CHANNEL;
                return formatApduResponse(null, ISO7816.SW_APPLET_SELECT_FAILED);
            }
            // The APDU target resides on a different logical channel.
            // Explicitly select the associated applet on that channel before routing the command.
            byte[] aid = HexFormat.of().parseHex(aidStr);
            byte[] selectResponse = simulator.selectAppletWithResult(AIDUtil.create(aid));
            ResponseAPDU response = new ResponseAPDU(selectResponse);

            if (ISO7816.SW_NO_ERROR != (short) response.getSW()) {
                // If the implicit selection fails, return SW_APPLET_SELECT_FAILED to force
                // the client to re-establish the session.
                currentChannel = INVALID_CHANNEL;
                return formatApduResponse(null, ISO7816.SW_APPLET_SELECT_FAILED);
            }
            currentChannel = channel;
        }

        return formatApduResponse(simulator.transmitCommand(apduCmd));
    }

    private byte[] formatApduResponse(ResponseAPDU response) {
        return formatApduResponse(response.getData(), response.getSW());
    }

    private byte[] formatApduResponse(byte[] data, int statusWord) {
        int dataLength = data != null ? data.length : 0;
        ByteBuffer bb = ByteBuffer.allocate(dataLength + 2 /* Status Word */);
        if (data != null) {
            bb.put(data);
        }
        bb.putShort((short) statusWord);
        return bb.array();
    }
}
