/*
 * Copyright (C) 2023 The Android Open Source Project
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

package com.android.tests.abi;

import static org.junit.Assert.assertTrue;

import android.platform.test.annotations.RequiresDevice;
import com.android.compatibility.common.util.VsrTest;
import com.android.tradefed.device.ITestDevice;
import com.android.tradefed.testtype.DeviceJUnit4ClassRunner;
import com.android.tradefed.testtype.junit4.BaseHostJUnit4Test;
import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(DeviceJUnit4ClassRunner.class)
public class KernelAbilistTest extends BaseHostJUnit4Test {
    @VsrTest(requirements = {"VSR-3.12-002"})
    @RequiresDevice
    @Test
    public void testAbilist() throws Exception {
        String abi = getProp("ro.product.cpu.abi");
        if (!abi.startsWith("arm")) {
            // Only Arm currently has 64-bit-only cores.
            return;
        }

        // ro.vendor.api_level is the VSR requirement API level
        // calculated from ro.product.first_api_level, ro.board.api_level,
        // and ro.board.first_api_level.
        int api_level = Integer.parseInt(getProp("ro.vendor.api_level"));
        if (api_level < first64BitOnlyApiLevel()) {
            return;
        }

        // Verify at least one 64 bit ABI is supported.
        String abilist64 = getProp("ro.product.cpu.abilist");
        assertTrue("VSR-3.12: must support at least one 64 bit ABI", !abilist64.isEmpty());

        // Verify no 32 bit ABIs are supported.
        String abilist32 = getProp("ro.product.cpu.abilist32");
        assertTrue("VSR-3.12: must not support any 32 bit ABIs; found \"" + abilist32 + "\"",
                abilist32.isEmpty());

        // Verify the full supported ABI list is the same as the 64 bit ABI list.
        String abilist = getProp("ro.product.cpu.abilist64");
        assertTrue("VSR-3.12: supported ABIs must be the 64-bit ABIs; supported ABIs=\"" + abilist
                        + "\", 64 bit ABIs=\"" + abilist64 + "\"",
                abilist.equals(abilist64));
    }

    private int first64BitOnlyApiLevel() throws Exception {
        // Android Go and other low-ram devices haven't finished
        // the transition to 64-bit yet.
        if (hasDeviceFeature("android.hardware.ram.low")) {
            return 36;
        }

        // Android TV hasn't finished the transition to 64-bit yet.
        if (hasDeviceFeature("android.software.leanback") || hasDeviceFeature("android.hardware.type.television")) {
            return 36;
        }

        // Android Wear hasn't finished the transition to 64-bit yet.
        if (hasDeviceFeature("android.hardware.type.watch")) {
            return 36;
        }

        // For regular "mobile", the transition finished in API level 34.
        return 34;
    }

    private String getProp(String name) throws Exception {
        String result = getDevice().getProperty(name);
        return result != null ? result : "";
    }
}
