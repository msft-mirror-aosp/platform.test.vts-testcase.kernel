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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;

import android.platform.test.annotations.RequiresDevice;
import com.android.compatibility.common.util.VsrTest;
import com.android.tradefed.device.ITestDevice;
import com.android.tradefed.testtype.DeviceJUnit4ClassRunner;
import com.android.tradefed.testtype.junit4.BaseHostJUnit4Test;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.Test;
import org.junit.runner.RunWith;

// Verify that the abilist of an armv9 core does not include any 32 bit abis.
@RunWith(DeviceJUnit4ClassRunner.class)
public class KernelAbilistTest extends BaseHostJUnit4Test {
    private static final String FIRST_API_LEVEL_PROP = "ro.product.first_api_level";
    private static final String ABI_PROP = "ro.product.cpu.abi";
    private static final String ABILIST_PROP = "ro.product.cpu.abilist";
    private static final String ABILIST32_PROP = "ro.product.cpu.abilist32";
    private static final String ABILIST64_PROP = "ro.product.cpu.abilist64";
    private static final int TIRAMISU_API_LEVEL = 33;

    @VsrTest(requirements = {"VSR-3.12-002"})
    @RequiresDevice
    @Test
    public void testAbilistOnArmv9() throws Exception {
        String abi = getDevice().getProperty(ABI_PROP);
        if (!abi.startsWith("arm")) {
            // Only Arm currently has 64-bit-only cores.
            return;
        }

        String first_api_level_str = getDevice().getProperty(FIRST_API_LEVEL_PROP);

        int first_api_level = Integer.parseInt(first_api_level_str);
        // Only run this test on devices that initially installed on U or later.
        if (first_api_level <= TIRAMISU_API_LEVEL) {
            // Installed before UDC, skip any checking.
            return;
        }

        // Check to see if this is an armv9 processor by looking for bti support.
        String cpuinfo_output = getDevice().executeShellCommand("cat /proc/cpuinfo");
        Pattern p = Pattern.compile("Features\\s*:(.*)");
        Matcher m = p.matcher(cpuinfo_output);
        assertTrue("Cannot find CPU features in /proc/cpuinfo output", m.find());
        // Look for bti in the output.
        p = Pattern.compile("\\bbti\\b");
        m = p.matcher(m.group(1));
        if (!m.find()) {
            // Not armv9, no checking necessary.
            return;
        }

        // Verify that this supports 64 bit ABI.
        String abilist64 = getDevice().getProperty(ABILIST64_PROP);
        if (abilist64 == null) {
            abilist64 = "";
        }
        assertTrue("Arvm9 must support at least one 64 bit ABI", !abilist64.isEmpty());

        // Verify no 32 bit ABIs supported.
        String abilist32 = getDevice().getProperty(ABILIST32_PROP);
        if (abilist32 == null) {
            abilist32 = "";
        }
        assertTrue("Armv9 devices must not support any 32 bit ABIs \"" + abilist32 + "\"",
                abilist32.isEmpty());

        // Verify the fully supported ABI list is the same as the 64 bit ABI list.
        String abilist = getDevice().getProperty(ABILIST_PROP);
        assertTrue("Armv9 devices must have the 64 bit ABIs the same as the ABIs: ABIs \"" + abilist
                        + "\" versus 64 bit ABIs \"" + abilist64 + "\"",
                abilist.equals(abilist64));
    }
}
