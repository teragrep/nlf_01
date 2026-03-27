/*
 * Teragrep Neon log format plugin for AKV_01
 * Copyright (C) 2025 Suomen Kanuuna Oy
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 *
 * Additional permission under GNU Affero General Public License version 3
 * section 7
 *
 * If you modify this Program, or any covered work, by linking or combining it
 * with other code, such other code is not for that reason alone subject to any
 * of the requirements of the GNU Affero GPL version 3 as long as this Program
 * is the same Program as licensed from Suomen Kanuuna Oy without any additional
 * modifications.
 *
 * Supplemented terms under GNU Affero General Public License version 3
 * section 7
 *
 * Origin of the software must be attributed to Suomen Kanuuna Oy. Any modified
 * versions must be marked as "Modified version of" The Program.
 *
 * Names of the licensors and authors may not be used for publicity purposes.
 *
 * No rights are granted for use of trade names, trademarks, or service marks
 * which are in The Program if any.
 *
 * Licensee must indemnify licensors and authors for any liability that these
 * contractual assumptions impose on licensors and authors.
 *
 * To the extent this program is licensed as part of the Commercial versions of
 * Teragrep, the applicable Commercial License may apply to this file if you as
 * a licensee so wish it.
 */
package com.teragrep.nlf_01;

import com.teragrep.akv_01.plugin.PluginException;
import com.teragrep.nlf_01.util.ValidRFC5424Timestamp;
import java.time.Instant;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public final class ValidRFC5424TimestampTest {

    @Test
    void testWithIdealCase() {
        final String timestamp = "2020-01-01T00:00:00.123Z";
        final ValidRFC5424Timestamp validRFC5424Timestamp = new ValidRFC5424Timestamp(timestamp);
        Assertions
                .assertEquals(
                        timestamp,
                        Assertions.assertDoesNotThrow(() -> Instant.ofEpochMilli(validRFC5424Timestamp.validTimestamp()).toString())
                );
    }

    @Test
    void testWith6Fractions() {
        final String timestamp = "2020-01-01T00:00:00.123456Z";
        final ValidRFC5424Timestamp validRFC5424Timestamp = new ValidRFC5424Timestamp(timestamp);
        Assertions
                .assertEquals(
                        "2020-01-01T00:00:00.123Z",
                        Assertions.assertDoesNotThrow(() -> Instant.ofEpochMilli(validRFC5424Timestamp.validTimestamp()).toString())
                );
    }

    @Test
    void testWith9Fractions() {
        final String timestamp = "2020-01-01T00:00:00.123456789Z";
        final ValidRFC5424Timestamp validRFC5424Timestamp = new ValidRFC5424Timestamp(timestamp);
        Assertions
                .assertEquals(
                        "2020-01-01T00:00:00.123Z",
                        Assertions.assertDoesNotThrow(() -> Instant.ofEpochMilli(validRFC5424Timestamp.validTimestamp()).toString())
                );
    }

    @Test
    void testWithInvalidTimestamp() {
        final String timestamp = "invalid timestamp";
        final ValidRFC5424Timestamp validRFC5424Timestamp = new ValidRFC5424Timestamp(timestamp);
        Assertions.assertThrows(PluginException.class, validRFC5424Timestamp::validTimestamp);
    }

}
