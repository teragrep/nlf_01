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

import com.teragrep.nlf_01.util.ValidRFC5424Hostname;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class ValidRFC5424HostnameTest {

    @Test
    void testValidName() {
        final ValidRFC5424Hostname hostname = new ValidRFC5424Hostname("valid.hostname.example");
        Assertions.assertDoesNotThrow(hostname::validHostname);
    }

    @Test
    void testStartsWithDigit() {
        final ValidRFC5424Hostname hostname = new ValidRFC5424Hostname("1.hostname.example");
        Assertions.assertThrows(IllegalArgumentException.class, hostname::validHostname);
    }

    @Test
    void testEndsWithDigit() {
        final ValidRFC5424Hostname hostname = new ValidRFC5424Hostname("valid.hostname.example3");
        Assertions.assertDoesNotThrow(hostname::validHostname);
    }

    @Test
    void testStartsWithDot() {
        final ValidRFC5424Hostname hostname = new ValidRFC5424Hostname(".hostname.example");
        Assertions.assertThrows(IllegalArgumentException.class, hostname::validHostname);
    }

    @Test
    void testEndsWithDot() {
        final ValidRFC5424Hostname hostname = new ValidRFC5424Hostname("hostname.example.");
        Assertions.assertThrows(IllegalArgumentException.class, hostname::validHostname);
    }

    @Test
    void testStartsWithDash() {
        final ValidRFC5424Hostname hostname = new ValidRFC5424Hostname("-hostname.example");
        Assertions.assertThrows(IllegalArgumentException.class, hostname::validHostname);
    }

    @Test
    void testEndsWithDash() {
        final ValidRFC5424Hostname hostname = new ValidRFC5424Hostname("hostname.example-");
        Assertions.assertThrows(IllegalArgumentException.class, hostname::validHostname);
    }

    @Test
    void testNonAsciiCharacters() {
        final ValidRFC5424Hostname hostname = new ValidRFC5424Hostname("höstnamë.exämple-");
        Assertions.assertThrows(IllegalArgumentException.class, hostname::validHostname);
    }

    @Test
    void testTooManyCharacters() {
        final ValidRFC5424Hostname hostname = new ValidRFC5424Hostname("a".repeat(256));
        Assertions.assertThrows(IllegalArgumentException.class, hostname::validHostname);
    }

    @Test
    void testMaxCharacters() {
        final ValidRFC5424Hostname hostname = new ValidRFC5424Hostname("a".repeat(255));
        Assertions.assertDoesNotThrow(hostname::validHostname);
    }

    @Test
    void testEmptyString() {
        final ValidRFC5424Hostname hostname = new ValidRFC5424Hostname("");
        Assertions.assertDoesNotThrow(hostname::validHostname);
    }
}
