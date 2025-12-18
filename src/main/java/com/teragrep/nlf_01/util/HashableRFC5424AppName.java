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
package com.teragrep.nlf_01.util;

import com.teragrep.akv_01.plugin.PluginException;

public final class HashableRFC5424AppName implements RFC5424AppName {

    private final static int MAX_LENGTH = 48;
    private final String rfc5424AppName;

    public HashableRFC5424AppName(final String rfc5424AppName) {
        this.rfc5424AppName = rfc5424AppName;
    }

    /**
     * Returns a {@link #rfc5424AppName} without further modification if {@link #rfc5424AppName} if shorter than 48
     * characters long. Otherwise, creates an MD5 hash of that field and shortens that to less than 48 characters. <br>
     * Does not provide a fully safe RFC 5424 appName, so most likely should be wrapped with {@link ValidRFC5424AppName}
     *
     * @return
     *         <li>Hashed appName if length is longer than {@link #MAX_LENGTH}</li>
     *         <li>{@link #rfc5424AppName} if length is shorter than {@link #MAX_LENGTH}</li>
     */
    @Override
    public String appName() throws PluginException {
        final String returnedRFC5424AppName;

        if (this.rfc5424AppName.length() > MAX_LENGTH) {
            returnedRFC5424AppName = "md5-".concat(new MD5Hash(rfc5424AppName).md5()); // Will be 36 characters long
        }
        else {
            returnedRFC5424AppName = this.rfc5424AppName;
        }
        return returnedRFC5424AppName;
    }
}
