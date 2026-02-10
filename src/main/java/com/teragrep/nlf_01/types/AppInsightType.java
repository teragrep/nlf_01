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
package com.teragrep.nlf_01.types;

import com.teragrep.akv_01.event.ParsedEvent;
import com.teragrep.akv_01.plugin.PluginException;
import com.teragrep.nlf_01.util.*;
import com.teragrep.rlo_14.Facility;
import com.teragrep.rlo_14.SDElement;
import com.teragrep.rlo_14.Severity;
import jakarta.json.JsonObject;

import java.util.Set;

public final class AppInsightType implements EventType {

    private final ParsedEvent parsedEvent;
    private final String realHostname;

    public AppInsightType(final ParsedEvent parsedEvent, final String realHostname) {
        this.parsedEvent = parsedEvent;
        this.realHostname = realHostname;
    }

    @Override
    public Severity severity() {
        return Severity.NOTICE;
    }

    @Override
    public Facility facility() {
        return Facility.AUDIT;
    }

    @Override
    public String hostname() throws PluginException {
        final JsonObject record = parsedEvent.asJsonStructure().asJsonObject();

        final ValidKey<String> validKey = new ValidStringKey(record, "_ResourceId");

        return new ValidRFC5424Hostname(
                "md5-".concat(new MD5Hash(validKey.value()).md5().concat("-").concat(new ASCIIString(new ResourceId(validKey.value()).resourceName()).withNonAsciiCharsRemoved()))
        ).hostnameWithInvalidCharsRemoved();

    }

    @Override
    public String appName() throws PluginException {
        final JsonObject record = parsedEvent.asJsonStructure().asJsonObject();

        return new ValidRFC5424AppName(
                new ASCIIString(new ValidStringKey(record, "AppRoleName").value()).withNonAsciiCharsRemoved()
        ).appName();
    }

    @Override
    public long timestamp() throws PluginException {
        final JsonObject record = parsedEvent.asJsonStructure().asJsonObject();

        return new ValidRFC5424Timestamp(new ValidStringKey(record, "TimeGenerated").value()).validTimestamp();
    }

    @Override
    public Set<SDElement> sdElements() {
        final SDElements defaultSDElements = new DefaultSDElements(parsedEvent, realHostname, this.getClass());

        return defaultSDElements.sdElements();
    }

    @Override
    public String msgId() {
        String sequenceNumber = "";
        if (!parsedEvent.systemProperties().isStub()) {
            sequenceNumber = String.valueOf(parsedEvent.systemProperties().asMap().getOrDefault("SequenceNumber", ""));
        }
        return sequenceNumber;
    }

    @Override
    public String msg() {
        return parsedEvent.asString();
    }
}
