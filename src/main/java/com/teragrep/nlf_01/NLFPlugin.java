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

import com.teragrep.akv_01.event.ParsedEvent;
import com.teragrep.akv_01.plugin.Plugin;
import com.teragrep.nlf_01.types.*;
import com.teragrep.nlf_01.util.EnvironmentSource;
import com.teragrep.nlf_01.util.Sourceable;
import com.teragrep.rlo_14.Facility;
import com.teragrep.rlo_14.SDElement;
import com.teragrep.rlo_14.Severity;
import com.teragrep.rlo_14.SyslogMessage;
import jakarta.json.JsonException;
import jakarta.json.JsonObject;
import jakarta.json.JsonStructure;
import jakarta.json.JsonValue;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

public final class NLFPlugin implements Plugin {

    private final Sourceable source;

    public NLFPlugin() {
        this(new EnvironmentSource());
    }

    public NLFPlugin(final Sourceable source) {
        this.source = source;
    }

    @Override
    public List<SyslogMessage> syslogMessage(final ParsedEvent parsedEvent) {
        EventType eventType = new StubType();

        if (!parsedEvent.isJsonStructure()) {
            // non-applicable
            throw new JsonException("Event was not a JSON structure");
        }

        final JsonStructure json = parsedEvent.asJsonStructure();
        // Check if main structure is JsonObject
        if (!json.getValueType().equals(JsonValue.ValueType.OBJECT)) {
            throw new JsonException("Event was not a JSON object");
        }

        final JsonObject jsonObject = json.asJsonObject();

        if (
            jsonObject.containsKey("records")
                    && jsonObject.get("records").getValueType().equals(JsonValue.ValueType.ARRAY)
        ) {
            eventType = new AppInsightType(parsedEvent);
        }
        else if (
            jsonObject.containsKey("Type") && jsonObject.get("Type").getValueType().equals(JsonValue.ValueType.STRING)
        ) {

            if (jsonObject.getString("Type").endsWith("_CL")) {
                eventType = new CLType(parsedEvent);
            }
            else if (jsonObject.getString("Type").equals("ContainerLogV2")) {
                eventType = new ContainerType(source, parsedEvent);
            }

        }

        final List<SyslogMessage> rv = new ArrayList<>();

        final List<Facility> facilities = eventType.facilities();
        final List<Severity> severities = eventType.severities();
        final List<String> timestamps = eventType.timestamps();
        final List<String> appNames = eventType.appNames();
        final List<String> hostnames = eventType.hostnames();
        final List<String> msgIds = eventType.msgIds();
        final List<String> msgs = eventType.msgs();
        final List<Set<SDElement>> sdElements = eventType.sdElements();

        for (int i = 0; i < msgs.size(); i++) {
            final SyslogMessage syslogMessage = new SyslogMessage()
                    .withFacility(facilities.get(i))
                    .withSeverity(severities.get(i))
                    .withTimestamp(timestamps.get(i))
                    .withAppName(appNames.get(i))
                    .withHostname(hostnames.get(i))
                    .withMsgId(msgIds.get(i))
                    .withMsg(msgs.get(i));
            syslogMessage.setSDElements(sdElements.get(i));
            rv.add(syslogMessage);
        }

        return rv;
    }
}
