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
import com.teragrep.akv_01.plugin.PluginException;
import com.teragrep.nlf_01.types.AppInsightType;
import com.teragrep.nlf_01.types.CLType;
import com.teragrep.nlf_01.types.ContainerType;
import com.teragrep.nlf_01.types.EventType;
import com.teragrep.nlf_01.util.EnvironmentSource;
import com.teragrep.nlf_01.util.Sourceable;
import com.teragrep.rlo_14.SyslogMessage;
import jakarta.json.JsonException;
import jakarta.json.JsonObject;
import jakarta.json.JsonStructure;
import jakarta.json.JsonValue;

import java.util.ArrayList;
import java.util.List;

public final class NLFPlugin implements Plugin {

    private final Sourceable source;

    public NLFPlugin() {
        this(new EnvironmentSource());
    }

    public NLFPlugin(final Sourceable source) {
        this.source = source;
    }

    @Override
    public List<SyslogMessage> syslogMessage(final ParsedEvent parsedEvent) throws PluginException {
        final List<EventType> eventTypes = new ArrayList<>();
        final List<SyslogMessage> syslogMessages = new ArrayList<>();
        final String containerLogAppNameKey = source.source("containerlog.appname.annotation");
        final String containerLogHostnameKey = source.source("containerlog.hostname.annotation");

        if (!parsedEvent.isJsonStructure()) {
            // non-applicable
            throw new PluginException(new JsonException("Event was not a JSON structure"));
        }

        final JsonStructure json = parsedEvent.asJsonStructure();
        // Check if main structure is JsonObject
        if (!json.getValueType().equals(JsonValue.ValueType.OBJECT)) {
            throw new PluginException(new JsonException("Event was not a JSON object"));
        }

        final JsonObject jsonObject = parsedEvent.asJsonStructure().asJsonObject();
        if (
            jsonObject.containsKey("Type") && jsonObject.get("Type").getValueType().equals(JsonValue.ValueType.STRING)
        ) {

            if (jsonObject.getString("Type").equals("AppTraces")) {
                eventTypes.add(new AppInsightType(parsedEvent));
            }
            else if (jsonObject.getString("Type").endsWith("_CL")) {
                eventTypes.add(new CLType(parsedEvent));
            }
            else if (jsonObject.getString("Type").equals("ContainerLogV2")) {
                eventTypes.add(new ContainerType(containerLogHostnameKey, containerLogAppNameKey, parsedEvent));
            }
            else {
                throw new PluginException(
                        new IllegalArgumentException("Invalid event type: " + jsonObject.getString("Type"))
                );
            }

        }
        else {
            throw new PluginException(
                    new IllegalArgumentException("Event was not of expected log format or type was not found")
            );
        }

        for (final EventType eventType : eventTypes) {
            final SyslogMessage syslogMessage = new SyslogMessage()
                    .withFacility(eventType.facility())
                    .withSeverity(eventType.severity())
                    .withTimestamp(eventType.timestamp())
                    .withAppName(eventType.appName())
                    .withHostname(eventType.hostname())
                    .withMsgId(eventType.msgId())
                    .withMsg(eventType.msg());
            syslogMessage.setSDElements(eventType.sdElements());
            syslogMessages.add(syslogMessage);
        }

        return syslogMessages;
    }
}
