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
import com.teragrep.nlf_01.PropertiesJson;
import com.teragrep.nlf_01.util.*;
import com.teragrep.rlo_14.Facility;
import com.teragrep.rlo_14.SDElement;
import com.teragrep.rlo_14.Severity;
import jakarta.json.JsonObject;

import java.time.Instant;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class SyslogType implements EventType {

    private final ParsedEvent parsedEvent;
    private final String expectedProcessName;
    private final String realHostname;
    private final Pattern appNamePattern;

    public SyslogType(final ParsedEvent parsedEvent, final String expectedProcessName, final String realHostname) {
        this(
                parsedEvent,
                expectedProcessName,
                realHostname,
                Pattern.compile("^.*?(?<uuid>[a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12})")
        );
    }

    public SyslogType(
            final ParsedEvent parsedEvent,
            final String expectedProcessName,
            final String realHostname,
            final Pattern appNamePattern
    ) {
        this.parsedEvent = parsedEvent;
        this.expectedProcessName = expectedProcessName;
        this.realHostname = realHostname;
        this.appNamePattern = appNamePattern;
    }

    private void validateProcessName() throws PluginException {
        final JsonObject mainObject = parsedEvent.asJsonStructure().asJsonObject();
        final ValidStringKey validKey = new ValidStringKey(mainObject, "ProcessName");

        final String processName = validKey.value();
        if (!processName.equals(expectedProcessName)) {
            throw new PluginException("Expected <[" + expectedProcessName + "]> but found <[" + processName + "]>");
        }
    }

    @Override
    public Severity severity() throws PluginException {
        validateProcessName();
        return Severity.NOTICE;
    }

    @Override
    public Facility facility() throws PluginException {
        validateProcessName();
        return Facility.AUDIT;
    }

    @Override
    public String hostname() throws PluginException {
        validateProcessName();
        final JsonObject mainObject = parsedEvent.asJsonStructure().asJsonObject();

        final ValidStringKey validKey = new ValidStringKey(mainObject, "_Internal_WorkspaceResourceId");

        final String internalWorkspaceResourceId = validKey.value();

        // hostname = internal workspace resource id MD5 + resourceName from resourceId, with non-ascii chars removed
        return new ValidRFC5424Hostname(
                "md5-".concat(new MD5Hash(internalWorkspaceResourceId).md5().concat("-").concat(new ASCIIString(new ResourceId(internalWorkspaceResourceId).resourceName()).withNonAsciiCharsRemoved()))
        ).hostnameWithInvalidCharsRemoved();
    }

    @Override
    public String appName() throws PluginException {
        validateProcessName();
        final JsonObject mainObject = parsedEvent.asJsonStructure().asJsonObject();

        final ValidStringKey validKey = new ValidStringKey(mainObject, "SyslogMessage");

        final String syslogMessage = validKey.value();

        final Matcher matcher = appNamePattern.matcher(syslogMessage);
        if (matcher.find()) {
            final String uuid = matcher.group("uuid");
            if (uuid == null) {
                throw new PluginException("Capture group 'uuid' was not found");
            }
            return new ValidRFC5424AppName(uuid).appName();
        }

        throw new PluginException("Could not parse appName from SyslogMessage key");

    }

    @Override
    public long timestamp() throws PluginException {
        validateProcessName();
        final JsonObject mainObject = parsedEvent.asJsonStructure().asJsonObject();
        final ValidStringKey validKey = new ValidStringKey(mainObject, "TimeGenerated");

        return new ValidRFC5424Timestamp(validKey.value()).validTimestamp();
    }

    @Override
    public Set<SDElement> sdElements() throws PluginException {
        validateProcessName();
        Set<SDElement> elems = new HashSet<>();
        String time = "";
        if (!parsedEvent.enqueuedTimeUtc().isStub()) {
            time = parsedEvent.enqueuedTimeUtc().zonedDateTime().toString();
        }

        String fullyQualifiedNamespace = "";
        String eventHubName = "";
        String partitionId = "";
        String consumerGroup = "";
        if (!parsedEvent.partitionCtx().isStub()) {
            fullyQualifiedNamespace = String
                    .valueOf(parsedEvent.partitionCtx().asMap().getOrDefault("FullyQualifiedNamespace", ""));
            eventHubName = String.valueOf(parsedEvent.partitionCtx().asMap().getOrDefault("EventHubName", ""));
            partitionId = String.valueOf(parsedEvent.partitionCtx().asMap().getOrDefault("PartitionId", ""));
            consumerGroup = String.valueOf(parsedEvent.partitionCtx().asMap().getOrDefault("ConsumerGroup", ""));
        }

        elems
                .add(new SDElement("aer_02_partition@48577").addSDParam("fully_qualified_namespace", fullyQualifiedNamespace).addSDParam("eventhub_name", eventHubName).addSDParam("partition_id", partitionId).addSDParam("consumer_group", consumerGroup));

        elems
                .add(new SDElement("event_id@48577").addSDParam("uuid", UUID.randomUUID().toString()).addSDParam("hostname", realHostname).addSDParam("unixtime", Instant.now().toString()).addSDParam("id_source", "aer_02"));

        String partitionKey = "";
        if (!parsedEvent.systemProperties().isStub()) {
            partitionKey = String.valueOf(parsedEvent.systemProperties().asMap().getOrDefault("PartitionKey", ""));
        }

        String offset = "";
        if (!parsedEvent.offset().isStub()) {
            offset = parsedEvent.offset().value();
        }

        elems
                .add(new SDElement("aer_02_event@48577").addSDParam("offset", offset).addSDParam("enqueued_time", time).addSDParam("partition_key", partitionKey).addSDParam("properties", new PropertiesJson(parsedEvent.properties()).toJsonObject().toString()));

        elems
                .add(new SDElement("aer_02@48577").addSDParam("timestamp_source", time.isEmpty() ? "generated" : "timeEnqueued"));

        elems.add(new SDElement("nlf_01@48577").addSDParam("eventType", this.getClass().getSimpleName()));

        return elems;
    }

    @Override
    public String msgId() throws PluginException {
        validateProcessName();
        String sequenceNumber = "";
        if (!parsedEvent.systemProperties().isStub()) {
            sequenceNumber = String.valueOf(parsedEvent.systemProperties().asMap().getOrDefault("SequenceNumber", ""));
        }
        return sequenceNumber;
    }

    @Override
    public String msg() throws PluginException {
        validateProcessName();
        return parsedEvent.asString();
    }
}
