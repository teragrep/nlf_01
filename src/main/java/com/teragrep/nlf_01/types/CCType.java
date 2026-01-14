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
import com.teragrep.nlf_01.util.ASCIIString;
import com.teragrep.nlf_01.util.MD5Hash;
import com.teragrep.nlf_01.util.ResourceId;
import com.teragrep.nlf_01.util.ValidRFC5424AppName;
import com.teragrep.nlf_01.util.ValidRFC5424Hostname;
import com.teragrep.nlf_01.util.ValidRFC5424Timestamp;
import com.teragrep.rlo_14.Facility;
import com.teragrep.rlo_14.SDElement;
import com.teragrep.rlo_14.Severity;
import jakarta.json.JsonObject;
import jakarta.json.JsonValue;
import java.time.Instant;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class CCType implements EventType {

    private final ParsedEvent parsedEvent;
    private final String realHostname;
    private final Pattern appNamePattern;

    /**
     * Parses the appName from data.resourceName's value between the second '=' symbol and the next '/' symbol
     */
    public CCType(final ParsedEvent parsedEvent, final String realHostname) {
        this(parsedEvent, realHostname, Pattern.compile("=.*?=(?<value>.*?)(?=/)"));
    }

    private CCType(final ParsedEvent parsedEvent, final String realHostname, final Pattern appNamePattern) {
        this.parsedEvent = parsedEvent;
        this.realHostname = realHostname;
        this.appNamePattern = appNamePattern;
    }

    private void assertKey(final JsonObject obj, final String key, final JsonValue.ValueType type)
            throws PluginException {
        if (!obj.containsKey(key)) {
            throw new PluginException(new IllegalArgumentException("Key " + key + " does not exist"));
        }

        if (!obj.get(key).getValueType().equals(type)) {
            throw new PluginException(new IllegalArgumentException("Key " + key + " is not of type " + type));
        }
    }

    @Override
    public Severity severity() throws PluginException {
        return Severity.NOTICE;
    }

    @Override
    public Facility facility() throws PluginException {
        return Facility.AUDIT;
    }

    @Override
    public String hostname() throws PluginException {
        final JsonObject record = parsedEvent.asJsonStructure().asJsonObject();

        assertKey(record, "_Internal_WorkspaceResourceId", JsonValue.ValueType.STRING);
        final String resourceId = record.getString("_Internal_WorkspaceResourceId");

        return new ValidRFC5424Hostname(
                "md5-".concat(new MD5Hash(resourceId).md5().concat("-").concat(new ASCIIString(new ResourceId(resourceId).resourceName()).withNonAsciiCharsRemoved()))
        ).hostnameWithInvalidCharsRemoved();
    }

    @Override
    public String appName() throws PluginException {
        final JsonObject record = parsedEvent.asJsonStructure().asJsonObject();

        assertKey(record, "data", JsonValue.ValueType.OBJECT);
        final JsonObject data = record.getJsonObject("data");
        assertKey(data, "resourceName", JsonValue.ValueType.STRING);
        final String resourceName = data.getString("resourceName");

        final Matcher matcher = appNamePattern.matcher(resourceName);
        if (!matcher.find()) {
            throw new PluginException("Could not parse environment from data.resourceName");
        }
        final String value = matcher.group("value");
        if (value == null || value.isEmpty()) {
            throw new PluginException("Capture group 'value' was not found");
        }

        return new ValidRFC5424AppName(new ASCIIString(value).withNonAsciiCharsRemoved()).appName();
    }

    @Override
    public long timestamp() throws PluginException {
        final JsonObject record = parsedEvent.asJsonStructure().asJsonObject();
        assertKey(record, "TimeGenerated", JsonValue.ValueType.STRING);
        final String time = record.getString("TimeGenerated");

        return new ValidRFC5424Timestamp(time).validTimestamp();
    }

    @Override
    public Set<SDElement> sdElements() throws PluginException {
        final Set<SDElement> elems = new HashSet<>();
        final String time;
        if (!parsedEvent.enqueuedTimeUtc().isStub()) {
            time = parsedEvent.enqueuedTimeUtc().zonedDateTime().toString();
        }
        else {
            time = "";
        }

        final String fullyQualifiedNamespace;
        final String eventHubName;
        final String partitionId;
        final String consumerGroup;
        if (!parsedEvent.partitionCtx().isStub()) {
            fullyQualifiedNamespace = String
                    .valueOf(parsedEvent.partitionCtx().asMap().getOrDefault("FullyQualifiedNamespace", ""));
            eventHubName = String.valueOf(parsedEvent.partitionCtx().asMap().getOrDefault("EventHubName", ""));
            partitionId = String.valueOf(parsedEvent.partitionCtx().asMap().getOrDefault("PartitionId", ""));
            consumerGroup = String.valueOf(parsedEvent.partitionCtx().asMap().getOrDefault("ConsumerGroup", ""));
        }
        else {
            fullyQualifiedNamespace = "";
            eventHubName = "";
            partitionId = "";
            consumerGroup = "";
        }

        elems
                .add(new SDElement("aer_02_partition@48577").addSDParam("fully_qualified_namespace", fullyQualifiedNamespace).addSDParam("eventhub_name", eventHubName).addSDParam("partition_id", partitionId).addSDParam("consumer_group", consumerGroup));

        elems
                .add(new SDElement("event_id@48577").addSDParam("uuid", UUID.randomUUID().toString()).addSDParam("hostname", realHostname).addSDParam("unixtime", Instant.now().toString()).addSDParam("id_source", "aer_02"));

        final String partitionKey;
        if (!parsedEvent.systemProperties().isStub()) {
            partitionKey = String.valueOf(parsedEvent.systemProperties().asMap().getOrDefault("PartitionKey", ""));
        }
        else {
            partitionKey = "";
        }

        final String offset;
        if (!parsedEvent.offset().isStub()) {
            offset = parsedEvent.offset().value();
        }
        else {
            offset = "";
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
        final String sequenceNumber;
        if (!parsedEvent.systemProperties().isStub()) {
            sequenceNumber = String.valueOf(parsedEvent.systemProperties().asMap().getOrDefault("SequenceNumber", ""));
        }
        else {
            sequenceNumber = "";
        }
        return sequenceNumber;
    }

    @Override
    public String msg() throws PluginException {
        return parsedEvent.asString();
    }
}
