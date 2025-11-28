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
import jakarta.json.JsonValue;

import java.nio.file.Paths;
import java.time.Instant;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

public final class CLType implements EventType {

    private final ParsedEvent parsedEvent;
    private final String realHostname;

    public CLType(final ParsedEvent parsedEvent, final String realHostname) {
        this.parsedEvent = parsedEvent;
        this.realHostname = realHostname;
    }

    private void assertKey(final JsonObject obj, final String key, JsonValue.ValueType type) throws PluginException {
        if (!obj.containsKey(key)) {
            throw new PluginException(new IllegalArgumentException("Key " + key + " does not exist"));
        }

        if (!obj.get(key).getValueType().equals(type)) {
            throw new PluginException(new IllegalArgumentException("Key " + key + " is not of type " + type));
        }
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
        final JsonObject mainObject = parsedEvent.asJsonStructure().asJsonObject();
        assertKey(mainObject, "_Internal_WorkspaceResourceId", JsonValue.ValueType.STRING);
        final String internalWorkspaceResourceId = mainObject.getString("_Internal_WorkspaceResourceId");

        // hostname = internal workspace resource id MD5 + resourceName from resourceId, with non-ascii chars removed
        return new ValidRFC5424Hostname(
                "md5-".concat(new MD5Hash(internalWorkspaceResourceId).md5().concat("-").concat(new ASCIIString(new ResourceId(internalWorkspaceResourceId).resourceName()).withNonAsciiCharsRemoved()))
        ).hostnameWithInvalidCharsRemoved();
    }

    @Override
    public String appName() throws PluginException {
        final JsonObject mainObject = parsedEvent.asJsonStructure().asJsonObject();
        assertKey(mainObject, "FilePath", JsonValue.ValueType.STRING);
        final String filePath = mainObject.getString("FilePath");

        final String truncatedMd5 = new MD5Hash(filePath).md5().substring(0, 8);

        final String filename = Paths.get(filePath).getFileName().toString();
        final String truncatedFilePath = filename.length() < 39 ? filename : filename.substring(0, 39);

        // appname = first 8 chars of filePath MD5 + dash (-) + filename truncated to max 39 chars
        return new ValidRFC5424AppName(truncatedMd5.concat("-").concat(truncatedFilePath)).appName();
    }

    @Override
    public long timestamp() throws PluginException {
        final JsonObject mainObject = parsedEvent.asJsonStructure().asJsonObject();
        assertKey(mainObject, "TimeGenerated", JsonValue.ValueType.STRING);

        return new ValidRFC5424Timestamp(mainObject.getString("TimeGenerated")).validTimestamp();
    }

    @Override
    public Set<SDElement> sdElements() throws PluginException {
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

        final JsonObject mainObject = parsedEvent.asJsonStructure().asJsonObject();

        assertKey(mainObject, "_ResourceId", JsonValue.ValueType.STRING);
        final String resourceId = mainObject.getString("_ResourceId");

        elems.add(new SDElement("origin@48577").addSDParam("_ResourceId", resourceId));
        elems.add(new SDElement("nlf_01@48577").addSDParam("eventType", this.getClass().getSimpleName()));

        return elems;
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
