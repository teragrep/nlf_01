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
import com.teragrep.nlf_01.util.*;
import com.teragrep.rlo_14.Facility;
import com.teragrep.rlo_14.SDElement;
import com.teragrep.rlo_14.Severity;
import jakarta.json.JsonArray;
import jakarta.json.JsonException;
import jakarta.json.JsonObject;
import jakarta.json.JsonValue;

import java.time.Instant;
import java.util.*;

public final class AppInsightType implements EventType {

    private final ParsedEvent parsedEvent;

    public AppInsightType(final ParsedEvent parsedEvent) {
        this.parsedEvent = parsedEvent;
    }

    private void assertKey(final JsonObject obj, final String key, final JsonValue.ValueType type) {
        if (!obj.containsKey(key)) {
            throw new IllegalArgumentException("Key " + key + " does not exist");
        }

        if (!obj.get(key).getValueType().equals(type)) {
            throw new IllegalArgumentException("Key " + key + " is not of type " + type);
        }
    }

    @Override
    public List<Severity> severities() {
        return Collections.singletonList(Severity.INFORMATIONAL);
    }

    @Override
    public List<Facility> facilities() {
        return Collections.singletonList(Facility.LOCAL0);
    }

    @Override
    public List<String> hostnames() {
        final JsonArray recordsArray = parsedEvent.asJsonStructure().asJsonObject().getJsonArray("records");

        return recordsArray.getValuesAs((jsonValue) -> {
            if (!jsonValue.getValueType().equals(JsonValue.ValueType.OBJECT)) {
                throw new JsonException("Expected JsonObject as record but got: " + jsonValue.getValueType());
            }

            final JsonObject record = jsonValue.asJsonObject();
            assertKey(record, "_ResourceId", JsonValue.ValueType.STRING);
            final String resourceId = record.getString("_ResourceId");

            return new ValidRFC5424Hostname(
                    "md5-".concat(new MD5Hash(resourceId).md5().concat(new ASCIIString(new ResourceId(resourceId).resourceName()).withNonAsciiCharsRemoved()))
            ).validateOrThrow();
        });
    }

    @Override
    public List<String> appNames() {
        final JsonArray recordsArray = parsedEvent.asJsonStructure().asJsonObject().getJsonArray("records");

        return recordsArray.getValuesAs((jsonValue) -> {
            if (!jsonValue.getValueType().equals(JsonValue.ValueType.OBJECT)) {
                throw new JsonException("Expected JsonObject as record but got: " + jsonValue.getValueType());
            }

            final JsonObject record = jsonValue.asJsonObject();

            assertKey(record, "AppRoleName", JsonValue.ValueType.STRING);

            return new ValidRFC5424Appname(record.getString("AppRoleName")).validateOrThrow();
        });
    }

    @Override
    public List<String> timestamps() {
        final JsonArray recordsArray = parsedEvent.asJsonStructure().asJsonObject().getJsonArray("records");

        return recordsArray.getValuesAs((jsonValue) -> {
            if (!jsonValue.getValueType().equals(JsonValue.ValueType.OBJECT)) {
                throw new JsonException("Expected JsonObject as record but got: " + jsonValue.getValueType());
            }

            final JsonObject record = jsonValue.asJsonObject();
            assertKey(record, "TimeGenerated", JsonValue.ValueType.STRING);

            return record.getString("TimeGenerated");
        });
    }

    @Override
    public List<Set<SDElement>> sdElements() {
        Set<SDElement> elems = new HashSet<>();

        elems
                .add(new SDElement("event_id@48577").addSDParam("uuid", UUID.randomUUID().toString()).addSDParam("hostname", new RealHostname("localhost").hostname()).addSDParam("unixtime", Instant.now().toString()).addSDParam("id_source", "aer_02"));

        elems
                .add(new SDElement("aer_02_partition@48577").addSDParam("fully_qualified_namespace", String.valueOf(parsedEvent.partitionContext().getOrDefault("FullyQualifiedNamespace", ""))).addSDParam("eventhub_name", String.valueOf(parsedEvent.partitionContext().getOrDefault("EventHubName", ""))).addSDParam("partition_id", String.valueOf(parsedEvent.partitionContext().getOrDefault("PartitionId", ""))).addSDParam("consumer_group", String.valueOf(parsedEvent.partitionContext().getOrDefault("ConsumerGroup", ""))));

        final String partitionKey = String.valueOf(parsedEvent.systemProperties().getOrDefault("PartitionKey", ""));

        final SDElement sdEvent = new SDElement("aer_02_event@48577")
                .addSDParam("offset", parsedEvent.offset() == null ? "" : parsedEvent.offset())
                .addSDParam(
                        "enqueued_time", parsedEvent.enqueuedTime() == null ? "" : parsedEvent.enqueuedTime().toString()
                )
                .addSDParam("partition_key", partitionKey == null ? "" : partitionKey);
        parsedEvent.properties().forEach((key, value) -> sdEvent.addSDParam("property_" + key, value.toString()));
        elems.add(sdEvent);

        elems
                .add(new SDElement("aer_02@48577").addSDParam("timestamp_source", parsedEvent.enqueuedTime() == null ? "generated" : "timeEnqueued"));

        return Collections.singletonList(elems);
    }

    @Override
    public List<String> msgIds() {
        return Collections
                .singletonList(String.valueOf(parsedEvent.systemProperties().getOrDefault("SequenceNumber", "0")));
    }

    @Override
    public List<String> msgs() {
        final JsonArray recordsArray = parsedEvent.asJsonStructure().asJsonObject().getJsonArray("records");

        return recordsArray.getValuesAs((jsonValue) -> {
            if (!jsonValue.getValueType().equals(JsonValue.ValueType.OBJECT)) {
                throw new JsonException("Expected JsonObject as record but got: " + jsonValue.getValueType());
            }

            return jsonValue.asJsonObject().toString();
        });
    }
}
