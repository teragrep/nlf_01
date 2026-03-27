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

import com.teragrep.akv_01.event.ParsedEvent;
import com.teragrep.nlf_01.PropertiesJson;
import com.teragrep.rlo_14.SDElement;
import java.time.Instant;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

public final class DefaultSDElements implements SDElements {

    private final ParsedEvent parsedEvent;
    private final String realHostname;
    private final String className;
    private final String componentNameForPartitions;

    public DefaultSDElements(
            final ParsedEvent parsedEvent,
            final String realHostname,
            final Class<?> inputClass,
            final String componentNameForPartitions
    ) {
        this(parsedEvent, realHostname, inputClass.getSimpleName(), componentNameForPartitions);
    }

    public DefaultSDElements(
            final ParsedEvent parsedEvent,
            final String realHostname,
            final String className,
            final String componentNameForPartitions
    ) {
        this.parsedEvent = parsedEvent;
        this.realHostname = realHostname;
        this.className = className;
        this.componentNameForPartitions = componentNameForPartitions;
    }

    @Override
    public Set<SDElement> sdElements() {
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
                .add(new SDElement(componentNameForPartitions + "_partition@48577").addSDParam("fully_qualified_namespace", fullyQualifiedNamespace).addSDParam("eventhub_name", eventHubName).addSDParam("partition_id", partitionId).addSDParam("consumer_group", consumerGroup));

        elems
                .add(new SDElement("event_id@48577").addSDParam("uuid", UUID.randomUUID().toString()).addSDParam("hostname", realHostname).addSDParam("unixtime", Instant.now().toString()).addSDParam("id_source", componentNameForPartitions));

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
                .add(new SDElement(componentNameForPartitions + "_event@48577").addSDParam("offset", offset).addSDParam("enqueued_time", time).addSDParam("partition_key", partitionKey).addSDParam("properties", new PropertiesJson(parsedEvent.properties()).toJsonObject().toString()));

        elems
                .add(new SDElement(componentNameForPartitions + "@48577").addSDParam("timestamp_source", time.isEmpty() ? "generated" : "timeEnqueued"));

        elems.add(new SDElement("nlf_01@48577").addSDParam("eventType", className));

        return elems;
    }

    @Override
    public boolean equals(final Object o) {
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        final DefaultSDElements that = (DefaultSDElements) o;
        return Objects.equals(parsedEvent, that.parsedEvent) && Objects
                .equals(realHostname, that.realHostname) && Objects.equals(className, that.className)
                && Objects.equals(componentNameForPartitions, that.componentNameForPartitions);
    }

    @Override
    public int hashCode() {
        return Objects.hash(parsedEvent, realHostname, className, componentNameForPartitions);
    }
}
