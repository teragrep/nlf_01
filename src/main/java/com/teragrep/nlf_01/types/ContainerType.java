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
import jakarta.json.JsonException;
import jakarta.json.JsonObject;
import jakarta.json.JsonValue;

import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

public final class ContainerType implements EventType {

    private final Sourceable source;
    private final ParsedEvent parsedEvent;

    public ContainerType(final Sourceable source, final ParsedEvent parsedEvent) {
        this.source = source;
        this.parsedEvent = parsedEvent;
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

        assertKey(mainObject, "KubernetesMetadata", JsonValue.ValueType.OBJECT);
        final JsonObject kubernetesMetadata = mainObject.getJsonObject("KubernetesMetadata");
        assertKey(kubernetesMetadata, "podAnnotations", JsonValue.ValueType.OBJECT);
        final JsonObject podAnnotations = kubernetesMetadata.getJsonObject("podAnnotations");

        return new ValidRFC5424Hostname(podAnnotations.getString(source.source("containerlog.hostname.annotation")))
                .validHostname();
    }

    @Override
    public String appName() throws PluginException {
        final JsonObject mainObject = parsedEvent.asJsonStructure().asJsonObject();

        assertKey(mainObject, "KubernetesMetadata", JsonValue.ValueType.OBJECT);
        final JsonObject kubernetesMetadata = mainObject.getJsonObject("KubernetesMetadata");
        assertKey(kubernetesMetadata, "podAnnotations", JsonValue.ValueType.OBJECT);
        final JsonObject podAnnotations = kubernetesMetadata.getJsonObject("podAnnotations");

        assertKey(mainObject, "LogSource", JsonValue.ValueType.STRING);
        final String logSource = mainObject.getString("LogSource");
        final String logSourceSuffix;

        if ("stdout".equals(logSource)) {
            logSourceSuffix = ":o";
        }
        else if ("stderr".equals(logSource)) {
            logSourceSuffix = ":e";
        }
        else {
            throw new PluginException(new JsonException("Unknown log source: " + logSource));
        }

        return new ValidRFC5424AppName(
                podAnnotations.getString(source.source("containerlog.appname.annotation")) + logSourceSuffix
        ).validAppName();
    }

    @Override
    public long timestamp() throws PluginException {
        final JsonObject mainObject = parsedEvent.asJsonStructure().asJsonObject();
        assertKey(mainObject, "TimeGenerated", JsonValue.ValueType.STRING);

        return new ValidRFC5424Timestamp(mainObject.getString("TimeGenerated")).validTimestamp();
    }

    @Override
    public Set<SDElement> sdElements() throws PluginException {
        final Set<SDElement> elems = new HashSet<>();
        String time;
        try {
            time = parsedEvent.enqueuedTime().zonedDateTime().toString();
        }
        catch (DateTimeParseException ignored) {
            time = "";
        }
        elems
                .add(new SDElement("event_id@48577").addSDParam("uuid", UUID.randomUUID().toString()).addSDParam("hostname", new RealHostname("localhost").hostname()).addSDParam("unixtime", Instant.now().toString()).addSDParam("id_source", "aer_02"));

        elems
                .add(new SDElement("aer_02_partition@48577").addSDParam("fully_qualified_namespace", String.valueOf(parsedEvent.partitionContext().getOrDefault("FullyQualifiedNamespace", ""))).addSDParam("eventhub_name", String.valueOf(parsedEvent.partitionContext().getOrDefault("EventHubName", ""))).addSDParam("partition_id", String.valueOf(parsedEvent.partitionContext().getOrDefault("PartitionId", ""))).addSDParam("consumer_group", String.valueOf(parsedEvent.partitionContext().getOrDefault("ConsumerGroup", ""))));

        final String partitionKey = String.valueOf(parsedEvent.systemProperties().getOrDefault("PartitionKey", ""));

        elems
                .add(new SDElement("aer_02_event@48577").addSDParam("offset", parsedEvent.offset() == null ? "" : parsedEvent.offset()).addSDParam("enqueued_time", time).addSDParam("partition_key", partitionKey == null ? "" : partitionKey));

        final SDElement sdProperties = new SDElement("aer_02_props@48577");
        for (final Map.Entry<String, Object> propEntry : parsedEvent.properties().entrySet()) {
            sdProperties.addSDParam(propEntry.getKey(), String.valueOf(propEntry.getValue()));
        }

        elems.add(sdProperties);

        elems
                .add(new SDElement("aer_02@48577").addSDParam("timestamp_source", time.isEmpty() ? "generated" : "timeEnqueued"));

        final JsonObject mainObject = parsedEvent.asJsonStructure().asJsonObject();

        assertKey(mainObject, "_ResourceId", JsonValue.ValueType.STRING);
        final ResourceId resourceId = new ResourceId(mainObject.getString("_ResourceId"));
        final String subscriptionId = resourceId.subscriptionId();
        final String clusterName = resourceId.resourceName();

        assertKey(mainObject, "PodName", JsonValue.ValueType.STRING);
        final String podName = mainObject.getString("PodName");

        assertKey(mainObject, "PodNamespace", JsonValue.ValueType.STRING);
        final String podNamespace = mainObject.getString("PodNamespace");

        assertKey(mainObject, "ContainerId", JsonValue.ValueType.STRING);
        final String containerId = mainObject.getString("ContainerId");

        elems
                .add(new SDElement("origin@48577").addSDParam("subscription", subscriptionId).addSDParam("clusterName", clusterName).addSDParam("namespace", podNamespace).addSDParam("pod", podName).addSDParam("containerId", containerId));

        elems.add(new SDElement("nlf_01@48577").addSDParam("eventType", this.getClass().getSimpleName()));

        return elems;
    }

    @Override
    public String msgId() {
        return String.valueOf(parsedEvent.systemProperties().getOrDefault("SequenceNumber", "0"));
    }

    @Override
    public String msg() {
        return parsedEvent.asString();
    }
}
