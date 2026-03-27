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

import java.util.Set;

public final class ContainerType implements EventType {

    private final ParsedEvent parsedEvent;
    private final String containerLogHostnameKey;
    private final String containerLogAppNameKey;
    private final String realHostname;
    private final String componentNameForPartitions;

    public ContainerType(
            final ParsedEvent parsedEvent,
            final String containerLogHostnameKey,
            final String containerLogAppNameKey,
            final String realHostname,
            final String componentNameForPartitions
    ) {
        this.parsedEvent = parsedEvent;
        this.containerLogHostnameKey = containerLogHostnameKey;
        this.containerLogAppNameKey = containerLogAppNameKey;
        this.realHostname = realHostname;
        this.componentNameForPartitions = componentNameForPartitions;
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

        final ValidKey<JsonObject> kubernetesMetadataValidKey = new ValidJsonObjectKey(
                mainObject,
                "KubernetesMetadata"
        );
        final JsonObject kubernetesMetadata = kubernetesMetadataValidKey.value();

        final ValidKey<JsonObject> podAnnotationsValidKey = new ValidJsonObjectKey(
                kubernetesMetadata,
                "podAnnotations"
        );
        final JsonObject podAnnotations = podAnnotationsValidKey.value();

        final ValidKey<String> containerLogHostnameKeyValidKey = new ValidStringKey(
                podAnnotations,
                containerLogHostnameKey
        );

        return new ValidRFC5424Hostname(containerLogHostnameKeyValidKey.value()).validHostname();
    }

    @Override
    public String appName() throws PluginException {
        final JsonObject mainObject = parsedEvent.asJsonStructure().asJsonObject();

        final ValidKey<JsonObject> kubernetesMetadataValidKey = new ValidJsonObjectKey(
                mainObject,
                "KubernetesMetadata"
        );
        final JsonObject kubernetesMetadata = kubernetesMetadataValidKey.value();

        final ValidKey<JsonObject> podAnnotationsValidKey = new ValidJsonObjectKey(
                kubernetesMetadata,
                "podAnnotations"
        );
        final JsonObject podAnnotations = podAnnotationsValidKey.value();

        final ValidKey<String> logSourceValidKey = new ValidStringKey(mainObject, "LogSource");
        final String logSource = logSourceValidKey.value();
        final String logSourceSuffix;

        if ("stdout".equals(logSource)) {
            logSourceSuffix = ".o";
        }
        else if ("stderr".equals(logSource)) {
            logSourceSuffix = ".e";
        }
        else {
            throw new PluginException(new JsonException("Unknown log source: " + logSource));
        }

        final ValidKey<String> containerLogAppNameKeyValidKey = new ValidStringKey(
                podAnnotations,
                containerLogAppNameKey
        );

        return new ValidRFC5424AppName(containerLogAppNameKeyValidKey.value() + logSourceSuffix).appName();
    }

    @Override
    public long timestamp() throws PluginException {
        final JsonObject mainObject = parsedEvent.asJsonStructure().asJsonObject();

        return new ValidRFC5424Timestamp(new ValidStringKey(mainObject, "TimeGenerated").value()).validTimestamp();
    }

    @Override
    public Set<SDElement> sdElements() throws PluginException {
        final SDElements defaultSDElements = new DefaultSDElements(
                parsedEvent,
                realHostname,
                this.getClass(),
                componentNameForPartitions
        );
        final Set<SDElement> elems = defaultSDElements.sdElements();

        final JsonObject mainObject = parsedEvent.asJsonStructure().asJsonObject();

        final ValidKey<String> resourceIdValidKey = new ValidStringKey(mainObject, "_ResourceId");
        final ResourceId resourceId = new ResourceId(resourceIdValidKey.value());
        final String subscriptionId = resourceId.subscriptionId();
        final String clusterName = resourceId.resourceName();

        final ValidKey<String> podNameValidKey = new ValidStringKey(mainObject, "PodName");
        final String podName = podNameValidKey.value();

        final ValidKey<String> podNamespaceValidKey = new ValidStringKey(mainObject, "PodNamespace");
        final String podNamespace = podNamespaceValidKey.value();

        final ValidKey<String> containerIdValidKey = new ValidStringKey(mainObject, "ContainerId");
        final String containerId = containerIdValidKey.value();

        elems
                .add(new SDElement("origin@48577").addSDParam("subscription", subscriptionId).addSDParam("clusterName", clusterName).addSDParam("namespace", podNamespace).addSDParam("pod", podName).addSDParam("containerId", containerId));

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
