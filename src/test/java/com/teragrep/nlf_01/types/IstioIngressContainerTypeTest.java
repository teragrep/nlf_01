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
import com.teragrep.akv_01.event.ParsedEventFactory;
import com.teragrep.akv_01.event.UnparsedEventImpl;
import com.teragrep.akv_01.event.metadata.offset.EventOffset;
import com.teragrep.akv_01.event.metadata.offset.EventOffsetImpl;
import com.teragrep.akv_01.event.metadata.offset.EventOffsetStub;
import com.teragrep.akv_01.event.metadata.partitionContext.EventPartitionContext;
import com.teragrep.akv_01.event.metadata.partitionContext.EventPartitionContextStub;
import com.teragrep.akv_01.event.metadata.properties.EventProperties;
import com.teragrep.akv_01.event.metadata.properties.EventPropertiesStub;
import com.teragrep.akv_01.event.metadata.systemProperties.EventSystemProperties;
import com.teragrep.akv_01.event.metadata.systemProperties.EventSystemPropertiesStub;
import com.teragrep.akv_01.event.metadata.time.EnqueuedTime;
import com.teragrep.akv_01.event.metadata.time.EnqueuedTimeImpl;
import com.teragrep.akv_01.event.metadata.time.EnqueuedTimeStub;
import com.teragrep.akv_01.plugin.PluginException;
import com.teragrep.nlf_01.fakes.EventPartitionContextFake;
import com.teragrep.nlf_01.fakes.EventPropertiesFake;
import com.teragrep.nlf_01.fakes.EventSystemPropertiesFake;
import com.teragrep.rlo_14.Facility;
import com.teragrep.rlo_14.SDElement;
import com.teragrep.rlo_14.SDParam;
import com.teragrep.rlo_14.Severity;
import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonReader;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

class IstioIngressContainerTypeTest {

    private ParsedEvent testEvent(
            final String path,
            final EventPartitionContext partitionCtx,
            final EventProperties props,
            final EventSystemProperties sysProps,
            final EnqueuedTime enqueuedTime,
            final EventOffset offset
    ) {
        final InputStream is = Assertions.assertDoesNotThrow(() -> Files.newInputStream(Paths.get(path)));
        final JsonReader reader = Json.createReader(is);

        final JsonObject json = reader.readObject();

        Assertions.assertDoesNotThrow(reader::close);
        Assertions.assertDoesNotThrow(is::close);

        return new ParsedEventFactory(
                new UnparsedEventImpl(json.toString(), partitionCtx, props, sysProps, enqueuedTime, offset)
        ).parsedEvent();
    }

    @Test
    void testIdealCase() {
        final ParsedEvent parsedEvent = testEvent(
                "src/test/resources/istiocontainer.json", new EventPartitionContextFake(), new EventPropertiesFake(),
                new EventSystemPropertiesFake(), new EnqueuedTimeImpl("2010-01-01T00:00:00"), new EventOffsetImpl("0")
        );

        final IstioIngressContainerType type = new IstioIngressContainerType(parsedEvent, "localhost");

        final String actualAppName = Assertions.assertDoesNotThrow(type::appName);
        final Facility actualFacility = Assertions.assertDoesNotThrow(type::facility);
        final String actualHostname = Assertions.assertDoesNotThrow(type::hostname);
        final String actualMsg = Assertions.assertDoesNotThrow(type::msg);
        final String actualMsgId = Assertions.assertDoesNotThrow(type::msgId);
        final Severity actualSeverity = Assertions.assertDoesNotThrow(type::severity);
        final Long actualTimestamp = Assertions.assertDoesNotThrow(type::timestamp);
        final Set<SDElement> actualSDElements = Assertions.assertDoesNotThrow(type::sdElements);

        Assertions.assertEquals("istio-ingress", actualAppName);
        Assertions.assertEquals(Facility.AUDIT, actualFacility);
        Assertions.assertEquals("aks-istio-ingress-pod-namespace", actualHostname);
        Assertions
                .assertEquals(
                        "{\"TimeGenerated\":\"2020-01-01T01:23:34.5678999Z\",\"Computer\":\"computer\",\"ContainerId\":\"container-id\",\"ContainerName\":\"container-name\",\"PodName\":\"pod-name\",\"PodNamespace\":\"aks-istio-ingress-pod-namespace\",\"LogMessage\":{\"level\":\"info\",\"ts\":\"2020-01-01T01:23:45.678Z\",\"logger\":\"logger\",\"msg\":\"message\",\"namespace\":\"namespace\"},\"LogSource\":\"stdout\",\"KubernetesMetadata\":{\"image\":\"image\",\"imageID\":\"123-456-789\",\"imageRepo\":\"imagerepo\",\"imageTag\":\"imagetag\",\"podAnnotations\":{\"appname-annotation\":\"APP-NAME\",\"hostname-annotation\":\"HOST-NAME\"},\"podLabels\":{\"x\":\"y\"},\"podUid\":\"123\"},\"LogLevel\":\"info\",\"_ItemId\":\"123\",\"_Internal_WorkspaceResourceId\":\"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}\",\"Type\":\"ContainerLogV2\",\"TenantId\":\"456\",\"_ResourceId\":\"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}\"}",
                        actualMsg
                );
        Assertions.assertEquals("12345678900", actualMsgId);
        Assertions.assertEquals(Severity.NOTICE, actualSeverity);
        Assertions.assertEquals(1577841814567L, actualTimestamp);

        final Map<String, Map<String, String>> sdElementMap = actualSDElements
                .stream()
                .collect(Collectors.toMap((SDElement::getSdID), (sdElem) -> sdElem.getSdParams().stream().collect(Collectors.toMap(SDParam::getParamName, SDParam::getParamValue))));

        Assertions
                .assertEquals("fully-qualified-namespace", sdElementMap.get("aer_02_partition@48577").get("fully_qualified_namespace"));
        Assertions.assertEquals("event-hub-name", sdElementMap.get("aer_02_partition@48577").get("eventhub_name"));
        Assertions.assertEquals("123", sdElementMap.get("aer_02_partition@48577").get("partition_id"));
        Assertions.assertEquals("consumer-group", sdElementMap.get("aer_02_partition@48577").get("consumer_group"));

        Assertions.assertEquals("0", sdElementMap.get("aer_02_event@48577").get("offset"));
        Assertions.assertEquals("2010-01-01T00:00Z", sdElementMap.get("aer_02_event@48577").get("enqueued_time"));
        Assertions.assertEquals("456", sdElementMap.get("aer_02_event@48577").get("partition_key"));
        Assertions
                .assertEquals(
                        "{\"null\":\"important-null-value\",\"prop-key\":\"prop-value\",\"important-key\":null}",
                        sdElementMap.get("aer_02_event@48577").get("properties")
                );

        Assertions.assertEquals("timeEnqueued", sdElementMap.get("aer_02@48577").get("timestamp_source"));

        Assertions.assertEquals("{subscriptionId}", sdElementMap.get("origin@48577").get("subscription"));
        Assertions.assertEquals("{resourceName}", sdElementMap.get("origin@48577").get("clusterName"));
        Assertions.assertEquals("aks-istio-ingress-pod-namespace", sdElementMap.get("origin@48577").get("namespace"));
        Assertions.assertEquals("pod-name", sdElementMap.get("origin@48577").get("pod"));
        Assertions.assertEquals("container-id", sdElementMap.get("origin@48577").get("containerId"));

        Assertions
                .assertEquals(IstioIngressContainerType.class.getSimpleName(), sdElementMap.get("nlf_01@48577").get("eventType"));
    }

    @Test
    void testWithAllMetadataStubs() {
        final ParsedEvent parsedEvent = testEvent(
                "src/test/resources/istiocontainer.json", new EventPartitionContextStub(), new EventPropertiesStub(),
                new EventSystemPropertiesStub(), new EnqueuedTimeStub(), new EventOffsetStub()
        );

        final IstioIngressContainerType type = new IstioIngressContainerType(parsedEvent, "localhost");

        final String actualAppName = Assertions.assertDoesNotThrow(type::appName);
        final Facility actualFacility = Assertions.assertDoesNotThrow(type::facility);
        final String actualHostname = Assertions.assertDoesNotThrow(type::hostname);
        final String actualMsg = Assertions.assertDoesNotThrow(type::msg);
        final String actualMsgId = Assertions.assertDoesNotThrow(type::msgId);
        final Severity actualSeverity = Assertions.assertDoesNotThrow(type::severity);
        final Long actualTimestamp = Assertions.assertDoesNotThrow(type::timestamp);
        final Set<SDElement> actualSDElements = Assertions.assertDoesNotThrow(type::sdElements);

        Assertions.assertEquals("istio-ingress", actualAppName);
        Assertions.assertEquals(Facility.AUDIT, actualFacility);
        Assertions.assertEquals("aks-istio-ingress-pod-namespace", actualHostname);
        Assertions
                .assertEquals(
                        "{\"TimeGenerated\":\"2020-01-01T01:23:34.5678999Z\",\"Computer\":\"computer\",\"ContainerId\":\"container-id\",\"ContainerName\":\"container-name\",\"PodName\":\"pod-name\",\"PodNamespace\":\"aks-istio-ingress-pod-namespace\",\"LogMessage\":{\"level\":\"info\",\"ts\":\"2020-01-01T01:23:45.678Z\",\"logger\":\"logger\",\"msg\":\"message\",\"namespace\":\"namespace\"},\"LogSource\":\"stdout\",\"KubernetesMetadata\":{\"image\":\"image\",\"imageID\":\"123-456-789\",\"imageRepo\":\"imagerepo\",\"imageTag\":\"imagetag\",\"podAnnotations\":{\"appname-annotation\":\"APP-NAME\",\"hostname-annotation\":\"HOST-NAME\"},\"podLabels\":{\"x\":\"y\"},\"podUid\":\"123\"},\"LogLevel\":\"info\",\"_ItemId\":\"123\",\"_Internal_WorkspaceResourceId\":\"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}\",\"Type\":\"ContainerLogV2\",\"TenantId\":\"456\",\"_ResourceId\":\"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}\"}",
                        actualMsg
                );
        Assertions.assertEquals("", actualMsgId);
        Assertions.assertEquals(Severity.NOTICE, actualSeverity);
        Assertions.assertEquals(1577841814567L, actualTimestamp);

        final Map<String, Map<String, String>> sdElementMap = actualSDElements
                .stream()
                .collect(Collectors.toMap((SDElement::getSdID), (sdElem) -> sdElem.getSdParams().stream().collect(Collectors.toMap(SDParam::getParamName, SDParam::getParamValue))));

        Assertions.assertEquals("", sdElementMap.get("aer_02_partition@48577").get("fully_qualified_namespace"));
        Assertions.assertEquals("", sdElementMap.get("aer_02_partition@48577").get("eventhub_name"));
        Assertions.assertEquals("", sdElementMap.get("aer_02_partition@48577").get("partition_id"));
        Assertions.assertEquals("", sdElementMap.get("aer_02_partition@48577").get("consumer_group"));

        Assertions.assertEquals("", sdElementMap.get("aer_02_event@48577").get("offset"));
        Assertions.assertEquals("", sdElementMap.get("aer_02_event@48577").get("enqueued_time"));
        Assertions.assertEquals("", sdElementMap.get("aer_02_event@48577").get("partition_key"));
        Assertions.assertEquals("{}", sdElementMap.get("aer_02_event@48577").get("properties"));

        Assertions.assertEquals("generated", sdElementMap.get("aer_02@48577").get("timestamp_source"));

        Assertions.assertEquals("{subscriptionId}", sdElementMap.get("origin@48577").get("subscription"));
        Assertions.assertEquals("{resourceName}", sdElementMap.get("origin@48577").get("clusterName"));
        Assertions.assertEquals("aks-istio-ingress-pod-namespace", sdElementMap.get("origin@48577").get("namespace"));
        Assertions.assertEquals("pod-name", sdElementMap.get("origin@48577").get("pod"));
        Assertions.assertEquals("container-id", sdElementMap.get("origin@48577").get("containerId"));

        Assertions
                .assertEquals(IstioIngressContainerType.class.getSimpleName(), sdElementMap.get("nlf_01@48577").get("eventType"));
    }

    @Test
    void testWithMissingJsonKeys() {
        final ParsedEvent parsedEvent = testEvent(
                "src/test/resources/istiocontainer_missing_keys.json", new EventPartitionContextStub(),
                new EventPropertiesStub(), new EventSystemPropertiesStub(), new EnqueuedTimeStub(),
                new EventOffsetStub()
        );

        final IstioIngressContainerType type = new IstioIngressContainerType(parsedEvent, "localhost");

        Assertions
                .assertDoesNotThrow(
                        type::appName, "appName method should not throw an Exception, since it uses a static value"
                );
        final Facility actualFacility = Assertions.assertDoesNotThrow(type::facility);
        Assertions.assertThrows(PluginException.class, type::hostname);
        final String actualMsg = Assertions.assertDoesNotThrow(type::msg);
        final String actualMsgId = Assertions.assertDoesNotThrow(type::msgId);
        final Severity actualSeverity = Assertions.assertDoesNotThrow(type::severity);
        Assertions.assertThrows(PluginException.class, type::timestamp);
        Assertions.assertThrows(PluginException.class, type::sdElements);

        Assertions.assertEquals(Facility.AUDIT, actualFacility);
        Assertions
                .assertEquals(
                        "{\"Computer\":\"computer\",\"ContainerId\":\"container-id\",\"ContainerName\":\"container-name\",\"PodName\":\"pod-name\",\"LogMessage\":{\"level\":\"info\",\"ts\":\"2020-01-01T01:23:45.678Z\",\"logger\":\"logger\",\"msg\":\"message\",\"namespace\":\"namespace\"},\"LogSource\":\"stdout\",\"KubernetesMetadata\":{\"image\":\"image\",\"imageID\":\"123-456-789\",\"imageRepo\":\"imagerepo\",\"imageTag\":\"imagetag\",\"podAnnotations\":{\"appname-annotation\":\"APP-NAME\",\"hostname-annotation\":\"HOST-NAME\"},\"podLabels\":{\"x\":\"y\"},\"podUid\":\"123\"},\"LogLevel\":\"info\",\"_ItemId\":\"123\",\"_Internal_WorkspaceResourceId\":\"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}\",\"Type\":\"ContainerLogV2\",\"TenantId\":\"456\",\"_ResourceId\":\"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}\"}",
                        actualMsg
                );
        Assertions.assertEquals("", actualMsgId);
        Assertions.assertEquals(Severity.NOTICE, actualSeverity);
    }
}
