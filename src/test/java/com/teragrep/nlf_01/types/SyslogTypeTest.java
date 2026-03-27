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
import com.teragrep.akv_01.event.metadata.partitionContext.EventPartitionContextImpl;
import com.teragrep.akv_01.event.metadata.partitionContext.EventPartitionContextStub;
import com.teragrep.akv_01.event.metadata.properties.EventProperties;
import com.teragrep.akv_01.event.metadata.properties.EventPropertiesImpl;
import com.teragrep.akv_01.event.metadata.properties.EventPropertiesStub;
import com.teragrep.akv_01.event.metadata.systemProperties.EventSystemProperties;
import com.teragrep.akv_01.event.metadata.systemProperties.EventSystemPropertiesImpl;
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
import jakarta.json.JsonValue;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

public final class SyslogTypeTest {

    private ParsedEvent testEvent(
            String path,
            EventPartitionContext partitionCtx,
            EventProperties props,
            EventSystemProperties sysProps,
            EnqueuedTime enqueuedTime,
            EventOffset offset
    ) {
        JsonObject json = JsonValue.EMPTY_JSON_OBJECT;
        try (
                final InputStream is = Files.newInputStream(Paths.get(path)); final JsonReader reader = Json.createReader(is)
        ) {
            json = reader.readObject();
        }
        catch (final IOException e) {
            Assertions.fail("Failed to read test data from file", e);
        }

        return new ParsedEventFactory(
                new UnparsedEventImpl(json.toString(), partitionCtx, props, sysProps, enqueuedTime, offset)
        ).parsedEvent();
    }

    @Test
    void testIdealCase() {
        final ParsedEvent parsedEvent = testEvent(
                "src/test/resources/syslog.json", new EventPartitionContextFake(), new EventPropertiesFake(),
                new EventSystemPropertiesFake(), new EnqueuedTimeImpl("2010-01-01T00:00:00"), new EventOffsetImpl("0")
        );

        final SyslogType type = new SyslogType(parsedEvent, "Soft-Ware", "localhost");

        final String actualAppName = Assertions.assertDoesNotThrow(type::appName);
        final Facility actualFacility = Assertions.assertDoesNotThrow(type::facility);
        final String actualHostname = Assertions.assertDoesNotThrow(type::hostname);
        final String actualMsg = Assertions.assertDoesNotThrow(type::msg);
        final String actualMsgId = Assertions.assertDoesNotThrow(type::msgId);
        final Severity actualSeverity = Assertions.assertDoesNotThrow(type::severity);
        final Long actualTimestamp = Assertions.assertDoesNotThrow(type::timestamp);
        final Set<SDElement> actualSDElements = Assertions.assertDoesNotThrow(type::sdElements);

        Assertions.assertEquals("10660186-5aec-4f2b-a021-6be9edfb9555", actualAppName);
        Assertions.assertEquals(Facility.AUDIT, actualFacility);
        Assertions.assertEquals("md5-35166b001e9028e0085c05498ffd1235-n-n-law", actualHostname);
        Assertions
                .assertEquals(
                        "{\"Collectorhostname\":\"xyz\",\"Computer\":\"10660186-5aec-4f2b-a021-6be9edfb9555\",\"EventTime\":\"2025-02-18T13:47:27.0000000Z\",\"Facility\":\"user\",\"HostIP\":\"Unknown IP\",\"HostName\":\"10660186-5aec-4f2b-a021-6be9edfb9555\",\"MG\":\"00000000-0000-0000-0000-000000000002\",\"ProcessName\":\"Soft-Ware\",\"SeverityLevel\":\"info\",\"SourceSystem\":\"Linux\",\"SyslogMessage\":\"Tue, 18 Feb 2025 15:47:27 EET 27:63 10660186-5aec-4f2b-a021-6be9edfb9555-a-b-c-d-e-f-g-h [INFO] says yes\",\"TenantId\":\"01bfa0b2-7986-4de8-8cd6-9da6db0400f5\",\"TimeGenerated\":\"2025-02-18T13:47:27.0644670Z\",\"Type\":\"Syslog\",\"_Internal_WorkspaceResourceId\":\"/subscriptions/ce5ef585-60c3-4e37-a326-7bb6df0e5750/resourcegroups/res-g1/providers/pro-v1/workspaces/n-n-law\",\"_ItemId\":\"5a6ae031-689a-479e-92d7-dfd8eea5158b\",\"_ResourceId\":\"/subscriptions/ce5ef585-60c3-4e37-a326-7bb6df0e5750/resourceGroups/res-g2/providers/.../workspaces/...\"}",
                        actualMsg
                );
        Assertions.assertEquals("12345678900", actualMsgId);
        Assertions.assertEquals(Severity.NOTICE, actualSeverity);
        Assertions.assertEquals(1739886447064L, actualTimestamp);

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

        Assertions.assertEquals(SyslogType.class.getSimpleName(), sdElementMap.get("nlf_01@48577").get("eventType"));
    }

    @Test
    void testWithAllMetadataStubs() {
        final ParsedEvent parsedEvent = testEvent(
                "src/test/resources/syslog.json", new EventPartitionContextStub(), new EventPropertiesStub(),
                new EventSystemPropertiesStub(), new EnqueuedTimeStub(), new EventOffsetStub()
        );

        final SyslogType type = new SyslogType(parsedEvent, "Soft-Ware", "localhost");

        final String actualAppName = Assertions.assertDoesNotThrow(type::appName);
        final Facility actualFacility = Assertions.assertDoesNotThrow(type::facility);
        final String actualHostname = Assertions.assertDoesNotThrow(type::hostname);
        final String actualMsg = Assertions.assertDoesNotThrow(type::msg);
        final String actualMsgId = Assertions.assertDoesNotThrow(type::msgId);
        final Severity actualSeverity = Assertions.assertDoesNotThrow(type::severity);
        final Long actualTimestamp = Assertions.assertDoesNotThrow(type::timestamp);
        final Set<SDElement> actualSDElements = Assertions.assertDoesNotThrow(type::sdElements);

        Assertions.assertEquals("10660186-5aec-4f2b-a021-6be9edfb9555", actualAppName);
        Assertions.assertEquals(Facility.AUDIT, actualFacility);
        Assertions.assertEquals("md5-35166b001e9028e0085c05498ffd1235-n-n-law", actualHostname);
        Assertions
                .assertEquals(
                        "{\"Collectorhostname\":\"xyz\",\"Computer\":\"10660186-5aec-4f2b-a021-6be9edfb9555\",\"EventTime\":\"2025-02-18T13:47:27.0000000Z\",\"Facility\":\"user\",\"HostIP\":\"Unknown IP\",\"HostName\":\"10660186-5aec-4f2b-a021-6be9edfb9555\",\"MG\":\"00000000-0000-0000-0000-000000000002\",\"ProcessName\":\"Soft-Ware\",\"SeverityLevel\":\"info\",\"SourceSystem\":\"Linux\",\"SyslogMessage\":\"Tue, 18 Feb 2025 15:47:27 EET 27:63 10660186-5aec-4f2b-a021-6be9edfb9555-a-b-c-d-e-f-g-h [INFO] says yes\",\"TenantId\":\"01bfa0b2-7986-4de8-8cd6-9da6db0400f5\",\"TimeGenerated\":\"2025-02-18T13:47:27.0644670Z\",\"Type\":\"Syslog\",\"_Internal_WorkspaceResourceId\":\"/subscriptions/ce5ef585-60c3-4e37-a326-7bb6df0e5750/resourcegroups/res-g1/providers/pro-v1/workspaces/n-n-law\",\"_ItemId\":\"5a6ae031-689a-479e-92d7-dfd8eea5158b\",\"_ResourceId\":\"/subscriptions/ce5ef585-60c3-4e37-a326-7bb6df0e5750/resourceGroups/res-g2/providers/.../workspaces/...\"}",
                        actualMsg
                );
        Assertions.assertEquals("", actualMsgId);
        Assertions.assertEquals(Severity.NOTICE, actualSeverity);
        Assertions.assertEquals(1739886447064L, actualTimestamp);

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

        Assertions.assertEquals(SyslogType.class.getSimpleName(), sdElementMap.get("nlf_01@48577").get("eventType"));
    }

    @Test
    void testWithUnexpectedSyslogMessage() {
        final ParsedEvent parsedEvent = testEvent(
                "src/test/resources/syslog_unexpected_message.json", new EventPartitionContextStub(),
                new EventPropertiesStub(), new EventSystemPropertiesStub(), new EnqueuedTimeStub(),
                new EventOffsetStub()
        );

        final SyslogType type = new SyslogType(parsedEvent, "Soft-Ware", "localhost");

        Assertions.assertThrows(PluginException.class, type::appName);
        final Facility actualFacility = Assertions.assertDoesNotThrow(type::facility);
        final String actualHostname = Assertions.assertDoesNotThrow(type::hostname);
        final String actualMsg = Assertions.assertDoesNotThrow(type::msg);
        final String actualMsgId = Assertions.assertDoesNotThrow(type::msgId);
        final Severity actualSeverity = Assertions.assertDoesNotThrow(type::severity);
        final Long actualTimestamp = Assertions.assertDoesNotThrow(type::timestamp);
        final Set<SDElement> actualSDElements = Assertions.assertDoesNotThrow(type::sdElements);

        Assertions.assertEquals(Facility.AUDIT, actualFacility);
        Assertions.assertEquals("md5-35166b001e9028e0085c05498ffd1235-n-n-law", actualHostname);
        Assertions
                .assertEquals(
                        "{\"Collectorhostname\":\"xyz\",\"Computer\":\"10660186-5aec-4f2b-a021-6be9edfb9555\",\"EventTime\":\"2025-02-18T13:47:27.0000000Z\",\"Facility\":\"user\",\"HostIP\":\"Unknown IP\",\"HostName\":\"10660186-5aec-4f2b-a021-6be9edfb9555\",\"MG\":\"00000000-0000-0000-0000-000000000002\",\"ProcessName\":\"Soft-Ware\",\"SeverityLevel\":\"info\",\"SourceSystem\":\"Linux\",\"SyslogMessage\":\"something unexpected here\",\"TenantId\":\"01bfa0b2-7986-4de8-8cd6-9da6db0400f5\",\"TimeGenerated\":\"2025-02-18T13:47:27.0644670Z\",\"Type\":\"Syslog\",\"_Internal_WorkspaceResourceId\":\"/subscriptions/ce5ef585-60c3-4e37-a326-7bb6df0e5750/resourcegroups/res-g1/providers/pro-v1/workspaces/n-n-law\",\"_ItemId\":\"5a6ae031-689a-479e-92d7-dfd8eea5158b\",\"_ResourceId\":\"/subscriptions/ce5ef585-60c3-4e37-a326-7bb6df0e5750/resourceGroups/res-g2/providers/.../workspaces/...\"}",
                        actualMsg
                );
        Assertions.assertEquals("", actualMsgId);
        Assertions.assertEquals(Severity.NOTICE, actualSeverity);
        Assertions.assertEquals(1739886447064L, actualTimestamp);

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

        Assertions.assertEquals(SyslogType.class.getSimpleName(), sdElementMap.get("nlf_01@48577").get("eventType"));
    }

    @Test
    void testWithMissingJsonKeys() {
        final ParsedEvent parsedEvent = testEvent(
                "src/test/resources/syslog_missing_keys.json", new EventPartitionContextStub(),
                new EventPropertiesStub(), new EventSystemPropertiesStub(), new EnqueuedTimeStub(),
                new EventOffsetStub()
        );

        final SyslogType type = new SyslogType(parsedEvent, "Soft-Ware", "localhost");

        // All should throw an error because ProcessName is missing from JSON
        Assertions.assertThrows(PluginException.class, type::appName);
        Assertions.assertThrows(PluginException.class, type::facility);
        Assertions.assertThrows(PluginException.class, type::hostname);
        Assertions.assertThrows(PluginException.class, type::msg);
        Assertions.assertThrows(PluginException.class, type::msgId);
        Assertions.assertThrows(PluginException.class, type::severity);
        Assertions.assertThrows(PluginException.class, type::timestamp);
        Assertions.assertThrows(PluginException.class, type::sdElements);
    }

    @Test
    void testWithMissingJsonKeysExceptProcessName() {
        final ParsedEvent parsedEvent = testEvent(
                "src/test/resources/syslog_missing_keys_except_processName.json", new EventPartitionContextStub(),
                new EventPropertiesStub(), new EventSystemPropertiesStub(), new EnqueuedTimeStub(),
                new EventOffsetStub()
        );

        final SyslogType type = new SyslogType(parsedEvent, "Soft-Ware", "localhost");

        Assertions.assertThrows(PluginException.class, type::appName);
        final Facility actualFacility = Assertions.assertDoesNotThrow(type::facility);
        Assertions.assertThrows(PluginException.class, type::hostname);
        final String actualMsg = Assertions.assertDoesNotThrow(type::msg);
        final String actualMsgId = Assertions.assertDoesNotThrow(type::msgId);
        final Severity actualSeverity = Assertions.assertDoesNotThrow(type::severity);
        Assertions.assertThrows(PluginException.class, type::timestamp);
        final Set<SDElement> actualSDElements = Assertions.assertDoesNotThrow(type::sdElements);

        Assertions.assertEquals(Facility.AUDIT, actualFacility);
        Assertions
                .assertEquals(
                        "{\"Collectorhostname\":\"xyz\",\"Computer\":\"10660186-5aec-4f2b-a021-6be9edfb9555\",\"EventTime\":\"2025-02-18T13:47:27.0000000Z\",\"Facility\":\"user\",\"HostIP\":\"Unknown IP\",\"HostName\":\"10660186-5aec-4f2b-a021-6be9edfb9555\",\"MG\":\"00000000-0000-0000-0000-000000000002\",\"ProcessName\":\"Soft-Ware\",\"SeverityLevel\":\"info\",\"SourceSystem\":\"Linux\",\"TenantId\":\"01bfa0b2-7986-4de8-8cd6-9da6db0400f5\",\"Type\":\"Syslog\",\"_ItemId\":\"5a6ae031-689a-479e-92d7-dfd8eea5158b\"}",
                        actualMsg
                );
        Assertions.assertEquals("", actualMsgId);
        Assertions.assertEquals(Severity.NOTICE, actualSeverity);

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

        Assertions.assertEquals(SyslogType.class.getSimpleName(), sdElementMap.get("nlf_01@48577").get("eventType"));
    }

    @Test
    @DisplayName("test sdElement() return value")
    void testSdElementReturnValue() {
        final Map<String, Object> partitionContextMap = new HashMap<>();
        partitionContextMap.put("FullyQualifiedNamespace", "fully-qualified-namespace");
        partitionContextMap.put("EventHubName", "event-hub-name");
        partitionContextMap.put("PartitionId", "123");
        partitionContextMap.put("ConsumerGroup", "consumer-group");

        final Map<String, Object> systemPropertiesMap = new HashMap<>();
        systemPropertiesMap.put("PartitionKey", "456");
        systemPropertiesMap.put("SequenceNumber", "12345678900");

        final Map<String, Object> propertiesMap = new HashMap<>();
        propertiesMap.put("prop-key", "prop-value");
        propertiesMap.put(null, "important-null-value");
        propertiesMap.put("important-key", null);

        final ParsedEvent parsedEvent = testEvent(
                "src/test/resources/syslog.json", new EventPartitionContextImpl(partitionContextMap), new EventPropertiesImpl(propertiesMap), new EventSystemPropertiesImpl(systemPropertiesMap), new EnqueuedTimeImpl("2010-01-01T00:00:00"), new EventOffsetImpl("0")
        );

        final SyslogType type = new SyslogType(parsedEvent, "Soft-Ware", "localhost");

        final Set<SDElement> actualSDElements = Assertions.assertDoesNotThrow(type::sdElements);

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

        Assertions.assertEquals(SyslogType.class.getSimpleName(), sdElementMap.get("nlf_01@48577").get("eventType"));
    }
}
