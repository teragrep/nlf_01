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
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

class FunctionAppLogsTypeTest {

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

        Assertions.assertDoesNotThrow(is::close);
        Assertions.assertDoesNotThrow(reader::close);

        return new ParsedEventFactory(
                new UnparsedEventImpl(json.toString(), partitionCtx, props, sysProps, enqueuedTime, offset)
        ).parsedEvent();
    }

    @Test
    void testIdealCase() {
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
                "src/test/resources/function.json", new EventPartitionContextImpl(partitionContextMap), new EventPropertiesImpl(propertiesMap), new EventSystemPropertiesImpl(systemPropertiesMap), new EnqueuedTimeImpl("2010-01-01T00:00:00"), new EventOffsetImpl("0")
        );

        final FunctionAppLogsType type = new FunctionAppLogsType(parsedEvent, "localhost");

        final String actualAppName = Assertions.assertDoesNotThrow(type::appName);
        final Facility actualFacility = Assertions.assertDoesNotThrow(type::facility);
        final String actualHostname = Assertions.assertDoesNotThrow(type::hostname);
        final String actualMsg = Assertions.assertDoesNotThrow(type::msg);
        final String actualMsgId = Assertions.assertDoesNotThrow(type::msgId);
        final Severity actualSeverity = Assertions.assertDoesNotThrow(type::severity);
        final Long actualTimestamp = Assertions.assertDoesNotThrow(type::timestamp);
        final Set<SDElement> actualSDElements = Assertions.assertDoesNotThrow(type::sdElements);

        Assertions.assertEquals("app-name", actualAppName);
        Assertions.assertEquals(Facility.AUDIT, actualFacility);
        Assertions.assertEquals("md5-0ded52ef915af563e25778bf26b0f129-resourceName", actualHostname);
        Assertions
                .assertEquals(
                        "{\"AppName\":\"app-name\",\"Category\":\"function-logs\",\"EventId\":123,\"EventName\":\"event-name\",\"ExceptionDetails\":\"123abc\",\"ExceptionMessage\":\"Found a null value\",\"ExceptionType\":\"NPE\",\"FunctionInvocationId\":\"12345678\",\"FunctionName\":\"function-1\",\"HostInstanceId\":\"host-instance-1\",\"HostVersion\":\"1.2.3.4.a\",\"Level\":\"Debug\",\"LevelId\":1,\"Location\":\"function-1\",\"Message\":\"message\",\"ProcessId\":123456,\"RoleInstance\":\"message\",\"SourceSystem\":\"Azure\",\"TenantId\":\"12\",\"TimeGenerated\":\"2020-01-01T01:02:34.5678999Z\",\"Type\":\"FunctionAppLogs\",\"_BilledSize\":1,\"_ItemId\":\"12-34-56-78\",\"_Internal_WorkspaceResourceId\":\"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}\",\"_ResourceId\":\"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}\"}",
                        actualMsg
                );
        Assertions.assertEquals("12345678900", actualMsgId);
        Assertions.assertEquals(Severity.NOTICE, actualSeverity);
        Assertions.assertEquals(1577840554567L, actualTimestamp);

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

        Assertions
                .assertEquals(FunctionAppLogsType.class.getSimpleName(), sdElementMap.get("nlf_01@48577").get("eventType"));
    }

    @Test
    void testWithAllMetadataStubs() {
        final ParsedEvent parsedEvent = testEvent(
                "src/test/resources/function.json", new EventPartitionContextStub(), new EventPropertiesStub(),
                new EventSystemPropertiesStub(), new EnqueuedTimeStub(), new EventOffsetStub()
        );

        final FunctionAppLogsType type = new FunctionAppLogsType(parsedEvent, "localhost");

        final String actualAppName = Assertions.assertDoesNotThrow(type::appName);
        final Facility actualFacility = Assertions.assertDoesNotThrow(type::facility);
        final String actualHostname = Assertions.assertDoesNotThrow(type::hostname);
        final String actualMsg = Assertions.assertDoesNotThrow(type::msg);
        final String actualMsgId = Assertions.assertDoesNotThrow(type::msgId);
        final Severity actualSeverity = Assertions.assertDoesNotThrow(type::severity);
        final Long actualTimestamp = Assertions.assertDoesNotThrow(type::timestamp);
        final Set<SDElement> actualSDElements = Assertions.assertDoesNotThrow(type::sdElements);

        Assertions.assertEquals("app-name", actualAppName);
        Assertions.assertEquals(Facility.AUDIT, actualFacility);
        Assertions.assertEquals("md5-0ded52ef915af563e25778bf26b0f129-resourceName", actualHostname);
        Assertions
                .assertEquals(
                        "{\"AppName\":\"app-name\",\"Category\":\"function-logs\",\"EventId\":123,\"EventName\":\"event-name\",\"ExceptionDetails\":\"123abc\",\"ExceptionMessage\":\"Found a null value\",\"ExceptionType\":\"NPE\",\"FunctionInvocationId\":\"12345678\",\"FunctionName\":\"function-1\",\"HostInstanceId\":\"host-instance-1\",\"HostVersion\":\"1.2.3.4.a\",\"Level\":\"Debug\",\"LevelId\":1,\"Location\":\"function-1\",\"Message\":\"message\",\"ProcessId\":123456,\"RoleInstance\":\"message\",\"SourceSystem\":\"Azure\",\"TenantId\":\"12\",\"TimeGenerated\":\"2020-01-01T01:02:34.5678999Z\",\"Type\":\"FunctionAppLogs\",\"_BilledSize\":1,\"_ItemId\":\"12-34-56-78\",\"_Internal_WorkspaceResourceId\":\"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}\",\"_ResourceId\":\"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}\"}",
                        actualMsg
                );
        Assertions.assertEquals("", actualMsgId);
        Assertions.assertEquals(Severity.NOTICE, actualSeverity);
        Assertions.assertEquals(1577840554567L, actualTimestamp);

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

        Assertions
                .assertEquals(FunctionAppLogsType.class.getSimpleName(), sdElementMap.get("nlf_01@48577").get("eventType"));
    }

    @Test
    void testWithMissingJsonKeys() {
        final ParsedEvent parsedEvent = testEvent(
                "src/test/resources/function_missing_keys.json", new EventPartitionContextStub(),
                new EventPropertiesStub(), new EventSystemPropertiesStub(), new EnqueuedTimeStub(),
                new EventOffsetStub()
        );

        final FunctionAppLogsType type = new FunctionAppLogsType(parsedEvent, "localhost");

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
                        "{\"Category\":\"function-logs\",\"EventId\":123,\"EventName\":\"event-name\",\"ExceptionDetails\":\"123abc\",\"ExceptionMessage\":\"Found a null value\",\"ExceptionType\":\"NPE\",\"FunctionInvocationId\":\"12345678\",\"FunctionName\":\"function-1\",\"HostInstanceId\":\"host-instance-1\",\"HostVersion\":\"1.2.3.4.a\",\"Level\":\"Debug\",\"LevelId\":1,\"Location\":\"function-1\",\"Message\":\"message\",\"ProcessId\":123456,\"RoleInstance\":\"message\",\"SourceSystem\":\"Azure\",\"TenantId\":\"12\",\"Type\":\"FunctionAppLogs\",\"_BilledSize\":1,\"_ItemId\":\"12-34-56-78\"}",
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

        Assertions
                .assertEquals(FunctionAppLogsType.class.getSimpleName(), sdElementMap.get("nlf_01@48577").get("eventType"));
    }
}
