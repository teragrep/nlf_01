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
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

public final class PostgreSQLTypeTest {

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
                "src/test/resources/postgre.json", new EventPartitionContextFake(), new EventPropertiesFake(),
                new EventSystemPropertiesFake(), new EnqueuedTimeImpl("2010-01-01T00:00:00"), new EventOffsetImpl("0")
        );

        final EventType type = new PostgreSQLType(parsedEvent, "localhost");

        final String actualAppName = Assertions.assertDoesNotThrow(type::appName);
        final Facility actualFacility = Assertions.assertDoesNotThrow(type::facility);
        final String actualHostname = Assertions.assertDoesNotThrow(type::hostname);
        final String actualMsg = Assertions.assertDoesNotThrow(type::msg);
        final String actualMsgId = Assertions.assertDoesNotThrow(type::msgId);
        final Severity actualSeverity = Assertions.assertDoesNotThrow(type::severity);
        final Long actualTimestamp = Assertions.assertDoesNotThrow(type::timestamp);
        final Set<SDElement> actualSDElements = Assertions.assertDoesNotThrow(type::sdElements);

        Assertions.assertEquals("dbase_maintenance", actualAppName);
        Assertions.assertEquals(Facility.AUDIT, actualFacility);
        Assertions.assertEquals("md5-bfd1db26c3c4f8a2936317cf4ec729ea-efgh-ijklmn-xx-DEV-01", actualHostname);
        Assertions
                .assertEquals(
                        "{\"AppImage\":\"cinnamon/postgres_standalone_12_a1:12.3.456789\",\"AppType\":\"PostgreSQL\",\"AppVersion\":\"abcdefghj12_2020-01-01-12-34-56\",\"Region\":\"countrycentral\",\"category\":\"PostgreSQLLogs\",\"location\":\"countrycentral\",\"operationName\":\"LogEvent\",\"properties\":{\"timestamp\":\"2020-10-01 11:59:26.256 UTC\",\"processId\":1234567,\"errorLevel\":\"LOG\",\"sqlerrcode\":\"00000\",\"backend_type\":\"client backend\",\"message\":\"2020-10-01 11:59:26 UTC-12abcd3e.4f5678-user=user012,db=dbase_maintenance,app=[unknown],client=127.0.0.1LOG:  AUDIT: SESSION,4,1,WRITE,INSERT,,,\\\"insert into test.abcmover (id, update_time) select 1, now() on conflict on constraint abcmover_pk do update set id = test.abcmover.id+1, update_time=now()\\\",<not logged>\"},\"resourceId\":\"/SUBSCRIPTIONS/uuid/RESOURCEGROUPS/ab-cd-efgh-ijklmn-xx-DEV-01/PROVIDERS/postgres-db/FLEXIBLESERVERS/efgh-ijklmn-xx-DEV-01\",\"time\":\"2020-10-01T11:59:26.256Z\",\"ServerType\":\"PostgreSQL\",\"LogicalServerName\":\"efgh-ijklmn-xx-DEV-01\",\"ServerVersion\":\"abcdefghj12_2020-01-01-12-34-56\",\"ServerLocation\":\"prod:countrycentral\",\"ReplicaRole\":\"Primary\",\"OriginalPrimaryServerName\":\"efgh-ijklmn-xx-DEV-01\"}",
                        actualMsg
                );
        Assertions.assertEquals("12345678900", actualMsgId);
        Assertions.assertEquals(Severity.NOTICE, actualSeverity);
        Assertions.assertEquals(1601553566256L, actualTimestamp);

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
                .assertEquals(PostgreSQLType.class.getSimpleName(), sdElementMap.get("nlf_01@48577").get("eventType"));
    }

    @Test
    void testWithAllMetadataStubs() {
        final ParsedEvent parsedEvent = testEvent(
                "src/test/resources/postgre.json", new EventPartitionContextStub(), new EventPropertiesStub(),
                new EventSystemPropertiesStub(), new EnqueuedTimeStub(), new EventOffsetStub()
        );

        final EventType type = new PostgreSQLType(parsedEvent, "localhost");

        final String actualAppName = Assertions.assertDoesNotThrow(type::appName);
        final Facility actualFacility = Assertions.assertDoesNotThrow(type::facility);
        final String actualHostname = Assertions.assertDoesNotThrow(type::hostname);
        final String actualMsg = Assertions.assertDoesNotThrow(type::msg);
        final String actualMsgId = Assertions.assertDoesNotThrow(type::msgId);
        final Severity actualSeverity = Assertions.assertDoesNotThrow(type::severity);
        final Long actualTimestamp = Assertions.assertDoesNotThrow(type::timestamp);
        final Set<SDElement> actualSDElements = Assertions.assertDoesNotThrow(type::sdElements);

        Assertions.assertEquals("dbase_maintenance", actualAppName);
        Assertions.assertEquals(Facility.AUDIT, actualFacility);
        Assertions.assertEquals("md5-bfd1db26c3c4f8a2936317cf4ec729ea-efgh-ijklmn-xx-DEV-01", actualHostname);
        Assertions
                .assertEquals(
                        "{\"AppImage\":\"cinnamon/postgres_standalone_12_a1:12.3.456789\",\"AppType\":\"PostgreSQL\",\"AppVersion\":\"abcdefghj12_2020-01-01-12-34-56\",\"Region\":\"countrycentral\",\"category\":\"PostgreSQLLogs\",\"location\":\"countrycentral\",\"operationName\":\"LogEvent\",\"properties\":{\"timestamp\":\"2020-10-01 11:59:26.256 UTC\",\"processId\":1234567,\"errorLevel\":\"LOG\",\"sqlerrcode\":\"00000\",\"backend_type\":\"client backend\",\"message\":\"2020-10-01 11:59:26 UTC-12abcd3e.4f5678-user=user012,db=dbase_maintenance,app=[unknown],client=127.0.0.1LOG:  AUDIT: SESSION,4,1,WRITE,INSERT,,,\\\"insert into test.abcmover (id, update_time) select 1, now() on conflict on constraint abcmover_pk do update set id = test.abcmover.id+1, update_time=now()\\\",<not logged>\"},\"resourceId\":\"/SUBSCRIPTIONS/uuid/RESOURCEGROUPS/ab-cd-efgh-ijklmn-xx-DEV-01/PROVIDERS/postgres-db/FLEXIBLESERVERS/efgh-ijklmn-xx-DEV-01\",\"time\":\"2020-10-01T11:59:26.256Z\",\"ServerType\":\"PostgreSQL\",\"LogicalServerName\":\"efgh-ijklmn-xx-DEV-01\",\"ServerVersion\":\"abcdefghj12_2020-01-01-12-34-56\",\"ServerLocation\":\"prod:countrycentral\",\"ReplicaRole\":\"Primary\",\"OriginalPrimaryServerName\":\"efgh-ijklmn-xx-DEV-01\"}",
                        actualMsg
                );
        Assertions.assertEquals("", actualMsgId);
        Assertions.assertEquals(Severity.NOTICE, actualSeverity);
        Assertions.assertEquals(1601553566256L, actualTimestamp);

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
                .assertEquals(PostgreSQLType.class.getSimpleName(), sdElementMap.get("nlf_01@48577").get("eventType"));
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
                "src/test/resources/postgre.json", new EventPartitionContextImpl(partitionContextMap), new EventPropertiesImpl(propertiesMap), new EventSystemPropertiesImpl(systemPropertiesMap), new EnqueuedTimeImpl("2010-01-01T00:00:00"), new EventOffsetImpl("0")
        );

        final PostgreSQLType type = new PostgreSQLType(parsedEvent, "localhost");

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

        Assertions
                .assertEquals(PostgreSQLType.class.getSimpleName(), sdElementMap.get("nlf_01@48577").get("eventType"));
    }
}
