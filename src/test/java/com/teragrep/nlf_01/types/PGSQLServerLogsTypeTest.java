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

import static org.junit.jupiter.api.Assertions.*;

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

class PGSQLServerLogsTypeTest {

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
        final ParsedEvent parsedEvent = testEvent(
                "src/test/resources/pgsqlserverlogs.json", new EventPartitionContextFake(), new EventPropertiesFake(),
                new EventSystemPropertiesFake(), new EnqueuedTimeImpl("2010-01-01T00:00:00"), new EventOffsetImpl("0")
        );

        final PGSQLServerLogsType type = new PGSQLServerLogsType(parsedEvent, "localhost");

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
        Assertions.assertEquals("md5-0ded52ef915af563e25778bf26b0f129-resourceName", actualHostname);
        Assertions
                .assertEquals(
                        "{\"BackendType\":\"backend\",\"ErrorLevel\":\"LOG\",\"_Internal_WorkspaceResourceId\":\"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}\",\"Location\":\"countrycentral\",\"LogicalServerName\":\"efgh-ijklmn-xx-DEV-01\",\"Message\":\"2020-10-01 11:59:26 UTC-12abcd3e.4f5678-user=user012,db=dbase_maintenance,app=[unknown],client=127.0.0.1LOG:  AUDIT: SESSION,4,1,WRITE,INSERT,,,\\\"insert into test.abcmover (id, update_time) select 1, now() on conflict on constraint abcmover_pk do update set id = test.abcmover.id+1, update_time=now()\\\",<not logged>\",\"ProcessId\":12345,\"ReplicaRole\":\"Primary\",\"_ResourceId\":\"/SUBSCRIPTIONS/uuid/RESOURCEGROUPS/ab-cd-efgh-ijklmn-xx-DEV-01/PROVIDERS/postgres-db/FLEXIBLESERVERS/efgh-ijklmn-xx-DEV-01\",\"SourceSystem\":\"Azure\",\"SqlErrorCode\":\"07000\",\"_SubscriptionId\":\"bb41a487-309b-4d21-9ab8-2a8b948b2d18\",\"TenantId\":\"bb41a487-309b-4d21-9ab8-2a8b948b2d18\",\"TimeGenerated\":\"2020-10-01T11:59:26.256Z\",\"Type\":\"PGSQLServerLogs\"}",
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
                .assertEquals(
                        "/SUBSCRIPTIONS/uuid/RESOURCEGROUPS/ab-cd-efgh-ijklmn-xx-DEV-01/PROVIDERS/postgres-db/FLEXIBLESERVERS/efgh-ijklmn-xx-DEV-01",
                        sdElementMap.get("origin@48577").get("_ResourceId")
                );

        Assertions
                .assertEquals(PGSQLServerLogsType.class.getSimpleName(), sdElementMap.get("nlf_01@48577").get("eventType"));
    }

    @Test
    void testWithAllMetadataStubs() {
        final ParsedEvent parsedEvent = testEvent(
                "src/test/resources/pgsqlserverlogs.json", new EventPartitionContextStub(), new EventPropertiesStub(),
                new EventSystemPropertiesStub(), new EnqueuedTimeStub(), new EventOffsetStub()
        );

        final PGSQLServerLogsType type = new PGSQLServerLogsType(parsedEvent, "localhost");

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
        Assertions.assertEquals("md5-0ded52ef915af563e25778bf26b0f129-resourceName", actualHostname);
        Assertions
                .assertEquals(
                        "{\"BackendType\":\"backend\",\"ErrorLevel\":\"LOG\",\"_Internal_WorkspaceResourceId\":\"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}\",\"Location\":\"countrycentral\",\"LogicalServerName\":\"efgh-ijklmn-xx-DEV-01\",\"Message\":\"2020-10-01 11:59:26 UTC-12abcd3e.4f5678-user=user012,db=dbase_maintenance,app=[unknown],client=127.0.0.1LOG:  AUDIT: SESSION,4,1,WRITE,INSERT,,,\\\"insert into test.abcmover (id, update_time) select 1, now() on conflict on constraint abcmover_pk do update set id = test.abcmover.id+1, update_time=now()\\\",<not logged>\",\"ProcessId\":12345,\"ReplicaRole\":\"Primary\",\"_ResourceId\":\"/SUBSCRIPTIONS/uuid/RESOURCEGROUPS/ab-cd-efgh-ijklmn-xx-DEV-01/PROVIDERS/postgres-db/FLEXIBLESERVERS/efgh-ijklmn-xx-DEV-01\",\"SourceSystem\":\"Azure\",\"SqlErrorCode\":\"07000\",\"_SubscriptionId\":\"bb41a487-309b-4d21-9ab8-2a8b948b2d18\",\"TenantId\":\"bb41a487-309b-4d21-9ab8-2a8b948b2d18\",\"TimeGenerated\":\"2020-10-01T11:59:26.256Z\",\"Type\":\"PGSQLServerLogs\"}",
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
                .assertEquals(
                        "/SUBSCRIPTIONS/uuid/RESOURCEGROUPS/ab-cd-efgh-ijklmn-xx-DEV-01/PROVIDERS/postgres-db/FLEXIBLESERVERS/efgh-ijklmn-xx-DEV-01",
                        sdElementMap.get("origin@48577").get("_ResourceId")
                );

        Assertions
                .assertEquals(PGSQLServerLogsType.class.getSimpleName(), sdElementMap.get("nlf_01@48577").get("eventType"));
    }

    @Test
    void testWithMissingJsonKeys() {
        final ParsedEvent parsedEvent = testEvent(
                "src/test/resources/pgsqlserverlogs_missing_keys.json", new EventPartitionContextStub(),
                new EventPropertiesStub(), new EventSystemPropertiesStub(), new EnqueuedTimeStub(),
                new EventOffsetStub()
        );

        final PGSQLServerLogsType type = new PGSQLServerLogsType(parsedEvent, "localhost");

        Assertions.assertThrows(PluginException.class, type::appName);
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
                        "{\"BackendType\":\"backend\",\"ErrorLevel\":\"LOG\",\"Location\":\"countrycentral\",\"LogicalServerName\":\"efgh-ijklmn-xx-DEV-01\",\"ProcessId\":12345,\"ReplicaRole\":\"Primary\",\"SourceSystem\":\"Azure\",\"SqlErrorCode\":\"07000\",\"_SubscriptionId\":\"bb41a487-309b-4d21-9ab8-2a8b948b2d18\",\"TenantId\":\"bb41a487-309b-4d21-9ab8-2a8b948b2d18\",\"Type\":\"PGSQLServerLogs\"}",
                        actualMsg
                );
        Assertions.assertEquals("", actualMsgId);
        Assertions.assertEquals(Severity.NOTICE, actualSeverity);
    }
}
