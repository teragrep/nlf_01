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
package com.teragrep.nlf_01;

import com.teragrep.akv_01.event.ParsedEvent;
import com.teragrep.akv_01.event.ParsedEventFactory;
import com.teragrep.akv_01.event.UnparsedEventImpl;
import com.teragrep.akv_01.event.metadata.offset.EventOffsetImpl;
import com.teragrep.akv_01.event.metadata.partitionContext.EventPartitionContextImpl;
import com.teragrep.akv_01.event.metadata.properties.EventPropertiesImpl;
import com.teragrep.akv_01.event.metadata.systemProperties.EventSystemPropertiesImpl;
import com.teragrep.akv_01.event.metadata.time.EnqueuedTimeImpl;
import com.teragrep.nlf_01.fakes.FakeSourceable;
import com.teragrep.nlf_01.types.DefaultEventType;
import com.teragrep.rlo_14.SDElement;
import com.teragrep.rlo_14.SDParam;
import com.teragrep.rlo_14.SyslogMessage;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

final class NLFPluginDatabricksTest {

    @Test
    @DisplayName("Test NLFPlugin with DatabricksAccounts")
    void testNlfPluginWithDatabricksAccounts() {
        final String json = Assertions
                .assertDoesNotThrow(
                        () -> Files.readString(Paths.get("src/test/resources/databricks/databricksaccounts.json"))
                );
        final ParsedEvent parsedEvent = new ParsedEventFactory(
                new UnparsedEventImpl(json, new EventPartitionContextImpl(new HashMap<>()), new EventPropertiesImpl(new HashMap<>()), new EventSystemPropertiesImpl(new HashMap<>()), new EnqueuedTimeImpl("2020-01-01T00:00:00"), new EventOffsetImpl("0"))
        ).parsedEvent();

        final NLFPlugin plugin = new NLFPlugin(new FakeSourceable());
        final List<SyslogMessage> syslogMessages = Assertions
                .assertDoesNotThrow(() -> plugin.syslogMessage(parsedEvent));
        Assertions.assertEquals(1, syslogMessages.size());

        final SyslogMessage syslogMessage = syslogMessages.get(0);
        Assertions
                .assertEquals(
                        "{\n" + "  \"ActionName\": \"ActionName-1\",\n" + "  \"Category\": \"category-1\",\n"
                                + "  \"Identity\": \"identity-1\",\n"
                                + "  \"LogId\": \"12345678-1234-1234-abcd-1234567890bc\",\n"
                                + "  \"OperationName\": \"Operation-1\",\n" + "  \"OperationVersion\": \"1.0.0\",\n"
                                + "  \"RequestId\": \"12345678-1234-1234-abcd-1234567890cd\",\n"
                                + "  \"RequestParams\": \"\\\"key\\\":\\\"value\\\"\",\n"
                                + "  \"Response\": \"Success\",\n" + "  \"ServiceName\": \"service-1\",\n"
                                + "  \"SessionId\": \"12345678-1234-1234-abcd-1234567890de\",\n"
                                + "  \"SourceIPAddress\": \"127.0.0.1\",\n" + "  \"SourceSystem\": \"Azure\",\n"
                                + "  \"TenantId\": \"12345678-1234-1234-abcd-1234567890ef\",\n"
                                + "  \"TimeGenerated\": \"2025-10-06T00:00:00.0000000Z\",\n"
                                + "  \"Type\": \"DatabricksAccounts\",\n"
                                + "  \"UserAgent\": \"User-Agent: Mozilla/5.0 (<system-information>) <platform> (<platform-details>) <extensions>\",\n"
                                + "  \"_ResourceId\": \"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}\",\n"
                                + "  \"_SubscriptionId\": \"12345678-1234-1234-abcd-1234567890fg\"\n" + "}",
                        syslogMessage.getMsg()
                );
        Assertions.assertEquals("md5-0ded52ef915af563e25778bf26b0f129-resourceName", syslogMessage.getHostname());
        Assertions.assertEquals("DatabricksAccounts", syslogMessage.getAppName());
        Assertions.assertEquals("2025-10-06T00:00:00Z", syslogMessage.getTimestamp());

        final Map<String, Map<String, String>> sdElementMap = syslogMessage
                .getSDElements()
                .stream()
                .collect(Collectors.toMap((SDElement::getSdID), (sdElem) -> sdElem.getSdParams().stream().collect(Collectors.toMap(SDParam::getParamName, SDParam::getParamValue))));

        Assertions.assertEquals(1, sdElementMap.get("nlf_01@48577").size());
        Assertions
                .assertEquals(DefaultEventType.class.getSimpleName(), sdElementMap.get("nlf_01@48577").get("eventType"));

        Assertions.assertTrue(sdElementMap.get("aer_event@48577").containsKey("properties"));
    }

    @Test
    @DisplayName("Test NLFPlugin with DatabricksApps")
    void testNlfPluginWithDatabricksApps() {
        final String json = Assertions

                .assertDoesNotThrow(() -> Files.readString(Paths.get("src/test/resources/databricks/databricksapps.json")));
        final ParsedEvent parsedEvent = new ParsedEventFactory(
                new UnparsedEventImpl(json, new EventPartitionContextImpl(new HashMap<>()), new EventPropertiesImpl(new HashMap<>()), new EventSystemPropertiesImpl(new HashMap<>()), new EnqueuedTimeImpl("2020-01-01T00:00:00"), new EventOffsetImpl("0"))
        ).parsedEvent();

        final NLFPlugin plugin = new NLFPlugin(new FakeSourceable());
        final List<SyslogMessage> syslogMessages = Assertions

                .assertDoesNotThrow(() -> plugin.syslogMessage(parsedEvent));
        Assertions.assertEquals(1, syslogMessages.size());

        final SyslogMessage syslogMessage = syslogMessages.get(0);
        Assertions
                .assertEquals(
                        "{\n" + "  \"ActionName\": \"ActionName-2\",\n" + "  \"Category\": \"category-2\",\n"
                                + "  \"Identity\": \"identity-2\",\n"
                                + "  \"LogId\": \"12345678-1234-1234-abcd-1234567890bc\",\n"
                                + "  \"OperationName\": \"Operation-2\",\n" + "  \"OperationVersion\": \"1.0.0\",\n"
                                + "  \"RequestId\": \"12345678-1234-1234-abcd-1234567890cd\",\n"
                                + "  \"RequestParams\": \"\\\"key\\\":\\\"value\\\"\",\n"
                                + "  \"Response\": \"Success\",\n" + "  \"ServiceName\": \"service-2\",\n"
                                + "  \"SessionId\": \"12345678-1234-1234-abcd-1234567890de\",\n"
                                + "  \"SourceIpAddress\": \"127.0.0.1\",\n" + "  \"SourceSystem\": \"Azure\",\n"
                                + "  \"TenantId\": \"12345678-1234-1234-abcd-1234567890ef\",\n"
                                + "  \"TimeGenerated\": \"2025-10-06T00:00:00.0000000Z\",\n"
                                + "  \"Type\": \"DatabricksApps\",\n"
                                + "  \"UserAgent\": \"User-Agent: Mozilla/5.0 (<system-information>) <platform> (<platform-details>) <extensions>\",\n"
                                + "  \"_ResourceId\": \"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}\",\n"
                                + "  \"_SubscriptionId\": \"12345678-1234-1234-abcd-1234567890fg\"\n" + "}",
                        syslogMessage.getMsg()
                );
        Assertions.assertEquals("md5-0ded52ef915af563e25778bf26b0f129-resourceName", syslogMessage.getHostname());
        Assertions.assertEquals("DatabricksApps", syslogMessage.getAppName());
        Assertions.assertEquals("2025-10-06T00:00:00Z", syslogMessage.getTimestamp());

        final Map<String, Map<String, String>> sdElementMap = syslogMessage
                .getSDElements()
                .stream()
                .collect(Collectors.toMap((SDElement::getSdID), (sdElem) -> sdElem.getSdParams().stream().collect(Collectors.toMap(SDParam::getParamName, SDParam::getParamValue))));

        Assertions.assertEquals(1, sdElementMap.get("nlf_01@48577").size());
        Assertions
                .assertEquals(DefaultEventType.class.getSimpleName(), sdElementMap.get("nlf_01@48577").get("eventType"));

        Assertions.assertTrue(sdElementMap.get("aer_event@48577").containsKey("properties"));
    }

    @Test
    @DisplayName("Test NLFPlugin with DatabricksBrickStoreHttpGateway")
    void testNlfPluginWithDatabricksBrickStoreHttpGateway() {
        final String json = Assertions
                .assertDoesNotThrow(
                        () -> Files
                                .readString(
                                        Paths.get("src/test/resources/databricks/databricksbrickstorehttpgateway.json")
                                )
                );
        final ParsedEvent parsedEvent = new ParsedEventFactory(
                new UnparsedEventImpl(json, new EventPartitionContextImpl(new HashMap<>()), new EventPropertiesImpl(new HashMap<>()), new EventSystemPropertiesImpl(new HashMap<>()), new EnqueuedTimeImpl("2020-01-01T00:00:00"), new EventOffsetImpl("0"))
        ).parsedEvent();

        final NLFPlugin plugin = new NLFPlugin(new FakeSourceable());
        final List<SyslogMessage> syslogMessages = Assertions
                .assertDoesNotThrow(() -> plugin.syslogMessage(parsedEvent));
        Assertions.assertEquals(1, syslogMessages.size());

        final SyslogMessage syslogMessage = syslogMessages.get(0);
        Assertions
                .assertEquals(
                        "{\n" + "  \"ActionName\": \"ActionName-3\",\n" + "  \"Category\": \"category-3\",\n"
                                + "  \"Identity\": \"identity-3\",\n"
                                + "  \"LogId\": \"12345678-1234-1234-abcd-1234567890bc\",\n"
                                + "  \"OperationName\": \"Operation-3\",\n" + "  \"OperationVersion\": \"1.0.0\",\n"
                                + "  \"RequestId\": \"12345678-1234-1234-abcd-1234567890cd\",\n"
                                + "  \"RequestParams\": \"\\\"key\\\":\\\"value\\\"\",\n"
                                + "  \"Response\": \"Success\",\n" + "  \"ServiceName\": \"service-3\",\n"
                                + "  \"SessionId\": \"12345678-1234-1234-abcd-1234567890de\",\n"
                                + "  \"SourceIPAddress\": \"127.0.0.1\",\n" + "  \"SourceSystem\": \"Azure\",\n"
                                + "  \"TenantId\": \"12345678-1234-1234-abcd-1234567890ef\",\n"
                                + "  \"TimeGenerated\": \"2025-10-06T00:00:00.0000000Z\",\n"
                                + "  \"Type\": \"DatabricksBrickStoreHttpGateway\",\n"
                                + "  \"UserAgent\": \"User-Agent: Mozilla/5.0 (<system-information>) <platform> (<platform-details>) <extensions>\",\n"
                                + "  \"_ResourceId\": \"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}\",\n"
                                + "  \"_SubscriptionId\": \"12345678-1234-1234-abcd-1234567890fg\"\n" + "}",
                        syslogMessage.getMsg()
                );
        Assertions.assertEquals("md5-0ded52ef915af563e25778bf26b0f129-resourceName", syslogMessage.getHostname());
        Assertions.assertEquals("DatabricksBrickStoreHttpGateway", syslogMessage.getAppName());
        Assertions.assertEquals("2025-10-06T00:00:00Z", syslogMessage.getTimestamp());

        final Map<String, Map<String, String>> sdElementMap = syslogMessage
                .getSDElements()
                .stream()
                .collect(Collectors.toMap((SDElement::getSdID), (sdElem) -> sdElem.getSdParams().stream().collect(Collectors.toMap(SDParam::getParamName, SDParam::getParamValue))));

        Assertions.assertEquals(1, sdElementMap.get("nlf_01@48577").size());
        Assertions
                .assertEquals(DefaultEventType.class.getSimpleName(), sdElementMap.get("nlf_01@48577").get("eventType"));

        Assertions.assertTrue(sdElementMap.get("aer_event@48577").containsKey("properties"));
    }

    @Test
    @DisplayName("Test NLFPlugin with DatabricksBudgetPolicyCentral")
    void testNlfPluginWithDatabricksBudgetPolicyCentral() {
        final String json = Assertions
                .assertDoesNotThrow(
                        () -> Files
                                .readString(Paths.get("src/test/resources/databricks/databricksbudgetpolicycentral.json"))
                );
        final ParsedEvent parsedEvent = new ParsedEventFactory(
                new UnparsedEventImpl(json, new EventPartitionContextImpl(new HashMap<>()), new EventPropertiesImpl(new HashMap<>()), new EventSystemPropertiesImpl(new HashMap<>()), new EnqueuedTimeImpl("2020-01-01T00:00:00"), new EventOffsetImpl("0"))
        ).parsedEvent();

        final NLFPlugin plugin = new NLFPlugin(new FakeSourceable());
        final List<SyslogMessage> syslogMessages = Assertions
                .assertDoesNotThrow(() -> plugin.syslogMessage(parsedEvent));
        Assertions.assertEquals(1, syslogMessages.size());

        final SyslogMessage syslogMessage = syslogMessages.get(0);
        Assertions
                .assertEquals(
                        "{\n" + "  \"ActionName\": \"ActionName-4\",\n" + "  \"Category\": \"category-4\",\n"
                                + "  \"Identity\": \"identity-4\",\n"
                                + "  \"LogId\": \"12345678-1234-1234-abcd-1234567890bc\",\n"
                                + "  \"OperationName\": \"Operation-4\",\n" + "  \"OperationVersion\": \"1.0.0\",\n"
                                + "  \"RequestId\": \"12345678-1234-1234-abcd-1234567890cd\",\n"
                                + "  \"RequestParams\": \"\\\"key\\\":\\\"value\\\"\",\n"
                                + "  \"Response\": \"Success\",\n" + "  \"ServiceName\": \"service-4\",\n"
                                + "  \"SessionId\": \"12345678-1234-1234-abcd-1234567890de\",\n"
                                + "  \"SourceIpAddress\": \"127.0.0.1\",\n" + "  \"SourceSystem\": \"Azure\",\n"
                                + "  \"TenantId\": \"12345678-1234-1234-abcd-1234567890ef\",\n"
                                + "  \"TimeGenerated\": \"2025-10-06T00:00:00.0000000Z\",\n"
                                + "  \"Type\": \"DatabricksBudgetPolicyCentral\",\n"
                                + "  \"UserAgent\": \"User-Agent: Mozilla/5.0 (<system-information>) <platform> (<platform-details>) <extensions>\",\n"
                                + "  \"_ResourceId\": \"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}\",\n"
                                + "  \"_SubscriptionId\": \"12345678-1234-1234-abcd-1234567890fg\"\n" + "}",
                        syslogMessage.getMsg()
                );
        Assertions.assertEquals("md5-0ded52ef915af563e25778bf26b0f129-resourceName", syslogMessage.getHostname());
        Assertions.assertEquals("DatabricksBudgetPolicyCentral", syslogMessage.getAppName());
        Assertions.assertEquals("2025-10-06T00:00:00Z", syslogMessage.getTimestamp());

        final Map<String, Map<String, String>> sdElementMap = syslogMessage
                .getSDElements()
                .stream()
                .collect(Collectors.toMap((SDElement::getSdID), (sdElem) -> sdElem.getSdParams().stream().collect(Collectors.toMap(SDParam::getParamName, SDParam::getParamValue))));

        Assertions.assertEquals(1, sdElementMap.get("nlf_01@48577").size());
        Assertions
                .assertEquals(DefaultEventType.class.getSimpleName(), sdElementMap.get("nlf_01@48577").get("eventType"));

        Assertions.assertTrue(sdElementMap.get("aer_event@48577").containsKey("properties"));
    }

    @Test
    @DisplayName("Test NLFPlugin with DatabricksCapsule8Dataplane")
    void testNlfPluginWithDatabricksCapsule8Dataplane() {
        final String json = Assertions
                .assertDoesNotThrow(
                        () -> Files
                                .readString(Paths.get("src/test/resources/databricks/databrickscapsule8dataplane.json"))
                );
        final ParsedEvent parsedEvent = new ParsedEventFactory(
                new UnparsedEventImpl(json, new EventPartitionContextImpl(new HashMap<>()), new EventPropertiesImpl(new HashMap<>()), new EventSystemPropertiesImpl(new HashMap<>()), new EnqueuedTimeImpl("2020-01-01T00:00:00"), new EventOffsetImpl("0"))
        ).parsedEvent();

        final NLFPlugin plugin = new NLFPlugin(new FakeSourceable());
        final List<SyslogMessage> syslogMessages = Assertions
                .assertDoesNotThrow(() -> plugin.syslogMessage(parsedEvent));
        Assertions.assertEquals(1, syslogMessages.size());

        final SyslogMessage syslogMessage = syslogMessages.get(0);
        Assertions
                .assertEquals(
                        "{\n" + "  \"ActionName\": \"ActionName-5\",\n" + "  \"Category\": \"category-5\",\n"
                                + "  \"Identity\": \"identity-5\",\n"
                                + "  \"LogId\": \"12345678-1234-1234-abcd-1234567890bc\",\n"
                                + "  \"OperationName\": \"Operation-5\",\n" + "  \"OperationVersion\": \"1.0.0\",\n"
                                + "  \"RequestId\": \"12345678-1234-1234-abcd-1234567890cd\",\n"
                                + "  \"RequestParams\": \"\\\"key\\\":\\\"value\\\"\",\n"
                                + "  \"Response\": \"Success\",\n" + "  \"ServiceName\": \"service-5\",\n"
                                + "  \"SessionId\": \"12345678-1234-1234-abcd-1234567890de\",\n"
                                + "  \"SourceIPAddress\": \"127.0.0.1\",\n" + "  \"SourceSystem\": \"Azure\",\n"
                                + "  \"TenantId\": \"12345678-1234-1234-abcd-1234567890ef\",\n"
                                + "  \"TimeGenerated\": \"2025-10-06T00:00:00.0000000Z\",\n"
                                + "  \"Type\": \"DatabricksCapsule8Dataplane\",\n"
                                + "  \"UserAgent\": \"User-Agent: Mozilla/5.0 (<system-information>) <platform> (<platform-details>) <extensions>\",\n"
                                + "  \"_ResourceId\": \"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}\",\n"
                                + "  \"_SubscriptionId\": \"12345678-1234-1234-abcd-1234567890fg\"\n" + "}",
                        syslogMessage.getMsg()
                );
        Assertions.assertEquals("md5-0ded52ef915af563e25778bf26b0f129-resourceName", syslogMessage.getHostname());
        Assertions.assertEquals("DatabricksCapsule8Dataplane", syslogMessage.getAppName());
        Assertions.assertEquals("2025-10-06T00:00:00Z", syslogMessage.getTimestamp());

        final Map<String, Map<String, String>> sdElementMap = syslogMessage
                .getSDElements()
                .stream()
                .collect(Collectors.toMap((SDElement::getSdID), (sdElem) -> sdElem.getSdParams().stream().collect(Collectors.toMap(SDParam::getParamName, SDParam::getParamValue))));

        Assertions.assertEquals(1, sdElementMap.get("nlf_01@48577").size());
        Assertions
                .assertEquals(DefaultEventType.class.getSimpleName(), sdElementMap.get("nlf_01@48577").get("eventType"));

        Assertions.assertTrue(sdElementMap.get("aer_event@48577").containsKey("properties"));
    }

    @Test
    @DisplayName("Test NLFPlugin with DatabricksClamAVScan")
    void testNlfPluginWithDatabricksClamAvScan() {
        final String json = Assertions
                .assertDoesNotThrow(
                        () -> Files.readString(Paths.get("src/test/resources/databricks/databricksclamavscan.json"))
                );
        final ParsedEvent parsedEvent = new ParsedEventFactory(
                new UnparsedEventImpl(json, new EventPartitionContextImpl(new HashMap<>()), new EventPropertiesImpl(new HashMap<>()), new EventSystemPropertiesImpl(new HashMap<>()), new EnqueuedTimeImpl("2020-01-01T00:00:00"), new EventOffsetImpl("0"))
        ).parsedEvent();

        final NLFPlugin plugin = new NLFPlugin(new FakeSourceable());
        final List<SyslogMessage> syslogMessages = Assertions
                .assertDoesNotThrow(() -> plugin.syslogMessage(parsedEvent));
        Assertions.assertEquals(1, syslogMessages.size());

        final SyslogMessage syslogMessage = syslogMessages.get(0);
        Assertions
                .assertEquals(
                        "{\n" + "  \"ActionName\": \"ActionName-6\",\n" + "  \"Category\": \"category-6\",\n"
                                + "  \"Identity\": \"identity-6\",\n"
                                + "  \"LogId\": \"12345678-1234-1234-abcd-1234567890bc\",\n"
                                + "  \"OperationName\": \"Operation-6\",\n" + "  \"OperationVersion\": \"1.0.0\",\n"
                                + "  \"RequestId\": \"12345678-1234-1234-abcd-1234567890cd\",\n"
                                + "  \"RequestParams\": \"\\\"key\\\":\\\"value\\\"\",\n"
                                + "  \"Response\": \"Success\",\n" + "  \"ServiceName\": \"service-6\",\n"
                                + "  \"SessionId\": \"12345678-1234-1234-abcd-1234567890de\",\n"
                                + "  \"SourceIPAddress\": \"127.0.0.1\",\n" + "  \"SourceSystem\": \"Azure\",\n"
                                + "  \"TenantId\": \"12345678-1234-1234-abcd-1234567890ef\",\n"
                                + "  \"TimeGenerated\": \"2025-10-06T00:00:00.0000000Z\",\n"
                                + "  \"Type\": \"DatabricksClamAVScan\",\n"
                                + "  \"UserAgent\": \"User-Agent: Mozilla/5.0 (<system-information>) <platform> (<platform-details>) <extensions>\",\n"
                                + "  \"_ResourceId\": \"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}\",\n"
                                + "  \"_SubscriptionId\": \"12345678-1234-1234-abcd-1234567890fg\"\n" + "}",
                        syslogMessage.getMsg()
                );
        Assertions.assertEquals("md5-0ded52ef915af563e25778bf26b0f129-resourceName", syslogMessage.getHostname());
        Assertions.assertEquals("DatabricksClamAVScan", syslogMessage.getAppName());
        Assertions.assertEquals("2025-10-06T00:00:00Z", syslogMessage.getTimestamp());

        final Map<String, Map<String, String>> sdElementMap = syslogMessage
                .getSDElements()
                .stream()
                .collect(Collectors.toMap((SDElement::getSdID), (sdElem) -> sdElem.getSdParams().stream().collect(Collectors.toMap(SDParam::getParamName, SDParam::getParamValue))));

        Assertions.assertEquals(1, sdElementMap.get("nlf_01@48577").size());
        Assertions
                .assertEquals(DefaultEventType.class.getSimpleName(), sdElementMap.get("nlf_01@48577").get("eventType"));

        Assertions.assertTrue(sdElementMap.get("aer_event@48577").containsKey("properties"));
    }

    @Test
    @DisplayName("Test NLFPlugin with DatabricksCloudStorageMetadata")
    void testNlfPluginWithDatabricksCloudStorageMetadata() {
        final String json = Assertions
                .assertDoesNotThrow(
                        () -> Files
                                .readString(
                                        Paths.get("src/test/resources/databricks/databrickscloudstoragemetadata.json")
                                )
                );
        final ParsedEvent parsedEvent = new ParsedEventFactory(
                new UnparsedEventImpl(json, new EventPartitionContextImpl(new HashMap<>()), new EventPropertiesImpl(new HashMap<>()), new EventSystemPropertiesImpl(new HashMap<>()), new EnqueuedTimeImpl("2020-01-01T00:00:00"), new EventOffsetImpl("0"))
        ).parsedEvent();

        final NLFPlugin plugin = new NLFPlugin(new FakeSourceable());
        final List<SyslogMessage> syslogMessages = Assertions
                .assertDoesNotThrow(() -> plugin.syslogMessage(parsedEvent));
        Assertions.assertEquals(1, syslogMessages.size());

        final SyslogMessage syslogMessage = syslogMessages.get(0);
        Assertions
                .assertEquals(
                        "{\n" + "  \"ActionName\": \"ActionName-7\",\n" + "  \"Category\": \"category-7\",\n"
                                + "  \"Identity\": \"identity-7\",\n"
                                + "  \"LogId\": \"12345678-1234-1234-abcd-1234567890bc\",\n"
                                + "  \"OperationName\": \"Operation-7\",\n" + "  \"OperationVersion\": \"1.0.0\",\n"
                                + "  \"RequestId\": \"12345678-1234-1234-abcd-1234567890cd\",\n"
                                + "  \"RequestParams\": \"\\\"key\\\":\\\"value\\\"\",\n"
                                + "  \"Response\": \"Success\",\n" + "  \"ServiceName\": \"service-7\",\n"
                                + "  \"SessionId\": \"12345678-1234-1234-abcd-1234567890de\",\n"
                                + "  \"SourceIpAddress\": \"127.0.0.1\",\n" + "  \"SourceSystem\": \"Azure\",\n"
                                + "  \"TenantId\": \"12345678-1234-1234-abcd-1234567890ef\",\n"
                                + "  \"TimeGenerated\": \"2025-10-06T00:00:00.0000000Z\",\n"
                                + "  \"Type\": \"DatabricksCloudStorageMetadata\",\n"
                                + "  \"UserAgent\": \"User-Agent: Mozilla/5.0 (<system-information>) <platform> (<platform-details>) <extensions>\",\n"
                                + "  \"_ResourceId\": \"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}\",\n"
                                + "  \"_SubscriptionId\": \"12345678-1234-1234-abcd-1234567890fg\"\n" + "}",
                        syslogMessage.getMsg()
                );
        Assertions.assertEquals("md5-0ded52ef915af563e25778bf26b0f129-resourceName", syslogMessage.getHostname());
        Assertions.assertEquals("DatabricksCloudStorageMetadata", syslogMessage.getAppName());
        Assertions.assertEquals("2025-10-06T00:00:00Z", syslogMessage.getTimestamp());

        final Map<String, Map<String, String>> sdElementMap = syslogMessage
                .getSDElements()
                .stream()
                .collect(Collectors.toMap((SDElement::getSdID), (sdElem) -> sdElem.getSdParams().stream().collect(Collectors.toMap(SDParam::getParamName, SDParam::getParamValue))));

        Assertions.assertEquals(1, sdElementMap.get("nlf_01@48577").size());
        Assertions
                .assertEquals(DefaultEventType.class.getSimpleName(), sdElementMap.get("nlf_01@48577").get("eventType"));

        Assertions.assertTrue(sdElementMap.get("aer_event@48577").containsKey("properties"));
    }

    @Test
    @DisplayName("Test NLFPlugin with DatabricksClusterLibraries")
    void testNlfPluginWithDatabricksClusterLibraries() {
        final String json = Assertions
                .assertDoesNotThrow(
                        () -> Files.readString(Paths.get("src/test/resources/databricks/databricksclusterlibraries.json"))
                );
        final ParsedEvent parsedEvent = new ParsedEventFactory(
                new UnparsedEventImpl(json, new EventPartitionContextImpl(new HashMap<>()), new EventPropertiesImpl(new HashMap<>()), new EventSystemPropertiesImpl(new HashMap<>()), new EnqueuedTimeImpl("2020-01-01T00:00:00"), new EventOffsetImpl("0"))
        ).parsedEvent();

        final NLFPlugin plugin = new NLFPlugin(new FakeSourceable());
        final List<SyslogMessage> syslogMessages = Assertions
                .assertDoesNotThrow(() -> plugin.syslogMessage(parsedEvent));
        Assertions.assertEquals(1, syslogMessages.size());

        final SyslogMessage syslogMessage = syslogMessages.get(0);
        Assertions
                .assertEquals(
                        "{\n" + "  \"ActionName\": \"ActionName-8\",\n" + "  \"Category\": \"category-8\",\n"
                                + "  \"Identity\": \"identity-8\",\n"
                                + "  \"LogId\": \"12345678-1234-1234-abcd-1234567890bc\",\n"
                                + "  \"OperationName\": \"Operation-8\",\n" + "  \"OperationVersion\": \"1.0.0\",\n"
                                + "  \"RequestId\": \"12345678-1234-1234-abcd-1234567890cd\",\n"
                                + "  \"RequestParams\": \"\\\"key\\\":\\\"value\\\"\",\n"
                                + "  \"Response\": \"Success\",\n" + "  \"ServiceName\": \"service-8\",\n"
                                + "  \"SessionId\": \"12345678-1234-1234-abcd-1234567890de\",\n"
                                + "  \"SourceIPAddress\": \"127.0.0.1\",\n" + "  \"SourceSystem\": \"Azure\",\n"
                                + "  \"TenantId\": \"12345678-1234-1234-abcd-1234567890ef\",\n"
                                + "  \"TimeGenerated\": \"2025-10-06T00:00:00.0000000Z\",\n"
                                + "  \"Type\": \"DatabricksClusterLibraries\",\n"
                                + "  \"UserAgent\": \"User-Agent: Mozilla/5.0 (<system-information>) <platform> (<platform-details>) <extensions>\",\n"
                                + "  \"_ResourceId\": \"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}\",\n"
                                + "  \"_SubscriptionId\": \"12345678-1234-1234-abcd-1234567890fg\"\n" + "}",
                        syslogMessage.getMsg()
                );
        Assertions.assertEquals("md5-0ded52ef915af563e25778bf26b0f129-resourceName", syslogMessage.getHostname());
        Assertions.assertEquals("DatabricksClusterLibraries", syslogMessage.getAppName());
        Assertions.assertEquals("2025-10-06T00:00:00Z", syslogMessage.getTimestamp());

        final Map<String, Map<String, String>> sdElementMap = syslogMessage
                .getSDElements()
                .stream()
                .collect(Collectors.toMap((SDElement::getSdID), (sdElem) -> sdElem.getSdParams().stream().collect(Collectors.toMap(SDParam::getParamName, SDParam::getParamValue))));

        Assertions.assertEquals(1, sdElementMap.get("nlf_01@48577").size());
        Assertions
                .assertEquals(DefaultEventType.class.getSimpleName(), sdElementMap.get("nlf_01@48577").get("eventType"));

        Assertions.assertTrue(sdElementMap.get("aer_event@48577").containsKey("properties"));
    }

    @Test
    @DisplayName("Test NLFPlugin with DatabricksClusterPolicies")
    void testNlfPluginWithDatabricksClusterPolicies() {
        final String json = Assertions
                .assertDoesNotThrow(
                        () -> Files.readString(Paths.get("src/test/resources/databricks/databricksclusterpolicies.json"))
                );
        final ParsedEvent parsedEvent = new ParsedEventFactory(
                new UnparsedEventImpl(json, new EventPartitionContextImpl(new HashMap<>()), new EventPropertiesImpl(new HashMap<>()), new EventSystemPropertiesImpl(new HashMap<>()), new EnqueuedTimeImpl("2020-01-01T00:00:00"), new EventOffsetImpl("0"))
        ).parsedEvent();

        final NLFPlugin plugin = new NLFPlugin(new FakeSourceable());
        final List<SyslogMessage> syslogMessages = Assertions
                .assertDoesNotThrow(() -> plugin.syslogMessage(parsedEvent));
        Assertions.assertEquals(1, syslogMessages.size());

        final SyslogMessage syslogMessage = syslogMessages.get(0);
        Assertions
                .assertEquals(
                        "{\n" + "  \"ActionName\": \"ActionName-9\",\n" + "  \"Category\": \"category-9\",\n"
                                + "  \"Identity\": \"identity-9\",\n"
                                + "  \"LogId\": \"12345678-1234-1234-abcd-1234567890bc\",\n"
                                + "  \"OperationName\": \"Operation-9\",\n" + "  \"OperationVersion\": \"1.0.0\",\n"
                                + "  \"RequestId\": \"12345678-1234-1234-abcd-1234567890cd\",\n"
                                + "  \"RequestParams\": \"\\\"key\\\":\\\"value\\\"\",\n"
                                + "  \"Response\": \"Success\",\n" + "  \"ServiceName\": \"service-9\",\n"
                                + "  \"SessionId\": \"12345678-1234-1234-abcd-1234567890de\",\n"
                                + "  \"SourceIpAddress\": \"127.0.0.1\",\n" + "  \"SourceSystem\": \"Azure\",\n"
                                + "  \"TenantId\": \"12345678-1234-1234-abcd-1234567890ef\",\n"
                                + "  \"TimeGenerated\": \"2025-10-06T00:00:00.0000000Z\",\n"
                                + "  \"Type\": \"DatabricksClusterPolicies\",\n"
                                + "  \"UserAgent\": \"User-Agent: Mozilla/5.0 (<system-information>) <platform> (<platform-details>) <extensions>\",\n"
                                + "  \"_ResourceId\": \"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}\",\n"
                                + "  \"_SubscriptionId\": \"12345678-1234-1234-abcd-1234567890fg\"\n" + "}",
                        syslogMessage.getMsg()
                );
        Assertions.assertEquals("md5-0ded52ef915af563e25778bf26b0f129-resourceName", syslogMessage.getHostname());
        Assertions.assertEquals("DatabricksClusterPolicies", syslogMessage.getAppName());
        Assertions.assertEquals("2025-10-06T00:00:00Z", syslogMessage.getTimestamp());

        final Map<String, Map<String, String>> sdElementMap = syslogMessage
                .getSDElements()
                .stream()
                .collect(Collectors.toMap((SDElement::getSdID), (sdElem) -> sdElem.getSdParams().stream().collect(Collectors.toMap(SDParam::getParamName, SDParam::getParamValue))));

        Assertions.assertEquals(1, sdElementMap.get("nlf_01@48577").size());
        Assertions
                .assertEquals(DefaultEventType.class.getSimpleName(), sdElementMap.get("nlf_01@48577").get("eventType"));

        Assertions.assertTrue(sdElementMap.get("aer_event@48577").containsKey("properties"));
    }

    @Test
    @DisplayName("Test NLFPlugin with DatabricksClusters")
    void testNlfPluginWithDatabricksClusters() {
        final String json = Assertions
                .assertDoesNotThrow(
                        () -> Files.readString(Paths.get("src/test/resources/databricks/databricksclusters.json"))
                );
        final ParsedEvent parsedEvent = new ParsedEventFactory(
                new UnparsedEventImpl(json, new EventPartitionContextImpl(new HashMap<>()), new EventPropertiesImpl(new HashMap<>()), new EventSystemPropertiesImpl(new HashMap<>()), new EnqueuedTimeImpl("2020-01-01T00:00:00"), new EventOffsetImpl("0"))
        ).parsedEvent();

        final NLFPlugin plugin = new NLFPlugin(new FakeSourceable());
        final List<SyslogMessage> syslogMessages = Assertions
                .assertDoesNotThrow(() -> plugin.syslogMessage(parsedEvent));
        Assertions.assertEquals(1, syslogMessages.size());

        final SyslogMessage syslogMessage = syslogMessages.get(0);
        Assertions
                .assertEquals(
                        "{\n" + "  \"ActionName\": \"ActionName-10\",\n" + "  \"Category\": \"category-10\",\n"
                                + "  \"Identity\": \"identity-10\",\n"
                                + "  \"LogId\": \"12345678-1234-1234-abcd-1234567890bc\",\n"
                                + "  \"OperationName\": \"Operation-10\",\n" + "  \"OperationVersion\": \"1.0.0\",\n"
                                + "  \"RequestId\": \"12345678-1234-1234-abcd-1234567890cd\",\n"
                                + "  \"RequestParams\": \"\\\"key\\\":\\\"value\\\"\",\n"
                                + "  \"Response\": \"Success\",\n" + "  \"ServiceName\": \"service-10\",\n"
                                + "  \"SessionId\": \"12345678-1234-1234-abcd-1234567890de\",\n"
                                + "  \"SourceIPAddress\": \"127.0.0.1\",\n" + "  \"SourceSystem\": \"Azure\",\n"
                                + "  \"TenantId\": \"12345678-1234-1234-abcd-1234567890ef\",\n"
                                + "  \"TimeGenerated\": \"2025-10-06T00:00:00.0000000Z\",\n"
                                + "  \"Type\": \"DatabricksClusters\",\n"
                                + "  \"UserAgent\": \"User-Agent: Mozilla/5.0 (<system-information>) <platform> (<platform-details>) <extensions>\",\n"
                                + "  \"_ResourceId\": \"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}\",\n"
                                + "  \"_SubscriptionId\": \"12345678-1234-1234-abcd-1234567890fg\"\n" + "}",
                        syslogMessage.getMsg()
                );
        Assertions.assertEquals("md5-0ded52ef915af563e25778bf26b0f129-resourceName", syslogMessage.getHostname());
        Assertions.assertEquals("DatabricksClusters", syslogMessage.getAppName());
        Assertions.assertEquals("2025-10-06T00:00:00Z", syslogMessage.getTimestamp());

        final Map<String, Map<String, String>> sdElementMap = syslogMessage
                .getSDElements()
                .stream()
                .collect(Collectors.toMap((SDElement::getSdID), (sdElem) -> sdElem.getSdParams().stream().collect(Collectors.toMap(SDParam::getParamName, SDParam::getParamValue))));

        Assertions.assertEquals(1, sdElementMap.get("nlf_01@48577").size());
        Assertions
                .assertEquals(DefaultEventType.class.getSimpleName(), sdElementMap.get("nlf_01@48577").get("eventType"));

        Assertions.assertTrue(sdElementMap.get("aer_event@48577").containsKey("properties"));
    }

    @Test
    @DisplayName("Test NLFPlugin with DatabricksDashboards")
    void testNlfPluginWithDatabricksDashboards() {
        final String json = Assertions
                .assertDoesNotThrow(
                        () -> Files.readString(Paths.get("src/test/resources/databricks/databricksdashboards.json"))
                );
        final ParsedEvent parsedEvent = new ParsedEventFactory(
                new UnparsedEventImpl(json, new EventPartitionContextImpl(new HashMap<>()), new EventPropertiesImpl(new HashMap<>()), new EventSystemPropertiesImpl(new HashMap<>()), new EnqueuedTimeImpl("2020-01-01T00:00:00"), new EventOffsetImpl("0"))
        ).parsedEvent();

        final NLFPlugin plugin = new NLFPlugin(new FakeSourceable());
        final List<SyslogMessage> syslogMessages = Assertions
                .assertDoesNotThrow(() -> plugin.syslogMessage(parsedEvent));
        Assertions.assertEquals(1, syslogMessages.size());

        final SyslogMessage syslogMessage = syslogMessages.get(0);
        Assertions
                .assertEquals(
                        "{\n" + "  \"ActionName\": \"ActionName-11\",\n" + "  \"Category\": \"category-11\",\n"
                                + "  \"Identity\": \"identity-11\",\n"
                                + "  \"LogId\": \"12345678-1234-1234-abcd-1234567890bc\",\n"
                                + "  \"OperationName\": \"Operation-11\",\n" + "  \"OperationVersion\": \"1.0.0\",\n"
                                + "  \"RequestId\": \"12345678-1234-1234-abcd-1234567890cd\",\n"
                                + "  \"RequestParams\": \"\\\"key\\\":\\\"value\\\"\",\n"
                                + "  \"Response\": \"Success\",\n" + "  \"ServiceName\": \"service-11\",\n"
                                + "  \"SessionId\": \"12345678-1234-1234-abcd-1234567890de\",\n"
                                + "  \"SourceIpAddress\": \"127.0.0.1\",\n" + "  \"SourceSystem\": \"Azure\",\n"
                                + "  \"TenantId\": \"12345678-1234-1234-abcd-1234567890ef\",\n"
                                + "  \"TimeGenerated\": \"2025-10-06T00:00:00.0000000Z\",\n"
                                + "  \"Type\": \"DatabricksDashboards\",\n"
                                + "  \"UserAgent\": \"User-Agent: Mozilla/5.0 (<system-information>) <platform> (<platform-details>) <extensions>\",\n"
                                + "  \"_ResourceId\": \"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}\",\n"
                                + "  \"_SubscriptionId\": \"12345678-1234-1234-abcd-1234567890fg\"\n" + "}",
                        syslogMessage.getMsg()
                );
        Assertions.assertEquals("md5-0ded52ef915af563e25778bf26b0f129-resourceName", syslogMessage.getHostname());
        Assertions.assertEquals("DatabricksDashboards", syslogMessage.getAppName());
        Assertions.assertEquals("2025-10-06T00:00:00Z", syslogMessage.getTimestamp());

        final Map<String, Map<String, String>> sdElementMap = syslogMessage
                .getSDElements()
                .stream()
                .collect(Collectors.toMap((SDElement::getSdID), (sdElem) -> sdElem.getSdParams().stream().collect(Collectors.toMap(SDParam::getParamName, SDParam::getParamValue))));

        Assertions.assertEquals(1, sdElementMap.get("nlf_01@48577").size());
        Assertions
                .assertEquals(DefaultEventType.class.getSimpleName(), sdElementMap.get("nlf_01@48577").get("eventType"));

        Assertions.assertTrue(sdElementMap.get("aer_event@48577").containsKey("properties"));
    }

    @Test
    @DisplayName("Test NLFPlugin with DatabricksDatabricksSQL")
    void testNlfPluginWithDatabricksDatabricksSql() {
        final String json = Assertions
                .assertDoesNotThrow(
                        () -> Files.readString(Paths.get("src/test/resources/databricks/databricksdatabrickssql.json"))
                );
        final ParsedEvent parsedEvent = new ParsedEventFactory(
                new UnparsedEventImpl(json, new EventPartitionContextImpl(new HashMap<>()), new EventPropertiesImpl(new HashMap<>()), new EventSystemPropertiesImpl(new HashMap<>()), new EnqueuedTimeImpl("2020-01-01T00:00:00"), new EventOffsetImpl("0"))
        ).parsedEvent();

        final NLFPlugin plugin = new NLFPlugin(new FakeSourceable());
        final List<SyslogMessage> syslogMessages = Assertions
                .assertDoesNotThrow(() -> plugin.syslogMessage(parsedEvent));
        Assertions.assertEquals(1, syslogMessages.size());

        final SyslogMessage syslogMessage = syslogMessages.get(0);
        Assertions
                .assertEquals(
                        "{\n" + "  \"ActionName\": \"ActionName-12\",\n" + "  \"Category\": \"category-12\",\n"
                                + "  \"Identity\": \"identity-12\",\n"
                                + "  \"LogId\": \"12345678-1234-1234-abcd-1234567890bc\",\n"
                                + "  \"OperationName\": \"Operation-12\",\n" + "  \"OperationVersion\": \"1.0.0\",\n"
                                + "  \"RequestId\": \"12345678-1234-1234-abcd-1234567890cd\",\n"
                                + "  \"RequestParams\": \"\\\"key\\\":\\\"value\\\"\",\n"
                                + "  \"Response\": \"Success\",\n" + "  \"ServiceName\": \"service-12\",\n"
                                + "  \"SessionId\": \"12345678-1234-1234-abcd-1234567890de\",\n"
                                + "  \"SourceIPAddress\": \"127.0.0.1\",\n" + "  \"SourceSystem\": \"Azure\",\n"
                                + "  \"TenantId\": \"12345678-1234-1234-abcd-1234567890ef\",\n"
                                + "  \"TimeGenerated\": \"2025-10-06T00:00:00.0000000Z\",\n"
                                + "  \"Type\": \"DatabricksDatabricksSQL\",\n"
                                + "  \"UserAgent\": \"User-Agent: Mozilla/5.0 (<system-information>) <platform> (<platform-details>) <extensions>\",\n"
                                + "  \"_ResourceId\": \"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}\",\n"
                                + "  \"_SubscriptionId\": \"12345678-1234-1234-abcd-1234567890fg\"\n" + "}",
                        syslogMessage.getMsg()
                );
        Assertions.assertEquals("md5-0ded52ef915af563e25778bf26b0f129-resourceName", syslogMessage.getHostname());
        Assertions.assertEquals("DatabricksDatabricksSQL", syslogMessage.getAppName());
        Assertions.assertEquals("2025-10-06T00:00:00Z", syslogMessage.getTimestamp());

        final Map<String, Map<String, String>> sdElementMap = syslogMessage
                .getSDElements()
                .stream()
                .collect(Collectors.toMap((SDElement::getSdID), (sdElem) -> sdElem.getSdParams().stream().collect(Collectors.toMap(SDParam::getParamName, SDParam::getParamValue))));

        Assertions.assertEquals(1, sdElementMap.get("nlf_01@48577").size());
        Assertions
                .assertEquals(DefaultEventType.class.getSimpleName(), sdElementMap.get("nlf_01@48577").get("eventType"));

        Assertions.assertTrue(sdElementMap.get("aer_event@48577").containsKey("properties"));
    }

    @Test
    @DisplayName("Test NLFPlugin with DatabricksDataMonitoring")
    void testNlfPluginWithDatabricksDataMonitoring() {
        final String json = Assertions
                .assertDoesNotThrow(
                        () -> Files.readString(Paths.get("src/test/resources/databricks/databricksdatamonitoring.json"))
                );
        final ParsedEvent parsedEvent = new ParsedEventFactory(
                new UnparsedEventImpl(json, new EventPartitionContextImpl(new HashMap<>()), new EventPropertiesImpl(new HashMap<>()), new EventSystemPropertiesImpl(new HashMap<>()), new EnqueuedTimeImpl("2020-01-01T00:00:00"), new EventOffsetImpl("0"))
        ).parsedEvent();

        final NLFPlugin plugin = new NLFPlugin(new FakeSourceable());
        final List<SyslogMessage> syslogMessages = Assertions
                .assertDoesNotThrow(() -> plugin.syslogMessage(parsedEvent));
        Assertions.assertEquals(1, syslogMessages.size());

        final SyslogMessage syslogMessage = syslogMessages.get(0);
        Assertions
                .assertEquals(
                        "{\n" + "  \"ActionName\": \"ActionName-13\",\n" + "  \"Category\": \"category-13\",\n"
                                + "  \"Identity\": \"identity-13\",\n"
                                + "  \"LogId\": \"12345678-1234-1234-abcd-1234567890bc\",\n"
                                + "  \"OperationName\": \"Operation-13\",\n" + "  \"OperationVersion\": \"1.0.0\",\n"
                                + "  \"RequestId\": \"12345678-1234-1234-abcd-1234567890cd\",\n"
                                + "  \"RequestParams\": \"\\\"key\\\":\\\"value\\\"\",\n"
                                + "  \"Response\": \"Success\",\n" + "  \"ServiceName\": \"service-13\",\n"
                                + "  \"SessionId\": \"12345678-1234-1234-abcd-1234567890de\",\n"
                                + "  \"SourceIpAddress\": \"127.0.0.1\",\n" + "  \"SourceSystem\": \"Azure\",\n"
                                + "  \"TenantId\": \"12345678-1234-1234-abcd-1234567890ef\",\n"
                                + "  \"TimeGenerated\": \"2025-10-06T00:00:00.0000000Z\",\n"
                                + "  \"Type\": \"DatabricksDataMonitoring\",\n"
                                + "  \"UserAgent\": \"User-Agent: Mozilla/5.0 (<system-information>) <platform> (<platform-details>) <extensions>\",\n"
                                + "  \"_ResourceId\": \"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}\",\n"
                                + "  \"_SubscriptionId\": \"12345678-1234-1234-abcd-1234567890fg\"\n" + "}",
                        syslogMessage.getMsg()
                );
        Assertions.assertEquals("md5-0ded52ef915af563e25778bf26b0f129-resourceName", syslogMessage.getHostname());
        Assertions.assertEquals("DatabricksDataMonitoring", syslogMessage.getAppName());
        Assertions.assertEquals("2025-10-06T00:00:00Z", syslogMessage.getTimestamp());

        final Map<String, Map<String, String>> sdElementMap = syslogMessage
                .getSDElements()
                .stream()
                .collect(Collectors.toMap((SDElement::getSdID), (sdElem) -> sdElem.getSdParams().stream().collect(Collectors.toMap(SDParam::getParamName, SDParam::getParamValue))));

        Assertions.assertEquals(1, sdElementMap.get("nlf_01@48577").size());
        Assertions
                .assertEquals(DefaultEventType.class.getSimpleName(), sdElementMap.get("nlf_01@48577").get("eventType"));

        Assertions.assertTrue(sdElementMap.get("aer_event@48577").containsKey("properties"));
    }

    @Test
    @DisplayName("Test NLFPlugin with DatabricksDataRooms")
    void testNlfPluginWithDatabricksDataRooms() {
        final String json = Assertions
                .assertDoesNotThrow(
                        () -> Files.readString(Paths.get("src/test/resources/databricks/databricksdatarooms.json"))
                );
        final ParsedEvent parsedEvent = new ParsedEventFactory(
                new UnparsedEventImpl(json, new EventPartitionContextImpl(new HashMap<>()), new EventPropertiesImpl(new HashMap<>()), new EventSystemPropertiesImpl(new HashMap<>()), new EnqueuedTimeImpl("2020-01-01T00:00:00"), new EventOffsetImpl("0"))
        ).parsedEvent();

        final NLFPlugin plugin = new NLFPlugin(new FakeSourceable());
        final List<SyslogMessage> syslogMessages = Assertions
                .assertDoesNotThrow(() -> plugin.syslogMessage(parsedEvent));
        Assertions.assertEquals(1, syslogMessages.size());

        final SyslogMessage syslogMessage = syslogMessages.get(0);
        Assertions
                .assertEquals(
                        "{\n" + "  \"ActionName\": \"ActionName-14\",\n" + "  \"Category\": \"category-14\",\n"
                                + "  \"Identity\": \"identity-14\",\n"
                                + "  \"LogId\": \"12345678-1234-1234-abcd-1234567890bc\",\n"
                                + "  \"OperationName\": \"Operation-14\",\n" + "  \"OperationVersion\": \"1.0.0\",\n"
                                + "  \"RequestId\": \"12345678-1234-1234-abcd-1234567890cd\",\n"
                                + "  \"RequestParams\": \"\\\"key\\\":\\\"value\\\"\",\n"
                                + "  \"Response\": \"Success\",\n" + "  \"ServiceName\": \"service-14\",\n"
                                + "  \"SessionId\": \"12345678-1234-1234-abcd-1234567890de\",\n"
                                + "  \"SourceIpAddress\": \"127.0.0.1\",\n" + "  \"SourceSystem\": \"Azure\",\n"
                                + "  \"TenantId\": \"12345678-1234-1234-abcd-1234567890ef\",\n"
                                + "  \"TimeGenerated\": \"2025-10-06T00:00:00.0000000Z\",\n"
                                + "  \"Type\": \"DatabricksDataRooms\",\n"
                                + "  \"UserAgent\": \"User-Agent: Mozilla/5.0 (<system-information>) <platform> (<platform-details>) <extensions>\",\n"
                                + "  \"_ResourceId\": \"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}\",\n"
                                + "  \"_SubscriptionId\": \"12345678-1234-1234-abcd-1234567890fg\"\n" + "}",
                        syslogMessage.getMsg()
                );
        Assertions.assertEquals("md5-0ded52ef915af563e25778bf26b0f129-resourceName", syslogMessage.getHostname());
        Assertions.assertEquals("DatabricksDataRooms", syslogMessage.getAppName());
        Assertions.assertEquals("2025-10-06T00:00:00Z", syslogMessage.getTimestamp());

        final Map<String, Map<String, String>> sdElementMap = syslogMessage
                .getSDElements()
                .stream()
                .collect(Collectors.toMap((SDElement::getSdID), (sdElem) -> sdElem.getSdParams().stream().collect(Collectors.toMap(SDParam::getParamName, SDParam::getParamValue))));

        Assertions.assertEquals(1, sdElementMap.get("nlf_01@48577").size());
        Assertions
                .assertEquals(DefaultEventType.class.getSimpleName(), sdElementMap.get("nlf_01@48577").get("eventType"));

        Assertions.assertTrue(sdElementMap.get("aer_event@48577").containsKey("properties"));
    }

    @Test
    @DisplayName("Test NLFPlugin with DatabricksDBFS")
    void testNlfPluginWithDatabricksDbfs() {
        final String json = Assertions
                .assertDoesNotThrow(() -> Files.readString(Paths.get("src/test/resources/databricks/databricksdbfs.json")));
        final ParsedEvent parsedEvent = new ParsedEventFactory(
                new UnparsedEventImpl(json, new EventPartitionContextImpl(new HashMap<>()), new EventPropertiesImpl(new HashMap<>()), new EventSystemPropertiesImpl(new HashMap<>()), new EnqueuedTimeImpl("2020-01-01T00:00:00"), new EventOffsetImpl("0"))
        ).parsedEvent();

        final NLFPlugin plugin = new NLFPlugin(new FakeSourceable());
        final List<SyslogMessage> syslogMessages = Assertions
                .assertDoesNotThrow(() -> plugin.syslogMessage(parsedEvent));
        Assertions.assertEquals(1, syslogMessages.size());

        final SyslogMessage syslogMessage = syslogMessages.get(0);
        Assertions
                .assertEquals(
                        "{\n" + "  \"ActionName\": \"ActionName-15\",\n" + "  \"Category\": \"category-15\",\n"
                                + "  \"Identity\": \"identity-15\",\n"
                                + "  \"LogId\": \"12345678-1234-1234-abcd-1234567890bc\",\n"
                                + "  \"OperationName\": \"Operation-15\",\n" + "  \"OperationVersion\": \"1.0.0\",\n"
                                + "  \"RequestId\": \"12345678-1234-1234-abcd-1234567890cd\",\n"
                                + "  \"RequestParams\": \"\\\"key\\\":\\\"value\\\"\",\n"
                                + "  \"Response\": \"Success\",\n" + "  \"ServiceName\": \"service-15\",\n"
                                + "  \"SessionId\": \"12345678-1234-1234-abcd-1234567890de\",\n"
                                + "  \"SourceIPAddress\": \"127.0.0.1\",\n" + "  \"SourceSystem\": \"Azure\",\n"
                                + "  \"TenantId\": \"12345678-1234-1234-abcd-1234567890ef\",\n"
                                + "  \"TimeGenerated\": \"2025-10-06T00:00:00.0000000Z\",\n"
                                + "  \"Type\": \"DatabricksDBFS\",\n"
                                + "  \"UserAgent\": \"User-Agent: Mozilla/5.0 (<system-information>) <platform> (<platform-details>) <extensions>\",\n"
                                + "  \"_ResourceId\": \"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}\",\n"
                                + "  \"_SubscriptionId\": \"12345678-1234-1234-abcd-1234567890fg\"\n" + "}",
                        syslogMessage.getMsg()
                );
        Assertions.assertEquals("md5-0ded52ef915af563e25778bf26b0f129-resourceName", syslogMessage.getHostname());
        Assertions.assertEquals("DatabricksDBFS", syslogMessage.getAppName());
        Assertions.assertEquals("2025-10-06T00:00:00Z", syslogMessage.getTimestamp());

        final Map<String, Map<String, String>> sdElementMap = syslogMessage
                .getSDElements()
                .stream()
                .collect(Collectors.toMap((SDElement::getSdID), (sdElem) -> sdElem.getSdParams().stream().collect(Collectors.toMap(SDParam::getParamName, SDParam::getParamValue))));

        Assertions.assertEquals(1, sdElementMap.get("nlf_01@48577").size());
        Assertions
                .assertEquals(DefaultEventType.class.getSimpleName(), sdElementMap.get("nlf_01@48577").get("eventType"));

        Assertions.assertTrue(sdElementMap.get("aer_event@48577").containsKey("properties"));
    }

    @Test
    @DisplayName("Test NLFPlugin with DatabricksDeltaPipelines")
    void testNlfPluginWithDatabricksDeltaPipelines() {
        final String json = Assertions
                .assertDoesNotThrow(
                        () -> Files.readString(Paths.get("src/test/resources/databricks/databricksdeltapipelines.json"))
                );
        final ParsedEvent parsedEvent = new ParsedEventFactory(
                new UnparsedEventImpl(json, new EventPartitionContextImpl(new HashMap<>()), new EventPropertiesImpl(new HashMap<>()), new EventSystemPropertiesImpl(new HashMap<>()), new EnqueuedTimeImpl("2020-01-01T00:00:00"), new EventOffsetImpl("0"))
        ).parsedEvent();

        final NLFPlugin plugin = new NLFPlugin(new FakeSourceable());
        final List<SyslogMessage> syslogMessages = Assertions
                .assertDoesNotThrow(() -> plugin.syslogMessage(parsedEvent));
        Assertions.assertEquals(1, syslogMessages.size());

        final SyslogMessage syslogMessage = syslogMessages.get(0);
        Assertions
                .assertEquals(
                        "{\n" + "  \"ActionName\": \"ActionName-16\",\n" + "  \"Category\": \"category-16\",\n"
                                + "  \"Identity\": \"identity-16\",\n"
                                + "  \"LogId\": \"12345678-1234-1234-abcd-1234567890bc\",\n"
                                + "  \"OperationName\": \"Operation-16\",\n" + "  \"OperationVersion\": \"1.0.0\",\n"
                                + "  \"RequestId\": \"12345678-1234-1234-abcd-1234567890cd\",\n"
                                + "  \"RequestParams\": \"\\\"key\\\":\\\"value\\\"\",\n"
                                + "  \"Response\": \"Success\",\n" + "  \"ServiceName\": \"service-16\",\n"
                                + "  \"SessionId\": \"12345678-1234-1234-abcd-1234567890de\",\n"
                                + "  \"SourceIPAddress\": \"127.0.0.1\",\n" + "  \"SourceSystem\": \"Azure\",\n"
                                + "  \"TenantId\": \"12345678-1234-1234-abcd-1234567890ef\",\n"
                                + "  \"TimeGenerated\": \"2025-10-06T00:00:00.0000000Z\",\n"
                                + "  \"Type\": \"DatabricksDeltaPipelines\",\n"
                                + "  \"UserAgent\": \"User-Agent: Mozilla/5.0 (<system-information>) <platform> (<platform-details>) <extensions>\",\n"
                                + "  \"_ResourceId\": \"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}\",\n"
                                + "  \"_SubscriptionId\": \"12345678-1234-1234-abcd-1234567890fg\"\n" + "}",
                        syslogMessage.getMsg()
                );
        Assertions.assertEquals("md5-0ded52ef915af563e25778bf26b0f129-resourceName", syslogMessage.getHostname());
        Assertions.assertEquals("DatabricksDeltaPipelines", syslogMessage.getAppName());
        Assertions.assertEquals("2025-10-06T00:00:00Z", syslogMessage.getTimestamp());

        final Map<String, Map<String, String>> sdElementMap = syslogMessage
                .getSDElements()
                .stream()
                .collect(Collectors.toMap((SDElement::getSdID), (sdElem) -> sdElem.getSdParams().stream().collect(Collectors.toMap(SDParam::getParamName, SDParam::getParamValue))));

        Assertions.assertEquals(1, sdElementMap.get("nlf_01@48577").size());
        Assertions
                .assertEquals(DefaultEventType.class.getSimpleName(), sdElementMap.get("nlf_01@48577").get("eventType"));

        Assertions.assertTrue(sdElementMap.get("aer_event@48577").containsKey("properties"));
    }

    @Test
    @DisplayName("Test NLFPlugin with DatabricksFeatureStore")
    void testNlfPluginWithDatabricksFeatureStore() {
        final String json = Assertions
                .assertDoesNotThrow(
                        () -> Files.readString(Paths.get("src/test/resources/databricks/databricksfeaturestore.json"))
                );
        final ParsedEvent parsedEvent = new ParsedEventFactory(
                new UnparsedEventImpl(json, new EventPartitionContextImpl(new HashMap<>()), new EventPropertiesImpl(new HashMap<>()), new EventSystemPropertiesImpl(new HashMap<>()), new EnqueuedTimeImpl("2020-01-01T00:00:00"), new EventOffsetImpl("0"))
        ).parsedEvent();

        final NLFPlugin plugin = new NLFPlugin(new FakeSourceable());
        final List<SyslogMessage> syslogMessages = Assertions
                .assertDoesNotThrow(() -> plugin.syslogMessage(parsedEvent));
        Assertions.assertEquals(1, syslogMessages.size());

        final SyslogMessage syslogMessage = syslogMessages.get(0);
        Assertions
                .assertEquals(
                        "{\n" + "  \"ActionName\": \"ActionName-17\",\n" + "  \"Category\": \"category-17\",\n"
                                + "  \"Identity\": \"identity-17\",\n"
                                + "  \"LogId\": \"12345678-1234-1234-abcd-1234567890bc\",\n"
                                + "  \"OperationName\": \"Operation-17\",\n" + "  \"OperationVersion\": \"1.0.0\",\n"
                                + "  \"RequestId\": \"12345678-1234-1234-abcd-1234567890cd\",\n"
                                + "  \"RequestParams\": \"\\\"key\\\":\\\"value\\\"\",\n"
                                + "  \"Response\": \"Success\",\n" + "  \"ServiceName\": \"service-17\",\n"
                                + "  \"SessionId\": \"12345678-1234-1234-abcd-1234567890de\",\n"
                                + "  \"SourceIPAddress\": \"127.0.0.1\",\n" + "  \"SourceSystem\": \"Azure\",\n"
                                + "  \"TenantId\": \"12345678-1234-1234-abcd-1234567890ef\",\n"
                                + "  \"TimeGenerated\": \"2025-10-06T00:00:00.0000000Z\",\n"
                                + "  \"Type\": \"DatabricksFeatureStore\",\n"
                                + "  \"UserAgent\": \"User-Agent: Mozilla/5.0 (<system-information>) <platform> (<platform-details>) <extensions>\",\n"
                                + "  \"_ResourceId\": \"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}\",\n"
                                + "  \"_SubscriptionId\": \"12345678-1234-1234-abcd-1234567890fg\"\n" + "}",
                        syslogMessage.getMsg()
                );
        Assertions.assertEquals("md5-0ded52ef915af563e25778bf26b0f129-resourceName", syslogMessage.getHostname());
        Assertions.assertEquals("DatabricksFeatureStore", syslogMessage.getAppName());
        Assertions.assertEquals("2025-10-06T00:00:00Z", syslogMessage.getTimestamp());

        final Map<String, Map<String, String>> sdElementMap = syslogMessage
                .getSDElements()
                .stream()
                .collect(Collectors.toMap((SDElement::getSdID), (sdElem) -> sdElem.getSdParams().stream().collect(Collectors.toMap(SDParam::getParamName, SDParam::getParamValue))));

        Assertions.assertEquals(1, sdElementMap.get("nlf_01@48577").size());
        Assertions
                .assertEquals(DefaultEventType.class.getSimpleName(), sdElementMap.get("nlf_01@48577").get("eventType"));

        Assertions.assertTrue(sdElementMap.get("aer_event@48577").containsKey("properties"));
    }

    @Test
    @DisplayName("Test NLFPlugin with DatabricksFiles")
    void testNlfPluginWithDatabricksFiles() {
        final String json = Assertions
                .assertDoesNotThrow(
                        () -> Files.readString(Paths.get("src/test/resources/databricks/databricksfiles.json"))
                );
        final ParsedEvent parsedEvent = new ParsedEventFactory(
                new UnparsedEventImpl(json, new EventPartitionContextImpl(new HashMap<>()), new EventPropertiesImpl(new HashMap<>()), new EventSystemPropertiesImpl(new HashMap<>()), new EnqueuedTimeImpl("2020-01-01T00:00:00"), new EventOffsetImpl("0"))
        ).parsedEvent();

        final NLFPlugin plugin = new NLFPlugin(new FakeSourceable());
        final List<SyslogMessage> syslogMessages = Assertions
                .assertDoesNotThrow(() -> plugin.syslogMessage(parsedEvent));
        Assertions.assertEquals(1, syslogMessages.size());

        final SyslogMessage syslogMessage = syslogMessages.get(0);
        Assertions
                .assertEquals(
                        "{\n" + "  \"ActionName\": \"ActionName-18\",\n" + "  \"Category\": \"category-18\",\n"
                                + "  \"Identity\": \"identity-18\",\n"
                                + "  \"LogId\": \"12345678-1234-1234-abcd-1234567890bc\",\n"
                                + "  \"OperationName\": \"Operation-18\",\n" + "  \"OperationVersion\": \"1.0.0\",\n"
                                + "  \"RequestId\": \"12345678-1234-1234-abcd-1234567890cd\",\n"
                                + "  \"RequestParams\": \"\\\"key\\\":\\\"value\\\"\",\n"
                                + "  \"Response\": \"Success\",\n" + "  \"ServiceName\": \"service-18\",\n"
                                + "  \"SessionId\": \"12345678-1234-1234-abcd-1234567890de\",\n"
                                + "  \"SourceIpAddress\": \"127.0.0.1\",\n" + "  \"SourceSystem\": \"Azure\",\n"
                                + "  \"TenantId\": \"12345678-1234-1234-abcd-1234567890ef\",\n"
                                + "  \"TimeGenerated\": \"2025-10-06T00:00:00.0000000Z\",\n"
                                + "  \"Type\": \"DatabricksFiles\",\n"
                                + "  \"UserAgent\": \"User-Agent: Mozilla/5.0 (<system-information>) <platform> (<platform-details>) <extensions>\",\n"
                                + "  \"_ResourceId\": \"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}\",\n"
                                + "  \"_SubscriptionId\": \"12345678-1234-1234-abcd-1234567890fg\"\n" + "}",
                        syslogMessage.getMsg()
                );
        Assertions.assertEquals("md5-0ded52ef915af563e25778bf26b0f129-resourceName", syslogMessage.getHostname());
        Assertions.assertEquals("DatabricksFiles", syslogMessage.getAppName());
        Assertions.assertEquals("2025-10-06T00:00:00Z", syslogMessage.getTimestamp());

        final Map<String, Map<String, String>> sdElementMap = syslogMessage
                .getSDElements()
                .stream()
                .collect(Collectors.toMap((SDElement::getSdID), (sdElem) -> sdElem.getSdParams().stream().collect(Collectors.toMap(SDParam::getParamName, SDParam::getParamValue))));

        Assertions.assertEquals(1, sdElementMap.get("nlf_01@48577").size());
        Assertions
                .assertEquals(DefaultEventType.class.getSimpleName(), sdElementMap.get("nlf_01@48577").get("eventType"));

        Assertions.assertTrue(sdElementMap.get("aer_event@48577").containsKey("properties"));
    }

    @Test
    @DisplayName("Test NLFPlugin with DatabricksFilesystem")
    void testNlfPluginWithDatabricksFilesystem() {
        final String json = Assertions
                .assertDoesNotThrow(
                        () -> Files.readString(Paths.get("src/test/resources/databricks/databricksfilesystem.json"))
                );
        final ParsedEvent parsedEvent = new ParsedEventFactory(
                new UnparsedEventImpl(json, new EventPartitionContextImpl(new HashMap<>()), new EventPropertiesImpl(new HashMap<>()), new EventSystemPropertiesImpl(new HashMap<>()), new EnqueuedTimeImpl("2020-01-01T00:00:00"), new EventOffsetImpl("0"))
        ).parsedEvent();

        final NLFPlugin plugin = new NLFPlugin(new FakeSourceable());
        final List<SyslogMessage> syslogMessages = Assertions
                .assertDoesNotThrow(() -> plugin.syslogMessage(parsedEvent));
        Assertions.assertEquals(1, syslogMessages.size());

        final SyslogMessage syslogMessage = syslogMessages.get(0);
        Assertions
                .assertEquals(
                        "{\n" + "  \"ActionName\": \"ActionName-19\",\n" + "  \"Category\": \"category-19\",\n"
                                + "  \"Identity\": \"identity-19\",\n"
                                + "  \"LogId\": \"12345678-1234-1234-abcd-1234567890bc\",\n"
                                + "  \"OperationName\": \"Operation-19\",\n" + "  \"OperationVersion\": \"1.0.0\",\n"
                                + "  \"RequestId\": \"12345678-1234-1234-abcd-1234567890cd\",\n"
                                + "  \"RequestParams\": \"\\\"key\\\":\\\"value\\\"\",\n"
                                + "  \"Response\": \"Success\",\n" + "  \"ServiceName\": \"service-19\",\n"
                                + "  \"SessionId\": \"12345678-1234-1234-abcd-1234567890de\",\n"
                                + "  \"SourceIpAddress\": \"127.0.0.1\",\n" + "  \"SourceSystem\": \"Azure\",\n"
                                + "  \"TenantId\": \"12345678-1234-1234-abcd-1234567890ef\",\n"
                                + "  \"TimeGenerated\": \"2025-10-06T00:00:00.0000000Z\",\n"
                                + "  \"Type\": \"DatabricksFilesystem\",\n"
                                + "  \"UserAgent\": \"User-Agent: Mozilla/5.0 (<system-information>) <platform> (<platform-details>) <extensions>\",\n"
                                + "  \"_ResourceId\": \"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}\",\n"
                                + "  \"_SubscriptionId\": \"12345678-1234-1234-abcd-1234567890fg\"\n" + "}",
                        syslogMessage.getMsg()
                );
        Assertions.assertEquals("md5-0ded52ef915af563e25778bf26b0f129-resourceName", syslogMessage.getHostname());
        Assertions.assertEquals("DatabricksFilesystem", syslogMessage.getAppName());
        Assertions.assertEquals("2025-10-06T00:00:00Z", syslogMessage.getTimestamp());

        final Map<String, Map<String, String>> sdElementMap = syslogMessage
                .getSDElements()
                .stream()
                .collect(Collectors.toMap((SDElement::getSdID), (sdElem) -> sdElem.getSdParams().stream().collect(Collectors.toMap(SDParam::getParamName, SDParam::getParamValue))));

        Assertions.assertEquals(1, sdElementMap.get("nlf_01@48577").size());
        Assertions
                .assertEquals(DefaultEventType.class.getSimpleName(), sdElementMap.get("nlf_01@48577").get("eventType"));

        Assertions.assertTrue(sdElementMap.get("aer_event@48577").containsKey("properties"));
    }

    @Test
    @DisplayName("Test NLFPlugin with DatabricksGenie")
    void testNlfPluginWithDatabricksGenie() {
        final String json = Assertions
                .assertDoesNotThrow(
                        () -> Files.readString(Paths.get("src/test/resources/databricks/databricksgenie.json"))
                );
        final ParsedEvent parsedEvent = new ParsedEventFactory(
                new UnparsedEventImpl(json, new EventPartitionContextImpl(new HashMap<>()), new EventPropertiesImpl(new HashMap<>()), new EventSystemPropertiesImpl(new HashMap<>()), new EnqueuedTimeImpl("2020-01-01T00:00:00"), new EventOffsetImpl("0"))
        ).parsedEvent();

        final NLFPlugin plugin = new NLFPlugin(new FakeSourceable());
        final List<SyslogMessage> syslogMessages = Assertions
                .assertDoesNotThrow(() -> plugin.syslogMessage(parsedEvent));
        Assertions.assertEquals(1, syslogMessages.size());

        final SyslogMessage syslogMessage = syslogMessages.get(0);
        Assertions
                .assertEquals(
                        "{\n" + "  \"ActionName\": \"ActionName-20\",\n" + "  \"Category\": \"category-20\",\n"
                                + "  \"Identity\": \"identity-20\",\n"
                                + "  \"LogId\": \"12345678-1234-1234-abcd-1234567890bc\",\n"
                                + "  \"OperationName\": \"Operation-20\",\n" + "  \"OperationVersion\": \"1.0.0\",\n"
                                + "  \"RequestId\": \"12345678-1234-1234-abcd-1234567890cd\",\n"
                                + "  \"RequestParams\": \"\\\"key\\\":\\\"value\\\"\",\n"
                                + "  \"Response\": \"Success\",\n" + "  \"ServiceName\": \"service-20\",\n"
                                + "  \"SessionId\": \"12345678-1234-1234-abcd-1234567890de\",\n"
                                + "  \"SourceIPAddress\": \"127.0.0.1\",\n" + "  \"SourceSystem\": \"Azure\",\n"
                                + "  \"TenantId\": \"12345678-1234-1234-abcd-1234567890ef\",\n"
                                + "  \"TimeGenerated\": \"2025-10-06T00:00:00.0000000Z\",\n"
                                + "  \"Type\": \"DatabricksGenie\",\n"
                                + "  \"UserAgent\": \"User-Agent: Mozilla/5.0 (<system-information>) <platform> (<platform-details>) <extensions>\",\n"
                                + "  \"_ResourceId\": \"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}\",\n"
                                + "  \"_SubscriptionId\": \"12345678-1234-1234-abcd-1234567890fg\"\n" + "}",
                        syslogMessage.getMsg()
                );
        Assertions.assertEquals("md5-0ded52ef915af563e25778bf26b0f129-resourceName", syslogMessage.getHostname());
        Assertions.assertEquals("DatabricksGenie", syslogMessage.getAppName());
        Assertions.assertEquals("2025-10-06T00:00:00Z", syslogMessage.getTimestamp());

        final Map<String, Map<String, String>> sdElementMap = syslogMessage
                .getSDElements()
                .stream()
                .collect(Collectors.toMap((SDElement::getSdID), (sdElem) -> sdElem.getSdParams().stream().collect(Collectors.toMap(SDParam::getParamName, SDParam::getParamValue))));

        Assertions.assertEquals(1, sdElementMap.get("nlf_01@48577").size());
        Assertions
                .assertEquals(DefaultEventType.class.getSimpleName(), sdElementMap.get("nlf_01@48577").get("eventType"));

        Assertions.assertTrue(sdElementMap.get("aer_event@48577").containsKey("properties"));
    }

    @Test
    @DisplayName("Test NLFPlugin with DatabricksGitCredentials")
    void testNlfPluginWithDatabricksGitCredentials() {
        final String json = Assertions
                .assertDoesNotThrow(
                        () -> Files.readString(Paths.get("src/test/resources/databricks/databricksgitcredentials.json"))
                );
        final ParsedEvent parsedEvent = new ParsedEventFactory(
                new UnparsedEventImpl(json, new EventPartitionContextImpl(new HashMap<>()), new EventPropertiesImpl(new HashMap<>()), new EventSystemPropertiesImpl(new HashMap<>()), new EnqueuedTimeImpl("2020-01-01T00:00:00"), new EventOffsetImpl("0"))
        ).parsedEvent();

        final NLFPlugin plugin = new NLFPlugin(new FakeSourceable());
        final List<SyslogMessage> syslogMessages = Assertions
                .assertDoesNotThrow(() -> plugin.syslogMessage(parsedEvent));
        Assertions.assertEquals(1, syslogMessages.size());

        final SyslogMessage syslogMessage = syslogMessages.get(0);
        Assertions
                .assertEquals(
                        "{\n" + "  \"ActionName\": \"ActionName-21\",\n" + "  \"Category\": \"category-21\",\n"
                                + "  \"Identity\": \"identity-21\",\n"
                                + "  \"LogId\": \"12345678-1234-1234-abcd-1234567890bc\",\n"
                                + "  \"OperationName\": \"Operation-21\",\n" + "  \"OperationVersion\": \"1.0.0\",\n"
                                + "  \"RequestId\": \"12345678-1234-1234-abcd-1234567890cd\",\n"
                                + "  \"RequestParams\": \"\\\"key\\\":\\\"value\\\"\",\n"
                                + "  \"Response\": \"Success\",\n" + "  \"ServiceName\": \"service-21\",\n"
                                + "  \"SessionId\": \"12345678-1234-1234-abcd-1234567890de\",\n"
                                + "  \"SourceIPAddress\": \"127.0.0.1\",\n" + "  \"SourceSystem\": \"Azure\",\n"
                                + "  \"TenantId\": \"12345678-1234-1234-abcd-1234567890ef\",\n"
                                + "  \"TimeGenerated\": \"2025-10-06T00:00:00.0000000Z\",\n"
                                + "  \"Type\": \"DatabricksGitCredentials\",\n"
                                + "  \"UserAgent\": \"User-Agent: Mozilla/5.0 (<system-information>) <platform> (<platform-details>) <extensions>\",\n"
                                + "  \"_ResourceId\": \"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}\",\n"
                                + "  \"_SubscriptionId\": \"12345678-1234-1234-abcd-1234567890fg\"\n" + "}",
                        syslogMessage.getMsg()
                );
        Assertions.assertEquals("md5-0ded52ef915af563e25778bf26b0f129-resourceName", syslogMessage.getHostname());
        Assertions.assertEquals("DatabricksGitCredentials", syslogMessage.getAppName());
        Assertions.assertEquals("2025-10-06T00:00:00Z", syslogMessage.getTimestamp());

        final Map<String, Map<String, String>> sdElementMap = syslogMessage
                .getSDElements()
                .stream()
                .collect(Collectors.toMap((SDElement::getSdID), (sdElem) -> sdElem.getSdParams().stream().collect(Collectors.toMap(SDParam::getParamName, SDParam::getParamValue))));

        Assertions.assertEquals(1, sdElementMap.get("nlf_01@48577").size());
        Assertions
                .assertEquals(DefaultEventType.class.getSimpleName(), sdElementMap.get("nlf_01@48577").get("eventType"));

        Assertions.assertTrue(sdElementMap.get("aer_event@48577").containsKey("properties"));
    }

    @Test
    @DisplayName("Test NLFPlugin with DatabricksGlobalInitScripts")
    void testNlfPluginWithDatabricksGlobalInitScripts() {
        final String json = Assertions
                .assertDoesNotThrow(
                        () -> Files
                                .readString(Paths.get("src/test/resources/databricks/databricksglobalinitscripts.json"))
                );
        final ParsedEvent parsedEvent = new ParsedEventFactory(
                new UnparsedEventImpl(json, new EventPartitionContextImpl(new HashMap<>()), new EventPropertiesImpl(new HashMap<>()), new EventSystemPropertiesImpl(new HashMap<>()), new EnqueuedTimeImpl("2020-01-01T00:00:00"), new EventOffsetImpl("0"))
        ).parsedEvent();

        final NLFPlugin plugin = new NLFPlugin(new FakeSourceable());
        final List<SyslogMessage> syslogMessages = Assertions
                .assertDoesNotThrow(() -> plugin.syslogMessage(parsedEvent));
        Assertions.assertEquals(1, syslogMessages.size());

        final SyslogMessage syslogMessage = syslogMessages.get(0);
        Assertions
                .assertEquals(
                        "{\n" + "  \"ActionName\": \"ActionName-22\",\n" + "  \"Category\": \"category-22\",\n"
                                + "  \"Identity\": \"identity-22\",\n"
                                + "  \"LogId\": \"12345678-1234-1234-abcd-1234567890bc\",\n"
                                + "  \"OperationName\": \"Operation-22\",\n" + "  \"OperationVersion\": \"1.0.0\",\n"
                                + "  \"RequestId\": \"12345678-1234-1234-abcd-1234567890cd\",\n"
                                + "  \"RequestParams\": \"\\\"key\\\":\\\"value\\\"\",\n"
                                + "  \"Response\": \"Success\",\n" + "  \"ServiceName\": \"service-22\",\n"
                                + "  \"SessionId\": \"12345678-1234-1234-abcd-1234567890de\",\n"
                                + "  \"SourceIPAddress\": \"127.0.0.1\",\n" + "  \"SourceSystem\": \"Azure\",\n"
                                + "  \"TenantId\": \"12345678-1234-1234-abcd-1234567890ef\",\n"
                                + "  \"TimeGenerated\": \"2025-10-06T00:00:00.0000000Z\",\n"
                                + "  \"Type\": \"DatabricksGlobalInitScripts\",\n"
                                + "  \"UserAgent\": \"User-Agent: Mozilla/5.0 (<system-information>) <platform> (<platform-details>) <extensions>\",\n"
                                + "  \"_ResourceId\": \"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}\",\n"
                                + "  \"_SubscriptionId\": \"12345678-1234-1234-abcd-1234567890fg\"\n" + "}",
                        syslogMessage.getMsg()
                );
        Assertions.assertEquals("md5-0ded52ef915af563e25778bf26b0f129-resourceName", syslogMessage.getHostname());
        Assertions.assertEquals("DatabricksGlobalInitScripts", syslogMessage.getAppName());
        Assertions.assertEquals("2025-10-06T00:00:00Z", syslogMessage.getTimestamp());

        final Map<String, Map<String, String>> sdElementMap = syslogMessage
                .getSDElements()
                .stream()
                .collect(Collectors.toMap((SDElement::getSdID), (sdElem) -> sdElem.getSdParams().stream().collect(Collectors.toMap(SDParam::getParamName, SDParam::getParamValue))));

        Assertions.assertEquals(1, sdElementMap.get("nlf_01@48577").size());
        Assertions
                .assertEquals(DefaultEventType.class.getSimpleName(), sdElementMap.get("nlf_01@48577").get("eventType"));

        Assertions.assertTrue(sdElementMap.get("aer_event@48577").containsKey("properties"));
    }

    @Test
    @DisplayName("Test NLFPlugin with DatabricksGroups")
    void testNlfPluginWithDatabricksGroups() {
        final String json = Assertions
                .assertDoesNotThrow(
                        () -> Files.readString(Paths.get("src/test/resources/databricks/databricksgroups.json"))
                );
        final ParsedEvent parsedEvent = new ParsedEventFactory(
                new UnparsedEventImpl(json, new EventPartitionContextImpl(new HashMap<>()), new EventPropertiesImpl(new HashMap<>()), new EventSystemPropertiesImpl(new HashMap<>()), new EnqueuedTimeImpl("2020-01-01T00:00:00"), new EventOffsetImpl("0"))
        ).parsedEvent();

        final NLFPlugin plugin = new NLFPlugin(new FakeSourceable());
        final List<SyslogMessage> syslogMessages = Assertions
                .assertDoesNotThrow(() -> plugin.syslogMessage(parsedEvent));
        Assertions.assertEquals(1, syslogMessages.size());

        final SyslogMessage syslogMessage = syslogMessages.get(0);
        Assertions
                .assertEquals(
                        "{\n" + "  \"ActionName\": \"ActionName-23\",\n" + "  \"Category\": \"category-23\",\n"
                                + "  \"Identity\": \"identity-23\",\n"
                                + "  \"LogId\": \"12345678-1234-1234-abcd-1234567890bc\",\n"
                                + "  \"OperationName\": \"Operation-23\",\n" + "  \"OperationVersion\": \"1.0.0\",\n"
                                + "  \"RequestId\": \"12345678-1234-1234-abcd-1234567890cd\",\n"
                                + "  \"RequestParams\": \"\\\"key\\\":\\\"value\\\"\",\n"
                                + "  \"Response\": \"Success\",\n" + "  \"ServiceName\": \"service-23\",\n"
                                + "  \"SessionId\": \"12345678-1234-1234-abcd-1234567890de\",\n"
                                + "  \"SourceIpAddress\": \"127.0.0.1\",\n" + "  \"SourceSystem\": \"Azure\",\n"
                                + "  \"TenantId\": \"12345678-1234-1234-abcd-1234567890ef\",\n"
                                + "  \"TimeGenerated\": \"2025-10-06T00:00:00.0000000Z\",\n"
                                + "  \"Type\": \"DatabricksGroups\",\n"
                                + "  \"UserAgent\": \"User-Agent: Mozilla/5.0 (<system-information>) <platform> (<platform-details>) <extensions>\",\n"
                                + "  \"_ResourceId\": \"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}\",\n"
                                + "  \"_SubscriptionId\": \"12345678-1234-1234-abcd-1234567890fg\"\n" + "}",
                        syslogMessage.getMsg()
                );
        Assertions.assertEquals("md5-0ded52ef915af563e25778bf26b0f129-resourceName", syslogMessage.getHostname());
        Assertions.assertEquals("DatabricksGroups", syslogMessage.getAppName());
        Assertions.assertEquals("2025-10-06T00:00:00Z", syslogMessage.getTimestamp());

        final Map<String, Map<String, String>> sdElementMap = syslogMessage
                .getSDElements()
                .stream()
                .collect(Collectors.toMap((SDElement::getSdID), (sdElem) -> sdElem.getSdParams().stream().collect(Collectors.toMap(SDParam::getParamName, SDParam::getParamValue))));

        Assertions.assertEquals(1, sdElementMap.get("nlf_01@48577").size());
        Assertions
                .assertEquals(DefaultEventType.class.getSimpleName(), sdElementMap.get("nlf_01@48577").get("eventType"));

        Assertions.assertTrue(sdElementMap.get("aer_event@48577").containsKey("properties"));
    }

    @Test
    @DisplayName("Test NLFPlugin with DatabricksIAMRole")
    void testNlfPluginWithDatabricksIamRole() {
        final String json = Assertions
                .assertDoesNotThrow(
                        () -> Files.readString(Paths.get("src/test/resources/databricks/databricksiamrole.json"))
                );
        final ParsedEvent parsedEvent = new ParsedEventFactory(
                new UnparsedEventImpl(json, new EventPartitionContextImpl(new HashMap<>()), new EventPropertiesImpl(new HashMap<>()), new EventSystemPropertiesImpl(new HashMap<>()), new EnqueuedTimeImpl("2020-01-01T00:00:00"), new EventOffsetImpl("0"))
        ).parsedEvent();

        final NLFPlugin plugin = new NLFPlugin(new FakeSourceable());
        final List<SyslogMessage> syslogMessages = Assertions
                .assertDoesNotThrow(() -> plugin.syslogMessage(parsedEvent));
        Assertions.assertEquals(1, syslogMessages.size());

        final SyslogMessage syslogMessage = syslogMessages.get(0);
        Assertions
                .assertEquals(
                        "{\n" + "  \"ActionName\": \"ActionName-24\",\n" + "  \"Category\": \"category-24\",\n"
                                + "  \"Identity\": \"identity-24\",\n"
                                + "  \"LogId\": \"12345678-1234-1234-abcd-1234567890bc\",\n"
                                + "  \"OperationName\": \"Operation-24\",\n" + "  \"OperationVersion\": \"1.0.0\",\n"
                                + "  \"RequestId\": \"12345678-1234-1234-abcd-1234567890cd\",\n"
                                + "  \"RequestParams\": \"\\\"key\\\":\\\"value\\\"\",\n"
                                + "  \"Response\": \"Success\",\n" + "  \"ServiceName\": \"service-24\",\n"
                                + "  \"SessionId\": \"12345678-1234-1234-abcd-1234567890de\",\n"
                                + "  \"SourceIPAddress\": \"127.0.0.1\",\n" + "  \"SourceSystem\": \"Azure\",\n"
                                + "  \"TenantId\": \"12345678-1234-1234-abcd-1234567890ef\",\n"
                                + "  \"TimeGenerated\": \"2025-10-06T00:00:00.0000000Z\",\n"
                                + "  \"Type\": \"DatabricksIAMRole\",\n"
                                + "  \"UserAgent\": \"User-Agent: Mozilla/5.0 (<system-information>) <platform> (<platform-details>) <extensions>\",\n"
                                + "  \"_ResourceId\": \"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}\",\n"
                                + "  \"_SubscriptionId\": \"12345678-1234-1234-abcd-1234567890fg\"\n" + "}",
                        syslogMessage.getMsg()
                );
        Assertions.assertEquals("md5-0ded52ef915af563e25778bf26b0f129-resourceName", syslogMessage.getHostname());
        Assertions.assertEquals("DatabricksIAMRole", syslogMessage.getAppName());
        Assertions.assertEquals("2025-10-06T00:00:00Z", syslogMessage.getTimestamp());

        final Map<String, Map<String, String>> sdElementMap = syslogMessage
                .getSDElements()
                .stream()
                .collect(Collectors.toMap((SDElement::getSdID), (sdElem) -> sdElem.getSdParams().stream().collect(Collectors.toMap(SDParam::getParamName, SDParam::getParamValue))));

        Assertions.assertEquals(1, sdElementMap.get("nlf_01@48577").size());
        Assertions
                .assertEquals(DefaultEventType.class.getSimpleName(), sdElementMap.get("nlf_01@48577").get("eventType"));

        Assertions.assertTrue(sdElementMap.get("aer_event@48577").containsKey("properties"));
    }

    @Test
    @DisplayName("Test NLFPlugin with DatabricksIngestion")
    void testNlfPluginWithDatabricksIngestion() {
        final String json = Assertions
                .assertDoesNotThrow(
                        () -> Files.readString(Paths.get("src/test/resources/databricks/databricksingestion.json"))
                );
        final ParsedEvent parsedEvent = new ParsedEventFactory(
                new UnparsedEventImpl(json, new EventPartitionContextImpl(new HashMap<>()), new EventPropertiesImpl(new HashMap<>()), new EventSystemPropertiesImpl(new HashMap<>()), new EnqueuedTimeImpl("2020-01-01T00:00:00"), new EventOffsetImpl("0"))
        ).parsedEvent();

        final NLFPlugin plugin = new NLFPlugin(new FakeSourceable());
        final List<SyslogMessage> syslogMessages = Assertions
                .assertDoesNotThrow(() -> plugin.syslogMessage(parsedEvent));
        Assertions.assertEquals(1, syslogMessages.size());

        final SyslogMessage syslogMessage = syslogMessages.get(0);
        Assertions
                .assertEquals(
                        "{\n" + "  \"ActionName\": \"ActionName-25\",\n" + "  \"Category\": \"category-25\",\n"
                                + "  \"Identity\": \"identity-25\",\n"
                                + "  \"LogId\": \"12345678-1234-1234-abcd-1234567890bc\",\n"
                                + "  \"OperationName\": \"Operation-25\",\n" + "  \"OperationVersion\": \"1.0.0\",\n"
                                + "  \"RequestId\": \"12345678-1234-1234-abcd-1234567890cd\",\n"
                                + "  \"RequestParams\": \"\\\"key\\\":\\\"value\\\"\",\n"
                                + "  \"Response\": \"Success\",\n" + "  \"ServiceName\": \"service-25\",\n"
                                + "  \"SessionId\": \"12345678-1234-1234-abcd-1234567890de\",\n"
                                + "  \"SourceIpAddress\": \"127.0.0.1\",\n" + "  \"SourceSystem\": \"Azure\",\n"
                                + "  \"TenantId\": \"12345678-1234-1234-abcd-1234567890ef\",\n"
                                + "  \"TimeGenerated\": \"2025-10-06T00:00:00.0000000Z\",\n"
                                + "  \"Type\": \"DatabricksIngestion\",\n"
                                + "  \"UserAgent\": \"User-Agent: Mozilla/5.0 (<system-information>) <platform> (<platform-details>) <extensions>\",\n"
                                + "  \"_ResourceId\": \"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}\",\n"
                                + "  \"_SubscriptionId\": \"12345678-1234-1234-abcd-1234567890fg\"\n" + "}",
                        syslogMessage.getMsg()
                );
        Assertions.assertEquals("md5-0ded52ef915af563e25778bf26b0f129-resourceName", syslogMessage.getHostname());
        Assertions.assertEquals("DatabricksIngestion", syslogMessage.getAppName());
        Assertions.assertEquals("2025-10-06T00:00:00Z", syslogMessage.getTimestamp());

        final Map<String, Map<String, String>> sdElementMap = syslogMessage
                .getSDElements()
                .stream()
                .collect(Collectors.toMap((SDElement::getSdID), (sdElem) -> sdElem.getSdParams().stream().collect(Collectors.toMap(SDParam::getParamName, SDParam::getParamValue))));

        Assertions.assertEquals(1, sdElementMap.get("nlf_01@48577").size());
        Assertions
                .assertEquals(DefaultEventType.class.getSimpleName(), sdElementMap.get("nlf_01@48577").get("eventType"));

        Assertions.assertTrue(sdElementMap.get("aer_event@48577").containsKey("properties"));
    }

    @Test
    @DisplayName("Test NLFPlugin with DatabricksInstancePools")
    void testNlfPluginWithDatabricksInstancePools() {
        final String json = Assertions
                .assertDoesNotThrow(
                        () -> Files.readString(Paths.get("src/test/resources/databricks/databricksinstancepools.json"))
                );
        final ParsedEvent parsedEvent = new ParsedEventFactory(
                new UnparsedEventImpl(json, new EventPartitionContextImpl(new HashMap<>()), new EventPropertiesImpl(new HashMap<>()), new EventSystemPropertiesImpl(new HashMap<>()), new EnqueuedTimeImpl("2020-01-01T00:00:00"), new EventOffsetImpl("0"))
        ).parsedEvent();

        final NLFPlugin plugin = new NLFPlugin(new FakeSourceable());
        final List<SyslogMessage> syslogMessages = Assertions
                .assertDoesNotThrow(() -> plugin.syslogMessage(parsedEvent));
        Assertions.assertEquals(1, syslogMessages.size());

        final SyslogMessage syslogMessage = syslogMessages.get(0);
        Assertions
                .assertEquals(
                        "{\n" + "  \"ActionName\": \"ActionName-26\",\n" + "  \"Category\": \"category-26\",\n"
                                + "  \"Identity\": \"identity-26\",\n"
                                + "  \"LogId\": \"12345678-1234-1234-abcd-1234567890bc\",\n"
                                + "  \"OperationName\": \"Operation-26\",\n" + "  \"OperationVersion\": \"1.0.0\",\n"
                                + "  \"RequestId\": \"12345678-1234-1234-abcd-1234567890cd\",\n"
                                + "  \"RequestParams\": \"\\\"key\\\":\\\"value\\\"\",\n"
                                + "  \"Response\": \"Success\",\n" + "  \"ServiceName\": \"service-26\",\n"
                                + "  \"SessionId\": \"12345678-1234-1234-abcd-1234567890de\",\n"
                                + "  \"SourceIPAddress\": \"127.0.0.1\",\n" + "  \"SourceSystem\": \"Azure\",\n"
                                + "  \"TenantId\": \"12345678-1234-1234-abcd-1234567890ef\",\n"
                                + "  \"TimeGenerated\": \"2025-10-06T00:00:00.0000000Z\",\n"
                                + "  \"Type\": \"DatabricksInstancePools\",\n"
                                + "  \"UserAgent\": \"User-Agent: Mozilla/5.0 (<system-information>) <platform> (<platform-details>) <extensions>\",\n"
                                + "  \"_ResourceId\": \"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}\",\n"
                                + "  \"_SubscriptionId\": \"12345678-1234-1234-abcd-1234567890fg\"\n" + "}",
                        syslogMessage.getMsg()
                );
        Assertions.assertEquals("md5-0ded52ef915af563e25778bf26b0f129-resourceName", syslogMessage.getHostname());
        Assertions.assertEquals("DatabricksInstancePools", syslogMessage.getAppName());
        Assertions.assertEquals("2025-10-06T00:00:00Z", syslogMessage.getTimestamp());

        final Map<String, Map<String, String>> sdElementMap = syslogMessage
                .getSDElements()
                .stream()
                .collect(Collectors.toMap((SDElement::getSdID), (sdElem) -> sdElem.getSdParams().stream().collect(Collectors.toMap(SDParam::getParamName, SDParam::getParamValue))));

        Assertions.assertEquals(1, sdElementMap.get("nlf_01@48577").size());
        Assertions
                .assertEquals(DefaultEventType.class.getSimpleName(), sdElementMap.get("nlf_01@48577").get("eventType"));

        Assertions.assertTrue(sdElementMap.get("aer_event@48577").containsKey("properties"));
    }

    @Test
    @DisplayName("Test NLFPlugin with DatabricksJobs")
    void testNlfPluginWithDatabricksJobs() {
        final String json = Assertions
                .assertDoesNotThrow(() -> Files.readString(Paths.get("src/test/resources/databricks/databricksjobs.json")));
        final ParsedEvent parsedEvent = new ParsedEventFactory(
                new UnparsedEventImpl(json, new EventPartitionContextImpl(new HashMap<>()), new EventPropertiesImpl(new HashMap<>()), new EventSystemPropertiesImpl(new HashMap<>()), new EnqueuedTimeImpl("2020-01-01T00:00:00"), new EventOffsetImpl("0"))
        ).parsedEvent();

        final NLFPlugin plugin = new NLFPlugin(new FakeSourceable());
        final List<SyslogMessage> syslogMessages = Assertions
                .assertDoesNotThrow(() -> plugin.syslogMessage(parsedEvent));
        Assertions.assertEquals(1, syslogMessages.size());

        final SyslogMessage syslogMessage = syslogMessages.get(0);
        Assertions
                .assertEquals(
                        "{\n" + "  \"ActionName\": \"ActionName-27\",\n" + "  \"Category\": \"category-27\",\n"
                                + "  \"Identity\": \"identity-27\",\n"
                                + "  \"LogId\": \"12345678-1234-1234-abcd-1234567890bc\",\n"
                                + "  \"OperationName\": \"Operation-27\",\n" + "  \"OperationVersion\": \"1.0.0\",\n"
                                + "  \"RequestId\": \"12345678-1234-1234-abcd-1234567890cd\",\n"
                                + "  \"RequestParams\": \"\\\"key\\\":\\\"value\\\"\",\n"
                                + "  \"Response\": \"Success\",\n" + "  \"ServiceName\": \"service-27\",\n"
                                + "  \"SessionId\": \"12345678-1234-1234-abcd-1234567890de\",\n"
                                + "  \"SourceIPAddress\": \"127.0.0.1\",\n" + "  \"SourceSystem\": \"Azure\",\n"
                                + "  \"TenantId\": \"12345678-1234-1234-abcd-1234567890ef\",\n"
                                + "  \"TimeGenerated\": \"2025-10-06T00:00:00.0000000Z\",\n"
                                + "  \"Type\": \"DatabricksJobs\",\n"
                                + "  \"UserAgent\": \"User-Agent: Mozilla/5.0 (<system-information>) <platform> (<platform-details>) <extensions>\",\n"
                                + "  \"_ResourceId\": \"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}\",\n"
                                + "  \"_SubscriptionId\": \"12345678-1234-1234-abcd-1234567890fg\"\n" + "}",
                        syslogMessage.getMsg()
                );
        Assertions.assertEquals("md5-0ded52ef915af563e25778bf26b0f129-resourceName", syslogMessage.getHostname());
        Assertions.assertEquals("DatabricksJobs", syslogMessage.getAppName());
        Assertions.assertEquals("2025-10-06T00:00:00Z", syslogMessage.getTimestamp());

        final Map<String, Map<String, String>> sdElementMap = syslogMessage
                .getSDElements()
                .stream()
                .collect(Collectors.toMap((SDElement::getSdID), (sdElem) -> sdElem.getSdParams().stream().collect(Collectors.toMap(SDParam::getParamName, SDParam::getParamValue))));

        Assertions.assertEquals(1, sdElementMap.get("nlf_01@48577").size());
        Assertions
                .assertEquals(DefaultEventType.class.getSimpleName(), sdElementMap.get("nlf_01@48577").get("eventType"));

        Assertions.assertTrue(sdElementMap.get("aer_event@48577").containsKey("properties"));
    }

    @Test
    @DisplayName("Test NLFPlugin with DatabricksLakeviewConfig")
    void testNlfPluginWithDatabricksLakeviewConfig() {
        final String json = Assertions
                .assertDoesNotThrow(
                        () -> Files.readString(Paths.get("src/test/resources/databricks/databrickslakeviewconfig.json"))
                );
        final ParsedEvent parsedEvent = new ParsedEventFactory(
                new UnparsedEventImpl(json, new EventPartitionContextImpl(new HashMap<>()), new EventPropertiesImpl(new HashMap<>()), new EventSystemPropertiesImpl(new HashMap<>()), new EnqueuedTimeImpl("2020-01-01T00:00:00"), new EventOffsetImpl("0"))
        ).parsedEvent();

        final NLFPlugin plugin = new NLFPlugin(new FakeSourceable());
        final List<SyslogMessage> syslogMessages = Assertions
                .assertDoesNotThrow(() -> plugin.syslogMessage(parsedEvent));
        Assertions.assertEquals(1, syslogMessages.size());

        final SyslogMessage syslogMessage = syslogMessages.get(0);
        Assertions
                .assertEquals(
                        "{\n" + "  \"ActionName\": \"ActionName-28\",\n" + "  \"Category\": \"category-28\",\n"
                                + "  \"Identity\": \"identity-28\",\n"
                                + "  \"LogId\": \"12345678-1234-1234-abcd-1234567890bc\",\n"
                                + "  \"OperationName\": \"Operation-28\",\n" + "  \"OperationVersion\": \"1.0.0\",\n"
                                + "  \"RequestId\": \"12345678-1234-1234-abcd-1234567890cd\",\n"
                                + "  \"RequestParams\": \"\\\"key\\\":\\\"value\\\"\",\n"
                                + "  \"Response\": \"Success\",\n" + "  \"ServiceName\": \"service-28\",\n"
                                + "  \"SessionId\": \"12345678-1234-1234-abcd-1234567890de\",\n"
                                + "  \"SourceIpAddress\": \"127.0.0.1\",\n" + "  \"SourceSystem\": \"Azure\",\n"
                                + "  \"TenantId\": \"12345678-1234-1234-abcd-1234567890ef\",\n"
                                + "  \"TimeGenerated\": \"2025-10-06T00:00:00.0000000Z\",\n"
                                + "  \"Type\": \"DatabricksLakeviewConfig\",\n"
                                + "  \"UserAgent\": \"User-Agent: Mozilla/5.0 (<system-information>) <platform> (<platform-details>) <extensions>\",\n"
                                + "  \"_ResourceId\": \"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}\",\n"
                                + "  \"_SubscriptionId\": \"12345678-1234-1234-abcd-1234567890fg\"\n" + "}",
                        syslogMessage.getMsg()
                );
        Assertions.assertEquals("md5-0ded52ef915af563e25778bf26b0f129-resourceName", syslogMessage.getHostname());
        Assertions.assertEquals("DatabricksLakeviewConfig", syslogMessage.getAppName());
        Assertions.assertEquals("2025-10-06T00:00:00Z", syslogMessage.getTimestamp());

        final Map<String, Map<String, String>> sdElementMap = syslogMessage
                .getSDElements()
                .stream()
                .collect(Collectors.toMap((SDElement::getSdID), (sdElem) -> sdElem.getSdParams().stream().collect(Collectors.toMap(SDParam::getParamName, SDParam::getParamValue))));

        Assertions.assertEquals(1, sdElementMap.get("nlf_01@48577").size());
        Assertions
                .assertEquals(DefaultEventType.class.getSimpleName(), sdElementMap.get("nlf_01@48577").get("eventType"));

        Assertions.assertTrue(sdElementMap.get("aer_event@48577").containsKey("properties"));
    }

    @Test
    @DisplayName("Test NLFPlugin with DatabricksLineageTracking")
    void testNlfPluginWithDatabricksLineageTracking() {
        final String json = Assertions
                .assertDoesNotThrow(
                        () -> Files.readString(Paths.get("src/test/resources/databricks/databrickslineagetracking.json"))
                );
        final ParsedEvent parsedEvent = new ParsedEventFactory(
                new UnparsedEventImpl(json, new EventPartitionContextImpl(new HashMap<>()), new EventPropertiesImpl(new HashMap<>()), new EventSystemPropertiesImpl(new HashMap<>()), new EnqueuedTimeImpl("2020-01-01T00:00:00"), new EventOffsetImpl("0"))
        ).parsedEvent();

        final NLFPlugin plugin = new NLFPlugin(new FakeSourceable());
        final List<SyslogMessage> syslogMessages = Assertions
                .assertDoesNotThrow(() -> plugin.syslogMessage(parsedEvent));
        Assertions.assertEquals(1, syslogMessages.size());

        final SyslogMessage syslogMessage = syslogMessages.get(0);
        Assertions
                .assertEquals(
                        "{\n" + "  \"ActionName\": \"ActionName-29\",\n" + "  \"Category\": \"category-29\",\n"
                                + "  \"Identity\": \"identity-29\",\n"
                                + "  \"LogId\": \"12345678-1234-1234-abcd-1234567890bc\",\n"
                                + "  \"OperationName\": \"Operation-29\",\n" + "  \"OperationVersion\": \"1.0.0\",\n"
                                + "  \"RequestId\": \"12345678-1234-1234-abcd-1234567890cd\",\n"
                                + "  \"RequestParams\": \"\\\"key\\\":\\\"value\\\"\",\n"
                                + "  \"Response\": \"Success\",\n" + "  \"ServiceName\": \"service-29\",\n"
                                + "  \"SessionId\": \"12345678-1234-1234-abcd-1234567890de\",\n"
                                + "  \"SourceIpAddress\": \"127.0.0.1\",\n" + "  \"SourceSystem\": \"Azure\",\n"
                                + "  \"TenantId\": \"12345678-1234-1234-abcd-1234567890ef\",\n"
                                + "  \"TimeGenerated\": \"2025-10-06T00:00:00.0000000Z\",\n"
                                + "  \"Type\": \"DatabricksLineageTracking\",\n"
                                + "  \"UserAgent\": \"User-Agent: Mozilla/5.0 (<system-information>) <platform> (<platform-details>) <extensions>\",\n"
                                + "  \"_ResourceId\": \"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}\",\n"
                                + "  \"_SubscriptionId\": \"12345678-1234-1234-abcd-1234567890fg\"\n" + "}",
                        syslogMessage.getMsg()
                );
        Assertions.assertEquals("md5-0ded52ef915af563e25778bf26b0f129-resourceName", syslogMessage.getHostname());
        Assertions.assertEquals("DatabricksLineageTracking", syslogMessage.getAppName());
        Assertions.assertEquals("2025-10-06T00:00:00Z", syslogMessage.getTimestamp());

        final Map<String, Map<String, String>> sdElementMap = syslogMessage
                .getSDElements()
                .stream()
                .collect(Collectors.toMap((SDElement::getSdID), (sdElem) -> sdElem.getSdParams().stream().collect(Collectors.toMap(SDParam::getParamName, SDParam::getParamValue))));

        Assertions.assertEquals(1, sdElementMap.get("nlf_01@48577").size());
        Assertions
                .assertEquals(DefaultEventType.class.getSimpleName(), sdElementMap.get("nlf_01@48577").get("eventType"));

        Assertions.assertTrue(sdElementMap.get("aer_event@48577").containsKey("properties"));
    }

    @Test
    @DisplayName("Test NLFPlugin with DatabricksMarketplaceConsumer")
    void testNlfPluginWithDatabricksMarketplaceConsumer() {
        final String json = Assertions
                .assertDoesNotThrow(
                        () -> Files
                                .readString(Paths.get("src/test/resources/databricks/databricksmarketplaceconsumer.json"))
                );
        final ParsedEvent parsedEvent = new ParsedEventFactory(
                new UnparsedEventImpl(json, new EventPartitionContextImpl(new HashMap<>()), new EventPropertiesImpl(new HashMap<>()), new EventSystemPropertiesImpl(new HashMap<>()), new EnqueuedTimeImpl("2020-01-01T00:00:00"), new EventOffsetImpl("0"))
        ).parsedEvent();

        final NLFPlugin plugin = new NLFPlugin(new FakeSourceable());
        final List<SyslogMessage> syslogMessages = Assertions
                .assertDoesNotThrow(() -> plugin.syslogMessage(parsedEvent));
        Assertions.assertEquals(1, syslogMessages.size());

        final SyslogMessage syslogMessage = syslogMessages.get(0);
        Assertions
                .assertEquals(
                        "{\n" + "  \"ActionName\": \"ActionName-30\",\n" + "  \"Category\": \"category-30\",\n"
                                + "  \"Identity\": \"identity-30\",\n"
                                + "  \"LogId\": \"12345678-1234-1234-abcd-1234567890bc\",\n"
                                + "  \"OperationName\": \"Operation-30\",\n" + "  \"OperationVersion\": \"1.0.0\",\n"
                                + "  \"RequestId\": \"12345678-1234-1234-abcd-1234567890cd\",\n"
                                + "  \"RequestParams\": \"\\\"key\\\":\\\"value\\\"\",\n"
                                + "  \"Response\": \"Success\",\n" + "  \"ServiceName\": \"service-30\",\n"
                                + "  \"SessionId\": \"12345678-1234-1234-abcd-1234567890de\",\n"
                                + "  \"SourceIpAddress\": \"127.0.0.1\",\n" + "  \"SourceSystem\": \"Azure\",\n"
                                + "  \"TenantId\": \"12345678-1234-1234-abcd-1234567890ef\",\n"
                                + "  \"TimeGenerated\": \"2025-10-06T00:00:00.0000000Z\",\n"
                                + "  \"Type\": \"DatabricksMarketplaceConsumer\",\n"
                                + "  \"UserAgent\": \"User-Agent: Mozilla/5.0 (<system-information>) <platform> (<platform-details>) <extensions>\",\n"
                                + "  \"_ResourceId\": \"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}\",\n"
                                + "  \"_SubscriptionId\": \"12345678-1234-1234-abcd-1234567890fg\"\n" + "}",
                        syslogMessage.getMsg()
                );
        Assertions.assertEquals("md5-0ded52ef915af563e25778bf26b0f129-resourceName", syslogMessage.getHostname());
        Assertions.assertEquals("DatabricksMarketplaceConsumer", syslogMessage.getAppName());
        Assertions.assertEquals("2025-10-06T00:00:00Z", syslogMessage.getTimestamp());

        final Map<String, Map<String, String>> sdElementMap = syslogMessage
                .getSDElements()
                .stream()
                .collect(Collectors.toMap((SDElement::getSdID), (sdElem) -> sdElem.getSdParams().stream().collect(Collectors.toMap(SDParam::getParamName, SDParam::getParamValue))));

        Assertions.assertEquals(1, sdElementMap.get("nlf_01@48577").size());
        Assertions
                .assertEquals(DefaultEventType.class.getSimpleName(), sdElementMap.get("nlf_01@48577").get("eventType"));

        Assertions.assertTrue(sdElementMap.get("aer_event@48577").containsKey("properties"));
    }

    @Test
    @DisplayName("Test NLFPlugin with DatabricksMarketplaceProvider")
    void testNlfPluginWithDatabricksMarketplaceProvider() {
        final String json = Assertions
                .assertDoesNotThrow(
                        () -> Files
                                .readString(Paths.get("src/test/resources/databricks/databricksmarketplaceprovider.json"))
                );
        final ParsedEvent parsedEvent = new ParsedEventFactory(
                new UnparsedEventImpl(json, new EventPartitionContextImpl(new HashMap<>()), new EventPropertiesImpl(new HashMap<>()), new EventSystemPropertiesImpl(new HashMap<>()), new EnqueuedTimeImpl("2020-01-01T00:00:00"), new EventOffsetImpl("0"))
        ).parsedEvent();

        final NLFPlugin plugin = new NLFPlugin(new FakeSourceable());
        final List<SyslogMessage> syslogMessages = Assertions
                .assertDoesNotThrow(() -> plugin.syslogMessage(parsedEvent));
        Assertions.assertEquals(1, syslogMessages.size());

        final SyslogMessage syslogMessage = syslogMessages.get(0);
        Assertions
                .assertEquals(
                        "{\n" + "  \"ActionName\": \"ActionName-31\",\n" + "  \"Category\": \"category-31\",\n"
                                + "  \"Identity\": \"identity-31\",\n"
                                + "  \"LogId\": \"12345678-1234-1234-abcd-1234567890bc\",\n"
                                + "  \"OperationName\": \"Operation-31\",\n" + "  \"OperationVersion\": \"1.0.0\",\n"
                                + "  \"RequestId\": \"12345678-1234-1234-abcd-1234567890cd\",\n"
                                + "  \"RequestParams\": \"\\\"key\\\":\\\"value\\\"\",\n"
                                + "  \"Response\": \"Success\",\n" + "  \"ServiceName\": \"service-31\",\n"
                                + "  \"SessionId\": \"12345678-1234-1234-abcd-1234567890de\",\n"
                                + "  \"SourceIpAddress\": \"127.0.0.1\",\n" + "  \"SourceSystem\": \"Azure\",\n"
                                + "  \"TenantId\": \"12345678-1234-1234-abcd-1234567890ef\",\n"
                                + "  \"TimeGenerated\": \"2025-10-06T00:00:00.0000000Z\",\n"
                                + "  \"Type\": \"DatabricksMarketplaceProvider\",\n"
                                + "  \"UserAgent\": \"User-Agent: Mozilla/5.0 (<system-information>) <platform> (<platform-details>) <extensions>\",\n"
                                + "  \"_ResourceId\": \"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}\",\n"
                                + "  \"_SubscriptionId\": \"12345678-1234-1234-abcd-1234567890fg\"\n" + "}",
                        syslogMessage.getMsg()
                );
        Assertions.assertEquals("md5-0ded52ef915af563e25778bf26b0f129-resourceName", syslogMessage.getHostname());
        Assertions.assertEquals("DatabricksMarketplaceProvider", syslogMessage.getAppName());
        Assertions.assertEquals("2025-10-06T00:00:00Z", syslogMessage.getTimestamp());

        final Map<String, Map<String, String>> sdElementMap = syslogMessage
                .getSDElements()
                .stream()
                .collect(Collectors.toMap((SDElement::getSdID), (sdElem) -> sdElem.getSdParams().stream().collect(Collectors.toMap(SDParam::getParamName, SDParam::getParamValue))));

        Assertions.assertEquals(1, sdElementMap.get("nlf_01@48577").size());
        Assertions
                .assertEquals(DefaultEventType.class.getSimpleName(), sdElementMap.get("nlf_01@48577").get("eventType"));

        Assertions.assertTrue(sdElementMap.get("aer_event@48577").containsKey("properties"));
    }

    @Test
    @DisplayName("Test NLFPlugin with DatabricksMLflowAcledArtifact")
    void testNlfPluginWithDatabricksMLflowAcledArtifact() {
        final String json = Assertions
                .assertDoesNotThrow(
                        () -> Files
                                .readString(Paths.get("src/test/resources/databricks/databricksmlflowacledartifact.json"))
                );
        final ParsedEvent parsedEvent = new ParsedEventFactory(
                new UnparsedEventImpl(json, new EventPartitionContextImpl(new HashMap<>()), new EventPropertiesImpl(new HashMap<>()), new EventSystemPropertiesImpl(new HashMap<>()), new EnqueuedTimeImpl("2020-01-01T00:00:00"), new EventOffsetImpl("0"))
        ).parsedEvent();

        final NLFPlugin plugin = new NLFPlugin(new FakeSourceable());
        final List<SyslogMessage> syslogMessages = Assertions
                .assertDoesNotThrow(() -> plugin.syslogMessage(parsedEvent));
        Assertions.assertEquals(1, syslogMessages.size());

        final SyslogMessage syslogMessage = syslogMessages.get(0);
        Assertions
                .assertEquals(
                        "{\n" + "  \"ActionName\": \"ActionName-32\",\n" + "  \"Category\": \"category-32\",\n"
                                + "  \"Identity\": \"identity-32\",\n"
                                + "  \"LogId\": \"12345678-1234-1234-abcd-1234567890bc\",\n"
                                + "  \"OperationName\": \"Operation-32\",\n" + "  \"OperationVersion\": \"1.0.0\",\n"
                                + "  \"RequestId\": \"12345678-1234-1234-abcd-1234567890cd\",\n"
                                + "  \"RequestParams\": \"\\\"key\\\":\\\"value\\\"\",\n"
                                + "  \"Response\": \"Success\",\n" + "  \"ServiceName\": \"service-32\",\n"
                                + "  \"SessionId\": \"12345678-1234-1234-abcd-1234567890de\",\n"
                                + "  \"SourceIPAddress\": \"127.0.0.1\",\n" + "  \"SourceSystem\": \"Azure\",\n"
                                + "  \"TenantId\": \"12345678-1234-1234-abcd-1234567890ef\",\n"
                                + "  \"TimeGenerated\": \"2025-10-06T00:00:00.0000000Z\",\n"
                                + "  \"Type\": \"DatabricksMLflowAcledArtifact\",\n"
                                + "  \"UserAgent\": \"User-Agent: Mozilla/5.0 (<system-information>) <platform> (<platform-details>) <extensions>\",\n"
                                + "  \"_ResourceId\": \"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}\",\n"
                                + "  \"_SubscriptionId\": \"12345678-1234-1234-abcd-1234567890fg\"\n" + "}",
                        syslogMessage.getMsg()
                );
        Assertions.assertEquals("md5-0ded52ef915af563e25778bf26b0f129-resourceName", syslogMessage.getHostname());
        Assertions.assertEquals("DatabricksMLflowAcledArtifact", syslogMessage.getAppName());
        Assertions.assertEquals("2025-10-06T00:00:00Z", syslogMessage.getTimestamp());

        final Map<String, Map<String, String>> sdElementMap = syslogMessage
                .getSDElements()
                .stream()
                .collect(Collectors.toMap((SDElement::getSdID), (sdElem) -> sdElem.getSdParams().stream().collect(Collectors.toMap(SDParam::getParamName, SDParam::getParamValue))));

        Assertions.assertEquals(1, sdElementMap.get("nlf_01@48577").size());
        Assertions
                .assertEquals(DefaultEventType.class.getSimpleName(), sdElementMap.get("nlf_01@48577").get("eventType"));

        Assertions.assertTrue(sdElementMap.get("aer_event@48577").containsKey("properties"));
    }

    @Test
    @DisplayName("Test NLFPlugin with DatabricksMLflowExperiment")
    void testNlfPluginWithDatabricksMLflowExperiment() {
        final String json = Assertions
                .assertDoesNotThrow(
                        () -> Files.readString(Paths.get("src/test/resources/databricks/databricksmlflowexperiment.json"))
                );
        final ParsedEvent parsedEvent = new ParsedEventFactory(
                new UnparsedEventImpl(json, new EventPartitionContextImpl(new HashMap<>()), new EventPropertiesImpl(new HashMap<>()), new EventSystemPropertiesImpl(new HashMap<>()), new EnqueuedTimeImpl("2020-01-01T00:00:00"), new EventOffsetImpl("0"))
        ).parsedEvent();

        final NLFPlugin plugin = new NLFPlugin(new FakeSourceable());
        final List<SyslogMessage> syslogMessages = Assertions
                .assertDoesNotThrow(() -> plugin.syslogMessage(parsedEvent));
        Assertions.assertEquals(1, syslogMessages.size());

        final SyslogMessage syslogMessage = syslogMessages.get(0);
        Assertions
                .assertEquals(
                        "{\n" + "  \"ActionName\": \"ActionName-33\",\n" + "  \"Category\": \"category-33\",\n"
                                + "  \"Identity\": \"identity-33\",\n"
                                + "  \"LogId\": \"12345678-1234-1234-abcd-1234567890bc\",\n"
                                + "  \"OperationName\": \"Operation-33\",\n" + "  \"OperationVersion\": \"1.0.0\",\n"
                                + "  \"RequestId\": \"12345678-1234-1234-abcd-1234567890cd\",\n"
                                + "  \"RequestParams\": \"\\\"key\\\":\\\"value\\\"\",\n"
                                + "  \"Response\": \"Success\",\n" + "  \"ServiceName\": \"service-33\",\n"
                                + "  \"SessionId\": \"12345678-1234-1234-abcd-1234567890de\",\n"
                                + "  \"SourceIPAddress\": \"127.0.0.1\",\n" + "  \"SourceSystem\": \"Azure\",\n"
                                + "  \"TenantId\": \"12345678-1234-1234-abcd-1234567890ef\",\n"
                                + "  \"TimeGenerated\": \"2025-10-06T00:00:00.0000000Z\",\n"
                                + "  \"Type\": \"DatabricksMLflowExperiment\",\n"
                                + "  \"UserAgent\": \"User-Agent: Mozilla/5.0 (<system-information>) <platform> (<platform-details>) <extensions>\",\n"
                                + "  \"_ResourceId\": \"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}\",\n"
                                + "  \"_SubscriptionId\": \"12345678-1234-1234-abcd-1234567890fg\"\n" + "}",
                        syslogMessage.getMsg()
                );
        Assertions.assertEquals("md5-0ded52ef915af563e25778bf26b0f129-resourceName", syslogMessage.getHostname());
        Assertions.assertEquals("DatabricksMLflowExperiment", syslogMessage.getAppName());
        Assertions.assertEquals("2025-10-06T00:00:00Z", syslogMessage.getTimestamp());

        final Map<String, Map<String, String>> sdElementMap = syslogMessage
                .getSDElements()
                .stream()
                .collect(Collectors.toMap((SDElement::getSdID), (sdElem) -> sdElem.getSdParams().stream().collect(Collectors.toMap(SDParam::getParamName, SDParam::getParamValue))));

        Assertions.assertEquals(1, sdElementMap.get("nlf_01@48577").size());
        Assertions
                .assertEquals(DefaultEventType.class.getSimpleName(), sdElementMap.get("nlf_01@48577").get("eventType"));

        Assertions.assertTrue(sdElementMap.get("aer_event@48577").containsKey("properties"));
    }

    @Test
    @DisplayName("Test NLFPlugin with DatabricksModelRegistry")
    void testNlfPluginWithDatabricksModelRegistry() {
        final String json = Assertions
                .assertDoesNotThrow(
                        () -> Files.readString(Paths.get("src/test/resources/databricks/databricksmodelregistry.json"))
                );
        final ParsedEvent parsedEvent = new ParsedEventFactory(
                new UnparsedEventImpl(json, new EventPartitionContextImpl(new HashMap<>()), new EventPropertiesImpl(new HashMap<>()), new EventSystemPropertiesImpl(new HashMap<>()), new EnqueuedTimeImpl("2020-01-01T00:00:00"), new EventOffsetImpl("0"))
        ).parsedEvent();

        final NLFPlugin plugin = new NLFPlugin(new FakeSourceable());
        final List<SyslogMessage> syslogMessages = Assertions
                .assertDoesNotThrow(() -> plugin.syslogMessage(parsedEvent));
        Assertions.assertEquals(1, syslogMessages.size());

        final SyslogMessage syslogMessage = syslogMessages.get(0);
        Assertions
                .assertEquals(
                        "{\n" + "  \"ActionName\": \"ActionName-34\",\n" + "  \"Category\": \"category-34\",\n"
                                + "  \"Identity\": \"identity-34\",\n"
                                + "  \"LogId\": \"12345678-1234-1234-abcd-1234567890bc\",\n"
                                + "  \"OperationName\": \"Operation-34\",\n" + "  \"OperationVersion\": \"1.0.0\",\n"
                                + "  \"RequestId\": \"12345678-1234-1234-abcd-1234567890cd\",\n"
                                + "  \"RequestParams\": \"\\\"key\\\":\\\"value\\\"\",\n"
                                + "  \"Response\": \"Success\",\n" + "  \"ServiceName\": \"service-34\",\n"
                                + "  \"SessionId\": \"12345678-1234-1234-abcd-1234567890de\",\n"
                                + "  \"SourceIPAddress\": \"127.0.0.1\",\n" + "  \"SourceSystem\": \"Azure\",\n"
                                + "  \"TenantId\": \"12345678-1234-1234-abcd-1234567890ef\",\n"
                                + "  \"TimeGenerated\": \"2025-10-06T00:00:00.0000000Z\",\n"
                                + "  \"Type\": \"DatabricksModelRegistry\",\n"
                                + "  \"UserAgent\": \"User-Agent: Mozilla/5.0 (<system-information>) <platform> (<platform-details>) <extensions>\",\n"
                                + "  \"_ResourceId\": \"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}\",\n"
                                + "  \"_SubscriptionId\": \"12345678-1234-1234-abcd-1234567890fg\"\n" + "}",
                        syslogMessage.getMsg()
                );
        Assertions.assertEquals("md5-0ded52ef915af563e25778bf26b0f129-resourceName", syslogMessage.getHostname());
        Assertions.assertEquals("DatabricksModelRegistry", syslogMessage.getAppName());
        Assertions.assertEquals("2025-10-06T00:00:00Z", syslogMessage.getTimestamp());

        final Map<String, Map<String, String>> sdElementMap = syslogMessage
                .getSDElements()
                .stream()
                .collect(Collectors.toMap((SDElement::getSdID), (sdElem) -> sdElem.getSdParams().stream().collect(Collectors.toMap(SDParam::getParamName, SDParam::getParamValue))));

        Assertions.assertEquals(1, sdElementMap.get("nlf_01@48577").size());
        Assertions
                .assertEquals(DefaultEventType.class.getSimpleName(), sdElementMap.get("nlf_01@48577").get("eventType"));

        Assertions.assertTrue(sdElementMap.get("aer_event@48577").containsKey("properties"));
    }

    @Test
    @DisplayName("Test NLFPlugin with DatabricksNotebook")
    void testNlfPluginWithDatabricksNotebook() {
        final String json = Assertions
                .assertDoesNotThrow(
                        () -> Files.readString(Paths.get("src/test/resources/databricks/databricksnotebook.json"))
                );
        final ParsedEvent parsedEvent = new ParsedEventFactory(
                new UnparsedEventImpl(json, new EventPartitionContextImpl(new HashMap<>()), new EventPropertiesImpl(new HashMap<>()), new EventSystemPropertiesImpl(new HashMap<>()), new EnqueuedTimeImpl("2020-01-01T00:00:00"), new EventOffsetImpl("0"))
        ).parsedEvent();

        final NLFPlugin plugin = new NLFPlugin(new FakeSourceable());
        final List<SyslogMessage> syslogMessages = Assertions
                .assertDoesNotThrow(() -> plugin.syslogMessage(parsedEvent));
        Assertions.assertEquals(1, syslogMessages.size());

        final SyslogMessage syslogMessage = syslogMessages.get(0);
        Assertions
                .assertEquals(
                        "{\n" + "  \"ActionName\": \"ActionName-35\",\n" + "  \"Category\": \"category-35\",\n"
                                + "  \"Identity\": \"identity-35\",\n"
                                + "  \"LogId\": \"12345678-1234-1234-abcd-1234567890bc\",\n"
                                + "  \"OperationName\": \"Operation-35\",\n" + "  \"OperationVersion\": \"1.0.0\",\n"
                                + "  \"RequestId\": \"12345678-1234-1234-abcd-1234567890cd\",\n"
                                + "  \"RequestParams\": \"\\\"key\\\":\\\"value\\\"\",\n"
                                + "  \"Response\": \"Success\",\n" + "  \"ServiceName\": \"service-35\",\n"
                                + "  \"SessionId\": \"12345678-1234-1234-abcd-1234567890de\",\n"
                                + "  \"SourceIPAddress\": \"127.0.0.1\",\n" + "  \"SourceSystem\": \"Azure\",\n"
                                + "  \"TenantId\": \"12345678-1234-1234-abcd-1234567890ef\",\n"
                                + "  \"TimeGenerated\": \"2025-10-06T00:00:00.0000000Z\",\n"
                                + "  \"Type\": \"DatabricksNotebook\",\n"
                                + "  \"UserAgent\": \"User-Agent: Mozilla/5.0 (<system-information>) <platform> (<platform-details>) <extensions>\",\n"
                                + "  \"_ResourceId\": \"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}\",\n"
                                + "  \"_SubscriptionId\": \"12345678-1234-1234-abcd-1234567890fg\"\n" + "}",
                        syslogMessage.getMsg()
                );
        Assertions.assertEquals("md5-0ded52ef915af563e25778bf26b0f129-resourceName", syslogMessage.getHostname());
        Assertions.assertEquals("DatabricksNotebook", syslogMessage.getAppName());
        Assertions.assertEquals("2025-10-06T00:00:00Z", syslogMessage.getTimestamp());

        final Map<String, Map<String, String>> sdElementMap = syslogMessage
                .getSDElements()
                .stream()
                .collect(Collectors.toMap((SDElement::getSdID), (sdElem) -> sdElem.getSdParams().stream().collect(Collectors.toMap(SDParam::getParamName, SDParam::getParamValue))));

        Assertions.assertEquals(1, sdElementMap.get("nlf_01@48577").size());
        Assertions
                .assertEquals(DefaultEventType.class.getSimpleName(), sdElementMap.get("nlf_01@48577").get("eventType"));

        Assertions.assertTrue(sdElementMap.get("aer_event@48577").containsKey("properties"));
    }

    @Test
    @DisplayName("Test NLFPlugin with DatabricksOnlineTables")
    void testNlfPluginWithDatabricksOnlineTables() {
        final String json = Assertions
                .assertDoesNotThrow(
                        () -> Files.readString(Paths.get("src/test/resources/databricks/databricksonlinetables.json"))
                );
        final ParsedEvent parsedEvent = new ParsedEventFactory(
                new UnparsedEventImpl(json, new EventPartitionContextImpl(new HashMap<>()), new EventPropertiesImpl(new HashMap<>()), new EventSystemPropertiesImpl(new HashMap<>()), new EnqueuedTimeImpl("2020-01-01T00:00:00"), new EventOffsetImpl("0"))
        ).parsedEvent();

        final NLFPlugin plugin = new NLFPlugin(new FakeSourceable());
        final List<SyslogMessage> syslogMessages = Assertions
                .assertDoesNotThrow(() -> plugin.syslogMessage(parsedEvent));
        Assertions.assertEquals(1, syslogMessages.size());

        final SyslogMessage syslogMessage = syslogMessages.get(0);
        Assertions
                .assertEquals(
                        "{\n" + "  \"ActionName\": \"ActionName-36\",\n" + "  \"Category\": \"category-36\",\n"
                                + "  \"Identity\": \"identity-36\",\n"
                                + "  \"LogId\": \"12345678-1234-1234-abcd-1234567890bc\",\n"
                                + "  \"OperationName\": \"Operation-36\",\n" + "  \"OperationVersion\": \"1.0.0\",\n"
                                + "  \"RequestId\": \"12345678-1234-1234-abcd-1234567890cd\",\n"
                                + "  \"RequestParams\": \"\\\"key\\\":\\\"value\\\"\",\n"
                                + "  \"Response\": \"Success\",\n" + "  \"ServiceName\": \"service-36\",\n"
                                + "  \"SessionId\": \"12345678-1234-1234-abcd-1234567890de\",\n"
                                + "  \"SourceIpAddress\": \"127.0.0.1\",\n" + "  \"SourceSystem\": \"Azure\",\n"
                                + "  \"TenantId\": \"12345678-1234-1234-abcd-1234567890ef\",\n"
                                + "  \"TimeGenerated\": \"2025-10-06T00:00:00.0000000Z\",\n"
                                + "  \"Type\": \"DatabricksOnlineTables\",\n"
                                + "  \"UserAgent\": \"User-Agent: Mozilla/5.0 (<system-information>) <platform> (<platform-details>) <extensions>\",\n"
                                + "  \"_ResourceId\": \"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}\",\n"
                                + "  \"_SubscriptionId\": \"12345678-1234-1234-abcd-1234567890fg\"\n" + "}",
                        syslogMessage.getMsg()
                );
        Assertions.assertEquals("md5-0ded52ef915af563e25778bf26b0f129-resourceName", syslogMessage.getHostname());
        Assertions.assertEquals("DatabricksOnlineTables", syslogMessage.getAppName());
        Assertions.assertEquals("2025-10-06T00:00:00Z", syslogMessage.getTimestamp());

        final Map<String, Map<String, String>> sdElementMap = syslogMessage
                .getSDElements()
                .stream()
                .collect(Collectors.toMap((SDElement::getSdID), (sdElem) -> sdElem.getSdParams().stream().collect(Collectors.toMap(SDParam::getParamName, SDParam::getParamValue))));

        Assertions.assertEquals(1, sdElementMap.get("nlf_01@48577").size());
        Assertions
                .assertEquals(DefaultEventType.class.getSimpleName(), sdElementMap.get("nlf_01@48577").get("eventType"));

        Assertions.assertTrue(sdElementMap.get("aer_event@48577").containsKey("properties"));
    }

    @Test
    @DisplayName("Test NLFPlugin with DatabricksPartnerHub")
    void testNlfPluginWithDatabricksPartnerHub() {
        final String json = Assertions
                .assertDoesNotThrow(
                        () -> Files.readString(Paths.get("src/test/resources/databricks/databrickspartnerhub.json"))
                );
        final ParsedEvent parsedEvent = new ParsedEventFactory(
                new UnparsedEventImpl(json, new EventPartitionContextImpl(new HashMap<>()), new EventPropertiesImpl(new HashMap<>()), new EventSystemPropertiesImpl(new HashMap<>()), new EnqueuedTimeImpl("2020-01-01T00:00:00"), new EventOffsetImpl("0"))
        ).parsedEvent();

        final NLFPlugin plugin = new NLFPlugin(new FakeSourceable());
        final List<SyslogMessage> syslogMessages = Assertions
                .assertDoesNotThrow(() -> plugin.syslogMessage(parsedEvent));
        Assertions.assertEquals(1, syslogMessages.size());

        final SyslogMessage syslogMessage = syslogMessages.get(0);
        Assertions
                .assertEquals(
                        "{\n" + "  \"ActionName\": \"ActionName-37\",\n" + "  \"Category\": \"category-37\",\n"
                                + "  \"Identity\": \"identity-37\",\n"
                                + "  \"LogId\": \"12345678-1234-1234-abcd-1234567890bc\",\n"
                                + "  \"OperationName\": \"Operation-37\",\n" + "  \"OperationVersion\": \"1.0.0\",\n"
                                + "  \"RequestId\": \"12345678-1234-1234-abcd-1234567890cd\",\n"
                                + "  \"RequestParams\": \"\\\"key\\\":\\\"value\\\"\",\n"
                                + "  \"Response\": \"Success\",\n" + "  \"ServiceName\": \"service-37\",\n"
                                + "  \"SessionId\": \"12345678-1234-1234-abcd-1234567890de\",\n"
                                + "  \"SourceIPAddress\": \"127.0.0.1\",\n" + "  \"SourceSystem\": \"Azure\",\n"
                                + "  \"TenantId\": \"12345678-1234-1234-abcd-1234567890ef\",\n"
                                + "  \"TimeGenerated\": \"2025-10-06T00:00:00.0000000Z\",\n"
                                + "  \"Type\": \"DatabricksPartnerHub\",\n"
                                + "  \"UserAgent\": \"User-Agent: Mozilla/5.0 (<system-information>) <platform> (<platform-details>) <extensions>\",\n"
                                + "  \"_ResourceId\": \"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}\",\n"
                                + "  \"_SubscriptionId\": \"12345678-1234-1234-abcd-1234567890fg\"\n" + "}",
                        syslogMessage.getMsg()
                );
        Assertions.assertEquals("md5-0ded52ef915af563e25778bf26b0f129-resourceName", syslogMessage.getHostname());
        Assertions.assertEquals("DatabricksPartnerHub", syslogMessage.getAppName());
        Assertions.assertEquals("2025-10-06T00:00:00Z", syslogMessage.getTimestamp());

        final Map<String, Map<String, String>> sdElementMap = syslogMessage
                .getSDElements()
                .stream()
                .collect(Collectors.toMap((SDElement::getSdID), (sdElem) -> sdElem.getSdParams().stream().collect(Collectors.toMap(SDParam::getParamName, SDParam::getParamValue))));

        Assertions.assertEquals(1, sdElementMap.get("nlf_01@48577").size());
        Assertions
                .assertEquals(DefaultEventType.class.getSimpleName(), sdElementMap.get("nlf_01@48577").get("eventType"));

        Assertions.assertTrue(sdElementMap.get("aer_event@48577").containsKey("properties"));
    }

    @Test
    @DisplayName("Test NLFPlugin with DatabricksPredictiveOptimization")
    void testNlfPluginWithDatabricksPredictiveOptimization() {
        final String json = Assertions
                .assertDoesNotThrow(
                        () -> Files
                                .readString(
                                        Paths.get("src/test/resources/databricks/databrickspredictiveoptimization.json")
                                )
                );
        final ParsedEvent parsedEvent = new ParsedEventFactory(
                new UnparsedEventImpl(json, new EventPartitionContextImpl(new HashMap<>()), new EventPropertiesImpl(new HashMap<>()), new EventSystemPropertiesImpl(new HashMap<>()), new EnqueuedTimeImpl("2020-01-01T00:00:00"), new EventOffsetImpl("0"))
        ).parsedEvent();

        final NLFPlugin plugin = new NLFPlugin(new FakeSourceable());
        final List<SyslogMessage> syslogMessages = Assertions
                .assertDoesNotThrow(() -> plugin.syslogMessage(parsedEvent));
        Assertions.assertEquals(1, syslogMessages.size());

        final SyslogMessage syslogMessage = syslogMessages.get(0);
        Assertions
                .assertEquals(
                        "{\n" + "  \"ActionName\": \"ActionName-38\",\n" + "  \"Category\": \"category-38\",\n"
                                + "  \"Identity\": \"identity-38\",\n"
                                + "  \"LogId\": \"12345678-1234-1234-abcd-1234567890bc\",\n"
                                + "  \"OperationName\": \"Operation-38\",\n" + "  \"OperationVersion\": \"1.0.0\",\n"
                                + "  \"RequestId\": \"12345678-1234-1234-abcd-1234567890cd\",\n"
                                + "  \"RequestParams\": \"\\\"key\\\":\\\"value\\\"\",\n"
                                + "  \"Response\": \"Success\",\n" + "  \"ServiceName\": \"service-38\",\n"
                                + "  \"SessionId\": \"12345678-1234-1234-abcd-1234567890de\",\n"
                                + "  \"SourceIpAddress\": \"127.0.0.1\",\n" + "  \"SourceSystem\": \"Azure\",\n"
                                + "  \"TenantId\": \"12345678-1234-1234-abcd-1234567890ef\",\n"
                                + "  \"TimeGenerated\": \"2025-10-06T00:00:00.0000000Z\",\n"
                                + "  \"Type\": \"DatabricksPredictiveOptimization\",\n"
                                + "  \"UserAgent\": \"User-Agent: Mozilla/5.0 (<system-information>) <platform> (<platform-details>) <extensions>\",\n"
                                + "  \"_ResourceId\": \"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}\",\n"
                                + "  \"_SubscriptionId\": \"12345678-1234-1234-abcd-1234567890fg\"\n" + "}",
                        syslogMessage.getMsg()
                );
        Assertions.assertEquals("md5-0ded52ef915af563e25778bf26b0f129-resourceName", syslogMessage.getHostname());
        Assertions.assertEquals("DatabricksPredictiveOptimization", syslogMessage.getAppName());
        Assertions.assertEquals("2025-10-06T00:00:00Z", syslogMessage.getTimestamp());

        final Map<String, Map<String, String>> sdElementMap = syslogMessage
                .getSDElements()
                .stream()
                .collect(Collectors.toMap((SDElement::getSdID), (sdElem) -> sdElem.getSdParams().stream().collect(Collectors.toMap(SDParam::getParamName, SDParam::getParamValue))));

        Assertions.assertEquals(1, sdElementMap.get("nlf_01@48577").size());
        Assertions
                .assertEquals(DefaultEventType.class.getSimpleName(), sdElementMap.get("nlf_01@48577").get("eventType"));

        Assertions.assertTrue(sdElementMap.get("aer_event@48577").containsKey("properties"));
    }

    @Test
    @DisplayName("Test NLFPlugin with DatabricksRBAC")
    void testNlfPluginWithDatabricksRbac() {
        final String json = Assertions
                .assertDoesNotThrow(() -> Files.readString(Paths.get("src/test/resources/databricks/databricksrbac.json")));
        final ParsedEvent parsedEvent = new ParsedEventFactory(
                new UnparsedEventImpl(json, new EventPartitionContextImpl(new HashMap<>()), new EventPropertiesImpl(new HashMap<>()), new EventSystemPropertiesImpl(new HashMap<>()), new EnqueuedTimeImpl("2020-01-01T00:00:00"), new EventOffsetImpl("0"))
        ).parsedEvent();

        final NLFPlugin plugin = new NLFPlugin(new FakeSourceable());
        final List<SyslogMessage> syslogMessages = Assertions
                .assertDoesNotThrow(() -> plugin.syslogMessage(parsedEvent));
        Assertions.assertEquals(1, syslogMessages.size());

        final SyslogMessage syslogMessage = syslogMessages.get(0);
        Assertions
                .assertEquals(
                        "{\n" + "  \"ActionName\": \"ActionName-39\",\n" + "  \"Category\": \"category-39\",\n"
                                + "  \"Identity\": \"identity-39\",\n"
                                + "  \"LogId\": \"12345678-1234-1234-abcd-1234567890bc\",\n"
                                + "  \"OperationName\": \"Operation-39\",\n" + "  \"OperationVersion\": \"1.0.0\",\n"
                                + "  \"RequestId\": \"12345678-1234-1234-abcd-1234567890cd\",\n"
                                + "  \"RequestParams\": \"\\\"key\\\":\\\"value\\\"\",\n"
                                + "  \"Response\": \"Success\",\n" + "  \"ServiceName\": \"service-39\",\n"
                                + "  \"SessionId\": \"12345678-1234-1234-abcd-1234567890de\",\n"
                                + "  \"SourceIpAddress\": \"127.0.0.1\",\n" + "  \"SourceSystem\": \"Azure\",\n"
                                + "  \"TenantId\": \"12345678-1234-1234-abcd-1234567890ef\",\n"
                                + "  \"TimeGenerated\": \"2025-10-06T00:00:00.0000000Z\",\n"
                                + "  \"Type\": \"DatabricksRBAC\",\n"
                                + "  \"UserAgent\": \"User-Agent: Mozilla/5.0 (<system-information>) <platform> (<platform-details>) <extensions>\",\n"
                                + "  \"_ResourceId\": \"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}\",\n"
                                + "  \"_SubscriptionId\": \"12345678-1234-1234-abcd-1234567890fg\"\n" + "}",
                        syslogMessage.getMsg()
                );
        Assertions.assertEquals("md5-0ded52ef915af563e25778bf26b0f129-resourceName", syslogMessage.getHostname());
        Assertions.assertEquals("DatabricksRBAC", syslogMessage.getAppName());
        Assertions.assertEquals("2025-10-06T00:00:00Z", syslogMessage.getTimestamp());

        final Map<String, Map<String, String>> sdElementMap = syslogMessage
                .getSDElements()
                .stream()
                .collect(Collectors.toMap((SDElement::getSdID), (sdElem) -> sdElem.getSdParams().stream().collect(Collectors.toMap(SDParam::getParamName, SDParam::getParamValue))));

        Assertions.assertEquals(1, sdElementMap.get("nlf_01@48577").size());
        Assertions
                .assertEquals(DefaultEventType.class.getSimpleName(), sdElementMap.get("nlf_01@48577").get("eventType"));

        Assertions.assertTrue(sdElementMap.get("aer_event@48577").containsKey("properties"));
    }

    @Test
    @DisplayName("Test NLFPlugin with DatabricksRemoteHistoryService")
    void testNlfPluginWithDatabricksRemoteHistoryService() {
        final String json = Assertions
                .assertDoesNotThrow(
                        () -> Files
                                .readString(
                                        Paths.get("src/test/resources/databricks/databricksremotehistoryservice.json")
                                )
                );
        final ParsedEvent parsedEvent = new ParsedEventFactory(
                new UnparsedEventImpl(json, new EventPartitionContextImpl(new HashMap<>()), new EventPropertiesImpl(new HashMap<>()), new EventSystemPropertiesImpl(new HashMap<>()), new EnqueuedTimeImpl("2020-01-01T00:00:00"), new EventOffsetImpl("0"))
        ).parsedEvent();

        final NLFPlugin plugin = new NLFPlugin(new FakeSourceable());
        final List<SyslogMessage> syslogMessages = Assertions
                .assertDoesNotThrow(() -> plugin.syslogMessage(parsedEvent));
        Assertions.assertEquals(1, syslogMessages.size());

        final SyslogMessage syslogMessage = syslogMessages.get(0);
        Assertions
                .assertEquals(
                        "{\n" + "  \"ActionName\": \"ActionName-40\",\n" + "  \"Category\": \"category-40\",\n"
                                + "  \"Identity\": \"identity-40\",\n"
                                + "  \"LogId\": \"12345678-1234-1234-abcd-1234567890bc\",\n"
                                + "  \"OperationName\": \"Operation-40\",\n" + "  \"OperationVersion\": \"1.0.0\",\n"
                                + "  \"RequestId\": \"12345678-1234-1234-abcd-1234567890cd\",\n"
                                + "  \"RequestParams\": \"\\\"key\\\":\\\"value\\\"\",\n"
                                + "  \"Response\": \"Success\",\n" + "  \"ServiceName\": \"service-40\",\n"
                                + "  \"SessionId\": \"12345678-1234-1234-abcd-1234567890de\",\n"
                                + "  \"SourceIPAddress\": \"127.0.0.1\",\n" + "  \"SourceSystem\": \"Azure\",\n"
                                + "  \"TenantId\": \"12345678-1234-1234-abcd-1234567890ef\",\n"
                                + "  \"TimeGenerated\": \"2025-10-06T00:00:00.0000000Z\",\n"
                                + "  \"Type\": \"DatabricksRemoteHistoryService\",\n"
                                + "  \"UserAgent\": \"User-Agent: Mozilla/5.0 (<system-information>) <platform> (<platform-details>) <extensions>\",\n"
                                + "  \"_ResourceId\": \"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}\",\n"
                                + "  \"_SubscriptionId\": \"12345678-1234-1234-abcd-1234567890fg\"\n" + "}",
                        syslogMessage.getMsg()
                );
        Assertions.assertEquals("md5-0ded52ef915af563e25778bf26b0f129-resourceName", syslogMessage.getHostname());
        Assertions.assertEquals("DatabricksRemoteHistoryService", syslogMessage.getAppName());
        Assertions.assertEquals("2025-10-06T00:00:00Z", syslogMessage.getTimestamp());

        final Map<String, Map<String, String>> sdElementMap = syslogMessage
                .getSDElements()
                .stream()
                .collect(Collectors.toMap((SDElement::getSdID), (sdElem) -> sdElem.getSdParams().stream().collect(Collectors.toMap(SDParam::getParamName, SDParam::getParamValue))));

        Assertions.assertEquals(1, sdElementMap.get("nlf_01@48577").size());
        Assertions
                .assertEquals(DefaultEventType.class.getSimpleName(), sdElementMap.get("nlf_01@48577").get("eventType"));

        Assertions.assertTrue(sdElementMap.get("aer_event@48577").containsKey("properties"));
    }

    @Test
    @DisplayName("Test NLFPlugin with DatabricksRepos")
    void testNlfPluginWithDatabricksRepos() {
        final String json = Assertions
                .assertDoesNotThrow(
                        () -> Files.readString(Paths.get("src/test/resources/databricks/databricksrepos.json"))
                );
        final ParsedEvent parsedEvent = new ParsedEventFactory(
                new UnparsedEventImpl(json, new EventPartitionContextImpl(new HashMap<>()), new EventPropertiesImpl(new HashMap<>()), new EventSystemPropertiesImpl(new HashMap<>()), new EnqueuedTimeImpl("2020-01-01T00:00:00"), new EventOffsetImpl("0"))
        ).parsedEvent();

        final NLFPlugin plugin = new NLFPlugin(new FakeSourceable());
        final List<SyslogMessage> syslogMessages = Assertions
                .assertDoesNotThrow(() -> plugin.syslogMessage(parsedEvent));
        Assertions.assertEquals(1, syslogMessages.size());

        final SyslogMessage syslogMessage = syslogMessages.get(0);
        Assertions
                .assertEquals(
                        "{\n" + "  \"ActionName\": \"ActionName-41\",\n" + "  \"Category\": \"category-41\",\n"
                                + "  \"Identity\": \"identity-41\",\n"
                                + "  \"LogId\": \"12345678-1234-1234-abcd-1234567890bc\",\n"
                                + "  \"OperationName\": \"Operation-41\",\n" + "  \"OperationVersion\": \"1.0.0\",\n"
                                + "  \"RequestId\": \"12345678-1234-1234-abcd-1234567890cd\",\n"
                                + "  \"RequestParams\": \"\\\"key\\\":\\\"value\\\"\",\n"
                                + "  \"Response\": \"Success\",\n" + "  \"ServiceName\": \"service-41\",\n"
                                + "  \"SessionId\": \"12345678-1234-1234-abcd-1234567890de\",\n"
                                + "  \"SourceIPAddress\": \"127.0.0.1\",\n" + "  \"SourceSystem\": \"Azure\",\n"
                                + "  \"TenantId\": \"12345678-1234-1234-abcd-1234567890ef\",\n"
                                + "  \"TimeGenerated\": \"2025-10-06T00:00:00.0000000Z\",\n"
                                + "  \"Type\": \"DatabricksRepos\",\n"
                                + "  \"UserAgent\": \"User-Agent: Mozilla/5.0 (<system-information>) <platform> (<platform-details>) <extensions>\",\n"
                                + "  \"_ResourceId\": \"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}\",\n"
                                + "  \"_SubscriptionId\": \"12345678-1234-1234-abcd-1234567890fg\"\n" + "}",
                        syslogMessage.getMsg()
                );
        Assertions.assertEquals("md5-0ded52ef915af563e25778bf26b0f129-resourceName", syslogMessage.getHostname());
        Assertions.assertEquals("DatabricksRepos", syslogMessage.getAppName());
        Assertions.assertEquals("2025-10-06T00:00:00Z", syslogMessage.getTimestamp());

        final Map<String, Map<String, String>> sdElementMap = syslogMessage
                .getSDElements()
                .stream()
                .collect(Collectors.toMap((SDElement::getSdID), (sdElem) -> sdElem.getSdParams().stream().collect(Collectors.toMap(SDParam::getParamName, SDParam::getParamValue))));

        Assertions.assertEquals(1, sdElementMap.get("nlf_01@48577").size());
        Assertions
                .assertEquals(DefaultEventType.class.getSimpleName(), sdElementMap.get("nlf_01@48577").get("eventType"));

        Assertions.assertTrue(sdElementMap.get("aer_event@48577").containsKey("properties"));
    }

    @Test
    @DisplayName("Test NLFPlugin with DatabricksRFA")
    void testNlfPluginWithDatabricksRfa() {
        final String json = Assertions
                .assertDoesNotThrow(() -> Files.readString(Paths.get("src/test/resources/databricks/databricksrfa.json")));
        final ParsedEvent parsedEvent = new ParsedEventFactory(
                new UnparsedEventImpl(json, new EventPartitionContextImpl(new HashMap<>()), new EventPropertiesImpl(new HashMap<>()), new EventSystemPropertiesImpl(new HashMap<>()), new EnqueuedTimeImpl("2020-01-01T00:00:00"), new EventOffsetImpl("0"))
        ).parsedEvent();

        final NLFPlugin plugin = new NLFPlugin(new FakeSourceable());
        final List<SyslogMessage> syslogMessages = Assertions
                .assertDoesNotThrow(() -> plugin.syslogMessage(parsedEvent));
        Assertions.assertEquals(1, syslogMessages.size());

        final SyslogMessage syslogMessage = syslogMessages.get(0);
        Assertions
                .assertEquals(
                        "{\n" + "  \"ActionName\": \"ActionName-42\",\n" + "  \"Category\": \"category-42\",\n"
                                + "  \"Identity\": \"identity-42\",\n"
                                + "  \"LogId\": \"12345678-1234-1234-abcd-1234567890bc\",\n"
                                + "  \"OperationName\": \"Operation-42\",\n" + "  \"OperationVersion\": \"1.0.0\",\n"
                                + "  \"RequestId\": \"12345678-1234-1234-abcd-1234567890cd\",\n"
                                + "  \"RequestParams\": \"\\\"key\\\":\\\"value\\\"\",\n"
                                + "  \"Response\": \"Success\",\n" + "  \"ServiceName\": \"service-42\",\n"
                                + "  \"SessionId\": \"12345678-1234-1234-abcd-1234567890de\",\n"
                                + "  \"SourceIpAddress\": \"127.0.0.1\",\n" + "  \"SourceSystem\": \"Azure\",\n"
                                + "  \"TenantId\": \"12345678-1234-1234-abcd-1234567890ef\",\n"
                                + "  \"TimeGenerated\": \"2025-10-06T00:00:00.0000000Z\",\n"
                                + "  \"Type\": \"DatabricksRFA\",\n"
                                + "  \"UserAgent\": \"User-Agent: Mozilla/5.0 (<system-information>) <platform> (<platform-details>) <extensions>\",\n"
                                + "  \"_ResourceId\": \"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}\",\n"
                                + "  \"_SubscriptionId\": \"12345678-1234-1234-abcd-1234567890fg\"\n" + "}",
                        syslogMessage.getMsg()
                );
        Assertions.assertEquals("md5-0ded52ef915af563e25778bf26b0f129-resourceName", syslogMessage.getHostname());
        Assertions.assertEquals("DatabricksRFA", syslogMessage.getAppName());
        Assertions.assertEquals("2025-10-06T00:00:00Z", syslogMessage.getTimestamp());

        final Map<String, Map<String, String>> sdElementMap = syslogMessage
                .getSDElements()
                .stream()
                .collect(Collectors.toMap((SDElement::getSdID), (sdElem) -> sdElem.getSdParams().stream().collect(Collectors.toMap(SDParam::getParamName, SDParam::getParamValue))));

        Assertions.assertEquals(1, sdElementMap.get("nlf_01@48577").size());
        Assertions
                .assertEquals(DefaultEventType.class.getSimpleName(), sdElementMap.get("nlf_01@48577").get("eventType"));

        Assertions.assertTrue(sdElementMap.get("aer_event@48577").containsKey("properties"));
    }

    @Test
    @DisplayName("Test NLFPlugin with DatabricksSecrets")
    void testNlfPluginWithDatabricksSecrets() {
        final String json = Assertions
                .assertDoesNotThrow(
                        () -> Files.readString(Paths.get("src/test/resources/databricks/databrickssecrets.json"))
                );
        final ParsedEvent parsedEvent = new ParsedEventFactory(
                new UnparsedEventImpl(json, new EventPartitionContextImpl(new HashMap<>()), new EventPropertiesImpl(new HashMap<>()), new EventSystemPropertiesImpl(new HashMap<>()), new EnqueuedTimeImpl("2020-01-01T00:00:00"), new EventOffsetImpl("0"))
        ).parsedEvent();

        final NLFPlugin plugin = new NLFPlugin(new FakeSourceable());
        final List<SyslogMessage> syslogMessages = Assertions
                .assertDoesNotThrow(() -> plugin.syslogMessage(parsedEvent));
        Assertions.assertEquals(1, syslogMessages.size());

        final SyslogMessage syslogMessage = syslogMessages.get(0);
        Assertions
                .assertEquals(
                        "{\n" + "  \"ActionName\": \"ActionName-43\",\n" + "  \"Category\": \"category-43\",\n"
                                + "  \"Identity\": \"identity-43\",\n"
                                + "  \"LogId\": \"12345678-1234-1234-abcd-1234567890bc\",\n"
                                + "  \"OperationName\": \"Operation-43\",\n" + "  \"OperationVersion\": \"1.0.0\",\n"
                                + "  \"RequestId\": \"12345678-1234-1234-abcd-1234567890cd\",\n"
                                + "  \"RequestParams\": \"\\\"key\\\":\\\"value\\\"\",\n"
                                + "  \"Response\": \"Success\",\n" + "  \"ServiceName\": \"service-43\",\n"
                                + "  \"SessionId\": \"12345678-1234-1234-abcd-1234567890de\",\n"
                                + "  \"SourceIPAddress\": \"127.0.0.1\",\n" + "  \"SourceSystem\": \"Azure\",\n"
                                + "  \"TenantId\": \"12345678-1234-1234-abcd-1234567890ef\",\n"
                                + "  \"TimeGenerated\": \"2025-10-06T00:00:00.0000000Z\",\n"
                                + "  \"Type\": \"DatabricksSecrets\",\n"
                                + "  \"UserAgent\": \"User-Agent: Mozilla/5.0 (<system-information>) <platform> (<platform-details>) <extensions>\",\n"
                                + "  \"_ResourceId\": \"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}\",\n"
                                + "  \"_SubscriptionId\": \"12345678-1234-1234-abcd-1234567890fg\"\n" + "}",
                        syslogMessage.getMsg()
                );
        Assertions.assertEquals("md5-0ded52ef915af563e25778bf26b0f129-resourceName", syslogMessage.getHostname());
        Assertions.assertEquals("DatabricksSecrets", syslogMessage.getAppName());
        Assertions.assertEquals("2025-10-06T00:00:00Z", syslogMessage.getTimestamp());

        final Map<String, Map<String, String>> sdElementMap = syslogMessage
                .getSDElements()
                .stream()
                .collect(Collectors.toMap((SDElement::getSdID), (sdElem) -> sdElem.getSdParams().stream().collect(Collectors.toMap(SDParam::getParamName, SDParam::getParamValue))));

        Assertions.assertEquals(1, sdElementMap.get("nlf_01@48577").size());
        Assertions
                .assertEquals(DefaultEventType.class.getSimpleName(), sdElementMap.get("nlf_01@48577").get("eventType"));

        Assertions.assertTrue(sdElementMap.get("aer_event@48577").containsKey("properties"));
    }

    @Test
    @DisplayName("Test NLFPlugin with DatabricksServerlessRealTimeInference")
    void testNlfPluginWithDatabricksServerlessRealTimeInference() {
        final String json = Assertions
                .assertDoesNotThrow(
                        () -> Files
                                .readString(
                                        Paths
                                                .get(
                                                        "src/test/resources/databricks/databricksserverlessrealtimeinference.json"
                                                )
                                )
                );
        final ParsedEvent parsedEvent = new ParsedEventFactory(
                new UnparsedEventImpl(json, new EventPartitionContextImpl(new HashMap<>()), new EventPropertiesImpl(new HashMap<>()), new EventSystemPropertiesImpl(new HashMap<>()), new EnqueuedTimeImpl("2020-01-01T00:00:00"), new EventOffsetImpl("0"))
        ).parsedEvent();

        final NLFPlugin plugin = new NLFPlugin(new FakeSourceable());
        final List<SyslogMessage> syslogMessages = Assertions
                .assertDoesNotThrow(() -> plugin.syslogMessage(parsedEvent));
        Assertions.assertEquals(1, syslogMessages.size());

        final SyslogMessage syslogMessage = syslogMessages.get(0);
        Assertions
                .assertEquals(
                        "{\n" + "  \"ActionName\": \"ActionName-44\",\n" + "  \"Category\": \"category-44\",\n"
                                + "  \"Identity\": \"identity-44\",\n"
                                + "  \"LogId\": \"12345678-1234-1234-abcd-1234567890bc\",\n"
                                + "  \"OperationName\": \"Operation-44\",\n" + "  \"OperationVersion\": \"1.0.0\",\n"
                                + "  \"RequestId\": \"12345678-1234-1234-abcd-1234567890cd\",\n"
                                + "  \"RequestParams\": \"\\\"key\\\":\\\"value\\\"\",\n"
                                + "  \"Response\": \"Success\",\n" + "  \"ServiceName\": \"service-44\",\n"
                                + "  \"SessionId\": \"12345678-1234-1234-abcd-1234567890de\",\n"
                                + "  \"SourceIPAddress\": \"127.0.0.1\",\n" + "  \"SourceSystem\": \"Azure\",\n"
                                + "  \"TenantId\": \"12345678-1234-1234-abcd-1234567890ef\",\n"
                                + "  \"TimeGenerated\": \"2025-10-06T00:00:00.0000000Z\",\n"
                                + "  \"Type\": \"DatabricksServerlessRealTimeInference\",\n"
                                + "  \"UserAgent\": \"User-Agent: Mozilla/5.0 (<system-information>) <platform> (<platform-details>) <extensions>\",\n"
                                + "  \"_ResourceId\": \"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}\",\n"
                                + "  \"_SubscriptionId\": \"12345678-1234-1234-abcd-1234567890fg\"\n" + "}",
                        syslogMessage.getMsg()
                );
        Assertions.assertEquals("md5-0ded52ef915af563e25778bf26b0f129-resourceName", syslogMessage.getHostname());
        Assertions.assertEquals("DatabricksServerlessRealTimeInference", syslogMessage.getAppName());
        Assertions.assertEquals("2025-10-06T00:00:00Z", syslogMessage.getTimestamp());

        final Map<String, Map<String, String>> sdElementMap = syslogMessage
                .getSDElements()
                .stream()
                .collect(Collectors.toMap((SDElement::getSdID), (sdElem) -> sdElem.getSdParams().stream().collect(Collectors.toMap(SDParam::getParamName, SDParam::getParamValue))));

        Assertions.assertEquals(1, sdElementMap.get("nlf_01@48577").size());
        Assertions
                .assertEquals(DefaultEventType.class.getSimpleName(), sdElementMap.get("nlf_01@48577").get("eventType"));

        Assertions.assertTrue(sdElementMap.get("aer_event@48577").containsKey("properties"));
    }

    @Test
    @DisplayName("Test NLFPlugin with DatabricksSQL")
    void testNlfPluginWithDatabricksSql() {
        final String json = Assertions
                .assertDoesNotThrow(() -> Files.readString(Paths.get("src/test/resources/databricks/databrickssql.json")));
        final ParsedEvent parsedEvent = new ParsedEventFactory(
                new UnparsedEventImpl(json, new EventPartitionContextImpl(new HashMap<>()), new EventPropertiesImpl(new HashMap<>()), new EventSystemPropertiesImpl(new HashMap<>()), new EnqueuedTimeImpl("2020-01-01T00:00:00"), new EventOffsetImpl("0"))
        ).parsedEvent();

        final NLFPlugin plugin = new NLFPlugin(new FakeSourceable());
        final List<SyslogMessage> syslogMessages = Assertions
                .assertDoesNotThrow(() -> plugin.syslogMessage(parsedEvent));
        Assertions.assertEquals(1, syslogMessages.size());

        final SyslogMessage syslogMessage = syslogMessages.get(0);
        Assertions
                .assertEquals(
                        "{\n" + "  \"ActionName\": \"ActionName-45\",\n" + "  \"Category\": \"category-45\",\n"
                                + "  \"Identity\": \"identity-45\",\n"
                                + "  \"LogId\": \"12345678-1234-1234-abcd-1234567890bc\",\n"
                                + "  \"OperationName\": \"Operation-45\",\n" + "  \"OperationVersion\": \"1.0.0\",\n"
                                + "  \"RequestId\": \"12345678-1234-1234-abcd-1234567890cd\",\n"
                                + "  \"RequestParams\": \"\\\"key\\\":\\\"value\\\"\",\n"
                                + "  \"Response\": \"Success\",\n" + "  \"ServiceName\": \"service-45\",\n"
                                + "  \"SessionId\": \"12345678-1234-1234-abcd-1234567890de\",\n"
                                + "  \"SourceIPAddress\": \"127.0.0.1\",\n" + "  \"SourceSystem\": \"Azure\",\n"
                                + "  \"TenantId\": \"12345678-1234-1234-abcd-1234567890ef\",\n"
                                + "  \"TimeGenerated\": \"2025-10-06T00:00:00.0000000Z\",\n"
                                + "  \"Type\": \"DatabricksSQL\",\n"
                                + "  \"UserAgent\": \"User-Agent: Mozilla/5.0 (<system-information>) <platform> (<platform-details>) <extensions>\",\n"
                                + "  \"_ResourceId\": \"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}\",\n"
                                + "  \"_SubscriptionId\": \"12345678-1234-1234-abcd-1234567890fg\"\n" + "}",
                        syslogMessage.getMsg()
                );
        Assertions.assertEquals("md5-0ded52ef915af563e25778bf26b0f129-resourceName", syslogMessage.getHostname());
        Assertions.assertEquals("DatabricksSQL", syslogMessage.getAppName());
        Assertions.assertEquals("2025-10-06T00:00:00Z", syslogMessage.getTimestamp());

        final Map<String, Map<String, String>> sdElementMap = syslogMessage
                .getSDElements()
                .stream()
                .collect(Collectors.toMap((SDElement::getSdID), (sdElem) -> sdElem.getSdParams().stream().collect(Collectors.toMap(SDParam::getParamName, SDParam::getParamValue))));

        Assertions.assertEquals(1, sdElementMap.get("nlf_01@48577").size());
        Assertions
                .assertEquals(DefaultEventType.class.getSimpleName(), sdElementMap.get("nlf_01@48577").get("eventType"));

        Assertions.assertTrue(sdElementMap.get("aer_event@48577").containsKey("properties"));
    }

    @Test
    @DisplayName("Test NLFPlugin with DatabricksSQLPermissions")
    void testNlfPluginWithDatabricksSqlPermissions() {
        final String json = Assertions
                .assertDoesNotThrow(
                        () -> Files.readString(Paths.get("src/test/resources/databricks/databrickssqlpermissions.json"))
                );
        final ParsedEvent parsedEvent = new ParsedEventFactory(
                new UnparsedEventImpl(json, new EventPartitionContextImpl(new HashMap<>()), new EventPropertiesImpl(new HashMap<>()), new EventSystemPropertiesImpl(new HashMap<>()), new EnqueuedTimeImpl("2020-01-01T00:00:00"), new EventOffsetImpl("0"))
        ).parsedEvent();

        final NLFPlugin plugin = new NLFPlugin(new FakeSourceable());
        final List<SyslogMessage> syslogMessages = Assertions
                .assertDoesNotThrow(() -> plugin.syslogMessage(parsedEvent));
        Assertions.assertEquals(1, syslogMessages.size());

        final SyslogMessage syslogMessage = syslogMessages.get(0);
        Assertions
                .assertEquals(
                        "{\n" + "  \"ActionName\": \"ActionName-46\",\n" + "  \"Category\": \"category-46\",\n"
                                + "  \"Identity\": \"identity-46\",\n"
                                + "  \"LogId\": \"12345678-1234-1234-abcd-1234567890bc\",\n"
                                + "  \"OperationName\": \"Operation-46\",\n" + "  \"OperationVersion\": \"1.0.0\",\n"
                                + "  \"RequestId\": \"12345678-1234-1234-abcd-1234567890cd\",\n"
                                + "  \"RequestParams\": \"\\\"key\\\":\\\"value\\\"\",\n"
                                + "  \"Response\": \"Success\",\n" + "  \"ServiceName\": \"service-46\",\n"
                                + "  \"SessionId\": \"12345678-1234-1234-abcd-1234567890de\",\n"
                                + "  \"SourceIPAddress\": \"127.0.0.1\",\n" + "  \"SourceSystem\": \"Azure\",\n"
                                + "  \"TenantId\": \"12345678-1234-1234-abcd-1234567890ef\",\n"
                                + "  \"TimeGenerated\": \"2025-10-06T00:00:00.0000000Z\",\n"
                                + "  \"Type\": \"DatabricksSQLPermissions\",\n"
                                + "  \"UserAgent\": \"User-Agent: Mozilla/5.0 (<system-information>) <platform> (<platform-details>) <extensions>\",\n"
                                + "  \"_ResourceId\": \"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}\",\n"
                                + "  \"_SubscriptionId\": \"12345678-1234-1234-abcd-1234567890fg\"\n" + "}",
                        syslogMessage.getMsg()
                );
        Assertions.assertEquals("md5-0ded52ef915af563e25778bf26b0f129-resourceName", syslogMessage.getHostname());
        Assertions.assertEquals("DatabricksSQLPermissions", syslogMessage.getAppName());
        Assertions.assertEquals("2025-10-06T00:00:00Z", syslogMessage.getTimestamp());

        final Map<String, Map<String, String>> sdElementMap = syslogMessage
                .getSDElements()
                .stream()
                .collect(Collectors.toMap((SDElement::getSdID), (sdElem) -> sdElem.getSdParams().stream().collect(Collectors.toMap(SDParam::getParamName, SDParam::getParamValue))));

        Assertions.assertEquals(1, sdElementMap.get("nlf_01@48577").size());
        Assertions
                .assertEquals(DefaultEventType.class.getSimpleName(), sdElementMap.get("nlf_01@48577").get("eventType"));

        Assertions.assertTrue(sdElementMap.get("aer_event@48577").containsKey("properties"));
    }

    @Test
    @DisplayName("Test NLFPlugin with DatabricksSSH")
    void testNlfPluginWithDatabricksSsh() {
        final String json = Assertions
                .assertDoesNotThrow(() -> Files.readString(Paths.get("src/test/resources/databricks/databricksssh.json")));
        final ParsedEvent parsedEvent = new ParsedEventFactory(
                new UnparsedEventImpl(json, new EventPartitionContextImpl(new HashMap<>()), new EventPropertiesImpl(new HashMap<>()), new EventSystemPropertiesImpl(new HashMap<>()), new EnqueuedTimeImpl("2020-01-01T00:00:00"), new EventOffsetImpl("0"))
        ).parsedEvent();

        final NLFPlugin plugin = new NLFPlugin(new FakeSourceable());
        final List<SyslogMessage> syslogMessages = Assertions
                .assertDoesNotThrow(() -> plugin.syslogMessage(parsedEvent));
        Assertions.assertEquals(1, syslogMessages.size());

        final SyslogMessage syslogMessage = syslogMessages.get(0);
        Assertions
                .assertEquals(
                        "{\n" + "  \"ActionName\": \"ActionName-47\",\n" + "  \"Category\": \"category-47\",\n"
                                + "  \"Identity\": \"identity-47\",\n"
                                + "  \"LogId\": \"12345678-1234-1234-abcd-1234567890bc\",\n"
                                + "  \"OperationName\": \"Operation-47\",\n" + "  \"OperationVersion\": \"1.0.0\",\n"
                                + "  \"RequestId\": \"12345678-1234-1234-abcd-1234567890cd\",\n"
                                + "  \"RequestParams\": \"\\\"key\\\":\\\"value\\\"\",\n"
                                + "  \"Response\": \"Success\",\n" + "  \"ServiceName\": \"service-47\",\n"
                                + "  \"SessionId\": \"12345678-1234-1234-abcd-1234567890de\",\n"
                                + "  \"SourceIPAddress\": \"127.0.0.1\",\n" + "  \"SourceSystem\": \"Azure\",\n"
                                + "  \"TenantId\": \"12345678-1234-1234-abcd-1234567890ef\",\n"
                                + "  \"TimeGenerated\": \"2025-10-06T00:00:00.0000000Z\",\n"
                                + "  \"Type\": \"DatabricksSSH\",\n"
                                + "  \"UserAgent\": \"User-Agent: Mozilla/5.0 (<system-information>) <platform> (<platform-details>) <extensions>\",\n"
                                + "  \"_ResourceId\": \"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}\",\n"
                                + "  \"_SubscriptionId\": \"12345678-1234-1234-abcd-1234567890fg\"\n" + "}",
                        syslogMessage.getMsg()
                );
        Assertions.assertEquals("md5-0ded52ef915af563e25778bf26b0f129-resourceName", syslogMessage.getHostname());
        Assertions.assertEquals("DatabricksSSH", syslogMessage.getAppName());
        Assertions.assertEquals("2025-10-06T00:00:00Z", syslogMessage.getTimestamp());

        final Map<String, Map<String, String>> sdElementMap = syslogMessage
                .getSDElements()
                .stream()
                .collect(Collectors.toMap((SDElement::getSdID), (sdElem) -> sdElem.getSdParams().stream().collect(Collectors.toMap(SDParam::getParamName, SDParam::getParamValue))));

        Assertions.assertEquals(1, sdElementMap.get("nlf_01@48577").size());
        Assertions
                .assertEquals(DefaultEventType.class.getSimpleName(), sdElementMap.get("nlf_01@48577").get("eventType"));

        Assertions.assertTrue(sdElementMap.get("aer_event@48577").containsKey("properties"));
    }

    @Test
    @DisplayName("Test NLFPlugin with DatabricksUnityCatalog")
    void testNlfPluginWithDatabricksUnityCatalog() {
        final String json = Assertions
                .assertDoesNotThrow(
                        () -> Files.readString(Paths.get("src/test/resources/databricks/databricksunitycatalog.json"))
                );
        final ParsedEvent parsedEvent = new ParsedEventFactory(
                new UnparsedEventImpl(json, new EventPartitionContextImpl(new HashMap<>()), new EventPropertiesImpl(new HashMap<>()), new EventSystemPropertiesImpl(new HashMap<>()), new EnqueuedTimeImpl("2020-01-01T00:00:00"), new EventOffsetImpl("0"))
        ).parsedEvent();

        final NLFPlugin plugin = new NLFPlugin(new FakeSourceable());
        final List<SyslogMessage> syslogMessages = Assertions
                .assertDoesNotThrow(() -> plugin.syslogMessage(parsedEvent));
        Assertions.assertEquals(1, syslogMessages.size());

        final SyslogMessage syslogMessage = syslogMessages.get(0);
        Assertions
                .assertEquals(
                        "{\n" + "  \"ActionName\": \"ActionName-48\",\n" + "  \"Category\": \"category-48\",\n"
                                + "  \"Identity\": \"identity-48\",\n"
                                + "  \"LogId\": \"12345678-1234-1234-abcd-1234567890bc\",\n"
                                + "  \"OperationName\": \"Operation-48\",\n" + "  \"OperationVersion\": \"1.0.0\",\n"
                                + "  \"RequestId\": \"12345678-1234-1234-abcd-1234567890cd\",\n"
                                + "  \"RequestParams\": \"\\\"key\\\":\\\"value\\\"\",\n"
                                + "  \"Response\": \"Success\",\n" + "  \"ServiceName\": \"service-48\",\n"
                                + "  \"SessionId\": \"12345678-1234-1234-abcd-1234567890de\",\n"
                                + "  \"SourceIPAddress\": \"127.0.0.1\",\n" + "  \"SourceSystem\": \"Azure\",\n"
                                + "  \"TenantId\": \"12345678-1234-1234-abcd-1234567890ef\",\n"
                                + "  \"TimeGenerated\": \"2025-10-06T00:00:00.0000000Z\",\n"
                                + "  \"Type\": \"DatabricksUnityCatalog\",\n"
                                + "  \"UserAgent\": \"User-Agent: Mozilla/5.0 (<system-information>) <platform> (<platform-details>) <extensions>\",\n"
                                + "  \"_ResourceId\": \"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}\",\n"
                                + "  \"_SubscriptionId\": \"12345678-1234-1234-abcd-1234567890fg\"\n" + "}",
                        syslogMessage.getMsg()
                );
        Assertions.assertEquals("md5-0ded52ef915af563e25778bf26b0f129-resourceName", syslogMessage.getHostname());
        Assertions.assertEquals("DatabricksUnityCatalog", syslogMessage.getAppName());
        Assertions.assertEquals("2025-10-06T00:00:00Z", syslogMessage.getTimestamp());

        final Map<String, Map<String, String>> sdElementMap = syslogMessage
                .getSDElements()
                .stream()
                .collect(Collectors.toMap((SDElement::getSdID), (sdElem) -> sdElem.getSdParams().stream().collect(Collectors.toMap(SDParam::getParamName, SDParam::getParamValue))));

        Assertions.assertEquals(1, sdElementMap.get("nlf_01@48577").size());
        Assertions
                .assertEquals(DefaultEventType.class.getSimpleName(), sdElementMap.get("nlf_01@48577").get("eventType"));

        Assertions.assertTrue(sdElementMap.get("aer_event@48577").containsKey("properties"));
    }

    @Test
    @DisplayName("Test NLFPlugin with DatabricksVectorSearch")
    void testNlfPluginWithDatabricksVectorSearch() {
        final String json = Assertions
                .assertDoesNotThrow(
                        () -> Files.readString(Paths.get("src/test/resources/databricks/databricksvectorsearch.json"))
                );
        final ParsedEvent parsedEvent = new ParsedEventFactory(
                new UnparsedEventImpl(json, new EventPartitionContextImpl(new HashMap<>()), new EventPropertiesImpl(new HashMap<>()), new EventSystemPropertiesImpl(new HashMap<>()), new EnqueuedTimeImpl("2020-01-01T00:00:00"), new EventOffsetImpl("0"))
        ).parsedEvent();

        final NLFPlugin plugin = new NLFPlugin(new FakeSourceable());
        final List<SyslogMessage> syslogMessages = Assertions
                .assertDoesNotThrow(() -> plugin.syslogMessage(parsedEvent));
        Assertions.assertEquals(1, syslogMessages.size());

        final SyslogMessage syslogMessage = syslogMessages.get(0);
        Assertions
                .assertEquals(
                        "{\n" + "  \"ActionName\": \"ActionName-49\",\n" + "  \"Category\": \"category-49\",\n"
                                + "  \"Identity\": \"identity-49\",\n"
                                + "  \"LogId\": \"12345678-1234-1234-abcd-1234567890bc\",\n"
                                + "  \"OperationName\": \"Operation-49\",\n" + "  \"OperationVersion\": \"1.0.0\",\n"
                                + "  \"RequestId\": \"12345678-1234-1234-abcd-1234567890cd\",\n"
                                + "  \"RequestParams\": \"\\\"key\\\":\\\"value\\\"\",\n"
                                + "  \"Response\": \"Success\",\n" + "  \"ServiceName\": \"service-49\",\n"
                                + "  \"SessionId\": \"12345678-1234-1234-abcd-1234567890de\",\n"
                                + "  \"SourceIpAddress\": \"127.0.0.1\",\n" + "  \"SourceSystem\": \"Azure\",\n"
                                + "  \"TenantId\": \"12345678-1234-1234-abcd-1234567890ef\",\n"
                                + "  \"TimeGenerated\": \"2025-10-06T00:00:00.0000000Z\",\n"
                                + "  \"Type\": \"DatabricksVectorSearch\",\n"
                                + "  \"UserAgent\": \"User-Agent: Mozilla/5.0 (<system-information>) <platform> (<platform-details>) <extensions>\",\n"
                                + "  \"_ResourceId\": \"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}\",\n"
                                + "  \"_SubscriptionId\": \"12345678-1234-1234-abcd-1234567890fg\"\n" + "}",
                        syslogMessage.getMsg()
                );
        Assertions.assertEquals("md5-0ded52ef915af563e25778bf26b0f129-resourceName", syslogMessage.getHostname());
        Assertions.assertEquals("DatabricksVectorSearch", syslogMessage.getAppName());
        Assertions.assertEquals("2025-10-06T00:00:00Z", syslogMessage.getTimestamp());

        final Map<String, Map<String, String>> sdElementMap = syslogMessage
                .getSDElements()
                .stream()
                .collect(Collectors.toMap((SDElement::getSdID), (sdElem) -> sdElem.getSdParams().stream().collect(Collectors.toMap(SDParam::getParamName, SDParam::getParamValue))));

        Assertions.assertEquals(1, sdElementMap.get("nlf_01@48577").size());
        Assertions
                .assertEquals(DefaultEventType.class.getSimpleName(), sdElementMap.get("nlf_01@48577").get("eventType"));

        Assertions.assertTrue(sdElementMap.get("aer_event@48577").containsKey("properties"));
    }

    @Test
    @DisplayName("Test NLFPlugin with DatabricksWebhookNotifications")
    void testNlfPluginWithDatabricksWebhookNotifications() {
        final String json = Assertions
                .assertDoesNotThrow(
                        () -> Files
                                .readString(
                                        Paths.get("src/test/resources/databricks/databrickswebhooknotifications.json")
                                )
                );
        final ParsedEvent parsedEvent = new ParsedEventFactory(
                new UnparsedEventImpl(json, new EventPartitionContextImpl(new HashMap<>()), new EventPropertiesImpl(new HashMap<>()), new EventSystemPropertiesImpl(new HashMap<>()), new EnqueuedTimeImpl("2020-01-01T00:00:00"), new EventOffsetImpl("0"))
        ).parsedEvent();

        final NLFPlugin plugin = new NLFPlugin(new FakeSourceable());
        final List<SyslogMessage> syslogMessages = Assertions
                .assertDoesNotThrow(() -> plugin.syslogMessage(parsedEvent));
        Assertions.assertEquals(1, syslogMessages.size());

        final SyslogMessage syslogMessage = syslogMessages.get(0);
        Assertions
                .assertEquals(
                        "{\n" + "  \"ActionName\": \"ActionName-50\",\n" + "  \"Category\": \"category-50\",\n"
                                + "  \"Identity\": \"identity-50\",\n"
                                + "  \"LogId\": \"12345678-1234-1234-abcd-1234567890bc\",\n"
                                + "  \"OperationName\": \"Operation-50\",\n" + "  \"OperationVersion\": \"1.0.0\",\n"
                                + "  \"RequestId\": \"12345678-1234-1234-abcd-1234567890cd\",\n"
                                + "  \"RequestParams\": \"\\\"key\\\":\\\"value\\\"\",\n"
                                + "  \"Response\": \"Success\",\n" + "  \"ServiceName\": \"service-50\",\n"
                                + "  \"SessionId\": \"12345678-1234-1234-abcd-1234567890de\",\n"
                                + "  \"SourceIpAddress\": \"127.0.0.1\",\n" + "  \"SourceSystem\": \"Azure\",\n"
                                + "  \"TenantId\": \"12345678-1234-1234-abcd-1234567890ef\",\n"
                                + "  \"TimeGenerated\": \"2025-10-06T00:00:00.0000000Z\",\n"
                                + "  \"Type\": \"DatabricksWebhookNotifications\",\n"
                                + "  \"UserAgent\": \"User-Agent: Mozilla/5.0 (<system-information>) <platform> (<platform-details>) <extensions>\",\n"
                                + "  \"_ResourceId\": \"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}\",\n"
                                + "  \"_SubscriptionId\": \"12345678-1234-1234-abcd-1234567890fg\"\n" + "}",
                        syslogMessage.getMsg()
                );
        Assertions.assertEquals("md5-0ded52ef915af563e25778bf26b0f129-resourceName", syslogMessage.getHostname());
        Assertions.assertEquals("DatabricksWebhookNotifications", syslogMessage.getAppName());
        Assertions.assertEquals("2025-10-06T00:00:00Z", syslogMessage.getTimestamp());

        final Map<String, Map<String, String>> sdElementMap = syslogMessage
                .getSDElements()
                .stream()
                .collect(Collectors.toMap((SDElement::getSdID), (sdElem) -> sdElem.getSdParams().stream().collect(Collectors.toMap(SDParam::getParamName, SDParam::getParamValue))));

        Assertions.assertEquals(1, sdElementMap.get("nlf_01@48577").size());
        Assertions
                .assertEquals(DefaultEventType.class.getSimpleName(), sdElementMap.get("nlf_01@48577").get("eventType"));

        Assertions.assertTrue(sdElementMap.get("aer_event@48577").containsKey("properties"));
    }

    @Test
    @DisplayName("Test NLFPlugin with DatabricksWebTerminal")
    void testNlfPluginWithDatabricksWebTerminal() {
        final String json = Assertions
                .assertDoesNotThrow(
                        () -> Files.readString(Paths.get("src/test/resources/databricks/databrickswebterminal.json"))
                );
        final ParsedEvent parsedEvent = new ParsedEventFactory(
                new UnparsedEventImpl(json, new EventPartitionContextImpl(new HashMap<>()), new EventPropertiesImpl(new HashMap<>()), new EventSystemPropertiesImpl(new HashMap<>()), new EnqueuedTimeImpl("2020-01-01T00:00:00"), new EventOffsetImpl("0"))
        ).parsedEvent();

        final NLFPlugin plugin = new NLFPlugin(new FakeSourceable());
        final List<SyslogMessage> syslogMessages = Assertions
                .assertDoesNotThrow(() -> plugin.syslogMessage(parsedEvent));
        Assertions.assertEquals(1, syslogMessages.size());

        final SyslogMessage syslogMessage = syslogMessages.get(0);
        Assertions
                .assertEquals(
                        "{\n" + "  \"ActionName\": \"ActionName-51\",\n" + "  \"Category\": \"category-51\",\n"
                                + "  \"Identity\": \"identity-51\",\n"
                                + "  \"LogId\": \"12345678-1234-1234-abcd-1234567890bc\",\n"
                                + "  \"OperationName\": \"Operation-51\",\n" + "  \"OperationVersion\": \"1.0.0\",\n"
                                + "  \"RequestId\": \"12345678-1234-1234-abcd-1234567890cd\",\n"
                                + "  \"RequestParams\": \"\\\"key\\\":\\\"value\\\"\",\n"
                                + "  \"Response\": \"Success\",\n" + "  \"ServiceName\": \"service-51\",\n"
                                + "  \"SessionId\": \"12345678-1234-1234-abcd-1234567890de\",\n"
                                + "  \"SourceIPAddress\": \"127.0.0.1\",\n" + "  \"SourceSystem\": \"Azure\",\n"
                                + "  \"TenantId\": \"12345678-1234-1234-abcd-1234567890ef\",\n"
                                + "  \"TimeGenerated\": \"2025-10-06T00:00:00.0000000Z\",\n"
                                + "  \"Type\": \"DatabricksWebTerminal\",\n"
                                + "  \"UserAgent\": \"User-Agent: Mozilla/5.0 (<system-information>) <platform> (<platform-details>) <extensions>\",\n"
                                + "  \"_ResourceId\": \"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}\",\n"
                                + "  \"_SubscriptionId\": \"12345678-1234-1234-abcd-1234567890fg\"\n" + "}",
                        syslogMessage.getMsg()
                );
        Assertions.assertEquals("md5-0ded52ef915af563e25778bf26b0f129-resourceName", syslogMessage.getHostname());
        Assertions.assertEquals("DatabricksWebTerminal", syslogMessage.getAppName());
        Assertions.assertEquals("2025-10-06T00:00:00Z", syslogMessage.getTimestamp());

        final Map<String, Map<String, String>> sdElementMap = syslogMessage
                .getSDElements()
                .stream()
                .collect(Collectors.toMap((SDElement::getSdID), (sdElem) -> sdElem.getSdParams().stream().collect(Collectors.toMap(SDParam::getParamName, SDParam::getParamValue))));

        Assertions.assertEquals(1, sdElementMap.get("nlf_01@48577").size());
        Assertions
                .assertEquals(DefaultEventType.class.getSimpleName(), sdElementMap.get("nlf_01@48577").get("eventType"));

        Assertions.assertTrue(sdElementMap.get("aer_event@48577").containsKey("properties"));
    }

    @Test
    @DisplayName("Test NLFPlugin with DatabricksWorkspace")
    void testNlfPluginWithDatabricksWorkspace() {
        final String json = Assertions
                .assertDoesNotThrow(
                        () -> Files.readString(Paths.get("src/test/resources/databricks/databricksworkspace.json"))
                );
        final ParsedEvent parsedEvent = new ParsedEventFactory(
                new UnparsedEventImpl(json, new EventPartitionContextImpl(new HashMap<>()), new EventPropertiesImpl(new HashMap<>()), new EventSystemPropertiesImpl(new HashMap<>()), new EnqueuedTimeImpl("2020-01-01T00:00:00"), new EventOffsetImpl("0"))
        ).parsedEvent();

        final NLFPlugin plugin = new NLFPlugin(new FakeSourceable());
        final List<SyslogMessage> syslogMessages = Assertions
                .assertDoesNotThrow(() -> plugin.syslogMessage(parsedEvent));
        Assertions.assertEquals(1, syslogMessages.size());

        final SyslogMessage syslogMessage = syslogMessages.get(0);
        Assertions
                .assertEquals(
                        "{\n" + "  \"ActionName\": \"ActionName-52\",\n" + "  \"Category\": \"category-52\",\n"
                                + "  \"Identity\": \"identity-52\",\n"
                                + "  \"LogId\": \"12345678-1234-1234-abcd-1234567890bc\",\n"
                                + "  \"OperationName\": \"Operation-52\",\n" + "  \"OperationVersion\": \"1.0.0\",\n"
                                + "  \"RequestId\": \"12345678-1234-1234-abcd-1234567890cd\",\n"
                                + "  \"RequestParams\": \"\\\"key\\\":\\\"value\\\"\",\n"
                                + "  \"Response\": \"Success\",\n" + "  \"ServiceName\": \"service-52\",\n"
                                + "  \"SessionId\": \"12345678-1234-1234-abcd-1234567890de\",\n"
                                + "  \"SourceIPAddress\": \"127.0.0.1\",\n" + "  \"SourceSystem\": \"Azure\",\n"
                                + "  \"TenantId\": \"12345678-1234-1234-abcd-1234567890ef\",\n"
                                + "  \"TimeGenerated\": \"2025-10-06T00:00:00.0000000Z\",\n"
                                + "  \"Type\": \"DatabricksWorkspace\",\n"
                                + "  \"UserAgent\": \"User-Agent: Mozilla/5.0 (<system-information>) <platform> (<platform-details>) <extensions>\",\n"
                                + "  \"_ResourceId\": \"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}\",\n"
                                + "  \"_SubscriptionId\": \"12345678-1234-1234-abcd-1234567890fg\"\n" + "}",
                        syslogMessage.getMsg()
                );
        Assertions.assertEquals("md5-0ded52ef915af563e25778bf26b0f129-resourceName", syslogMessage.getHostname());
        Assertions.assertEquals("DatabricksWorkspace", syslogMessage.getAppName());
        Assertions.assertEquals("2025-10-06T00:00:00Z", syslogMessage.getTimestamp());

        final Map<String, Map<String, String>> sdElementMap = syslogMessage
                .getSDElements()
                .stream()
                .collect(Collectors.toMap((SDElement::getSdID), (sdElem) -> sdElem.getSdParams().stream().collect(Collectors.toMap(SDParam::getParamName, SDParam::getParamValue))));

        Assertions.assertEquals(1, sdElementMap.get("nlf_01@48577").size());
        Assertions
                .assertEquals(DefaultEventType.class.getSimpleName(), sdElementMap.get("nlf_01@48577").get("eventType"));

        Assertions.assertTrue(sdElementMap.get("aer_event@48577").containsKey("properties"));
    }

    @Test
    @DisplayName("Test NLFPlugin with DatabricksWorkspaceFiles")
    void testNlfPluginWithDatabricksWorkspaceFiles() {
        final String json = Assertions
                .assertDoesNotThrow(
                        () -> Files.readString(Paths.get("src/test/resources/databricks/databricksworkspacefiles.json"))
                );
        final ParsedEvent parsedEvent = new ParsedEventFactory(
                new UnparsedEventImpl(json, new EventPartitionContextImpl(new HashMap<>()), new EventPropertiesImpl(new HashMap<>()), new EventSystemPropertiesImpl(new HashMap<>()), new EnqueuedTimeImpl("2020-01-01T00:00:00"), new EventOffsetImpl("0"))
        ).parsedEvent();

        final NLFPlugin plugin = new NLFPlugin(new FakeSourceable());
        final List<SyslogMessage> syslogMessages = Assertions
                .assertDoesNotThrow(() -> plugin.syslogMessage(parsedEvent));
        Assertions.assertEquals(1, syslogMessages.size());

        final SyslogMessage syslogMessage = syslogMessages.get(0);
        Assertions
                .assertEquals(
                        "{\n" + "  \"ActionName\": \"ActionName-53\",\n" + "  \"Category\": \"category-53\",\n"
                                + "  \"Identity\": \"identity-53\",\n"
                                + "  \"LogId\": \"12345678-1234-1234-abcd-1234567890bc\",\n"
                                + "  \"OperationName\": \"Operation-53\",\n" + "  \"OperationVersion\": \"1.0.0\",\n"
                                + "  \"RequestId\": \"12345678-1234-1234-abcd-1234567890cd\",\n"
                                + "  \"RequestParams\": \"\\\"key\\\":\\\"value\\\"\",\n"
                                + "  \"Response\": \"Success\",\n" + "  \"ServiceName\": \"service-53\",\n"
                                + "  \"SessionId\": \"12345678-1234-1234-abcd-1234567890de\",\n"
                                + "  \"SourceIpAddress\": \"127.0.0.1\",\n" + "  \"SourceSystem\": \"Azure\",\n"
                                + "  \"TenantId\": \"12345678-1234-1234-abcd-1234567890ef\",\n"
                                + "  \"TimeGenerated\": \"2025-10-06T00:00:00.0000000Z\",\n"
                                + "  \"Type\": \"DatabricksWorkspaceFiles\",\n"
                                + "  \"UserAgent\": \"User-Agent: Mozilla/5.0 (<system-information>) <platform> (<platform-details>) <extensions>\",\n"
                                + "  \"_ResourceId\": \"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}\",\n"
                                + "  \"_SubscriptionId\": \"12345678-1234-1234-abcd-1234567890fg\"\n" + "}",
                        syslogMessage.getMsg()
                );
        Assertions.assertEquals("md5-0ded52ef915af563e25778bf26b0f129-resourceName", syslogMessage.getHostname());
        Assertions.assertEquals("DatabricksWorkspaceFiles", syslogMessage.getAppName());
        Assertions.assertEquals("2025-10-06T00:00:00Z", syslogMessage.getTimestamp());

        final Map<String, Map<String, String>> sdElementMap = syslogMessage
                .getSDElements()
                .stream()
                .collect(Collectors.toMap((SDElement::getSdID), (sdElem) -> sdElem.getSdParams().stream().collect(Collectors.toMap(SDParam::getParamName, SDParam::getParamValue))));

        Assertions.assertEquals(1, sdElementMap.get("nlf_01@48577").size());
        Assertions
                .assertEquals(DefaultEventType.class.getSimpleName(), sdElementMap.get("nlf_01@48577").get("eventType"));

        Assertions.assertTrue(sdElementMap.get("aer_event@48577").containsKey("properties"));
    }
}
