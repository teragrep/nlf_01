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
import com.teragrep.akv_01.event.metadata.offset.EventOffsetStub;
import com.teragrep.akv_01.event.metadata.partitionContext.EventPartitionContextImpl;
import com.teragrep.akv_01.event.metadata.partitionContext.EventPartitionContextStub;
import com.teragrep.akv_01.event.metadata.properties.EventPropertiesImpl;
import com.teragrep.akv_01.event.metadata.properties.EventPropertiesStub;
import com.teragrep.akv_01.event.metadata.systemProperties.EventSystemPropertiesImpl;
import com.teragrep.akv_01.event.metadata.systemProperties.EventSystemPropertiesStub;
import com.teragrep.akv_01.event.metadata.time.EnqueuedTimeImpl;
import com.teragrep.akv_01.event.metadata.time.EnqueuedTimeStub;
import com.teragrep.akv_01.plugin.PluginException;
import com.teragrep.nlf_01.fakes.EmptySourceable;
import com.teragrep.nlf_01.fakes.FakeSourceable;
import com.teragrep.nlf_01.types.*;
import com.teragrep.rlo_14.*;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class NLFPluginTest {

    @Test
    void containerType() {
        final String json = Assertions
                .assertDoesNotThrow(() -> Files.readString(Paths.get("src/test/resources/container.json")));
        final ParsedEvent parsedEvent = new ParsedEventFactory(
                new UnparsedEventImpl(json, new EventPartitionContextImpl(new HashMap<>()), new EventPropertiesImpl(new HashMap<>()), new EventSystemPropertiesImpl(new HashMap<>()), new EnqueuedTimeImpl("2020-01-01T00:00:00"), new EventOffsetImpl("0"))
        ).parsedEvent();

        final NLFPlugin plugin = new NLFPlugin(new FakeSourceable());
        final List<SyslogMessage> syslogMessages = Assertions
                .assertDoesNotThrow(() -> plugin.syslogMessage(parsedEvent));
        Assertions.assertEquals(1, syslogMessages.size());

        final SyslogMessage syslogMessage = syslogMessages.get(0);
        Assertions.assertEquals(json, syslogMessage.getMsg());
        Assertions.assertEquals("HOST-NAME", syslogMessage.getHostname());
        Assertions.assertEquals("APP-NAME.o", syslogMessage.getAppName());
        Assertions.assertEquals("2020-01-01T01:23:34.567Z", syslogMessage.getTimestamp());

        final Map<String, Map<String, String>> sdElementMap = syslogMessage
                .getSDElements()
                .stream()
                .collect(Collectors.toMap((SDElement::getSdID), (sdElem) -> sdElem.getSdParams().stream().collect(Collectors.toMap(SDParam::getParamName, SDParam::getParamValue))));

        Assertions.assertEquals(5, sdElementMap.get("origin@48577").size());
        Assertions.assertEquals("{subscriptionId}", sdElementMap.get("origin@48577").get("subscription"));
        Assertions.assertEquals("{resourceName}", sdElementMap.get("origin@48577").get("clusterName"));
        Assertions.assertEquals("pod-namespace", sdElementMap.get("origin@48577").get("namespace"));
        Assertions.assertEquals("pod-name", sdElementMap.get("origin@48577").get("pod"));
        Assertions.assertEquals("container-id", sdElementMap.get("origin@48577").get("containerId"));

        Assertions.assertEquals(1, sdElementMap.get("nlf_01@48577").size());
        Assertions.assertEquals(ContainerType.class.getSimpleName(), sdElementMap.get("nlf_01@48577").get("eventType"));

        Assertions.assertTrue(sdElementMap.get("aer_02_event@48577").containsKey("properties"));

        Assertions.assertEquals("timeEnqueued", sdElementMap.get("aer_02@48577").get("timestamp_source"));
        Assertions.assertEquals("2020-01-01T00:00Z", sdElementMap.get("aer_02_event@48577").get("enqueued_time"));
    }

    @Test
    void containerTypeWithMissingEnvVariables() {
        final String json = Assertions
                .assertDoesNotThrow(() -> Files.readString(Paths.get("src/test/resources/container.json")));
        final ParsedEvent parsedEvent = new ParsedEventFactory(
                new UnparsedEventImpl(json, new EventPartitionContextImpl(new HashMap<>()), new EventPropertiesImpl(new HashMap<>()), new EventSystemPropertiesImpl(new HashMap<>()), new EnqueuedTimeImpl("2020-01-01T00:00:00"), new EventOffsetImpl("0"))
        ).parsedEvent();

        final NLFPlugin plugin = new NLFPlugin(new EmptySourceable());
        final PluginException pluginException = Assertions
                .assertThrows(PluginException.class, () -> plugin.syslogMessage(parsedEvent));
        Assertions
                .assertEquals(
                        "java.lang.IllegalArgumentException: No such environment variable: containerlog.appname.annotation",
                        pluginException.getMessage()
                );
    }

    @Test
    void containerTypeWithStubEnqueuedTime() {
        final String json = Assertions
                .assertDoesNotThrow(() -> Files.readString(Paths.get("src/test/resources/container.json")));
        final ParsedEvent parsedEvent = new ParsedEventFactory(
                new UnparsedEventImpl(json, new EventPartitionContextImpl(new HashMap<>()), new EventPropertiesImpl(new HashMap<>()), new EventSystemPropertiesImpl(new HashMap<>()), new EnqueuedTimeStub(), new EventOffsetImpl("0"))
        ).parsedEvent();

        final NLFPlugin plugin = new NLFPlugin(new FakeSourceable());
        final List<SyslogMessage> syslogMessages = Assertions
                .assertDoesNotThrow(() -> plugin.syslogMessage(parsedEvent));
        Assertions.assertEquals(1, syslogMessages.size());

        final SyslogMessage syslogMessage = syslogMessages.get(0);
        Assertions.assertEquals(json, syslogMessage.getMsg());
        Assertions.assertEquals("HOST-NAME", syslogMessage.getHostname());
        Assertions.assertEquals("APP-NAME.o", syslogMessage.getAppName());
        Assertions.assertEquals("2020-01-01T01:23:34.567Z", syslogMessage.getTimestamp());

        final Map<String, Map<String, String>> sdElementMap = syslogMessage
                .getSDElements()
                .stream()
                .collect(Collectors.toMap((SDElement::getSdID), (sdElem) -> sdElem.getSdParams().stream().collect(Collectors.toMap(SDParam::getParamName, SDParam::getParamValue))));

        Assertions.assertEquals(5, sdElementMap.get("origin@48577").size());
        Assertions.assertEquals("{subscriptionId}", sdElementMap.get("origin@48577").get("subscription"));
        Assertions.assertEquals("{resourceName}", sdElementMap.get("origin@48577").get("clusterName"));
        Assertions.assertEquals("pod-namespace", sdElementMap.get("origin@48577").get("namespace"));
        Assertions.assertEquals("pod-name", sdElementMap.get("origin@48577").get("pod"));
        Assertions.assertEquals("container-id", sdElementMap.get("origin@48577").get("containerId"));

        Assertions.assertEquals(1, sdElementMap.get("nlf_01@48577").size());
        Assertions.assertEquals(ContainerType.class.getSimpleName(), sdElementMap.get("nlf_01@48577").get("eventType"));

        Assertions.assertTrue(sdElementMap.get("aer_02_event@48577").containsKey("properties"));

        Assertions.assertEquals("generated", sdElementMap.get("aer_02@48577").get("timestamp_source"));
        Assertions.assertEquals("", sdElementMap.get("aer_02_event@48577").get("enqueued_time"));
    }

    @Test
    void appInsightType() {
        final String json = Assertions
                .assertDoesNotThrow(() -> Files.readString(Paths.get("src/test/resources/appinsight.json")));
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
                        "{\n" + "    \"AppRoleInstance\": \"app-role-instance\",\n"
                                + "    \"AppRoleName\": \"app-role-name\",\n" + "    \"ClientIP\": \"192.168.1.2\",\n"
                                + "    \"ClientType\": \"client-type\",\n" + "    \"IKey\": \"i-key\",\n"
                                + "    \"ItemCount\": 1,\n" + "    \"Message\": \"message\",\n"
                                + "    \"OperationId\": \"123\",\n" + "    \"ParentId\": \"456\",\n"
                                + "    \"Properties\": {\n" + "      \"ProcessId\":\"1234\",\n"
                                + "      \"HostInstanceId\":\"123456\",\n"
                                + "      \"prop__{OriginalFormat}\":\"abc\",\n" + "      \"prop__RouteName\":\"xyz\",\n"
                                + "      \"LogLevel\":\"Debug\",\n" + "      \"EventId\":\"1\",\n"
                                + "      \"prop__RouteTemplate\":\"route/template\",\n"
                                + "      \"Category\":\"192.168.3.1\",\n" + "      \"EventName\":\"event-name\"},\n"
                                + "\n" + "    \"ResourceGUID\": \"123456789\",\n"
                                + "    \"SDKVersion\": \"12: 192.168.x.x\",\n"
                                + "    \"SeverityLevel\": 0, \"SourceSystem\": \"Azure\",\n"
                                + "    \"TenantId\": \"12\",\n"
                                + "    \"TimeGenerated\": \"2020-01-01T01:02:34.5678999Z\",\n"
                                + "    \"Type\": \"AppTraces\",\n" + "    \"_BilledSize\": 1,\n"
                                + "    \"_ItemId\": \"12-34-56-78\",\n"
                                + "    \"_Internal_WorkspaceResourceId\": \"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}\",\n"
                                + "    \"_ResourceId\": \"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}\"\n"
                                + "  }",
                        syslogMessage.getMsg()
                );
        Assertions.assertEquals("md5-0ded52ef915af563e25778bf26b0f129-resourceName", syslogMessage.getHostname());
        Assertions.assertEquals("app-role-name", syslogMessage.getAppName());
        Assertions.assertEquals("2020-01-01T01:02:34.567Z", syslogMessage.getTimestamp());

        final Map<String, Map<String, String>> sdElementMap = syslogMessage
                .getSDElements()
                .stream()
                .collect(Collectors.toMap((SDElement::getSdID), (sdElem) -> sdElem.getSdParams().stream().collect(Collectors.toMap(SDParam::getParamName, SDParam::getParamValue))));

        Assertions.assertEquals(1, sdElementMap.get("nlf_01@48577").size());
        Assertions
                .assertEquals(AppInsightType.class.getSimpleName(), sdElementMap.get("nlf_01@48577").get("eventType"));

        Assertions.assertTrue(sdElementMap.get("aer_02_event@48577").containsKey("properties"));
    }

    @Test
    void ccType() {
        final String json = Assertions
                .assertDoesNotThrow(() -> Files.readString(Paths.get("src/test/resources/cc.json")));
        final ParsedEvent parsedEvent = new ParsedEventFactory(
                new UnparsedEventImpl(json, new EventPartitionContextImpl(new HashMap<>()), new EventPropertiesImpl(new HashMap<>()), new EventSystemPropertiesImpl(new HashMap<>()), new EnqueuedTimeImpl("2020-01-01T00:00:00"), new EventOffsetImpl("0"))
        ).parsedEvent();

        final NLFPlugin plugin = new NLFPlugin(new FakeSourceable());
        final List<SyslogMessage> syslogMessages = Assertions
                .assertDoesNotThrow(() -> plugin.syslogMessage(parsedEvent));
        Assertions.assertEquals(1, syslogMessages.size());

        final SyslogMessage syslogMessage = syslogMessages.get(0);
        Assertions.assertEquals(json, syslogMessage.getMsg());
        Assertions.assertEquals("md5-0ded52ef915af563e25778bf26b0f129-resourceName", syslogMessage.getHostname());
        Assertions.assertEquals("abc-d12efgh", syslogMessage.getAppName());
        Assertions.assertEquals("2025-10-06T00:00:00Z", syslogMessage.getTimestamp());

        final Map<String, Map<String, String>> sdElementMap = syslogMessage
                .getSDElements()
                .stream()
                .collect(Collectors.toMap((SDElement::getSdID), (sdElem) -> sdElem.getSdParams().stream().collect(Collectors.toMap(SDParam::getParamName, SDParam::getParamValue))));

        Assertions.assertNotNull(sdElementMap);
        Assertions.assertEquals(5, sdElementMap.size());
        Assertions.assertEquals(1, sdElementMap.get("nlf_01@48577").size());
        Assertions.assertEquals(CCType.class.getSimpleName(), sdElementMap.get("nlf_01@48577").get("eventType"));

        Assertions.assertTrue(sdElementMap.get("aer_02_event@48577").containsKey("properties"));

        Assertions.assertEquals("timeEnqueued", sdElementMap.get("aer_02@48577").get("timestamp_source"));
        Assertions.assertEquals("2020-01-01T00:00Z", sdElementMap.get("aer_02_event@48577").get("enqueued_time"));
    }

    @Test
    void clType() {
        final String json = Assertions
                .assertDoesNotThrow(() -> Files.readString(Paths.get("src/test/resources/cl.json")));
        final ParsedEvent parsedEvent = new ParsedEventFactory(
                new UnparsedEventImpl(json, new EventPartitionContextImpl(new HashMap<>()), new EventPropertiesImpl(new HashMap<>()), new EventSystemPropertiesImpl(new HashMap<>()), new EnqueuedTimeImpl("2020-01-01T00:00:00"), new EventOffsetImpl("0"))
        ).parsedEvent();

        final NLFPlugin plugin = new NLFPlugin(new FakeSourceable());
        final List<SyslogMessage> syslogMessages = Assertions
                .assertDoesNotThrow(() -> plugin.syslogMessage(parsedEvent));
        Assertions.assertEquals(1, syslogMessages.size());

        final SyslogMessage syslogMessage = syslogMessages.get(0);
        Assertions.assertEquals("md5-0ded52ef915af563e25778bf26b0f129-resourceName", syslogMessage.getHostname());
        Assertions.assertEquals("97bd8f02-xxxxx.log", syslogMessage.getAppName());
        Assertions.assertEquals("2020-01-01T01:02:34.567Z", syslogMessage.getTimestamp());
        Assertions.assertEquals(json, syslogMessage.getMsg());
        final Map<String, Map<String, String>> sdElementMap = syslogMessage
                .getSDElements()
                .stream()
                .collect(Collectors.toMap((SDElement::getSdID), (sdElem) -> sdElem.getSdParams().stream().collect(Collectors.toMap(SDParam::getParamName, SDParam::getParamValue))));

        Assertions
                .assertEquals(
                        "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}",
                        sdElementMap.get("origin@48577").get("_ResourceId")
                );

        Assertions.assertTrue(sdElementMap.get("aer_02_event@48577").containsKey("properties"));
    }

    @Test
    void adfPipelineRunType() {
        final String json = Assertions
                .assertDoesNotThrow(() -> Files.readString(Paths.get("src/test/resources/adfpipelinerun.json")));
        final ParsedEvent parsedEvent = new ParsedEventFactory(
                new UnparsedEventImpl(json, new EventPartitionContextImpl(new HashMap<>()), new EventPropertiesImpl(new HashMap<>()), new EventSystemPropertiesImpl(new HashMap<>()), new EnqueuedTimeImpl("2020-01-01T00:00:00"), new EventOffsetImpl("0"))
        ).parsedEvent();

        final NLFPlugin plugin = new NLFPlugin(new FakeSourceable());
        final List<SyslogMessage> syslogMessages = Assertions
                .assertDoesNotThrow(() -> plugin.syslogMessage(parsedEvent));
        Assertions.assertEquals(1, syslogMessages.size());

        final SyslogMessage syslogMessage = syslogMessages.get(0);
        Assertions.assertEquals(json, syslogMessage.getMsg());
        Assertions.assertEquals("md5-0ded52ef915af563e25778bf26b0f129-resourceName", syslogMessage.getHostname());
        Assertions.assertEquals("MainPipeline", syslogMessage.getAppName());
        Assertions.assertEquals("2025-10-06T00:00:00Z", syslogMessage.getTimestamp());

        final Map<String, Map<String, String>> sdElementMap = syslogMessage
                .getSDElements()
                .stream()
                .collect(Collectors.toMap((SDElement::getSdID), (sdElem) -> sdElem.getSdParams().stream().collect(Collectors.toMap(SDParam::getParamName, SDParam::getParamValue))));

        Assertions.assertNotNull(sdElementMap);
        Assertions.assertEquals(5, sdElementMap.size());
        Assertions.assertEquals(1, sdElementMap.get("nlf_01@48577").size());
        Assertions
                .assertEquals(ADFPipelineRunType.class.getSimpleName(), sdElementMap.get("nlf_01@48577").get("eventType"));

        Assertions.assertTrue(sdElementMap.get("aer_02_event@48577").containsKey("properties"));

        Assertions.assertEquals("timeEnqueued", sdElementMap.get("aer_02@48577").get("timestamp_source"));
        Assertions.assertEquals("2020-01-01T00:00Z", sdElementMap.get("aer_02_event@48577").get("enqueued_time"));
    }

    @Test
    void syslogType() {
        final String json = Assertions
                .assertDoesNotThrow(() -> Files.readString(Paths.get("src/test/resources/syslog.json")));
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
                        "{\n" + "  \"Collectorhostname\": \"xyz\",\n"
                                + "  \"Computer\": \"10660186-5aec-4f2b-a021-6be9edfb9555\",\n"
                                + "  \"EventTime\": \"2025-02-18T13:47:27.0000000Z\",\n" + "  \"Facility\": \"user\",\n"
                                + "  \"HostIP\": \"Unknown IP\",\n"
                                + "  \"HostName\": \"10660186-5aec-4f2b-a021-6be9edfb9555\",\n"
                                + "  \"MG\": \"00000000-0000-0000-0000-000000000002\",\n"
                                + "  \"ProcessName\": \"Soft-Ware\",\n" + "  \"SeverityLevel\": \"info\",\n"
                                + "  \"SourceSystem\": \"Linux\",\n"
                                + "  \"SyslogMessage\": \"Tue, 18 Feb 2025 15:47:27 EET 27:63 10660186-5aec-4f2b-a021-6be9edfb9555-a-b-c-d-e-f-g-h [INFO] says yes\",\n"
                                + "  \"TenantId\": \"01bfa0b2-7986-4de8-8cd6-9da6db0400f5\",\n"
                                + "  \"TimeGenerated\": \"2025-02-18T13:47:27.0644670Z\",\n"
                                + "  \"Type\": \"Syslog\",\n"
                                + "  \"_Internal_WorkspaceResourceId\": \"/subscriptions/ce5ef585-60c3-4e37-a326-7bb6df0e5750/resourcegroups/res-g1/providers/pro-v1/workspaces/n-n-law\",\n"
                                + "  \"_ItemId\": \"5a6ae031-689a-479e-92d7-dfd8eea5158b\",\n"
                                + "  \"_ResourceId\": \"/subscriptions/ce5ef585-60c3-4e37-a326-7bb6df0e5750/resourceGroups/res-g2/providers/.../workspaces/...\"\n"
                                + "}",
                        syslogMessage.getMsg()
                );
        Assertions.assertEquals("md5-35166b001e9028e0085c05498ffd1235-n-n-law", syslogMessage.getHostname());
        Assertions.assertEquals("10660186-5aec-4f2b-a021-6be9edfb9555", syslogMessage.getAppName());
        Assertions.assertEquals("2025-02-18T13:47:27.064Z", syslogMessage.getTimestamp());

        final Map<String, Map<String, String>> sdElementMap = syslogMessage
                .getSDElements()
                .stream()
                .collect(Collectors.toMap((SDElement::getSdID), (sdElem) -> sdElem.getSdParams().stream().collect(Collectors.toMap(SDParam::getParamName, SDParam::getParamValue))));

        Assertions.assertEquals(1, sdElementMap.get("nlf_01@48577").size());
        Assertions.assertEquals(SyslogType.class.getSimpleName(), sdElementMap.get("nlf_01@48577").get("eventType"));

        Assertions.assertTrue(sdElementMap.get("aer_02_event@48577").containsKey("properties"));
    }

    @Test
    void adfActivityRunType() {
        final String json = Assertions
                .assertDoesNotThrow(() -> Files.readString(Paths.get("src/test/resources/adfactivityrun.json")));
        final ParsedEvent parsedEvent = new ParsedEventFactory(
                new UnparsedEventImpl(json, new EventPartitionContextImpl(new HashMap<>()), new EventPropertiesImpl(new HashMap<>()), new EventSystemPropertiesImpl(new HashMap<>()), new EnqueuedTimeImpl("2020-01-01T00:00:00"), new EventOffsetImpl("0"))
        ).parsedEvent();

        final NLFPlugin plugin = new NLFPlugin(new FakeSourceable());
        final List<SyslogMessage> syslogMessages = Assertions
                .assertDoesNotThrow(() -> plugin.syslogMessage(parsedEvent));
        Assertions.assertEquals(1, syslogMessages.size());

        final SyslogMessage syslogMessage = syslogMessages.get(0);
        Assertions.assertEquals("md5-0ded52ef915af563e25778bf26b0f129-resourceName", syslogMessage.getHostname());
        Assertions.assertEquals("Pipeline-1", syslogMessage.getAppName());
        Assertions.assertEquals("2025-10-06T00:00:00Z", syslogMessage.getTimestamp());
        Assertions.assertEquals(json, syslogMessage.getMsg());
        final Map<String, Map<String, String>> sdElementMap = syslogMessage
                .getSDElements()
                .stream()
                .collect(Collectors.toMap((SDElement::getSdID), (sdElem) -> sdElem.getSdParams().stream().collect(Collectors.toMap(SDParam::getParamName, SDParam::getParamValue))));

        Assertions.assertEquals(1, sdElementMap.get("nlf_01@48577").size());
        Assertions
                .assertEquals(ADFActivityRunType.class.getSimpleName(), sdElementMap.get("nlf_01@48577").get("eventType"));

        Assertions.assertEquals(4, sdElementMap.get("aer_02_event@48577").size());
        Assertions.assertTrue(sdElementMap.get("aer_02_event@48577").containsKey("properties"));
    }

    @Test
    void containerAppConsoleLogsType() {
        final String json = Assertions
                .assertDoesNotThrow(() -> Files.readString(Paths.get("src/test/resources/containerappconsolelogs.json")));
        final ParsedEvent parsedEvent = new ParsedEventFactory(
                new UnparsedEventImpl(json, new EventPartitionContextImpl(new HashMap<>()), new EventPropertiesImpl(new HashMap<>()), new EventSystemPropertiesImpl(new HashMap<>()), new EnqueuedTimeImpl("2020-01-01T00:00:00"), new EventOffsetImpl("0"))
        ).parsedEvent();

        final NLFPlugin plugin = new NLFPlugin(new FakeSourceable());
        final List<SyslogMessage> syslogMessages = Assertions
                .assertDoesNotThrow(() -> plugin.syslogMessage(parsedEvent));
        Assertions.assertEquals(1, syslogMessages.size());

        final SyslogMessage syslogMessage = syslogMessages.get(0);
        Assertions.assertEquals("md5-0ded52ef915af563e25778bf26b0f129-resourceName", syslogMessage.getHostname());
        Assertions.assertEquals("container-app-name", syslogMessage.getAppName());
        Assertions.assertEquals("2020-01-01T01:23:34.567Z", syslogMessage.getTimestamp());
        Assertions.assertEquals(json, syslogMessage.getMsg());
        final Map<String, Map<String, String>> sdElementMap = syslogMessage
                .getSDElements()
                .stream()
                .collect(Collectors.toMap((SDElement::getSdID), (sdElem) -> sdElem.getSdParams().stream().collect(Collectors.toMap(SDParam::getParamName, SDParam::getParamValue))));

        Assertions.assertEquals(1, sdElementMap.get("nlf_01@48577").size());
        Assertions
                .assertEquals(ContainerAppConsoleLogsType.class.getSimpleName(), sdElementMap.get("nlf_01@48577").get("eventType"));

        Assertions.assertEquals(4, sdElementMap.get("aer_02_event@48577").size());
        Assertions.assertTrue(sdElementMap.get("aer_02_event@48577").containsKey("properties"));
    }

    @Test
    void functionAppLogsType() {
        final String json = Assertions
                .assertDoesNotThrow(() -> Files.readString(Paths.get("src/test/resources/function.json")));
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
                        "{\n" + "  \"AppName\": \"app-name\",\n" + "  \"Category\": \"function-logs\",\n"
                                + "  \"EventId\": 123,\n" + "  \"EventName\": \"event-name\",\n"
                                + "  \"ExceptionDetails\": \"123abc\",\n"
                                + "  \"ExceptionMessage\": \"Found a null value\",\n"
                                + "  \"ExceptionType\": \"NPE\",\n" + "  \"FunctionInvocationId\": \"12345678\",\n"
                                + "  \"FunctionName\": \"function-1\",\n"
                                + "  \"HostInstanceId\": \"host-instance-1\",\n" + "  \"HostVersion\": \"1.2.3.4.a\",\n"
                                + "  \"Level\": \"Debug\",\n" + "  \"LevelId\": 1,\n"
                                + "  \"Location\": \"function-1\",\n" + "  \"Message\": \"message\",\n"
                                + "  \"ProcessId\": 123456,\n" + "  \"RoleInstance\": \"message\",\n"
                                + "  \"SourceSystem\": \"Azure\",\n" + "  \"TenantId\": \"12\",\n"
                                + "  \"TimeGenerated\": \"2020-01-01T01:02:34.5678999Z\",\n"
                                + "  \"Type\": \"FunctionAppLogs\",\n" + "  \"_BilledSize\": 1,\n"
                                + "  \"_ItemId\": \"12-34-56-78\",\n"
                                + "  \"_Internal_WorkspaceResourceId\": \"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}\",\n"
                                + "  \"_ResourceId\": \"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}\"\n"
                                + "}",
                        syslogMessage.getMsg()
                );
        Assertions.assertEquals("md5-0ded52ef915af563e25778bf26b0f129-resourceName", syslogMessage.getHostname());
        Assertions.assertEquals("app-name", syslogMessage.getAppName());
        Assertions.assertEquals("2020-01-01T01:02:34.567Z", syslogMessage.getTimestamp());

        final Map<String, Map<String, String>> sdElementMap = syslogMessage
                .getSDElements()
                .stream()
                .collect(Collectors.toMap((SDElement::getSdID), (sdElem) -> sdElem.getSdParams().stream().collect(Collectors.toMap(SDParam::getParamName, SDParam::getParamValue))));

        Assertions.assertEquals(1, sdElementMap.get("nlf_01@48577").size());
        Assertions
                .assertEquals(FunctionAppLogsType.class.getSimpleName(), sdElementMap.get("nlf_01@48577").get("eventType"));

        Assertions.assertTrue(sdElementMap.get("aer_02_event@48577").containsKey("properties"));
    }

    @Test
    void testPostgreSQLType() {
        final String json = Assertions
                .assertDoesNotThrow(() -> Files.readString(Paths.get("src/test/resources/postgre.json")));
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
                        "{\n" + "  \"AppImage\":\"cinnamon/postgres_standalone_12_a1:12.3.456789\",\n"
                                + "  \"AppType\":\"PostgreSQL\",\n"
                                + "  \"AppVersion\":\"abcdefghj12_2020-01-01-12-34-56\",\n"
                                + "  \"Region\":\"countrycentral\",\n" + "  \"category\":\"PostgreSQLLogs\",\n"
                                + "  \"location\":\"countrycentral\",\n" + "  \"operationName\":\"LogEvent\",\n"
                                + "  \"properties\":\n" + "    {\n"
                                + "      \"timestamp\":\"2020-10-01 11:59:26.256 UTC\",\n"
                                + "      \"processId\":1234567,\n" + "      \"errorLevel\":\"LOG\",\n"
                                + "      \"sqlerrcode\":\"00000\",\n" + "      \"backend_type\":\"client backend\",\n"
                                + "      \"message\":\"2020-10-01 11:59:26 UTC-12abcd3e.4f5678-user=user012,db=dbase_maintenance,app=[unknown],client=127.0.0.1LOG:  AUDIT: SESSION,4,1,WRITE,INSERT,,,\\\"insert into test.abcmover (id, update_time) select 1, now() on conflict on constraint abcmover_pk do update set id = test.abcmover.id+1, update_time=now()\\\",<not logged>\"\n"
                                + "    },\n"
                                + "  \"resourceId\":\"/SUBSCRIPTIONS/uuid/RESOURCEGROUPS/ab-cd-efgh-ijklmn-xx-DEV-01/PROVIDERS/postgres-db/FLEXIBLESERVERS/efgh-ijklmn-xx-DEV-01\",\n"
                                + "  \"time\":\"2020-10-01T11:59:26.256Z\",\n" + "  \"ServerType\":\"PostgreSQL\",\n"
                                + "  \"LogicalServerName\":\"efgh-ijklmn-xx-DEV-01\",\n"
                                + "  \"ServerVersion\":\"abcdefghj12_2020-01-01-12-34-56\",\n"
                                + "  \"ServerLocation\":\"prod:countrycentral\",\n" + "  \"ReplicaRole\":\"Primary\",\n"
                                + "  \"OriginalPrimaryServerName\":\"efgh-ijklmn-xx-DEV-01\"\n" + "}",
                        syslogMessage.getMsg()
                );
        Assertions
                .assertEquals("md5-bfd1db26c3c4f8a2936317cf4ec729ea-efgh-ijklmn-xx-DEV-01", syslogMessage.getHostname());
        Assertions.assertEquals("dbase_maintenance", syslogMessage.getAppName());
        Assertions.assertEquals("2020-10-01T11:59:26.256Z", syslogMessage.getTimestamp());

        final Map<String, Map<String, String>> sdElementMap = syslogMessage
                .getSDElements()
                .stream()
                .collect(Collectors.toMap((SDElement::getSdID), (sdElem) -> sdElem.getSdParams().stream().collect(Collectors.toMap(SDParam::getParamName, SDParam::getParamValue))));

        Assertions.assertEquals(1, sdElementMap.get("nlf_01@48577").size());
        Assertions
                .assertEquals(PostgreSQLType.class.getSimpleName(), sdElementMap.get("nlf_01@48577").get("eventType"));

        Assertions.assertTrue(sdElementMap.get("aer_02_event@48577").containsKey("properties"));
    }

    @Test
    void logicAppWorkflowRuntimeTest() {
        final String json = Assertions
                .assertDoesNotThrow(() -> Files.readString(Paths.get("src/test/resources/logicapp_workflow_runtime.json")));
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
                        "{\n" + "  \"ActionName\": \"ActionName-1\",\n"
                                + "  \"ActionTrackingId\": \"bb41a487-309b-4d21-9ab8-2a8b948b2d18\",\n"
                                + "  \"ClientKeywords\": \"{}\",\n"
                                + "  \"ClientTrackingId\": \"bb41a487-309b-4d21-9ab8-2a8b948b2d18\",\n"
                                + "  \"Code\": \"400\",\n" + "  \"EndTime\": \"2025-10-06T00:00:00.0000000Z\",\n"
                                + "  \"Error\": \"Error 2\",\n" + "  \"Location\": \"locationcentral\",\n"
                                + "  \"OperationName\": \"Operation-1\",\n"
                                + "  \"OriginRunId\": \"bb41a487-309b-4d21-9ab8-2a8b948b2d18\",\n"
                                + "  \"RetryHistory\": \"None\",\n"
                                + "  \"RunId\": \"bb41a487-309b-4d21-9ab8-2a8b948b2d18\",\n"
                                + "  \"StartTime\": \"2025-10-06T00:00:00.0000000Z\",\n"
                                + "  \"TrackedProperties\": \"{}\",\n"
                                + "  \"PipelineRunId\": \"bb41a487-309b-4d21-9ab8-2a8b948b2d18\",\n"
                                + "  \"ResourceId\": \"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}\",\n"
                                + "  \"SourceSystem\": \"Azure\",\n" + "  \"Status\": \"Failed\",\n"
                                + "  \"Tags\": \"{}\",\n" + "  \"Type\": \"LogicAppWorkflowRuntime\",\n"
                                + "  \"WorkflowId\": \"bb41a487-309b-4d21-9ab8-2a8b948b2d18\",\n"
                                + "  \"WorkflowName\": \"Workflow-2\",\n" + "  \"TriggerName\": \"Trigger-1\",\n"
                                + "  \"TimeGenerated\": \"2025-10-06T00:00:00.0000000Z\",\n"
                                + "  \"_ItemId\": \"bb41a487-309b-4d21-9ab8-2a8b948b2d18\",\n"
                                + "  \"TenantId\": \"bb41a487-309b-4d21-9ab8-2a8b948b2d18\",\n"
                                + "  \"_ResourceId\": \"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}\",\n"
                                + "  \"_SubscriptionId\": \"bb41a487-309b-4d21-9ab8-2a8b948b2d18\",\n"
                                + "  \"_TimeReceived\": \"2025-10-06T00:00:00.0000000Z\",\n"
                                + "  \"_Internal_WorkspaceResourceId\": \"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}\"\n"
                                + "}",
                        syslogMessage.getMsg()
                );
        Assertions.assertEquals("md5-0ded52ef915af563e25778bf26b0f129-resourceName", syslogMessage.getHostname());
        Assertions.assertEquals("Workflow-2", syslogMessage.getAppName());
        Assertions.assertEquals("2025-10-06T00:00:00Z", syslogMessage.getTimestamp());

        final Map<String, Map<String, String>> sdElementMap = syslogMessage
                .getSDElements()
                .stream()
                .collect(Collectors.toMap((SDElement::getSdID), (sdElem) -> sdElem.getSdParams().stream().collect(Collectors.toMap(SDParam::getParamName, SDParam::getParamValue))));

        Assertions.assertEquals(1, sdElementMap.get("nlf_01@48577").size());
        Assertions
                .assertEquals(LogicAppWorkflowRuntimeType.class.getSimpleName(), sdElementMap.get("nlf_01@48577").get("eventType"));

        Assertions.assertTrue(sdElementMap.get("aer_02_event@48577").containsKey("properties"));
    }

    @Test
    void unexpectedType() {
        final String json = Assertions
                .assertDoesNotThrow(() -> Files.readString(Paths.get("src/test/resources/unexpected.json")));
        final ParsedEvent parsedEvent = new ParsedEventFactory(
                new UnparsedEventImpl(
                        json,
                        new EventPartitionContextStub(),
                        new EventPropertiesStub(),
                        new EventSystemPropertiesStub(),
                        new EnqueuedTimeStub(),
                        new EventOffsetStub()
                )
        ).parsedEvent();

        final NLFPlugin plugin = new NLFPlugin(new FakeSourceable());
        final PluginException pluginException = Assertions
                .assertThrows(PluginException.class, () -> plugin.syslogMessage(parsedEvent));
        Assertions
                .assertEquals(
                        "java.lang.IllegalArgumentException: Event was not of expected log format or type was not found",
                        pluginException.getMessage()
                );
    }

    @Test
    void emptyJsonObjectPayload() {
        final ParsedEvent parsedEvent = new ParsedEventFactory(
                new UnparsedEventImpl(
                        "{}",
                        new EventPartitionContextStub(),
                        new EventPropertiesStub(),
                        new EventSystemPropertiesStub(),
                        new EnqueuedTimeStub(),
                        new EventOffsetStub()
                )
        ).parsedEvent();

        final NLFPlugin plugin = new NLFPlugin(new FakeSourceable());
        final PluginException pluginException = Assertions
                .assertThrows(PluginException.class, () -> plugin.syslogMessage(parsedEvent));
        Assertions
                .assertEquals(
                        "java.lang.IllegalArgumentException: Event was not of expected log format or type was not found",
                        pluginException.getMessage()
                );
    }

    @Test
    void emptyJsonArrayPayload() {
        final ParsedEvent parsedEvent = new ParsedEventFactory(
                new UnparsedEventImpl(
                        "[]",
                        new EventPartitionContextStub(),
                        new EventPropertiesStub(),
                        new EventSystemPropertiesStub(),
                        new EnqueuedTimeStub(),
                        new EventOffsetStub()
                )
        ).parsedEvent();

        final NLFPlugin plugin = new NLFPlugin(new FakeSourceable());
        final PluginException pluginException = Assertions
                .assertThrows(PluginException.class, () -> plugin.syslogMessage(parsedEvent));
        Assertions
                .assertEquals("jakarta.json.JsonException: Event was not a JSON object", pluginException.getMessage());
    }

    @Test
    void nonJsonPayload() {
        final ParsedEvent parsedEvent = new ParsedEventFactory(
                new UnparsedEventImpl(
                        "non-json payload",
                        new EventPartitionContextStub(),
                        new EventPropertiesStub(),
                        new EventSystemPropertiesStub(),
                        new EnqueuedTimeStub(),
                        new EventOffsetStub()
                )
        ).parsedEvent();

        final NLFPlugin plugin = new NLFPlugin(new FakeSourceable());
        final PluginException pluginException = Assertions
                .assertThrows(PluginException.class, () -> plugin.syslogMessage(parsedEvent));
        Assertions
                .assertEquals("jakarta.json.JsonException: Event was not a JSON structure", pluginException.getMessage());
    }
}
