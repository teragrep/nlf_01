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

import com.teragrep.akv_01.event.EventImpl;
import com.teragrep.akv_01.event.ParsedEvent;
import com.teragrep.nlf_01.fakes.FakeSourceable;
import com.teragrep.nlf_01.types.AppInsightType;
import com.teragrep.nlf_01.types.ContainerType;
import com.teragrep.rlo_14.SDElement;
import com.teragrep.rlo_14.SDParam;
import com.teragrep.rlo_14.SyslogMessage;
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
        final ParsedEvent parsedEvent = new EventImpl(
                json,
                new HashMap<>(),
                new HashMap<>(),
                new HashMap<>(),
                "2020-01-01T00:00:00",
                "0"
        ).parsedEvent();

        final NLFPlugin plugin = new NLFPlugin(new FakeSourceable());
        final List<SyslogMessage> syslogMessages = Assertions
                .assertDoesNotThrow(() -> plugin.syslogMessage(parsedEvent));
        Assertions.assertEquals(1, syslogMessages.size());

        final SyslogMessage syslogMessage = syslogMessages.get(0);
        Assertions.assertEquals(json, syslogMessage.getMsg());
        Assertions.assertEquals("HOST-NAME", syslogMessage.getHostname());
        Assertions.assertEquals("APP-NAME:o", syslogMessage.getAppName());
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
    }

    @Test
    void appInsightType() {
        final String json = Assertions
                .assertDoesNotThrow(() -> Files.readString(Paths.get("src/test/resources/appinsight.json")));
        final ParsedEvent parsedEvent = new EventImpl(
                json,
                new HashMap<>(),
                new HashMap<>(),
                new HashMap<>(),
                "2020-01-01T00:00:00",
                "0"
        ).parsedEvent();

        final NLFPlugin plugin = new NLFPlugin();
        final List<SyslogMessage> syslogMessages = Assertions
                .assertDoesNotThrow(() -> plugin.syslogMessage(parsedEvent));
        Assertions.assertEquals(1, syslogMessages.size());

        final SyslogMessage syslogMessage = syslogMessages.get(0);
        Assertions
                .assertEquals(
                        "{\"AppRoleInstance\":\"app-role-instance\",\"AppRoleName\":\"app-role-name\",\"ClientIP\":\"192.168.1.2\",\"ClientType\":\"client-type\",\"IKey\":\"i-key\",\"ItemCount\":1,\"Message\":\"message\",\"OperationId\":\"123\",\"ParentId\":\"456\",\"Properties\":{\"ProcessId\":\"1234\",\"HostInstanceId\":\"123456\",\"prop__{OriginalFormat}\":\"abc\",\"prop__RouteName\":\"xyz\",\"LogLevel\":\"Debug\",\"EventId\":\"1\",\"prop__RouteTemplate\":\"route/template\",\"Category\":\"192.168.3.1\",\"EventName\":\"event-name\"},\"ResourceGUID\":\"123456789\",\"SDKVersion\":\"12: 192.168.x.x\",\"SeverityLevel\":0,\"SourceSystem\":\"Azure\",\"TenantId\":\"12\",\"TimeGenerated\":\"2020-01-01T01:02:34.5678999Z\",\"Type\":\"AppTraces\",\"_BilledSize\":1,\"_ItemId\":\"12-34-56-78\",\"_Internal_WorkspaceResourceId\":\"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}\",\"_ResourceId\":\"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}\"}",
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
    }

    @Test
    void appInsightType_MultipleRecords() {
        final String json = Assertions
                .assertDoesNotThrow(() -> Files.readString(Paths.get("src/test/resources/appinsight_2.json")));
        final ParsedEvent parsedEvent = new EventImpl(
                json,
                new HashMap<>(),
                new HashMap<>(),
                new HashMap<>(),
                "2020-01-01T00:00:00",
                "0"
        ).parsedEvent();

        final NLFPlugin plugin = new NLFPlugin();
        final List<SyslogMessage> syslogMessages = Assertions
                .assertDoesNotThrow(() -> plugin.syslogMessage(parsedEvent));
        Assertions.assertEquals(3, syslogMessages.size());

        final SyslogMessage syslogMessage = syslogMessages.get(0);
        Assertions.assertEquals("md5-0ded52ef915af563e25778bf26b0f129-resourceName", syslogMessage.getHostname());
        Assertions.assertEquals("app-role-name", syslogMessage.getAppName());
        Assertions.assertEquals("2020-01-01T01:02:34.567Z", syslogMessage.getTimestamp());
        Assertions
                .assertEquals(
                        "{\"AppRoleInstance\":\"app-role-instance\",\"AppRoleName\":\"app-role-name\",\"ClientIP\":\"192.168.1.2\",\"ClientType\":\"client-type\",\"IKey\":\"i-key\",\"ItemCount\":1,\"Message\":\"message\",\"OperationId\":\"123\",\"ParentId\":\"456\",\"Properties\":{\"ProcessId\":\"1234\",\"HostInstanceId\":\"123456\",\"prop__{OriginalFormat}\":\"abc\",\"prop__RouteName\":\"xyz\",\"LogLevel\":\"Debug\",\"EventId\":\"1\",\"prop__RouteTemplate\":\"route/template\",\"Category\":\"192.168.3.1\",\"EventName\":\"event-name\"},\"ResourceGUID\":\"123456789\",\"SDKVersion\":\"12: 192.168.x.x\",\"SeverityLevel\":0,\"SourceSystem\":\"Azure\",\"TenantId\":\"12\",\"TimeGenerated\":\"2020-01-01T01:02:34.5678999Z\",\"Type\":\"AppTraces\",\"_BilledSize\":1,\"_ItemId\":\"12-34-56-78\",\"_Internal_WorkspaceResourceId\":\"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}\",\"_ResourceId\":\"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}\"}",
                        syslogMessage.getMsg()
                );

        final Map<String, Map<String, String>> sdElementMap = syslogMessage
                .getSDElements()
                .stream()
                .collect(Collectors.toMap((SDElement::getSdID), (sdElem) -> sdElem.getSdParams().stream().collect(Collectors.toMap(SDParam::getParamName, SDParam::getParamValue))));

        Assertions.assertEquals(1, sdElementMap.get("nlf_01@48577").size());
        Assertions
                .assertEquals(AppInsightType.class.getSimpleName(), sdElementMap.get("nlf_01@48577").get("eventType"));

        final SyslogMessage syslogMessage2 = syslogMessages.get(1);
        Assertions.assertEquals("md5-0ded52ef915af563e25778bf26b0f129-resourceName", syslogMessage2.getHostname());
        Assertions.assertEquals("app-role-name2", syslogMessage2.getAppName());
        Assertions.assertEquals("2020-01-02T01:02:34.567Z", syslogMessage2.getTimestamp());
        Assertions
                .assertEquals(
                        "{\"AppRoleInstance\":\"app-role-instance2\",\"AppRoleName\":\"app-role-name2\",\"ClientIP\":\"192.168.1.2\",\"ClientType\":\"client-type\",\"IKey\":\"i-key\",\"ItemCount\":1,\"Message\":\"message2\",\"OperationId\":\"123\",\"ParentId\":\"456\",\"Properties\":{\"ProcessId\":\"1234\",\"HostInstanceId\":\"123456\",\"prop__{OriginalFormat}\":\"abc\",\"prop__RouteName\":\"xyz\",\"LogLevel\":\"Debug\",\"EventId\":\"1\",\"prop__RouteTemplate\":\"route/template\",\"Category\":\"192.168.3.1\",\"EventName\":\"event-name2\"},\"ResourceGUID\":\"123456789\",\"SDKVersion\":\"12: 192.168.x.x\",\"SeverityLevel\":0,\"SourceSystem\":\"Azure\",\"TenantId\":\"12\",\"TimeGenerated\":\"2020-01-02T01:02:34.5678999Z\",\"Type\":\"AppTraces\",\"_BilledSize\":1,\"_ItemId\":\"12-34-56-78\",\"_Internal_WorkspaceResourceId\":\"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}\",\"_ResourceId\":\"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}\"}",
                        syslogMessage2.getMsg()
                );

        final Map<String, Map<String, String>> sdElementMap2 = syslogMessage2
                .getSDElements()
                .stream()
                .collect(Collectors.toMap((SDElement::getSdID), (sdElem) -> sdElem.getSdParams().stream().collect(Collectors.toMap(SDParam::getParamName, SDParam::getParamValue))));

        Assertions.assertEquals(1, sdElementMap2.get("nlf_01@48577").size());
        Assertions
                .assertEquals(AppInsightType.class.getSimpleName(), sdElementMap2.get("nlf_01@48577").get("eventType"));

        final SyslogMessage syslogMessage3 = syslogMessages.get(2);
        Assertions.assertEquals("md5-0ded52ef915af563e25778bf26b0f129-resourceName", syslogMessage3.getHostname());
        Assertions.assertEquals("app-role-name3", syslogMessage3.getAppName());
        Assertions.assertEquals("2020-01-03T01:02:34.567Z", syslogMessage3.getTimestamp());
        Assertions
                .assertEquals(
                        "{\"AppRoleInstance\":\"app-role-instance3\",\"AppRoleName\":\"app-role-name3\",\"ClientIP\":\"192.168.1.2\",\"ClientType\":\"client-type\",\"IKey\":\"i-key\",\"ItemCount\":1,\"Message\":\"message3\",\"OperationId\":\"123\",\"ParentId\":\"456\",\"Properties\":{\"ProcessId\":\"1234\",\"HostInstanceId\":\"123456\",\"prop__{OriginalFormat}\":\"abc\",\"prop__RouteName\":\"xyz\",\"LogLevel\":\"Debug\",\"EventId\":\"1\",\"prop__RouteTemplate\":\"route/template\",\"Category\":\"192.168.3.1\",\"EventName\":\"event-name3\"},\"ResourceGUID\":\"123456789\",\"SDKVersion\":\"12: 192.168.x.x\",\"SeverityLevel\":0,\"SourceSystem\":\"Azure\",\"TenantId\":\"12\",\"TimeGenerated\":\"2020-01-03T01:02:34.5678999Z\",\"Type\":\"AppTraces\",\"_BilledSize\":1,\"_ItemId\":\"12-34-56-78\",\"_Internal_WorkspaceResourceId\":\"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}\",\"_ResourceId\":\"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}\"}",
                        syslogMessage3.getMsg()
                );

        final Map<String, Map<String, String>> sdElementMap3 = syslogMessage3
                .getSDElements()
                .stream()
                .collect(Collectors.toMap((SDElement::getSdID), (sdElem) -> sdElem.getSdParams().stream().collect(Collectors.toMap(SDParam::getParamName, SDParam::getParamValue))));

        Assertions.assertEquals(1, sdElementMap3.get("nlf_01@48577").size());
        Assertions
                .assertEquals(AppInsightType.class.getSimpleName(), sdElementMap3.get("nlf_01@48577").get("eventType"));
    }

    @Test
    void clType() {
        final String json = Assertions
                .assertDoesNotThrow(() -> Files.readString(Paths.get("src/test/resources/cl.json")));
        final ParsedEvent parsedEvent = new EventImpl(
                json,
                new HashMap<>(),
                new HashMap<>(),
                new HashMap<>(),
                "2020-01-01T00:00:00",
                "0"
        ).parsedEvent();

        final NLFPlugin plugin = new NLFPlugin();
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
    }

    @Test
    void multiRecordWithDifferentTypes() {
        final String json = Assertions
                .assertDoesNotThrow(() -> Files.readString(Paths.get("src/test/resources/multirecord.json")));
        final ParsedEvent parsedEvent = new EventImpl(
                json,
                new HashMap<>(),
                new HashMap<>(),
                new HashMap<>(),
                "2020-01-01T00:00:00",
                "0"
        ).parsedEvent();

        final NLFPlugin plugin = new NLFPlugin(new FakeSourceable());
        final List<SyslogMessage> syslogMessages = Assertions
                .assertDoesNotThrow(() -> plugin.syslogMessage(parsedEvent));
        Assertions.assertEquals(2, syslogMessages.size());

        final SyslogMessage syslogMessage = syslogMessages.get(0);
        Assertions.assertEquals("md5-0ded52ef915af563e25778bf26b0f129-resourceName", syslogMessage.getHostname());
        Assertions.assertEquals("app-role-name", syslogMessage.getAppName());
        Assertions.assertEquals("2020-01-01T01:02:34.567Z", syslogMessage.getTimestamp());
        Assertions
                .assertEquals(
                        "{\"AppRoleInstance\":\"app-role-instance\",\"AppRoleName\":\"app-role-name\",\"ClientIP\":\"192.168.1.2\",\"ClientType\":\"client-type\",\"IKey\":\"i-key\",\"ItemCount\":1,\"Message\":\"message\",\"OperationId\":\"123\",\"ParentId\":\"456\",\"Properties\":{\"ProcessId\":\"1234\",\"HostInstanceId\":\"123456\",\"prop__{OriginalFormat}\":\"abc\",\"prop__RouteName\":\"xyz\",\"LogLevel\":\"Debug\",\"EventId\":\"1\",\"prop__RouteTemplate\":\"route/template\",\"Category\":\"192.168.3.1\",\"EventName\":\"event-name\"},\"ResourceGUID\":\"123456789\",\"SDKVersion\":\"12: 192.168.x.x\",\"SeverityLevel\":0,\"SourceSystem\":\"Azure\",\"TenantId\":\"12\",\"TimeGenerated\":\"2020-01-01T01:02:34.5678999Z\",\"Type\":\"AppTraces\",\"_BilledSize\":1,\"_ItemId\":\"12-34-56-78\",\"_Internal_WorkspaceResourceId\":\"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}\",\"_ResourceId\":\"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}\"}",
                        syslogMessage.getMsg()
                );

        final SyslogMessage syslogMessage2 = syslogMessages.get(1);
        Assertions.assertEquals("HOST-NAME", syslogMessage2.getHostname());
        Assertions.assertEquals("APP-NAME:o", syslogMessage2.getAppName());
        Assertions.assertEquals("2020-01-01T01:23:34.567Z", syslogMessage2.getTimestamp());
        Assertions
                .assertEquals(
                        "{\"TimeGenerated\":\"2020-01-01T01:23:34.5678999Z\",\"Computer\":\"computer\",\"ContainerId\":\"container-id\",\"ContainerName\":\"container-name\",\"PodName\":\"pod-name\",\"PodNamespace\":\"pod-namespace\",\"LogMessage\":{\"level\":\"info\",\"ts\":\"2020-01-01T01:23:45.678Z\",\"logger\":\"logger\",\"msg\":\"message\",\"namespace\":\"namespace\"},\"LogSource\":\"stdout\",\"KubernetesMetadata\":{\"image\":\"image\",\"imageID\":\"123-456-789\",\"imageRepo\":\"imagerepo\",\"imageTag\":\"imagetag\",\"podAnnotations\":{\"appname-annotation\":\"APP-NAME\",\"hostname-annotation\":\"HOST-NAME\"},\"podLabels\":{\"x\":\"y\"},\"podUid\":\"123\"},\"LogLevel\":\"info\",\"_ItemId\":\"123\",\"_Internal_WorkspaceResourceId\":\"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}\",\"Type\":\"ContainerLogV2\",\"TenantId\":\"456\",\"_ResourceId\":\"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}\"}",
                        syslogMessage2.getMsg()
                );

        final Map<String, Map<String, String>> sdElementMap = syslogMessage
                .getSDElements()
                .stream()
                .collect(Collectors.toMap((SDElement::getSdID), (sdElem) -> sdElem.getSdParams().stream().collect(Collectors.toMap(SDParam::getParamName, SDParam::getParamValue))));

        final Map<String, Map<String, String>> sdElementMap2 = syslogMessage2
                .getSDElements()
                .stream()
                .collect(Collectors.toMap((SDElement::getSdID), (sdElem) -> sdElem.getSdParams().stream().collect(Collectors.toMap(SDParam::getParamName, SDParam::getParamValue))));

        Assertions.assertEquals(6, sdElementMap.size());
        Assertions.assertEquals(7, sdElementMap2.size());

        Assertions
                .assertEquals(AppInsightType.class.getSimpleName(), sdElementMap.get("nlf_01@48577").get("eventType"));
        Assertions
                .assertEquals(ContainerType.class.getSimpleName(), sdElementMap2.get("nlf_01@48577").get("eventType"));
    }

}
