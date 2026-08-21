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
import com.teragrep.nlf_01.types.*;
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

public final class NLFPluginAppInsightTest {

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

        Assertions.assertTrue(sdElementMap.get("aer_event@48577").containsKey("properties"));

        Assertions.assertEquals("AppInsightType", sdElementMap.get("nlf_01@48577").get("eventType"));
    }

    @Test
    void appAvailabilityResultsTest() {
        final String json = Assertions
                .assertDoesNotThrow(() -> Files.readString(Paths.get("src/test/resources/appavailabilityresults.json")));
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
                        "{\n" + "  \"AppRoleInstance\": \"app-role-instance\",\n"
                                + "  \"AppRoleName\": \"app-role-name\",\n" + "  \"AppVersion\": \"1.0.0\",\n"
                                + "  \"ClientBrowser\": \"Browser-1\",\n" + "  \"ClientIP\": \"192.168.1.2\",\n"
                                + "  \"ClientModel\": \"Model-1\",\n" + "  \"ClientOS\": \"OS-1\",\n"
                                + "  \"ClientStateOrProvince\": \"State-1\",\n" + "  \"ClientType\": \"client-type\",\n"
                                + "  \"Id\": \"id-123456\",\n" + "  \"IKey\": \"i-key\",\n" + "  \"ItemCount\": 1,\n"
                                + "  \"Measurements\": {},\n" + "  \"Message\": \"message\",\n"
                                + "  \"Name\": \"name1\",\n" + "  \"OperationId\": \"123\",\n"
                                + "  \"OperationName\": \"Operation-1\",\n" + "  \"ParentId\": \"456\",\n"
                                + "  \"Properties\": {\n" + "    \"ProcessId\": \"1234\",\n"
                                + "    \"HostInstanceId\": \"123456\",\n" + "    \"prop__{OriginalFormat}\": \"abc\",\n"
                                + "    \"prop__RouteName\": \"xyz\",\n" + "    \"LogLevel\": \"Debug\",\n"
                                + "    \"EventId\": \"1\",\n" + "    \"prop__RouteTemplate\": \"route/template\",\n"
                                + "    \"Category\": \"192.168.3.1\",\n" + "    \"EventName\": \"event-name\"\n"
                                + "  },\n" + "  \"ResourceGUID\": \"123456789\",\n"
                                + "  \"SDKVersion\": \"12: 192.168.x.x\",\n" + "  \"SessionId\": \"12345567890\",\n"
                                + "  \"SourceSystem\": \"Azure\",\n" + "  \"Success\": true,\n"
                                + "  \"SyntheticSource\": \"AzureAgain\",\n" + "  \"TenantId\": \"12\",\n"
                                + "  \"TimeGenerated\": \"2020-01-01T01:02:34.5678999Z\",\n"
                                + "  \"Type\": \"AppAvailabilityResults\",\n" + "  \"UserAccountId\": \"123456\",\n"
                                + "  \"UserAuthenticatedId\": \"234567\",\n" + "  \"UserId\": \"345678\",\n"
                                + "  \"_BilledSize\": 1,\n" + "  \"_ItemId\": \"12-34-56-78\",\n"
                                + "  \"_Internal_WorkspaceResourceId\": \"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}\",\n"
                                + "  \"_ResourceId\": \"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}\",\n"
                                + "  \"_SubscriptionId\": \"{subscriptionId}\"\n" + "}",
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

        Assertions.assertTrue(sdElementMap.get("aer_event@48577").containsKey("properties"));
        Assertions.assertEquals("AppInsightType", sdElementMap.get("nlf_01@48577").get("eventType"));
    }

    @Test
    void appBrowserTimingsTest() {
        final String json = Assertions
                .assertDoesNotThrow(() -> Files.readString(Paths.get("src/test/resources/appbrowsertimings.json")));
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
                        "{\n" + "  \"AppRoleInstance\": \"app-role-instance\",\n"
                                + "  \"AppRoleName\": \"app-role-name\",\n" + "  \"AppVersion\": \"1.0.0\",\n"
                                + "  \"ClientBrowser\": \"Browser-1\",\n" + "  \"ClientIP\": \"192.168.1.2\",\n"
                                + "  \"ClientModel\": \"Model-1\",\n" + "  \"ClientOS\": \"OS-1\",\n"
                                + "  \"ClientStateOrProvince\": \"State-1\",\n" + "  \"ClientType\": \"client-type\",\n"
                                + "  \"Id\": \"id-123456\",\n" + "  \"IKey\": \"i-key\",\n" + "  \"ItemCount\": 1,\n"
                                + "  \"Measurements\": {},\n" + "  \"Message\": \"message\",\n"
                                + "  \"Name\": \"name1\",\n" + "  \"NetworkDurationMs\": 1.1,\n"
                                + "  \"OperationId\": \"123\",\n" + "  \"OperationName\": \"Operation-1\",\n"
                                + "  \"ParentId\": \"456\",\n" + "  \"ProcessingDurationMs\": 1.2,\n"
                                + "  \"Properties\": {\n" + "    \"ProcessId\": \"1234\",\n"
                                + "    \"HostInstanceId\": \"123456\",\n" + "    \"prop__{OriginalFormat}\": \"abc\",\n"
                                + "    \"prop__RouteName\": \"xyz\",\n" + "    \"LogLevel\": \"Debug\",\n"
                                + "    \"EventId\": \"1\",\n" + "    \"prop__RouteTemplate\": \"route/template\",\n"
                                + "    \"Category\": \"192.168.3.1\",\n" + "    \"EventName\": \"event-name\"\n"
                                + "  },\n" + "  \"ReceiveDurationMs\": 1.3,\n" + "  \"ResourceGUID\": \"123456789\",\n"
                                + "  \"SDKVersion\": \"12: 192.168.x.x\",\n" + "  \"SendDurationMs\": 1.4,\n"
                                + "  \"SessionId\": \"12345567890\",\n" + "  \"SourceSystem\": \"Azure\",\n"
                                + "  \"SyntheticSource\": \"AzureAgain\",\n" + "  \"TenantId\": \"12\",\n"
                                + "  \"TimeGenerated\": \"2020-01-01T01:02:34.5678999Z\",\n"
                                + "  \"TotalDurationMs\": 1.5,\n" + "  \"Type\": \"AppBrowserTimings\",\n"
                                + "  \"UserAccountId\": \"123456\",\n" + "  \"UserAuthenticatedId\": \"234567\",\n"
                                + "  \"UserId\": \"345678\",\n" + "  \"_BilledSize\": 1,\n"
                                + "  \"_ItemId\": \"12-34-56-78\",\n"
                                + "  \"_Internal_WorkspaceResourceId\": \"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}\",\n"
                                + "  \"_ResourceId\": \"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}\",\n"
                                + "  \"_SubscriptionId\": \"{subscriptionId}\"\n" + "}",
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

        Assertions.assertTrue(sdElementMap.get("aer_event@48577").containsKey("properties"));
        Assertions.assertEquals("AppInsightType", sdElementMap.get("nlf_01@48577").get("eventType"));
    }

    @Test
    void appDependenciesType() {
        final String json = Assertions
                .assertDoesNotThrow(() -> Files.readString(Paths.get("src/test/resources/appdependencies.json")));
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
                        "{\n" + "  \"AppRoleInstance\": \"app-role-instance\",\n"
                                + "  \"AppRoleName\": \"app-role-name\",\n" + "  \"AppVersion\": \"1.0.0\",\n"
                                + "  \"ClientBrowser\": \"Browser-1\",\n" + "  \"ClientIP\": \"192.168.1.2\",\n"
                                + "  \"ClientModel\": \"Model-1\",\n" + "  \"ClientOS\": \"OS-1\",\n"
                                + "  \"ClientStateOrProvince\": \"State-1\",\n" + "  \"ClientType\": \"client-type\",\n"
                                + "  \"Data\": \"url://localhost.example.test\",\n"
                                + "  \"DependencyType\": \"http\",\n" + "  \"DurationMs\": 1234,\n"
                                + "  \"Id\": \"{id}\",\n" + "  \"IKey\": \"i-key\",\n" + "  \"ItemCount\": 1,\n"
                                + "  \"Measurements\": {},\n" + "  \"Name\": \"Dependency-1\",\n"
                                + "  \"OperationId\": \"123\",\n" + "  \"OperationName\": \"Operation-1\",\n"
                                + "  \"ParentId\": \"456\",\n" + "  \"Properties\": {\n"
                                + "    \"ProcessId\": \"1234\",\n" + "    \"HostInstanceId\": \"123456\",\n"
                                + "    \"prop__{OriginalFormat}\": \"abc\",\n" + "    \"prop__RouteName\": \"xyz\",\n"
                                + "    \"LogLevel\": \"Debug\",\n" + "    \"EventId\": \"1\",\n"
                                + "    \"prop__RouteTemplate\": \"route/template\",\n"
                                + "    \"Category\": \"192.168.3.1\",\n" + "    \"EventName\": \"event-name\"\n"
                                + "  },\n" + "  \"ReferencedItemId\": \"123456789\",\n"
                                + "  \"ReferencedType\": \"Table-1\",\n" + "  \"ResourceGUID\": \"123456789\",\n"
                                + "  \"ResultCode\": \"1\",\n" + "  \"SDKVersion\": \"12: 192.168.x.x\",\n"
                                + "  \"SessionId\": \"12345567890\",\n" + "  \"SourceSystem\": \"Azure\",\n"
                                + "  \"Success\": true,\n" + "  \"SyntheticSource\": \"AzureAgain\",\n"
                                + "  \"Target\": \"WebServer1\",\n" + "  \"TenantId\": \"12\",\n"
                                + "  \"TimeGenerated\": \"2020-01-01T01:02:34.5678999Z\",\n"
                                + "  \"Type\": \"AppDependencies\",\n" + "  \"_BilledSize\": 1,\n"
                                + "  \"_ItemId\": \"12-34-56-78\",\n"
                                + "  \"_Internal_WorkspaceResourceId\": \"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}\",\n"
                                + "  \"_ResourceId\": \"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}\",\n"
                                + "  \"_SubscriptionId\": \"{subscriptionId}\"\n" + "}",
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

        Assertions.assertTrue(sdElementMap.get("aer_event@48577").containsKey("properties"));
        Assertions.assertEquals("AppInsightType", sdElementMap.get("nlf_01@48577").get("eventType"));
    }

    @Test
    void appExceptionsType() {
        final String json = Assertions
                .assertDoesNotThrow(() -> Files.readString(Paths.get("src/test/resources/appexceptions.json")));
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
                        "{\n" + "  \"AppRoleInstance\": \"app-role-instance\",\n"
                                + "  \"AppRoleName\": \"app-role-name\",\n" + "  \"AppVersion\": \"1.0.0\",\n"
                                + "  \"ClientBrowser\": \"Browser-1\",\n" + "  \"ClientIP\": \"192.168.1.2\",\n"
                                + "  \"ClientModel\": \"Model-1\",\n" + "  \"ClientOS\": \"OS-1\",\n"
                                + "  \"ClientStateOrProvince\": \"State-1\",\n" + "  \"ClientType\": \"client-type\",\n"
                                + "  \"Details\": {},\n" + "  \"ExceptionType\": \"NullPointerException\",\n"
                                + "  \"HandledAt\": \"Location-1\",\n" + "  \"IKey\": \"i-key\",\n"
                                + "  \"InnermostAssembly\": \"InnermostAssembly\",\n"
                                + "  \"InnermostMessage\": \"InnermostMessage\",\n"
                                + "  \"InnermostMethod\": \"InnermostMethod\",\n"
                                + "  \"InnermostType\": \"InnermostType\",\n" + "  \"ItemCount\": 1,\n"
                                + "  \"Measurements\": {},\n" + "  \"Message\": \"message\",\n"
                                + "  \"Method\": \"app.Main\",\n" + "  \"OperationId\": \"123\",\n"
                                + "  \"OperationName\": \"Operation-1\",\n"
                                + "  \"OuterAssembly\": \"OuterAssembly\",\n"
                                + "  \"OuterMessage\": \"OuterMessage\",\n" + "  \"OuterMethod\": \"OuterMethod\",\n"
                                + "  \"OuterType\": \"OuterType\",\n" + "  \"ParentId\": \"456\",\n"
                                + "  \"ProblemId\": \"789\",\n" + "  \"Properties\": {\n"
                                + "    \"ProcessId\": \"1234\",\n" + "    \"HostInstanceId\": \"123456\",\n"
                                + "    \"prop__{OriginalFormat}\": \"abc\",\n" + "    \"prop__RouteName\": \"xyz\",\n"
                                + "    \"LogLevel\": \"Debug\",\n" + "    \"EventId\": \"1\",\n"
                                + "    \"prop__RouteTemplate\": \"route/template\",\n"
                                + "    \"Category\": \"192.168.3.1\",\n" + "    \"EventName\": \"event-name\"\n"
                                + "  },\n" + "  \"ResourceGUID\": \"123456789\",\n"
                                + "  \"SDKVersion\": \"12: 192.168.x.x\",\n" + "  \"SessionId\": \"12345567890\",\n"
                                + "  \"SeverityLevel\": 1,\n" + "  \"SourceSystem\": \"Azure\",\n"
                                + "  \"SyntheticSource\": \"AzureAgain\",\n" + "  \"Target\": \"WebServer1\",\n"
                                + "  \"TenantId\": \"12\",\n"
                                + "  \"TimeGenerated\": \"2020-01-01T01:02:34.5678999Z\",\n"
                                + "  \"Type\": \"AppExceptions\",\n" + "  \"_BilledSize\": 1,\n"
                                + "  \"_ItemId\": \"12-34-56-78\",\n"
                                + "  \"_Internal_WorkspaceResourceId\": \"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}\",\n"
                                + "  \"_ResourceId\": \"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}\",\n"
                                + "  \"_SubscriptionId\": \"{subscriptionId}\"\n" + "}",
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

        Assertions.assertTrue(sdElementMap.get("aer_event@48577").containsKey("properties"));
        Assertions.assertEquals("AppInsightType", sdElementMap.get("nlf_01@48577").get("eventType"));
    }

    @Test
    void appMetricsTest() {
        final String json = Assertions
                .assertDoesNotThrow(() -> Files.readString(Paths.get("src/test/resources/appmetrics.json")));
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
                        "{\n" + "  \"AppRoleInstance\": \"app-role-instance\",\n"
                                + "  \"AppRoleName\": \"app-role-name\",\n" + "  \"AppVersion\": \"1.0.0\",\n"
                                + "  \"ClientBrowser\": \"Browser-1\",\n" + "  \"ClientIP\": \"192.168.1.2\",\n"
                                + "  \"ClientModel\": \"Model-1\",\n" + "  \"ClientOS\": \"OS-1\",\n"
                                + "  \"ClientStateOrProvince\": \"State-1\",\n" + "  \"ClientType\": \"client-type\",\n"
                                + "  \"IKey\": \"i-key\",\n" + "  \"ItemCount\": 1,\n" + "  \"Max\": 1.3,\n"
                                + "  \"Min\": 1.2,\n" + "  \"Name\": \"name1\",\n" + "  \"OperationId\": \"123\",\n"
                                + "  \"OperationName\": \"Operation-1\",\n" + "  \"ParentId\": \"456\",\n"
                                + "  \"Properties\": {\n" + "    \"ProcessId\": \"1234\",\n"
                                + "    \"HostInstanceId\": \"123456\",\n" + "    \"prop__{OriginalFormat}\": \"abc\",\n"
                                + "    \"prop__RouteName\": \"xyz\",\n" + "    \"LogLevel\": \"Debug\",\n"
                                + "    \"EventId\": \"1\",\n" + "    \"prop__RouteTemplate\": \"route/template\",\n"
                                + "    \"Category\": \"192.168.3.1\",\n" + "    \"EventName\": \"event-name\"\n"
                                + "  },\n" + "  \"ResourceGUID\": \"123456789\",\n"
                                + "  \"SDKVersion\": \"12: 192.168.x.x\",\n" + "  \"SessionId\": \"12345567890\",\n"
                                + "  \"SourceSystem\": \"Azure\",\n" + "  \"Sum\": 2.5,\n"
                                + "  \"SyntheticSource\": \"AzureAgain\",\n" + "  \"TenantId\": \"12\",\n"
                                + "  \"TimeGenerated\": \"2020-01-01T01:02:34.5678999Z\",\n"
                                + "  \"Type\": \"AppMetrics\",\n" + "  \"UserAccountId\": \"123456\",\n"
                                + "  \"UserAuthenticatedId\": \"234567\",\n" + "  \"UserId\": \"345678\",\n"
                                + "  \"_BilledSize\": 1,\n" + "  \"_ItemId\": \"12-34-56-78\",\n"
                                + "  \"_Internal_WorkspaceResourceId\": \"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}\",\n"
                                + "  \"_ResourceId\": \"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}\",\n"
                                + "  \"_SubscriptionId\": \"{subscriptionId}\"\n" + "}",
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

        Assertions.assertTrue(sdElementMap.get("aer_event@48577").containsKey("properties"));
        Assertions.assertEquals("AppInsightType", sdElementMap.get("nlf_01@48577").get("eventType"));
    }

    @Test
    void appPageViewsTest() {
        final String json = Assertions
                .assertDoesNotThrow(() -> Files.readString(Paths.get("src/test/resources/apppageviews.json")));
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
                        "{\n" + "  \"AppRoleInstance\": \"app-role-instance\",\n"
                                + "  \"AppRoleName\": \"app-role-name\",\n" + "  \"AppVersion\": \"1.0.0\",\n"
                                + "  \"ClientBrowser\": \"Browser-1\",\n" + "  \"ClientIP\": \"192.168.1.2\",\n"
                                + "  \"ClientModel\": \"Model-1\",\n" + "  \"ClientOS\": \"OS-1\",\n"
                                + "  \"ClientStateOrProvince\": \"State-1\",\n" + "  \"ClientType\": \"client-type\",\n"
                                + "  \"DurationMs\": 1.1,\n" + "  \"Id\": \"id-123456\",\n" + "  \"IKey\": \"i-key\",\n"
                                + "  \"ItemCount\": 1,\n" + "  \"Measurements\": {},\n"
                                + "  \"Message\": \"message\",\n" + "  \"Name\": \"name1\",\n"
                                + "  \"OperationId\": \"123\",\n" + "  \"OperationName\": \"Operation-1\",\n"
                                + "  \"ParentId\": \"456\",\n" + "  \"Properties\": {\n"
                                + "    \"ProcessId\": \"1234\",\n" + "    \"HostInstanceId\": \"123456\",\n"
                                + "    \"prop__{OriginalFormat}\": \"abc\",\n" + "    \"prop__RouteName\": \"xyz\",\n"
                                + "    \"LogLevel\": \"Debug\",\n" + "    \"EventId\": \"1\",\n"
                                + "    \"prop__RouteTemplate\": \"route/template\",\n"
                                + "    \"Category\": \"192.168.3.1\",\n" + "    \"EventName\": \"event-name\"\n"
                                + "  },\n" + "  \"ResourceGUID\": \"123456789\",\n"
                                + "  \"SDKVersion\": \"12: 192.168.x.x\",\n" + "  \"SessionId\": \"12345567890\",\n"
                                + "  \"SourceSystem\": \"Azure\",\n" + "  \"SyntheticSource\": \"AzureAgain\",\n"
                                + "  \"TenantId\": \"12\",\n"
                                + "  \"TimeGenerated\": \"2020-01-01T01:02:34.5678999Z\",\n"
                                + "  \"Type\": \"AppPageViews\",\n" + "  \"Url\": \"https://example.localhost\",\n"
                                + "  \"UserAccountId\": \"123456\",\n" + "  \"UserAuthenticatedId\": \"234567\",\n"
                                + "  \"UserId\": \"345678\",\n" + "  \"_BilledSize\": 1,\n"
                                + "  \"_ItemId\": \"12-34-56-78\",\n"
                                + "  \"_Internal_WorkspaceResourceId\": \"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}\",\n"
                                + "  \"_ResourceId\": \"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}\",\n"
                                + "  \"_SubscriptionId\": \"{subscriptionId}\"\n" + "}",
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

        Assertions.assertTrue(sdElementMap.get("aer_event@48577").containsKey("properties"));
        Assertions.assertEquals("AppInsightType", sdElementMap.get("nlf_01@48577").get("eventType"));
    }

    @Test
    void appPerformanceCountersTest() {
        final String json = Assertions
                .assertDoesNotThrow(() -> Files.readString(Paths.get("src/test/resources/appperformancecounters.json")));
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
                        "{\n" + "  \"AppRoleInstance\": \"app-role-instance\",\n"
                                + "  \"AppRoleName\": \"app-role-name\",\n" + "  \"AppVersion\": \"1.0.0\",\n"
                                + "  \"ClientBrowser\": \"Browser-1\",\n" + "  \"ClientIP\": \"192.168.1.2\",\n"
                                + "  \"ClientModel\": \"Model-1\",\n" + "  \"ClientOS\": \"OS-1\",\n"
                                + "  \"ClientStateOrProvince\": \"State-1\",\n" + "  \"ClientType\": \"client-type\",\n"
                                + "  \"IKey\": \"i-key\",\n" + "  \"Instance\": \"instance-1\",\n"
                                + "  \"Name\": \"name1\",\n" + "  \"OperationId\": \"123\",\n"
                                + "  \"OperationName\": \"Operation-1\",\n" + "  \"ParentId\": \"456\",\n"
                                + "  \"Properties\": {\n" + "    \"ProcessId\": \"1234\",\n"
                                + "    \"HostInstanceId\": \"123456\",\n" + "    \"prop__{OriginalFormat}\": \"abc\",\n"
                                + "    \"prop__RouteName\": \"xyz\",\n" + "    \"LogLevel\": \"Debug\",\n"
                                + "    \"EventId\": \"1\",\n" + "    \"prop__RouteTemplate\": \"route/template\",\n"
                                + "    \"Category\": \"192.168.3.1\",\n" + "    \"EventName\": \"event-name\"\n"
                                + "  },\n" + "  \"ResourceGUID\": \"123456789\",\n"
                                + "  \"SDKVersion\": \"12: 192.168.x.x\",\n" + "  \"SessionId\": \"12345567890\",\n"
                                + "  \"SourceSystem\": \"Azure\",\n" + "  \"SyntheticSource\": \"AzureAgain\",\n"
                                + "  \"TenantId\": \"12\",\n"
                                + "  \"TimeGenerated\": \"2020-01-01T01:02:34.5678999Z\",\n"
                                + "  \"Type\": \"AppPerformanceCounters\",\n" + "  \"UserAccountId\": \"123456\",\n"
                                + "  \"UserAuthenticatedId\": \"234567\",\n" + "  \"UserId\": \"345678\",\n"
                                + "  \"Value\": 1.1,\n" + "  \"_BilledSize\": 1,\n"
                                + "  \"_ItemId\": \"12-34-56-78\",\n"
                                + "  \"_Internal_WorkspaceResourceId\": \"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}\",\n"
                                + "  \"_ResourceId\": \"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}\",\n"
                                + "  \"_SubscriptionId\": \"{subscriptionId}\"\n" + "}",
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

        Assertions.assertTrue(sdElementMap.get("aer_event@48577").containsKey("properties"));
        Assertions.assertEquals("AppInsightType", sdElementMap.get("nlf_01@48577").get("eventType"));
    }

    @Test
    void appRequestsType() {
        final String json = Assertions
                .assertDoesNotThrow(() -> Files.readString(Paths.get("src/test/resources/apprequests.json")));
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
                        "{\n" + "  \"AppRoleInstance\": \"app-role-instance\",\n"
                                + "  \"AppRoleName\": \"app-role-name\",\n" + "  \"AppVersion\": \"1.0.0\",\n"
                                + "  \"ClientBrowser\": \"Browser-1\",\n" + "  \"ClientIP\": \"192.168.1.2\",\n"
                                + "  \"ClientModel\": \"Model-1\",\n" + "  \"ClientOS\": \"OS-1\",\n"
                                + "  \"ClientStateOrProvince\": \"State-1\",\n" + "  \"ClientType\": \"client-type\",\n"
                                + "  \"Details\": {},\n" + "  \"DurationMs\": 1234,\n" + "  \"Id\": \"1234567\",\n"
                                + "  \"IKey\": \"i-key\",\n" + "  \"ItemCount\": 1,\n" + "  \"Measurements\": {},\n"
                                + "  \"Name\": \"Request-1\",\n" + "  \"OperationId\": \"123\",\n"
                                + "  \"OperationName\": \"Operation-1\",\n" + "  \"ParentId\": \"456\",\n"
                                + "  \"Properties\": {\n" + "    \"ProcessId\": \"1234\",\n"
                                + "    \"HostInstanceId\": \"123456\",\n" + "    \"prop__{OriginalFormat}\": \"abc\",\n"
                                + "    \"prop__RouteName\": \"xyz\",\n" + "    \"LogLevel\": \"Debug\",\n"
                                + "    \"EventId\": \"1\",\n" + "    \"prop__RouteTemplate\": \"route/template\",\n"
                                + "    \"Category\": \"192.168.3.1\",\n" + "    \"EventName\": \"event-name\"\n"
                                + "  },\n" + "  \"ReferencedItemId\": \"12345678\",\n"
                                + "  \"ReferencedType\": \"Table-1\",\n" + "  \"ResourceGUID\": \"123456789\",\n"
                                + "  \"ResultCode\": \"400\",\n" + "  \"SDKVersion\": \"12: 192.168.x.x\",\n"
                                + "  \"SessionId\": \"12345567890\",\n" + "  \"Source\": \"Source-1\",\n"
                                + "  \"SourceSystem\": \"Azure\",\n" + "  \"Success\": true,\n"
                                + "  \"SyntheticSource\": \"AzureAgain\",\n" + "  \"TenantId\": \"12\",\n"
                                + "  \"TimeGenerated\": \"2020-01-01T01:02:34.5678999Z\",\n"
                                + "  \"Type\": \"AppRequests\",\n" + "  \"Url\": \"url://localhost.example.test\",\n"
                                + "  \"UserAccountId\": \"1234567\",\n" + "  \"UserAuthenticatedId\": \"12345678\",\n"
                                + "  \"UserId\": \"1234\",\n" + "  \"_BilledSize\": 1,\n"
                                + "  \"_ItemId\": \"12-34-56-78\",\n"
                                + "  \"_Internal_WorkspaceResourceId\": \"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}\",\n"
                                + "  \"_ResourceId\": \"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}\",\n"
                                + "  \"_SubscriptionId\": \"{subscriptionId}\"\n" + "}",
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

        Assertions.assertTrue(sdElementMap.get("aer_event@48577").containsKey("properties"));
        Assertions.assertEquals("AppInsightType", sdElementMap.get("nlf_01@48577").get("eventType"));
    }

}
