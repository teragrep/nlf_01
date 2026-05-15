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
import com.teragrep.nlf_01.fakes.ConfigurableSourceable;
import com.teragrep.nlf_01.fakes.EmptySourceable;
import com.teragrep.nlf_01.fakes.FakeSourceable;
import com.teragrep.nlf_01.types.*;
import com.teragrep.nlf_01.util.Sourceable;
import com.teragrep.rlo_14.SDElement;
import com.teragrep.rlo_14.SDParam;
import com.teragrep.rlo_14.SyslogMessage;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class NLFPluginTest {

    @Test
    void azureDiagnosticsType() {
        final String json = Assertions
                .assertDoesNotThrow(() -> Files.readString(Paths.get("src/test/resources/azurediagnostics.json")));
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
        Assertions.assertEquals("AzureDiagnostics", syslogMessage.getAppName());
        Assertions.assertEquals("2020-01-01T01:02:34.567Z", syslogMessage.getTimestamp());

        final Map<String, Map<String, String>> sdElementMap = syslogMessage
                .getSDElements()
                .stream()
                .collect(Collectors.toMap((SDElement::getSdID), (sdElem) -> sdElem.getSdParams().stream().collect(Collectors.toMap(SDParam::getParamName, SDParam::getParamValue))));

        Assertions.assertEquals(1, sdElementMap.get("nlf_01@48577").size());
        Assertions
                .assertEquals(AzureDiagnosticsType.class.getSimpleName(), sdElementMap.get("nlf_01@48577").get("eventType"));

        Assertions.assertTrue(sdElementMap.get("aer_event@48577").containsKey("properties"));

        Assertions.assertEquals("timeEnqueued", sdElementMap.get("aer@48577").get("timestamp_source"));
        Assertions.assertEquals("2020-01-01T00:00Z", sdElementMap.get("aer_event@48577").get("enqueued_time"));
    }

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

        Assertions.assertTrue(sdElementMap.get("aer_event@48577").containsKey("properties"));

        Assertions.assertEquals("timeEnqueued", sdElementMap.get("aer@48577").get("timestamp_source"));
        Assertions.assertEquals("2020-01-01T00:00Z", sdElementMap.get("aer_event@48577").get("enqueued_time"));
    }

    @Test
    void istioContainerType() {
        final String json = Assertions
                .assertDoesNotThrow(() -> Files.readString(Paths.get("src/test/resources/istiocontainer.json")));
        final ParsedEvent parsedEvent = new ParsedEventFactory(
                new UnparsedEventImpl(json, new EventPartitionContextImpl(new HashMap<>()), new EventPropertiesImpl(new HashMap<>()), new EventSystemPropertiesImpl(new HashMap<>()), new EnqueuedTimeImpl("2020-01-01T00:00:00"), new EventOffsetImpl("0"))
        ).parsedEvent();

        final NLFPlugin plugin = new NLFPlugin(new FakeSourceable());
        final List<SyslogMessage> syslogMessages = Assertions
                .assertDoesNotThrow(() -> plugin.syslogMessage(parsedEvent));
        Assertions.assertEquals(1, syslogMessages.size());

        final SyslogMessage syslogMessage = syslogMessages.get(0);
        Assertions.assertEquals(json, syslogMessage.getMsg());
        Assertions.assertEquals("aks-istio-ingress", syslogMessage.getHostname());
        Assertions.assertEquals("istio-ingress", syslogMessage.getAppName());
        Assertions.assertEquals("2020-01-01T01:23:34.567Z", syslogMessage.getTimestamp());

        final Map<String, Map<String, String>> sdElementMap = syslogMessage
                .getSDElements()
                .stream()
                .collect(Collectors.toMap((SDElement::getSdID), (sdElem) -> sdElem.getSdParams().stream().collect(Collectors.toMap(SDParam::getParamName, SDParam::getParamValue))));

        Assertions.assertEquals(5, sdElementMap.get("origin@48577").size());
        Assertions.assertEquals("{subscriptionId}", sdElementMap.get("origin@48577").get("subscription"));
        Assertions.assertEquals("{resourceName}", sdElementMap.get("origin@48577").get("clusterName"));
        Assertions.assertEquals("aks-istio-ingress", sdElementMap.get("origin@48577").get("namespace"));
        Assertions.assertEquals("pod-name", sdElementMap.get("origin@48577").get("pod"));
        Assertions.assertEquals("container-id", sdElementMap.get("origin@48577").get("containerId"));

        Assertions.assertEquals(1, sdElementMap.get("nlf_01@48577").size());
        Assertions
                .assertEquals(IstioIngressContainerType.class.getSimpleName(), sdElementMap.get("nlf_01@48577").get("eventType"));

        Assertions.assertTrue(sdElementMap.get("aer_event@48577").containsKey("properties"));

        Assertions.assertEquals("timeEnqueued", sdElementMap.get("aer@48577").get("timestamp_source"));
        Assertions.assertEquals("2020-01-01T00:00Z", sdElementMap.get("aer_event@48577").get("enqueued_time"));
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

        Assertions.assertTrue(sdElementMap.get("aer_event@48577").containsKey("properties"));

        Assertions.assertEquals("generated", sdElementMap.get("aer@48577").get("timestamp_source"));
        Assertions.assertEquals("", sdElementMap.get("aer_event@48577").get("enqueued_time"));
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

        Assertions.assertTrue(sdElementMap.get("aer_event@48577").containsKey("properties"));
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
        Assertions.assertEquals("abc-a1b234", syslogMessage.getAppName());
        Assertions.assertEquals("2025-10-06T00:00:00Z", syslogMessage.getTimestamp());

        final Map<String, Map<String, String>> sdElementMap = syslogMessage
                .getSDElements()
                .stream()
                .collect(Collectors.toMap((SDElement::getSdID), (sdElem) -> sdElem.getSdParams().stream().collect(Collectors.toMap(SDParam::getParamName, SDParam::getParamValue))));

        Assertions.assertNotNull(sdElementMap);
        Assertions.assertEquals(5, sdElementMap.size());
        Assertions.assertEquals(1, sdElementMap.get("nlf_01@48577").size());
        Assertions.assertEquals(CCType.class.getSimpleName(), sdElementMap.get("nlf_01@48577").get("eventType"));

        Assertions.assertTrue(sdElementMap.get("aer_event@48577").containsKey("properties"));

        Assertions.assertEquals("timeEnqueued", sdElementMap.get("aer@48577").get("timestamp_source"));
        Assertions.assertEquals("2020-01-01T00:00Z", sdElementMap.get("aer_event@48577").get("enqueued_time"));
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

        Assertions.assertTrue(sdElementMap.get("aer_event@48577").containsKey("properties"));
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

        Assertions.assertTrue(sdElementMap.get("aer_event@48577").containsKey("properties"));

        Assertions.assertEquals("timeEnqueued", sdElementMap.get("aer@48577").get("timestamp_source"));
        Assertions.assertEquals("2020-01-01T00:00Z", sdElementMap.get("aer_event@48577").get("enqueued_time"));
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

        Assertions.assertTrue(sdElementMap.get("aer_event@48577").containsKey("properties"));
    }

    @Test
    void dataverseActivityType() {
        final String json = Assertions
                .assertDoesNotThrow(() -> Files.readString(Paths.get("src/test/resources/dataverseactivity.json")));
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
                        "{\n" + "  \"ClientIp\": \"127.0.0.1\",\n"
                                + "  \"CorrelationId\": \"bb41a487-309b-4d21-9ab8-2a8b948b2d18\",\n"
                                + "  \"CrmOrganizationUniqueName\": \"Organization-1\",\n"
                                + "  \"EntityId\": \"bb41a487-309b-4d21-9ab8-2a8b948b2d18\",\n"
                                + "  \"EntityName\": \"Entity-1\",\n" + "  \"Fields\": \"{}\",\n"
                                + "  \"InstanceUrl\": \"https://{uri1}\",\n" + "  \"ItemType\": \"Message\",\n"
                                + "  \"ItemUrl\": \"https://{uri1}.crm.{uri2}\",\n" + "  \"Message\": \"Message 1\",\n"
                                + "  \"Operation\": \"Operation 1\",\n"
                                + "  \"OrganizationId\": \"bb41a487-309b-4d21-9ab8-2a8b948b2d18\",\n"
                                + "  \"OriginalObjectId\": \"bb41a487-309b-4d21-9ab8-2a8b948b2d18\",\n"
                                + "  \"Query\": \"Query\",\n" + "  \"QueryResults\": \"2\",\n"
                                + "  \"ResultStatus\": \"Success\",\n"
                                + "  \"ServiceContextId\": \"bb41a487-309b-4d21-9ab8-2a8b948b2d18\",\n"
                                + "  \"ServiceContextIdType\": \"Token 1\",\n" + "  \"ServiceName\": \"Service 1\",\n"
                                + "  \"SourceRecordId\": \"bb41a487-309b-4d21-9ab8-2a8b948b2d18\",\n"
                                + "  \"SourceSystem\": \"Azure\",\n"
                                + "  \"SystemUserId\": \"bb41a487-309b-4d21-9ab8-2a8b948b2d18\",\n"
                                + "  \"TenantId\": \"bb41a487-309b-4d21-9ab8-2a8b948b2d18\",\n"
                                + "  \"TimeGenerated\": \"2025-10-06T00:00:00.0000000Z\",\n"
                                + "  \"Type\": \"DataverseActivity\",\n"
                                + "  \"UserAgent\": \"Mozilla/5.0 (<system-information>) <platform> (<platform-details>) <extensions>\",\n"
                                + "  \"UserId\": \"user@localhost.example.test\",\n" + "  \"UserKey\": \"UserKey-1\",\n"
                                + "  \"UserType\": \"Admin\",\n" + "  \"UserUpn\": \"user@localhost.example.test\",\n"
                                + "  \"Workload\": \"Service1\",\n"
                                + "  \"_ItemId\": \"bb41a487-309b-4d21-9ab8-2a8b948b2d18\",\n"
                                + "  \"_ResourceId\": \"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}\",\n"
                                + "  \"_SubscriptionId\": \"bb41a487-309b-4d21-9ab8-2a8b948b2d18\",\n"
                                + "  \"_TimeReceived\": \"2025-10-06T00:00:00.0000000Z\",\n"
                                + "  \"_Internal_WorkspaceResourceId\": \"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}\"\n"
                                + "}",
                        syslogMessage.getMsg()
                );
        Assertions.assertEquals("md5-0ded52ef915af563e25778bf26b0f129-resourceName", syslogMessage.getHostname());
        Assertions.assertEquals("DataverseA_{uri1}", syslogMessage.getAppName());
        Assertions.assertEquals("2025-10-06T00:00:00Z", syslogMessage.getTimestamp());

        final Map<String, Map<String, String>> sdElementMap = syslogMessage
                .getSDElements()
                .stream()
                .collect(Collectors.toMap((SDElement::getSdID), (sdElem) -> sdElem.getSdParams().stream().collect(Collectors.toMap(SDParam::getParamName, SDParam::getParamValue))));

        Assertions.assertEquals(1, sdElementMap.get("nlf_01@48577").size());
        Assertions
                .assertEquals(DataverseActivityType.class.getSimpleName(), sdElementMap.get("nlf_01@48577").get("eventType"));

        Assertions.assertTrue(sdElementMap.get("aer_event@48577").containsKey("properties"));
    }

    @Test
    void windowsEventTypeTest() {
        final String json = Assertions
                .assertDoesNotThrow(() -> Files.readString(Paths.get("src/test/resources/windows_event.json")));
        final ParsedEvent parsedEvent = new ParsedEventFactory(
                new UnparsedEventImpl(json, new EventPartitionContextImpl(new HashMap<>()), new EventPropertiesImpl(new HashMap<>()), new EventSystemPropertiesImpl(new HashMap<>()), new EnqueuedTimeImpl("2020-01-01T00:00:00"), new EventOffsetImpl("0"))
        ).parsedEvent();

        final NLFPlugin plugin = new NLFPlugin(new FakeSourceable());
        final List<SyslogMessage> syslogMessages = Assertions
                .assertDoesNotThrow(() -> plugin.syslogMessage(parsedEvent));
        Assertions.assertEquals(1, syslogMessages.size());

        final SyslogMessage syslogMessage = syslogMessages.get(0);
        Assertions.assertEquals("md5-0ded52ef915af563e25778bf26b0f129-resourceName", syslogMessage.getHostname());
        Assertions.assertEquals("Windows", syslogMessage.getAppName());
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
        Assertions
                .assertEquals(WindowsEventType.class.getSimpleName(), sdElementMap.get("nlf_01@48577").get("eventType"));
        Assertions.assertTrue(sdElementMap.get("aer_event@48577").containsKey("properties"));
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

        Assertions.assertEquals(4, sdElementMap.get("aer_event@48577").size());
        Assertions.assertTrue(sdElementMap.get("aer_event@48577").containsKey("properties"));
    }

    @Test
    void containerAppConsoleLogsTypeWithContainerAppName() {
        final String json = Assertions
                .assertDoesNotThrow(
                        () -> Files
                                .readString(
                                        Paths.get("src/test/resources/containerappconsolelogswithcontainerappname.json")
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
        Assertions.assertEquals("md5-c17ef061422271d0c5a9528446dd144e-resourceName", syslogMessage.getHostname());
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

        Assertions.assertEquals(4, sdElementMap.get("aer_event@48577").size());
        Assertions.assertTrue(sdElementMap.get("aer_event@48577").containsKey("properties"));
    }

    @Test
    void containerAppConsoleLogsTypeWithJobName() {
        final String json = Assertions
                .assertDoesNotThrow(
                        () -> Files.readString(Paths.get("src/test/resources/containerappconsolelogswithjobname.json"))
                );
        final ParsedEvent parsedEvent = new ParsedEventFactory(
                new UnparsedEventImpl(json, new EventPartitionContextImpl(new HashMap<>()), new EventPropertiesImpl(new HashMap<>()), new EventSystemPropertiesImpl(new HashMap<>()), new EnqueuedTimeImpl("2020-01-01T00:00:00"), new EventOffsetImpl("0"))
        ).parsedEvent();

        final NLFPlugin plugin = new NLFPlugin(new FakeSourceable());
        final List<SyslogMessage> syslogMessages = Assertions
                .assertDoesNotThrow(() -> plugin.syslogMessage(parsedEvent));
        Assertions.assertEquals(1, syslogMessages.size());

        final SyslogMessage syslogMessage = syslogMessages.get(0);
        Assertions.assertEquals("md5-c17ef061422271d0c5a9528446dd144e-resourceName", syslogMessage.getHostname());
        Assertions.assertEquals("job-name", syslogMessage.getAppName());
        Assertions.assertEquals("2020-01-01T01:23:34.567Z", syslogMessage.getTimestamp());
        Assertions.assertEquals(json, syslogMessage.getMsg());
        final Map<String, Map<String, String>> sdElementMap = syslogMessage
                .getSDElements()
                .stream()
                .collect(Collectors.toMap((SDElement::getSdID), (sdElem) -> sdElem.getSdParams().stream().collect(Collectors.toMap(SDParam::getParamName, SDParam::getParamValue))));

        Assertions.assertEquals(1, sdElementMap.get("nlf_01@48577").size());
        Assertions
                .assertEquals(ContainerAppConsoleLogsType.class.getSimpleName(), sdElementMap.get("nlf_01@48577").get("eventType"));

        Assertions.assertEquals(4, sdElementMap.get("aer_event@48577").size());
        Assertions.assertTrue(sdElementMap.get("aer_event@48577").containsKey("properties"));
    }

    @Test
    void appEventsTypeTest() {
        final String json = Assertions
                .assertDoesNotThrow(() -> Files.readString(Paths.get("src/test/resources/appevents.json")));
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
                                + "  \"AppRoleName\": \"app-role-name\",\n" + "  \"ClientBrowser\": \"Browser\",\n"
                                + "  \"ClientCity\": \"City\",\n" + "  \"ClientCountryOrRegion\": \"Country\",\n"
                                + "  \"ClientIP\": \"192.168.1.2\",\n" + "  \"ClientModel\": \"CModel\",\n"
                                + "  \"ClientOS\": \"OperatingSystem\",\n" + "  \"ClientStateOrProvince\": \"State\",\n"
                                + "  \"ClientType\": \"client-type\",\n" + "  \"IKey\": \"i-key\",\n"
                                + "  \"ItemCount\": 1,\n" + "  \"Measurements\": \"{}\",\n"
                                + "  \"Name\": \"Human Readable Name\",\n" + "  \"OperationId\": \"123\",\n"
                                + "  \"ParentId\": \"456\",\n" + "  \"Properties\": {\n"
                                + "    \"ProcessId\":\"1234\",\n" + "    \"HostInstanceId\":\"123456\",\n"
                                + "    \"prop__{OriginalFormat}\":\"abc\",\n" + "    \"prop__RouteName\":\"xyz\",\n"
                                + "    \"LogLevel\":\"Debug\",\n" + "    \"EventId\":\"1\",\n"
                                + "    \"prop__RouteTemplate\":\"route/template\",\n"
                                + "    \"Category\":\"192.168.3.1\",\n" + "    \"EventName\":\"event-name\"\n"
                                + "  },\n" + "  \"ResourceGUID\": \"123456789\",\n"
                                + "  \"SDKVersion\": \"12: 192.168.x.x\",\n" + "  \"SessionId\": \"12: 192.168.x.x\",\n"
                                + "  \"SourceSystem\": \"Azure\",\n" + "  \"SyntheticSource\": \"Source\",\n"
                                + "  \"TenantId\": \"bb41a487-309b-4d21-9ab8-2a8b948b2d18\",\n"
                                + "  \"TimeGenerated\": \"2020-01-01T01:02:34.5678999Z\",\n"
                                + "  \"Type\": \"AppEvents\",\n"
                                + "  \"UserAccountId\": \"bb41a487-309b-4d21-9ab8-2a8b948b2d18\",\n"
                                + "  \"UserAuthenticatedId\": \"bb41a487-309b-4d21-9ab8-2a8b948b2d18\",\n"
                                + "  \"UserId\": \"bb41a487-309b-4d21-9ab8-2a8b948b2d18\",\n"
                                + "  \"_BilledSize\": 1,\n" + "  \"_ItemId\": \"12-34-56-78\",\n"
                                + "  \"_Internal_WorkspaceResourceId\": \"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}\",\n"
                                + "  \"_ResourceId\": \"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}\"\n"
                                + "}",
                        syslogMessage.getMsg()
                );
        Assertions.assertEquals("md5-0ded52ef915af563e25778bf26b0f129-resourceName", syslogMessage.getHostname());
        Assertions.assertEquals("AppEvents", syslogMessage.getAppName());
        Assertions.assertEquals("2020-01-01T01:02:34.567Z", syslogMessage.getTimestamp());

        final Map<String, Map<String, String>> sdElementMap = syslogMessage
                .getSDElements()
                .stream()
                .collect(Collectors.toMap((SDElement::getSdID), (sdElem) -> sdElem.getSdParams().stream().collect(Collectors.toMap(SDParam::getParamName, SDParam::getParamValue))));

        Assertions.assertEquals(1, sdElementMap.get("nlf_01@48577").size());
        Assertions.assertEquals(AppEventsType.class.getSimpleName(), sdElementMap.get("nlf_01@48577").get("eventType"));

        Assertions.assertTrue(sdElementMap.get("aer_event@48577").containsKey("properties"));
    }

    @Test
    void appServiceConsoleLogsType() {
        final String json = Assertions
                .assertDoesNotThrow(() -> Files.readString(Paths.get("src/test/resources/appserviceconsolelogs.json")));
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
                        "{\n" + "  \"Category\": \"app-service-console-logs\",\n"
                                + "  \"ContainerId\": \"container-id\",\n" + "  \"Host\": \"host-1\",\n"
                                + "  \"Level\": \"Debug\",\n" + "  \"OperationName\": \"operation-1\",\n"
                                + "  \"ResultDescription\": \"description\",\n" + "  \"SourceSystem\": \"Azure\",\n"
                                + "  \"TenantId\": \"12\",\n"
                                + "  \"TimeGenerated\": \"2020-01-01T01:02:34.5678999Z\",\n"
                                + "  \"Type\": \"AppServiceConsoleLogs\",\n" + "  \"_BilledSize\": 1,\n"
                                + "  \"_Internal_WorkspaceResourceId\": \"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}\",\n"
                                + "  \"_ResourceId\": \"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}\"\n"
                                + "}",
                        syslogMessage.getMsg()
                );
        Assertions.assertEquals("md5-0ded52ef915af563e25778bf26b0f129-resourceName", syslogMessage.getHostname());
        Assertions.assertEquals("AppServiceConsoleLogs", syslogMessage.getAppName());
        Assertions.assertEquals("2020-01-01T01:02:34.567Z", syslogMessage.getTimestamp());

        final Map<String, Map<String, String>> sdElementMap = syslogMessage
                .getSDElements()
                .stream()
                .collect(Collectors.toMap((SDElement::getSdID), (sdElem) -> sdElem.getSdParams().stream().collect(Collectors.toMap(SDParam::getParamName, SDParam::getParamValue))));

        Assertions.assertEquals(1, sdElementMap.get("nlf_01@48577").size());
        Assertions
                .assertEquals(AppServiceConsoleLogsType.class.getSimpleName(), sdElementMap.get("nlf_01@48577").get("eventType"));

        Assertions.assertTrue(sdElementMap.get("aer_event@48577").containsKey("properties"));
    }

    @Test
    void azureActivityType() {
        final String json = Assertions
                .assertDoesNotThrow(() -> Files.readString(Paths.get("src/test/resources/azureactivity.json")));
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
                        "{\n" + "  \"ActivityStatus\": \"activity-status1\",\n"
                                + "  \"ActivityStatusValue\": \"Started\",\n"
                                + "  \"ActivitySubstatus\": \"Started substatus\",\n"
                                + "  \"ActivitySubstatusValue\": \"200\",\n"
                                + "  \"Authorization\": \"{\\\"action\\\": \\\"action1\\\"}\",\n"
                                + "  \"Authorization_d\": {\n" + "    \"action\": \"action1\"\n" + "  },\n"
                                + "  \"Caller\": \"12345678-1234-1234-abcd-1234567890ab\",\n"
                                + "  \"CallerIpAddress\": \"127.0.0.1\",\n" + "  \"Category\": \"category1\",\n"
                                + "  \"CategoryValue\": \"Administrative\",\n"
                                + "  \"Claims\": \"\\\"token\\\": \\\"123456788\\\"\",\n" + "  \"Claims_d\": {\n"
                                + "    \"token\": \"123456788\"\n" + "  },\n"
                                + "  \"CorrelationId\": \"12345678-1234-1234-abcd-1234567890bc\",\n"
                                + "  \"EventDataId\": \"1234567889\",\n"
                                + "  \"EventSubmissionTimestamp\": \"2020-01-01T01:02:34.5678999Z\",\n"
                                + "  \"Hierarchy\": \"hierarchy1\",\n" + "  \"HTTPRequest\": \"PUT\",\n"
                                + "  \"Level\": \"Debug\",\n" + "  \"OperationId\": \"operation-1\",\n"
                                + "  \"OperationName\": \"operation-name1\",\n"
                                + "  \"OperationNameValue\": \"operation-name-value1\",\n"
                                + "  \"Properties\": \"{}\",\n" + "  \"Properties_d\": {},\n"
                                + "  \"Resource\": \"{resourceName}\",\n"
                                + "  \"ResourceGroup\": \"{resourceGroupName}\",\n"
                                + "  \"ResourceId\": \"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}\",\n"
                                + "  \"ResourceProvider\": \"{resourceProviderNamespace}\",\n"
                                + "  \"ResourceProviderValue\": \"Microsoft.Storage\",\n"
                                + "  \"SourceSystem\": \"Azure\",\n" + "  \"SubscriptionId\": \"{subscriptionId}\",\n"
                                + "  \"TenantId\": \"12\",\n"
                                + "  \"TimeGenerated\": \"2020-01-01T01:02:34.5678999Z\",\n"
                                + "  \"Type\": \"AzureActivity\",\n" + "  \"_BilledSize\": 1,\n"
                                + "  \"_Internal_WorkspaceResourceId\": \"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}\",\n"
                                + "  \"_ResourceId\": \"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}\"\n"
                                + "}",
                        syslogMessage.getMsg()
                );
        Assertions.assertEquals("md5-9ccb3400a4e3cc188a82048d7d632a31", syslogMessage.getHostname());
        Assertions.assertEquals("AzureActivity", syslogMessage.getAppName());
        Assertions.assertEquals("2020-01-01T01:02:34.567Z", syslogMessage.getTimestamp());

        final Map<String, Map<String, String>> sdElementMap = syslogMessage
                .getSDElements()
                .stream()
                .collect(Collectors.toMap((SDElement::getSdID), (sdElem) -> sdElem.getSdParams().stream().collect(Collectors.toMap(SDParam::getParamName, SDParam::getParamValue))));

        Assertions.assertEquals(1, sdElementMap.get("nlf_01@48577").size());
        Assertions
                .assertEquals(AzureActivityType.class.getSimpleName(), sdElementMap.get("nlf_01@48577").get("eventType"));

        Assertions.assertTrue(sdElementMap.get("aer_event@48577").containsKey("properties"));
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

        Assertions.assertTrue(sdElementMap.get("aer_event@48577").containsKey("properties"));
    }

    @Test
    void pgsqlServerLogsTypeTest() {
        final String json = Assertions
                .assertDoesNotThrow(() -> Files.readString(Paths.get("src/test/resources/pgsqlserverlogs.json")));
        final ParsedEvent parsedEvent = new ParsedEventFactory(
                new UnparsedEventImpl(json, new EventPartitionContextImpl(new HashMap<>()), new EventPropertiesImpl(new HashMap<>()), new EventSystemPropertiesImpl(new HashMap<>()), new EnqueuedTimeImpl("2020-01-01T00:00:00"), new EventOffsetImpl("0"))
        ).parsedEvent();

        final NLFPlugin plugin = new NLFPlugin(new FakeSourceable());
        final List<SyslogMessage> syslogMessages = Assertions
                .assertDoesNotThrow(() -> plugin.syslogMessage(parsedEvent));
        Assertions.assertEquals(1, syslogMessages.size());

        final SyslogMessage syslogMessage = syslogMessages.get(0);
        Assertions.assertEquals("md5-0ded52ef915af563e25778bf26b0f129-resourceName", syslogMessage.getHostname());
        Assertions.assertEquals("dbase_maintenance", syslogMessage.getAppName());
        Assertions.assertEquals("2020-10-01T11:59:26.256Z", syslogMessage.getTimestamp());
        Assertions.assertEquals(json, syslogMessage.getMsg());
        final Map<String, Map<String, String>> sdElementMap = syslogMessage
                .getSDElements()
                .stream()
                .collect(Collectors.toMap((SDElement::getSdID), (sdElem) -> sdElem.getSdParams().stream().collect(Collectors.toMap(SDParam::getParamName, SDParam::getParamValue))));

        Assertions
                .assertEquals(
                        "/SUBSCRIPTIONS/uuid/RESOURCEGROUPS/ab-cd-efgh-ijklmn-xx-DEV-01/PROVIDERS/postgres-db/FLEXIBLESERVERS/efgh-ijklmn-xx-DEV-01",
                        sdElementMap.get("origin@48577").get("_ResourceId")
                );

        Assertions.assertTrue(sdElementMap.get("aer_event@48577").containsKey("properties"));
    }

    @Test
    void powerAutomateActivityType() {
        final String json = Assertions
                .assertDoesNotThrow(() -> Files.readString(Paths.get("src/test/resources/powerautomateactivity.json")));
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
                        "{\n" + "  \"ActorName\": \"localhost@localhost.example.test\",\n"
                                + "  \"ActorUserId\": \"bb41a487-309b-4d21-9ab8-2a8b948b2d18\",\n"
                                + "  \"ActorUserType\": \"Admin\",\n" + "  \"AdditionalInfo\": \"{}\",\n"
                                + "  \"EventOriginalType\": \"OriginalType\",\n"
                                + "  \"EventOriginalUid\": \"bb41a487-309b-4d21-9ab8-2a8b948b2d18\",\n"
                                + "  \"EventResult\": \"Succeeded\",\n" + "  \"FlowConnectorNames\": \"Connector\",\n"
                                + "  \"FlowDetailsUrl\": \"https://{uri1}/{uri2}/environments/EXAMPLE_FLOW_1/flows/{uri3}\",\n"
                                + "  \"LicenseDisplayName\": \"License1\",\n"
                                + "  \"ObjectId\": \"bb41a487-309b-4d21-9ab8-2a8b948b2d18\",\n"
                                + "  \"OrganizationId\": \"bb41a487-309b-4d21-9ab8-2a8b948b2d18\",\n"
                                + "  \"RecipientUpn\": \"bb41a487-309b-4d21-9ab8-2a8b948b2d18\",\n"
                                + "  \"RecordType\": \"exchangeAdmin\",\n" + "  \"SharingPermission\": \"2\",\n"
                                + "  \"SourceSystem\": \"Azure\",\n" + "  \"SrcIpAddr\": \"127.0.0.1\",\n"
                                + "  \"Type\": \"PowerAutomateActivity\",\n"
                                + "  \"TimeGenerated\": \"2025-10-06T00:00:00.0000000Z\",\n"
                                + "  \"_ItemId\": \"bb41a487-309b-4d21-9ab8-2a8b948b2d18\",\n"
                                + "  \"TenantId\": \"bb41a487-309b-4d21-9ab8-2a8b948b2d18\",\n"
                                + "  \"UserUpn\": \"bb41a487-309b-4d21-9ab8-2a8b948b2d18\",\n"
                                + "  \"Workload\": \"Service1\",\n"
                                + "  \"_ResourceId\": \"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}\",\n"
                                + "  \"_SubscriptionId\": \"bb41a487-309b-4d21-9ab8-2a8b948b2d18\",\n"
                                + "  \"_TimeReceived\": \"2025-10-06T00:00:00.0000000Z\",\n"
                                + "  \"_Internal_WorkspaceResourceId\": \"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}\"\n"
                                + "}",
                        syslogMessage.getMsg()
                );
        Assertions.assertEquals("md5-0ded52ef915af563e25778bf26b0f129-resourceName", syslogMessage.getHostname());
        Assertions.assertEquals("PowerAA_EXAMPLE_FLOW_1", syslogMessage.getAppName());
        Assertions.assertEquals("2025-10-06T00:00:00Z", syslogMessage.getTimestamp());

        final Map<String, Map<String, String>> sdElementMap = syslogMessage
                .getSDElements()
                .stream()
                .collect(Collectors.toMap((SDElement::getSdID), (sdElem) -> sdElem.getSdParams().stream().collect(Collectors.toMap(SDParam::getParamName, SDParam::getParamValue))));

        Assertions.assertEquals(1, sdElementMap.get("nlf_01@48577").size());
        Assertions
                .assertEquals(PowerAutomateActivityType.class.getSimpleName(), sdElementMap.get("nlf_01@48577").get("eventType"));

        Assertions.assertTrue(sdElementMap.get("aer_event@48577").containsKey("properties"));
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

        Assertions.assertTrue(sdElementMap.get("aer_event@48577").containsKey("properties"));
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

        Assertions.assertTrue(sdElementMap.get("aer_event@48577").containsKey("properties"));
    }

    @Test
    void testPowerPlatformAdminActivityType() {
        final String json = Assertions
                .assertDoesNotThrow(
                        () -> Files.readString(Paths.get("src/test/resources/powerplatformadminactivity.json"))
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
                        "{\n" + "  \"ActorName\": \"localhost@localhost.example.test\",\n"
                                + "  \"ActorUserId\": \"bb41a487-309b-4d21-9ab8-2a8b948b2d18\",\n"
                                + "  \"ActorUserType\": \"Admin\",\n" + "  \"EnvironmentId\": \"Environment-01\",\n"
                                + "  \"EventOriginalType\": \"OriginalType\",\n"
                                + "  \"EventOriginalUid\": \"bb41a487-309b-4d21-9ab8-2a8b948b2d18\",\n"
                                + "  \"EventResult\": \"Succeeded\",\n"
                                + "  \"OrganizationId\": \"bb41a487-309b-4d21-9ab8-2a8b948b2d18\",\n"
                                + "  \"Properties\": \"{}\",\n" + "  \"PropertyCollection\": \"{}\",\n"
                                + "  \"RecordType\": \"exchangeAdmin\",\n"
                                + "  \"RequiresCustomerKeyEncryption\": true,\n" + "  \"SourceSystem\": \"Azure\",\n"
                                + "  \"Type\": \"PowerPlatformAdminActivity\",\n"
                                + "  \"TenantId\": \"bb41a487-309b-4d21-9ab8-2a8b948b2d18\",\n"
                                + "  \"TimeGenerated\": \"2025-10-06T00:00:00.0000000Z\",\n"
                                + "  \"Workload\": \"Service1\",\n"
                                + "  \"_ItemId\": \"bb41a487-309b-4d21-9ab8-2a8b948b2d18\",\n"
                                + "  \"_ResourceId\": \"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}\",\n"
                                + "  \"_SubscriptionId\": \"bb41a487-309b-4d21-9ab8-2a8b948b2d18\",\n"
                                + "  \"_TimeReceived\": \"2025-10-06T00:00:00.0000000Z\",\n"
                                + "  \"_Internal_WorkspaceResourceId\": \"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}\"\n"
                                + "}",
                        syslogMessage.getMsg()
                );
        Assertions.assertEquals("md5-0ded52ef915af563e25778bf26b0f129-resourceName", syslogMessage.getHostname());
        Assertions.assertEquals("PowerPAA_Environment-01", syslogMessage.getAppName());
        Assertions.assertEquals("2025-10-06T00:00:00Z", syslogMessage.getTimestamp());

        final Map<String, Map<String, String>> sdElementMap = syslogMessage
                .getSDElements()
                .stream()
                .collect(Collectors.toMap((SDElement::getSdID), (sdElem) -> sdElem.getSdParams().stream().collect(Collectors.toMap(SDParam::getParamName, SDParam::getParamValue))));

        Assertions.assertEquals(1, sdElementMap.get("nlf_01@48577").size());
        Assertions
                .assertEquals(PowerPlatformAdminActivityType.class.getSimpleName(), sdElementMap.get("nlf_01@48577").get("eventType"));

        Assertions.assertTrue(sdElementMap.get("aer_event@48577").containsKey("properties"));
    }

    @Test
    void sqlSecurityAuditEventsTypeTest() {
        final String json = Assertions
                .assertDoesNotThrow(() -> Files.readString(Paths.get("src/test/resources/sqlsecurityauditevents.json")));
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
                        "{\n" + "  \"category\": \"SQLSecurityAuditEvents\",\n"
                                + "  \"operationName\": \"Operation-1\",\n"
                                + "  \"originalEventTimestamp\": \"2025-10-06T00:00:00.0000000Z\",\n"
                                + "  \"resourceId\": \"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}/{resourceSubtype}/{subtypeName}\"\n"
                                + "}",
                        syslogMessage.getMsg()
                );
        Assertions.assertEquals("md5-63a8be7673efd1bb7439550f2ad118ce-resourceName", syslogMessage.getHostname());
        Assertions.assertEquals("Operation-1", syslogMessage.getAppName());
        Assertions.assertEquals("2025-10-06T00:00:00Z", syslogMessage.getTimestamp());

        final Map<String, Map<String, String>> sdElementMap = syslogMessage
                .getSDElements()
                .stream()
                .collect(Collectors.toMap((SDElement::getSdID), (sdElem) -> sdElem.getSdParams().stream().collect(Collectors.toMap(SDParam::getParamName, SDParam::getParamValue))));

        Assertions.assertEquals(1, sdElementMap.get("nlf_01@48577").size());
        Assertions
                .assertEquals(SQLSecurityAuditEventsType.class.getSimpleName(), sdElementMap.get("nlf_01@48577").get("eventType"));

        Assertions.assertTrue(sdElementMap.get("aer_event@48577").containsKey("properties"));
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

    @Test
    void testSyslogMessageWithMissingComponentNameEnvironmentVariable() {
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

        final Map<String, String> envValues = new HashMap<>();
        envValues.put("containerlog.appname.annotation", "appname");
        envValues.put("containerlog.hostname.annotation", "appname");
        envValues.put("syslogtype.processname", "appname");

        final Sourceable sourceable = new ConfigurableSourceable(envValues);

        final NLFPlugin plugin = new NLFPlugin(sourceable);
        final PluginException pluginException = Assertions
                .assertThrows(PluginException.class, () -> plugin.syslogMessage(parsedEvent));

        Assertions
                .assertEquals(
                        "java.lang.IllegalArgumentException: No such environment variable: component.name",
                        pluginException.getMessage()
                );
    }
}
