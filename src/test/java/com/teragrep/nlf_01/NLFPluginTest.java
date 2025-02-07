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
        final List<SyslogMessage> syslogMessages = plugin.syslogMessage(parsedEvent);
        Assertions.assertEquals(1, syslogMessages.size());

        final SyslogMessage syslogMessage = syslogMessages.get(0);
        Assertions.assertEquals("HOST-NAME", syslogMessage.getHostname());
        Assertions.assertEquals("APP-NAME:o", syslogMessage.getAppName());
        Assertions.assertEquals("2020-01-01T01:23:34.567899900Z", syslogMessage.getTimestamp());
        final List<SDElement> origin = syslogMessage
                .getSDElements()
                .stream()
                .filter(elem -> elem.getSdID().equals("origin@48577"))
                .collect(Collectors.toList());
        Assertions.assertEquals(1, origin.size());
        final Map<String, String> params = origin
                .get(0)
                .getSdParams()
                .stream()
                .collect(Collectors.toMap(SDParam::getParamName, SDParam::getParamValue));
        Assertions.assertEquals(5, params.size());
        Assertions.assertEquals("{subscriptionId}", params.get("subscription"));
        Assertions.assertEquals("{resourceName}", params.get("clusterName"));
        Assertions.assertEquals("pod-namespace", params.get("namespace"));
        Assertions.assertEquals("pod-name", params.get("pod"));
        Assertions.assertEquals("container-id", params.get("containerId"));
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
        final List<SyslogMessage> syslogMessages = plugin.syslogMessage(parsedEvent);
        Assertions.assertEquals(1, syslogMessages.size());

        final SyslogMessage syslogMessage = syslogMessages.get(0);
        Assertions.assertEquals("0ded52ef915af563e25778bf26b0f129{resourceName}", syslogMessage.getHostname());
        Assertions.assertEquals("app-role-name", syslogMessage.getAppName());
        Assertions.assertEquals("2020-01-01T01:02:34.567899900Z", syslogMessage.getTimestamp());
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
        final List<SyslogMessage> syslogMessages = plugin.syslogMessage(parsedEvent);
        Assertions.assertEquals(1, syslogMessages.size());

        final SyslogMessage syslogMessage = syslogMessages.get(0);
        Assertions.assertEquals("0ded52ef915af563e25778bf26b0f129{resourceName}", syslogMessage.getHostname());
        Assertions.assertEquals("97bd8f02-xxxxx.log", syslogMessage.getAppName());
        Assertions.assertEquals("2020-01-01T01:02:34.567899900Z", syslogMessage.getTimestamp());
        final List<SDElement> origin = syslogMessage
                .getSDElements()
                .stream()
                .filter(elem -> elem.getSdID().equals("origin@48577"))
                .collect(Collectors.toList());
        Assertions.assertEquals(1, origin.size());

        final Map<String, String> params = origin
                .get(0)
                .getSdParams()
                .stream()
                .collect(Collectors.toMap(SDParam::getParamName, SDParam::getParamValue));
        Assertions.assertEquals(1, params.size());
        Assertions
                .assertEquals(
                        "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}",
                        params.get("_ResourceId")
                );
    }
}
