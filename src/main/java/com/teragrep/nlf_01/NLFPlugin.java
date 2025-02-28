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
import com.teragrep.akv_01.plugin.Plugin;
import com.teragrep.akv_01.plugin.PluginException;
import com.teragrep.nlf_01.rule.*;
import com.teragrep.nlf_01.types.*;
import com.teragrep.nlf_01.util.EnvironmentSource;
import com.teragrep.nlf_01.util.Sourceable;
import com.teragrep.rlo_14.SyslogMessage;

import java.util.ArrayList;
import java.util.List;

public final class NLFPlugin implements Plugin {

    private final Sourceable source;
    private final List<Rule> rules;

    public NLFPlugin() {
        this(new EnvironmentSource());
    }

    public NLFPlugin(final Sourceable source) {
        this(source, List.of(new AppInsightRule(), new SyslogRule(source), new ContainerRule(source), new CLRule()));
    }

    public NLFPlugin(final Sourceable source, final List<Rule> rules) {
        this.source = source;
        this.rules = rules;
    }

    @Override
    public List<SyslogMessage> syslogMessage(final ParsedEvent parsedEvent) throws PluginException {
        final List<SyslogMessage> syslogMessages = new ArrayList<>();

        if (rules.isEmpty()) {
            throw new PluginException("No rules found");
        }

        Rule currentRule = new RuleStub();
        for (final Rule rule : rules) {
            if (rule.matches(parsedEvent)) {
                System.out.println("Rule match: " + rule);
                currentRule = rule;
                break;
            }
        }

        if (currentRule.isStub()) {
            throw new PluginException("No applicable rule found for event");
        }

        EventType eventType = currentRule.eventType(parsedEvent);

        final SyslogMessage syslogMessage = new SyslogMessage()
                .withFacility(eventType.facility())
                .withSeverity(eventType.severity())
                .withTimestamp(eventType.timestamp())
                .withAppName(eventType.appName())
                .withHostname(eventType.hostname())
                .withMsgId(eventType.msgId())
                .withMsg(eventType.msg());
        syslogMessage.setSDElements(eventType.sdElements());
        syslogMessages.add(syslogMessage);

        return syslogMessages;
    }
}
