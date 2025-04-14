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
package com.teragrep.nlf_01.rule;

import com.teragrep.akv_01.event.ParsedEvent;
import com.teragrep.akv_01.plugin.PluginException;
import com.teragrep.nlf_01.condition.Condition;
import com.teragrep.nlf_01.condition.DefaultCondition;
import com.teragrep.nlf_01.condition.SyslogProcessNameCondition;
import com.teragrep.nlf_01.condition.TypeCondition;
import com.teragrep.nlf_01.types.EventType;
import com.teragrep.nlf_01.types.SyslogType;
import com.teragrep.nlf_01.util.RealHostname;
import com.teragrep.nlf_01.util.Sourceable;

import java.util.List;
import java.util.function.Predicate;

public final class SyslogRule implements Rule {

    private final List<Condition> conditions;

    public SyslogRule(final Sourceable source) {
        this(List.of(new TypeCondition("Syslog"), new SyslogProcessNameCondition(source)));
    }

    private SyslogRule(final List<Condition> conditions) {
        this.conditions = conditions;
    }

    @Override
    public boolean matches(final ParsedEvent parsedEvent) {
        Predicate<ParsedEvent> condition = new DefaultCondition();

        for (final Condition c : conditions) {
            condition = c.and(condition);
        }

        return condition.test(parsedEvent);
    }

    @Override
    public EventType eventType(final ParsedEvent parsedEvent) throws PluginException {
        return new SyslogType(parsedEvent, new RealHostname("localhost").hostname());
    }

    @Override
    public boolean isStub() {
        return false;
    }
}
