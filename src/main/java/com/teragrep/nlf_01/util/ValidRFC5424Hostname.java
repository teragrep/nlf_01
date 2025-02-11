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
package com.teragrep.nlf_01.util;

public final class ValidRFC5424Hostname {

    private final String uncheckedHostname;

    public ValidRFC5424Hostname(final String uncheckedHostname) {
        this.uncheckedHostname = uncheckedHostname;
    }

    public String validHostname() {
        if (uncheckedHostname.length() > 255) {
            throw new IllegalArgumentException(
                    "Hostname is too long: " + uncheckedHostname.length() + "; exceeds maximum of 255 characters"
            );
        }

        for (int i = 0; i < uncheckedHostname.length(); i++) {
            final char c = uncheckedHostname.charAt(i);

            if (i == 0 && (Character.isDigit(c) || c == '.' || c == '-')) {
                throw new IllegalArgumentException(String.format("Hostname cannot start with character '%s'", c));
            }

            if (i == uncheckedHostname.length() - 1 && (c == '.' || c == '-')) {
                throw new IllegalArgumentException(String.format("Hostname cannot end with character '%s'", c));
            }

            // 0-9
            if (Character.isDigit(c)) {
                continue;
            }

            // . or -
            if (c == '.' || c == '-') {
                continue;
            }

            // A-Z or a-z
            if (c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z') {
                continue;
            }

            throw new IllegalArgumentException(String.format("Hostname cannot contain character '%s'", c));
        }

        return uncheckedHostname;
    }

    public String hostnameWithInvalidCharsRemoved() {
        final StringBuilder hostname = new StringBuilder();
        int skippedChars = 0; // How many characters are skipped from unvalidated hostname
        int maxLength = Math.min(uncheckedHostname.length(), 255); // max length is either hostname length or 255
        final StringBuilder invalidChars = new StringBuilder(); // Holds invalid final characters

        for (int i = 0; i < uncheckedHostname.length(); i++) {
            final char c = uncheckedHostname.charAt(i);
            // Update max length based on skipped characters
            int currentMaxLength = maxLength - skippedChars;

            if (hostname.length() == currentMaxLength) {
                // produced hostname is at max length, stop processing
                break;
            }
            else if (hostname.length() == 0 && (c == '.' || c == '-' || Character.isDigit(c))) {
                // skip 0-9, '.' and '-' in the beginning
                skippedChars++;
            }
            else if (c == '.' || c == '-') {
                // mid-hostname, encountered illegal hostname last char
                invalidChars.append(c);
            }
            else if (Character.isDigit(c) || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')) {
                // append '.', '-', 0-9, A-Z and a-z
                // also means illegal last chars are not last chars, append them before
                if (hostname.length() + invalidChars.length() > currentMaxLength) {
                    // in case hostname + invalidChars is more than max length, add invalid chars up to max length - 1
                    final int overlap = (hostname.length() + invalidChars.length()) - currentMaxLength;
                    hostname.append(invalidChars, 0, invalidChars.length() - overlap - 1);
                }
                else {
                    hostname.append(invalidChars);
                }
                invalidChars.setLength(0);
                hostname.append(c);
            }
            else {
                skippedChars++;
            }
        }

        return hostname.toString();
    }
}
