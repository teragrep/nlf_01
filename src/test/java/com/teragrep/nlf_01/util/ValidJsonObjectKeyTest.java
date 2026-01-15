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

import com.teragrep.akv_01.plugin.PluginException;
import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonValue;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class ValidJsonObjectKeyTest {

    @Test
    @DisplayName("value() throws PluginException if JsonObject does not contain the key")
    void valueThrowsPluginExceptionIfJsonObjectDoesNotContainTheKey() {
        final JsonObject jsonObject = Json.createObjectBuilder().add("key2", "value").build();
        final ValidJsonObjectKey validKey = new ValidJsonObjectKey(jsonObject, "key1");

        final PluginException exception = Assertions.assertThrowsExactly(PluginException.class, validKey::value);

        final String expectedMessage = "Key <[key1]> was not valid";
        Assertions.assertEquals(expectedMessage, exception.getMessage());
    }

    @Test
    @DisplayName("value() throws PluginException if the requested key's ValueType is not the one requested")
    void valueThrowsPluginExceptionIfTheRequestedKeySValueTypeIsNotTheOneRequested() {
        final JsonObject jsonObject = Json.createObjectBuilder().add("key1", 1).build();
        final ValidJsonObjectKey validKey = new ValidJsonObjectKey(jsonObject, "key1");

        final PluginException exception = Assertions.assertThrowsExactly(PluginException.class, validKey::value);

        final String expectedMessage = "Key <[key1]> was not valid";
        Assertions.assertEquals(expectedMessage, exception.getMessage());
    }

    @Test
    @DisplayName("value() throws PluginException if the requested key's ValueType is STRING")
    void valueThrowsPluginExceptionIfTheRequestedKeySValueTypeIsString() {
        final JsonObject jsonObject = Json.createObjectBuilder().add("key1", "String").build();
        final ValidJsonObjectKey validKey = new ValidJsonObjectKey(jsonObject, "key1");

        final PluginException exception = Assertions.assertThrowsExactly(PluginException.class, validKey::value);

        final String expectedMessage = "Key <[key1]> was not valid";
        Assertions.assertEquals(expectedMessage, exception.getMessage());
    }

    @Test
    @DisplayName("value() throws PluginException if the requested key's ValueType is NUMBER")
    void valueThrowsPluginExceptionIfTheRequestedKeySValueTypeIsNumber() {
        final JsonObject jsonObject = Json.createObjectBuilder().add("key1", 1).build();
        final ValidJsonObjectKey validKey = new ValidJsonObjectKey(jsonObject, "key1");

        final PluginException exception = Assertions.assertThrowsExactly(PluginException.class, validKey::value);

        final String expectedMessage = "Key <[key1]> was not valid";
        Assertions.assertEquals(expectedMessage, exception.getMessage());
    }

    @Test
    @DisplayName("value() throws PluginException if the requested key's ValueType is TRUE")
    void valueThrowsPluginExceptionIfTheRequestedKeySValueTypeIsTrue() {
        final JsonObject jsonObject = Json.createObjectBuilder().add("key1", JsonValue.TRUE).build();
        final ValidJsonObjectKey validKey = new ValidJsonObjectKey(jsonObject, "key1");

        final PluginException exception = Assertions.assertThrowsExactly(PluginException.class, validKey::value);

        final String expectedMessage = "Key <[key1]> was not valid";
        Assertions.assertEquals(expectedMessage, exception.getMessage());
    }

    @Test
    @DisplayName("value() throws PluginException if the requested key's ValueType is FALSE")
    void valueThrowsPluginExceptionIfTheRequestedKeySValueTypeIsFalse() {
        final JsonObject jsonObject = Json.createObjectBuilder().add("key1", JsonValue.FALSE).build();
        final ValidJsonObjectKey validKey = new ValidJsonObjectKey(jsonObject, "key1");

        final PluginException exception = Assertions.assertThrowsExactly(PluginException.class, validKey::value);

        final String expectedMessage = "Key <[key1]> was not valid";
        Assertions.assertEquals(expectedMessage, exception.getMessage());
    }

    @Test
    @DisplayName("value() throws PluginException if the requested key's ValueType is ARRAY")
    void valueThrowsPluginExceptionIfTheRequestedKeySValueTypeIsArray() {
        final JsonObject jsonObject = Json.createObjectBuilder().add("key1", JsonValue.EMPTY_JSON_ARRAY).build();
        final ValidJsonObjectKey validKey = new ValidJsonObjectKey(jsonObject, "key1");

        final PluginException exception = Assertions.assertThrowsExactly(PluginException.class, validKey::value);

        final String expectedMessage = "Key <[key1]> was not valid";
        Assertions.assertEquals(expectedMessage, exception.getMessage());
    }

    @Test
    @DisplayName("value() throws PluginException if the requested key's ValueType is NULL")
    void valueThrowsPluginExceptionIfTheRequestedKeySValueTypeIsNull() {
        final JsonObject jsonObject = Json.createObjectBuilder().add("key1", JsonValue.NULL).build();
        final ValidJsonObjectKey validKey = new ValidJsonObjectKey(jsonObject, "key1");

        final PluginException exception = Assertions.assertThrowsExactly(PluginException.class, validKey::value);

        final String expectedMessage = "Key <[key1]> was not valid";
        Assertions.assertEquals(expectedMessage, exception.getMessage());
    }

    @Test
    @DisplayName("value returns JsonObject from the key's value if conditions are met")
    void valueReturnsJsonObjectFromTheKeysValueIfConditionsAreMet() {
        final JsonObject jsonObject = Json
                .createObjectBuilder()
                .add("key1", Json.createObjectBuilder().build())
                .build();
        final ValidJsonObjectKey validKey = new ValidJsonObjectKey(jsonObject, "key1");

        final JsonObject returnedJsonObject = Assertions.assertDoesNotThrow(validKey::value);

        final JsonObject expectedJsonObject = JsonValue.EMPTY_JSON_OBJECT;
        Assertions.assertEquals(expectedJsonObject, returnedJsonObject);
    }
}
