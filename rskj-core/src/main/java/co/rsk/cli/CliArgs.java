/*
 * This file is part of RskJ
 * Copyright (C) 2018 RSK Labs Ltd.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
package co.rsk.cli;

import java.util.*;
import java.util.stream.Collectors;

/**
 * A simple representation of command line arguments, broken into "options", "flags" and "arguments".
 */
public class CliArgs<O, F> {

    private final List<String> arguments;
    private final Map<O, String> options;
    private final Set<F> flags;
    private final Map<String, String> paramValueMap;

    private CliArgs(List<String> arguments, Map<O, String> options, Set<F> flags, Map<String, String> paramValueMap) {
        this.arguments = Collections.unmodifiableList(arguments);
        this.options = Collections.unmodifiableMap(options);
        this.flags = Collections.unmodifiableSet(flags);
        this.paramValueMap = Collections.unmodifiableMap(paramValueMap);
    }

    public static <O, F> CliArgs<O, F> empty() {
        return new CliArgs<>(
                Collections.emptyList(),
                Collections.emptyMap(),
                Collections.emptySet(),
                Collections.emptyMap()
        );
    }

    public List<String> getArguments() {
        return arguments;
    }

    public Map<O, String> getOptions() {
        return options;
    }

    public Set<F> getFlags() {
        return flags;
    }

    public Map<String, String> getParamValueMap() {
        return paramValueMap;
    }

    /**
     * Parses a {@code String[]} of command line arguments in order to populate a
     * {@link CliArgs} object.
     *
     * <h3>Working with option arguments</h3>
     * Option arguments must adhere to the exact syntax:
     * <pre class="code">-optName optValue</pre>
     * <pre class="code">--flagName</pre>
     * That is, options must be prefixed with "{@code -}", and must specify a value,
     * and flags must be prefixed with "{@code --}", and may not specify a value.
     */
    public static class Parser<O extends Enum<O> & OptionalizableCliArg, F extends Enum<F> & CliArg> {

        private final EnumSet<O> options;
        private final EnumSet<F> flags;

        public Parser(Class<O> optionsClass, Class<F> flagsClass) {
            this.options = EnumSet.allOf(optionsClass);
            this.flags = EnumSet.allOf(flagsClass);
        }

        public CliArgs<O, F> parse(String[] args) {
            List<String> arguments = new LinkedList<>();
            Map<O, String> options = new HashMap<>();
            Set<F> flags = new HashSet<>();
            Map<String, String> paramValueMap = new HashMap<>();

            for (int i = 0; i < args.length; i++) {
                switch (args[i].charAt(0)) {
                    case '-':
                        if (args[i].length() < 2) {
                            throw new IllegalArgumentException("You must provide an option name, e.g. -d");
                        }
                        char currentChar = Character.toLowerCase(args[i].charAt(1));
                        if (currentChar == '-') {
                            if (args[i].length() < 3) {
                                throw new IllegalArgumentException("You must provide a flag name, e.g. --quiet");
                            }
                            flags.add(getFlagByName(args[i].substring(2, args[i].length())));
                        } else if (currentChar == 'x') {
                            String arg = args[i].substring(2);
                            paramValueMap.putAll(parseArgToMap(arg));
                        } else {
                            if (args.length - 1 == i) {
                                throw new IllegalArgumentException(
                                        String.format("A value must be provided after the option -%s", args[i])
                                );
                            }
                            options.put(getOptionByName(args[i].substring(1, args[i].length())), args[i + 1]);
                            i++;
                        }
                        break;
                    default:
                        arguments.add(args[i]);
                        break;
                }
            }

            Set<O> missingOptions = this.options.stream()
                    .filter(arg -> !arg.isOptional())
                    .collect(Collectors.toSet());
            missingOptions.removeAll(options.keySet());
            if (!missingOptions.isEmpty()) {
                throw new IllegalArgumentException(
                        String.format("Missing configuration options: %s", missingOptions)
                );
            }

            return new CliArgs<>(arguments, options, flags, paramValueMap);
        }

        private F getFlagByName(String flagName) {
            return flags.stream()
                    .filter(flag -> flag.getName().equals(flagName))
                    .findFirst()
                    .orElseThrow(
                            () -> new NoSuchElementException(String.format("--%s is not a valid flag", flagName))
                    );
        }

        private O getOptionByName(String optionName) {
            return options.stream()
                    .filter(opt -> opt.getName().equals(optionName))
                    .findFirst()
                    .orElseThrow(
                            () -> new NoSuchElementException(String.format("-%s is not a valid option", optionName))
                    );
        }

        /**
         * Parses a string argument in the format e.g <i>database.dir=/home/rsk/core<i/> to a map in the following
         * structure:
         * <blockquote>
         *     {
         *         "database": {
         *             "dir": "/home/rsk/core"
         *         }
         *     }
         * </blockquote>
         * @param arg to parse
         * @return a string arg parsed to an equivalent map having the same structure system properties would have.
         */
        private Map<String, String> parseArgToMap(String arg) {
            String[] paramValue = arg.split("=", 2);

            if (paramValue.length != 2) {
                throw new IllegalArgumentException("You must provide a valid arg, e.g. -Xparam.part1.part2=value");
            }

            String param = paramValue[0];
            String value = paramValue[1];

            Map<String, String> paramValueMap = new HashMap<>();
            paramValueMap.put(param, value);

            return paramValueMap;
        }
    }
}
