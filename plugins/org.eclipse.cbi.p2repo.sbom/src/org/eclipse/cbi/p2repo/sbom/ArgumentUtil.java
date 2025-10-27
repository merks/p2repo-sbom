/**
 * Copyright (c) 2025 Eclipse contributors and others.
 *
 * This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License 2.0
 * which accompanies this distribution, and is available at
 * https://www.eclipse.org/legal/epl-2.0/
 *
 * SPDX-License-Identifier: EPL-2.0
 */
package org.eclipse.cbi.p2repo.sbom;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.eclipse.equinox.app.IApplicationContext;

public final class ArgumentUtil {
	private ArgumentUtil() {
		throw new UnsupportedOperationException("Do not instantiate");
	}

	public static List<String> getArguments(IApplicationContext context) {
		return new ArrayList<>(Arrays.asList((String[]) context.getArguments().get("application.args")));
	}

	public static boolean getArgument(String name, List<String> args) {
		return args.remove(name);
	}

	public static String getArgument(String name, List<String> args, String defaultValue) {
		var index = args.indexOf(name);
		if (index == -1) {
			return defaultValue;
		}
		args.remove(index);
		if (index >= args.size()) {
			throw new IllegalArgumentException("An argument value is expected after " + name);
		}
		return args.remove(index);
	}

	public static List<String> getArguments(String name, List<String> args, List<String> defaultValue) {
		var index = args.indexOf(name);
		if (index == -1) {
			return defaultValue;
		}
		args.remove(index);
		if (index >= args.size()) {
			throw new IllegalArgumentException("An argument value is expected after " + name);
		}

		var result = new ArrayList<String>();
		while (index < args.size() && !args.get(index).startsWith("-")) {
			result.add(args.remove(index));
		}
		return result;
	}
}