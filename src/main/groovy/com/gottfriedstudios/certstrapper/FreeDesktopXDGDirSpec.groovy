package com.gottfriedstudios.certstrapper

import java.nio.file.Path
import java.nio.file.Paths


class FreeDesktopXDGDirSpec {
	private static final String HOME_DIR = System.env."USERPROFILE" ?: System.env."HOME"
	private static final String XDG_DATA_HOME_DEFAULT = "$HOME_DIR/.local/share"
	private static final String XDG_CONFIG_HOME_DEFAULT = "$HOME_DIR/.config"
	private static final String XDG_STATE_HOME_DEFAULT  = "$HOME_DIR/.local/state"
	private static final String XDG_CACHE_HOME_DEFAULT = "$HOME_DIR/.cache"
	private static final String XDG_RUNTIME_DIR_DEFAULT  = "$HOME_DIR/.cache/certstrapper/run"

	static final Path XDG_DATA_HOME = testXDGAndReturnDir("XDG_DATA_HOME", XDG_DATA_HOME_DEFAULT)
	static final Path XDG_CONFIG_HOME = testXDGAndReturnDir("XDG_CONFIG_HOME", XDG_CONFIG_HOME_DEFAULT)
	static final Path XDG_STATE_HOME = testXDGAndReturnDir("XDG_STATE_HOME", XDG_STATE_HOME_DEFAULT)
	static final Path XDG_CACHE_HOME = testXDGAndReturnDir("XDG_CACHE_HOME", XDG_CACHE_HOME_DEFAULT)
	static final Path XDG_RUNTIME_DIR = testXDGAndReturnDir("XDG_RUNTIME_DIR", XDG_RUNTIME_DIR_DEFAULT)

	private static Path testXDGAndReturnDir(envTest, defaultPathString) {
		return Paths.get((System.getenv(envTest) ?: defaultPathString) + "/certstrapper")
	}
}