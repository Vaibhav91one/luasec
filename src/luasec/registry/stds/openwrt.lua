-- OpenWrt: the Lua layer shipped in the router firmware itself.
return {
   name = "openwrt",
   sources = {
      {pattern = "uci.get", id = "uci.get", name = "OpenWrt UCI value", confidence = "high"},
      {pattern = "uci.get.*", id = "uci.get", name = "OpenWrt UCI value", confidence = "high"},
      {pattern = "uci.get_all", id = "uci.get_all", name = "OpenWrt UCI config", confidence = "high"},
      {pattern = "uci.get_bool", id = "uci.get_bool", name = "OpenWrt UCI value", confidence = "high"},
      {pattern = "uci.get_first", id = "uci.get_first", name = "OpenWrt UCI value", confidence = "high"},
      {pattern = "luci.model.uci.get", id = "luci.model.uci.get", name = "LuCI UCI value", confidence = "high"},
      {pattern = "luci.model.uci.get_all", id = "luci.model.uci.get", name = "LuCI UCI config", confidence = "high"},
      {pattern = "ubus.call", id = "ubus.call", name = "ubus RPC result", confidence = "medium"},
      {pattern = "ubus.call.*", id = "ubus.call", name = "ubus RPC result", confidence = "medium"},
      {pattern = "ubus.connect", id = "ubus.connect", name = "ubus connection", confidence = "medium"},
      {pattern = "nixio.getenv", id = "nixio.getenv", name = "process environment", confidence = "medium"},
   },
   sinks = {
      -- nixio's process functions, all three, read out of
      -- corpus/luci-1806/libs/luci-lib-nixio/src/process.c:
      --
      --   325  static int nixio_exec(lua_State *L)  { return nixio__exec(L, NIXIO_EXECV); }
      --   329  static int nixio_execp(lua_State *L) { return nixio__exec(L, NIXIO_EXECVP); }
      --   333  static int nixio_exece(lua_State *L) { return nixio__exec(L, NIXIO_EXECVE); }
      --
      -- One implementation and three entry points, and process.c:31 reads the
      -- command from position 1 for all three: `luaL_checkstring(L, 1)` is the
      -- path, handed to execv, execvp or execve depending on which was called,
      -- and the second argument is the next argv element or -- for exece -- the
      -- argv table. So the command is FIRST in every form, and a declaration
      -- written for one of them is the declaration for the rest.
      --
      -- They are declared one by one because firmware code calls them one by
      -- one, and a call to an undeclared one was invisible: execp and exece
      -- reported nothing at all and scored 100/100, on a sink that reaches
      -- execve. Real code calls one of them --
      -- luci-app-nlbwmon/luasrc/controller/nlbw.lua:46 is
      -- `nixio.exece(cmd, args, nil)`, a command run through a pipe in a stock
      -- LuCI controller.
      {pattern = "nixio.execp", code = "701", kind = "exec", arg = {1}},
      {pattern = "nixio.exece", code = "701", kind = "exec", arg = {1}},
      -- `nixio.exec` is overloaded and the two forms disagree about where the
      -- command is:
      --     nixio.exec(command)                  -- first
      --     nixio.exec("/bin/sh", "-c", command)  -- third, and the dangerous one
      -- Declaring only the first left every shell call silent, which is the form
      -- OpenWrt code actually writes. Both positions are declared, so both
      -- report.
      --
      -- What this over-approximates: a third argument of a DIRECT call is an
      -- argv element, and nixio.exec hands it to execvp rather than to a shell,
      -- so `nixio.exec("/usr/bin/tool", "--label", tainted)` is reported where
      -- nixio itself treats it as an option. No corpus file does that. Telling
      -- the two forms apart needs a per-position guard -- position 3 counting
      -- only when position 2 is the literal "-c" -- and the sink declaration has
      -- no field for one.
      {pattern = "nixio.exec", code = "701", kind = "exec", arg = {1, 3}},
      -- There is deliberately no `nixio.process.*` entry. Two were declared --
      -- `nixio.process.exec` and `nixio.process.execute` -- and neither could
      -- ever match anything, because `nixio.process` is not a namespace:
      --
      --   process.c:448  void nixio_open_process(lua_State *L) {
      --                      luaL_register(L, NULL, R);
      --                  }
      --
      -- No `lua_newtable()`, no `lua_setfield(L, -2, "process")`: the table is
      -- the one already on the stack, which is `nixio`. Ten of nixio's
      -- seventeen openers are written that way and three are not -- fs.c:550
      -- does push a table and name it "fs", and that one really is `nixio.fs` --
      -- so the distinction has to be read off the source rather than inferred
      -- from a file name. The exports are therefore `nixio.exec`, `nixio.execp`,
      -- `nixio.exece`, `nixio.fork`, `nixio.getenv` and the rest, at the top
      -- level. Three independent corroborations: the library's own docsrc
      -- documents `@name nixio.exec` and ships no `nixio.process.*` page;
      -- `grep -rn "nixio\.process" --include=*.lua corpus/` returns nothing
      -- while `nixio.exec` appears in eight files; and luci-lua-runtime's
      -- sys.lua:30 reads `getenv = nixio.getenv` at the top level.
      --
      -- `nixio.process.execute` was wrong twice over: nixio exports no
      -- `execute` at all, because process.c:440-442 registers exec, execp and
      -- exece and nothing else. test/spec/registry_export_spec.lua now derives
      -- the exported names from the corpus's C sources and fails on any
      -- declaration that is not one of them, so neither spelling can return.
      -- luaposix, and the reason these three are not declared the way nixio's
      -- are. `posix.exec` and `posix.spawn` are the same shape of claim:
      -- `arg = {1}` says the command is the first argument, and #268's audit
      -- flagged that the shell form of luaposix's exec takes the file third.
      -- That is shape-based inference, not proof, and it could not be settled
      -- here: luaposix is not in corpus/. `find corpus -iname "*posix*"`
      -- returns `tools/include/asm/posix_types.h` and one gnulib patch and no
      -- binding at all, and no corpus Lua file mentions `posix.`, so there is
      -- nothing to derive the signature from and
      -- test/spec/registry_export_spec.lua deliberately reports these three as
      -- "the corpus implements no such namespace" rather than guessing.
      --
      -- They are left as they are rather than changed on a guess. Reading
      -- luaposix's posix/exec.c is the only thing that settles it, and that is
      -- a fetch this repo does not do.
      {pattern = "posix.exec", code = "701", kind = "exec", arg = {1}},
      {pattern = "posix.exec.*", code = "701", kind = "exec", arg = {1}},
      {pattern = "posix.spawn", code = "701", kind = "exec", arg = {1}},
      {pattern = "luci.sys.call", code = "701", kind = "exec", arg = {1}},
      {pattern = "luci.util.uci.*", code = "722", kind = "config", arg = {2, 3, 4}},
      {pattern = "uci.set", code = "722", kind = "config", arg = {4}},
      {pattern = "uci.add", code = "722", kind = "config", arg = {4}},
      {pattern = "uci.sets", code = "722", kind = "config", arg = {2}},
   },
   propagators = {
      {pattern = "luci.util.pcdata", arg = {1}},
      {pattern = "luci.sys.uniqueid", arg = {}},
      {pattern = "jsonc.parse", arg = {1}},
      {pattern = "json.decode", arg = {1}},
      {pattern = "cjson.decode", arg = {1}},
      {pattern = "nixio.fs.readfile", arg = {1}},
   },
   sanitizers = {
      shell = {"luci.util.shellquote"},
      dyncode = {},
      path = {},
   },
}
