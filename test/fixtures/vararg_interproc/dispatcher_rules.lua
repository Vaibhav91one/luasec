-- A dispatcher profile, scoped to one function.
--
-- The luci profile declares `{pattern = "*", file = "*/controller/*.lua"}`,
-- which makes *every* function under a controller directory an entry point. A
-- fixture placed there therefore reports the 709 from `execute_command`'s own
-- seeded vararg and never from the forward, so it passes with or without the
-- binding under test. Naming one entry point here is what makes the difference
-- visible: `execute_command` and `parse_cmdline` are ordinary functions, and the
-- only route from request data to the sink is the forward.
--
-- `arg = "*"` is what a dispatcher with an unknown arity declares, so the
-- handler's vararg is seeded rather than its (absent) named parameters.
return {
   name = "dispatcher-forward",
   entry_points = {
      {pattern = "action_run", arg = "*", confidence = "medium", channel = "web"},
   },
}