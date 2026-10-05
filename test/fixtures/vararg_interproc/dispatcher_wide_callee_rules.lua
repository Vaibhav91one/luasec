-- A dispatcher profile for the wide-callee case, scoped to one function so the
-- only route from request data to the sink is the forward.
return {
   name = "dispatcher-wide-callee",
   entry_points = {
      {pattern = "handler", arg = "*", confidence = "medium", channel = "web"},
   },
}
