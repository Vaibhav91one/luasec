-- ESP8266/ESP32 firmware: node, dofile and the Lua interpreter are reachable
-- from the web server, and the flash layout is the target.
return {
   name = "espressif",
   sources = {
      {pattern = "node:getArgument", id = "node:getArgument", name = "HTTP request argument",
         confidence = "certain"},
      {pattern = "httpServerRequest*", id = "http.request", name = "HTTP request", confidence = "high"},
      {pattern = "mqtt.getMessage", id = "mqtt.getMessage", name = "MQTT payload", confidence = "high"},
   },
   sinks = {
      {pattern = "node:exec", code = "701", kind = "exec", arg = {1}},
      {pattern = "file.remove", code = "726", kind = "destructive", arg = {1}},
      {pattern = "file.open", code = "721", kind = "flash", arg = {1}},
   },
   propagators = {},
   sanitizers = {shell = {}, dyncode = {}, path = {}},
}
