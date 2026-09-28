-- Fixture: a module installed through package.preload, which is how firmware
-- packages hand a module to the loader without a file named after it.
package.preload["preloaded_util"] = function(...)
   local M = {}

   function M.run(cmd)
      os.execute(cmd)
   end

   return M
end
