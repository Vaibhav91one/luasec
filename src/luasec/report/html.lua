-- Single-file HTML report with no external references, so it can be attached
-- to a CI run or opened offline from an air-gapped review machine.
local plain = require "luasec.report.plain"
local version = require "luasec.version"

local html = {}

local ESCAPES = {["&"] = "&amp;", ["<"] = "&lt;", [">"] = "&gt;", ['"'] = "&quot;", ["'"] = "&#39;"}

local function escape(str)
   return (tostring(str or ""):gsub("[&<>\"']", ESCAPES))
end

local function snippet_html(text)
   if not text then return "" end
   return "<code>" .. escape(text) .. "</code>"
end

function html.render(report, opts)
   opts = opts or {}
   local rows = {}

   for _, finding in ipairs(report) do
      rows[#rows + 1] = string.format([[
      <tr class="sev-%s">
        <td class="sev">%s</td>
        <td class="code">%s</td>
        <td class="loc">%s:%d:%d</td>
        <td class="msg">%s%s</td>
        <td class="cwe">%s</td>
        <td class="conf">%s</td>
      </tr>]], escape(finding.severity), escape(finding.severity), escape(finding.code),
      escape(finding.file or "source.lua"), finding.line or 0, finding.column or 0,
      escape(finding.message),
      finding.snippet and ("<div class='snip'>" .. snippet_html(finding.snippet) .. "</div>") or "",
      escape(finding.cwe and finding.cwe ~= "CWE-0" and finding.cwe or ""),
      escape(finding.confidence))
   end

   local counts = {}
   for _, finding in ipairs(report) do
      counts[finding.severity] = (counts[finding.severity] or 0) + 1
   end

   local summary = {}
   for _, severity in ipairs({"critical", "high", "medium", "low"}) do
      if counts[severity] then
         summary[#summary + 1] = string.format("<span class='pill sev-%s'>%d %s</span>",
            severity, counts[severity], severity)
      end
   end

   return table.concat({
      "<!doctype html><html><head><meta charset='utf-8'>",
      "<title>luasec report</title><style>",
      "body{font:14px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace;margin:2rem;color:#1c1c1c}",
      "h1{font-size:1.2rem}table{border-collapse:collapse;width:100%;margin-top:1rem}",
      "th,td{text-align:left;padding:.4rem .6rem;border-bottom:1px solid #e3e3e3;vertical-align:top}",
      "th{background:#f6f6f6}code{background:#f3f3f3;padding:0 .2rem}",
      ".sev-critical{color:#8b0000;font-weight:700}.sev-high{color:#b3400a;font-weight:600}",
      ".sev-medium{color:#8a6d00}.sev-low{color:#555}",
      ".pill{display:inline-block;padding:.1rem .5rem;border-radius:1rem;background:#eee;margin-right:.4rem}",
      ".snip{margin-top:.3rem;color:#555}code{word-break:break-all}",
      "</style></head><body>",
      "<h1>luasec " .. escape(version.luasec) .. " report</h1>",
      "<p>" .. (#summary > 0 and table.concat(summary, " ") or "no findings") .. "</p>",
      "<table><thead><tr><th>severity</th><th>code</th><th>location</th><th>message</th>",
      "<th>cwe</th><th>confidence</th></tr></thead><tbody>",
      table.concat(rows),
      "</tbody></table>",
      "</body></html>",
   }, "\n")
end

return html
