-- Single-file HTML report with no external references, so it can be attached
-- to a CI run or opened offline from an air-gapped review machine. Everything
-- the page needs is in the page: no script, no stylesheet link, no image, no
-- font fetched over the network. A report that pulls anything cannot be opened
-- where the finding was found, which is usually the interesting machine.
--
-- Findings are grouped by severity, worst first, because a reviewer opens this
-- to answer "is anything critical" and a critical finding in the middle of a
-- long table is a critical finding nobody reads.
--
-- Everything that comes from an analyzed file - the message, the file name, the
-- snippet, the CWE - is escaped. A scanned file is untrusted input: a report
-- that pastes a message into a page unescaped turns a scanned file into script
-- running in the reviewer's browser, which is the last thing a security report
-- should do.
local plain = require "luasec.report.plain"
local version = require "luasec.version"

local html = {}

local ESCAPES = {["&"] = "&amp;", ["<"] = "&lt;", [">"] = "&gt;", ['"'] = "&quot;", ["'"] = "&#39;"}

local function escape(str)
   return (tostring(str or ""):gsub("[&<>\"']", ESCAPES))
end

local SEVERITIES = {"critical", "high", "medium", "low"}

-- A fixed finding is history: it is marked, not dropped, and struck through so
-- it cannot be read as a live problem.
local STYLE = [[
:root{color-scheme:light dark}
body{font:14px/1.55 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;margin:2rem;color:#1c1c1c;background:#fff}
h1{font-size:1.15rem;margin:0 0 .2rem}
.sub{color:#666;margin:0 0 1.2rem;font-size:.85rem}
h2{font-size:.95rem;margin:1.6rem 0 .5rem;padding-bottom:.25rem;border-bottom:1px solid #e3e3e3}
table{border-collapse:collapse;width:100%}
th,td{text-align:left;padding:.4rem .6rem;border-bottom:1px solid #eee;vertical-align:top}
th{background:#f6f6f6;font-weight:600}
td.loc{white-space:nowrap;color:#444}
td.code,td.cwe,td.conf{white-space:nowrap}
td.msg{width:100%}
code{background:#f3f3f3;padding:0 .2rem;border-radius:2px}
.snip{display:block;margin-top:.3rem;color:#555;white-space:pre-wrap;word-break:break-all}
.flow{margin:.4rem 0 0;padding-left:1rem;border-left:2px solid #dcdcdc;list-style:none}
.flow li{padding:.15rem 0}
.flow .arrow{color:#999;padding:0 .35rem}
.pill{display:inline-block;padding:.1rem .55rem;border-radius:1rem;background:#eee;margin:0 .3rem .3rem 0;color:#333}
.pill.critical{background:#8b0000;color:#fff}
.pill.high{background:#f6d5cc;color:#7a2c06}
.pill.medium{background:#fbf0c4;color:#6b5400}
.pill.low{background:#eee;color:#444}
.sev-critical{color:#8b0000;font-weight:700}
.sev-high{color:#a33808;font-weight:600}
.sev-medium{color:#6b5400}
.sev-low{color:#555}
.empty{color:#666;font-style:italic}
.sev-fixed{opacity:.6}
.sev-fixed td.msg{text-decoration:line-through}
]]

-- The taint path, source first and sink last, as the chain the data took. This
-- is the reason the report exists in this form: "untrusted data reaches command
-- execution" is a claim, and these are the lines that make it.
local function flow_html(finding)
   if not finding.trace or #finding.trace == 0 then return "" end

   local items = {}
   for index, step in ipairs(finding.trace) do
      if index > 1 then
         items[#items + 1] = "<li><span class='arrow'>&rarr;</span></li>"
      end
      items[#items + 1] = string.format(
         "<li><b>%s</b> %s <span class='loc'>%s:%d</span></li>",
         escape(step.kind),
         escape(step.name ~= "" and step.name or step.kind),
         escape(finding.file ~= "" and finding.file or "source.lua"),
         step.line)
   end

   return "<ol class='flow'>" .. table.concat(items) .. "</ol>"
end

local function row_html(finding)
   local snippet = finding.snippet and finding.snippet ~= ""
      and "<span class='snip'><code>" .. escape(finding.snippet) .. "</code></span>" or ""

   -- A fixed finding is history: it is marked, not dropped, and struck through so
   -- it cannot be read as a live problem.
   local fixed = finding.status == "fixed"
   local badge = fixed and "<span class='pill'>fixed</span>" or ""

   return table.concat({
      "<tr class='row sev-", escape(finding.severity), fixed and " sev-fixed" or "", "'>",
      "<td class='code'>", escape(finding.code), badge, "</td>",
      "<td class='loc'>", escape(finding.file ~= "" and finding.file or "source.lua"),
      ":", tostring(finding.line), ":", tostring(finding.column), "</td>",
      "<td class='msg'>", escape(finding.message),
      snippet,
      flow_html(finding),
      "</td>",
      "<td class='cwe'>", escape(finding.cwe ~= "CWE-0" and finding.cwe or ""), "</td>",
      "<td class='conf'>", escape(finding.confidence), "</td>",
      "</tr>",
   }, "")
end

function html.render(report, opts)
   opts = opts or {}

   local by_severity = {}
   for _, finding in ipairs(report) do
      local severity = finding.severity
      by_severity[severity] = by_severity[severity] or {}
      table.insert(by_severity[severity], finding)
   end

   local pills, sections = {}, {}
   for _, severity in ipairs(SEVERITIES) do
      local group = by_severity[severity]
      if group and #group > 0 then
         pills[#pills + 1] = string.format("<span class='pill %s'>%d %s</span>",
            escape(severity), #group, escape(severity))
      end
   end
   for severity, _ in pairs(by_severity) do
      if not plain.severity_rank(severity) then
         pills[#pills + 1] = string.format("<span class='pill'>%d %s</span>",
            #by_severity[severity], escape(severity))
      end
   end

   for _, severity in ipairs(SEVERITIES) do
      local group = by_severity[severity]
      if group and #group > 0 then
         local rows = {}
         for _, finding in ipairs(group) do
            rows[#rows + 1] = row_html(finding)
         end
         sections[#sections + 1] = table.concat({
            "<h2>", escape(severity), " (", tostring(#group), ")</h2>",
            "<table><thead><tr><th>code</th><th>location</th><th>message</th>",
            "<th>cwe</th><th>confidence</th></tr></thead><tbody>",
            table.concat(rows),
            "</tbody></table>",
         }, "")
      end
   end

   return table.concat({
      "<!doctype html>",
      "<html lang='en'><head><meta charset='utf-8'>",
      "<meta name='viewport' content='width=device-width,initial-scale=1'>",
      "<title>luasec report</title>",
      "<style>", STYLE, "</style>",
      "</head><body>",
      "<h1>luasec ", escape(version.luasec), " report</h1>",
      "<p class='sub'>", tostring(#report), " finding",
      #report == 1 and "" or "s",
      #report == 0 and " - nothing to report" or "",
      "</p>",
      #pills > 0 and ("<p>" .. table.concat(pills) .. "</p>") or "",
      #sections > 0 and table.concat(sections) or "<p class='empty'>no findings</p>",
      "</body></html>",
   }, "\n")
end

return html
