-- The luasec signature pack: known exploits and malware, as data.
--
-- This file is a declaration and nothing else. `luasec` requires it, matches
-- every pattern in it against the file being analyzed, and reports a 750 for
-- each signature that matches. Adding a signature is a data change, and so is
-- retiring one.

-- luasec: ignore 750
-- Every string below is a signature, so this file matches every signature it
-- holds. That is the one file in the tree where the finding is true and the
-- finding is not news, and the directive says so where a reader of the file
-- will see it.
--
-- The directive has to be the first line of its own run of comment lines: the
-- parser folds consecutive `--` lines into one comment, and a folded one is no
-- longer a directive.

-- Shape of a signature:
--
--   id           stable identifier, reported as the finding's `signature` and
--                used as the yara rule's `id` meta
--   description  what it is, in one line, for the person reading the report
--   pattern      the text to look for. Alternatives are separated by `|`, and
--                every alternative is matched as a plain substring: no pattern
--                syntax, so no alternative can be made to backtrack
--   reference    where the string comes from, so a reader can check it
--
-- Matching is case sensitive, and the same in the yara ruleset, so that the two
-- cannot disagree about what a signature is. See docs/signatures.md.

local pack = {
   version = "2026.09.1",
   signatures = {
      {
         id = "mirai-default-credentials",
         description = "Mirai scanner default credential from the botnet's credential table",
         pattern = "vizxv|xc3511|Zte521|hi3518|juantech|jvbzd|anko|7ujMko0admin|xmhdipc",
         reference = "Mirai source, scanner/scanner.c TABLE_SCAN_CREDENTIALS",
      },
      {
         id = "mirai-user-agent",
         description = "Mirai's default HTTP User-Agent, sent by every scan request",
         pattern = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
            .. "Chrome/51.0.2704.103 Safari/537.36",
         reference = "Mirai source, scanner.c TABLE_SCAN_CB_USER_AGENT",
      },
      {
         id = "mirai-loader-paths",
         description = "file name or command string used by Mirai variants to install themselves",
         pattern = "/bin/busybox MIRAI|/tmp/.mirai|/var/run/mirai.pid",
         reference = "Mirai source, scanner.c and killer.c",
      },
      {
         id = "shellshock-cgi-environment",
         description = "Shellshock (CVE-2014-6271) environment prefix or Bash function export",
         pattern = "() { :; };|BASH_FUNC_|HTTP_PROXY=|HTTP_USER_AGENT=",
         reference = "CVE-2014-6271, the CGI request header form of the exploit",
      },
      {
         id = "cve-2017-17215-huawei-hg532",
         description = "Huawei HG532 router remote code execution, the DeviceUpgrade endpoint",
         pattern = "/ctrlt/DeviceUpgrade_1|setNewpwd",
         reference = "CVE-2017-17215, the SOAP request the published exploit sends",
      },
      {
         id = "cve-2018-10561-dlink-gpon",
         description = "D-Link and GPON router SOAPAction remote code execution",
         pattern = "NewStatusURL|AddPortMapping|urn:dslforum-org:service:WANCommonInterfaceConfig:1",
         reference = "CVE-2018-10561, the SOAPAction and body of the published exploit",
      },
      {
         id = "dvr-cgi-path-traversal",
         description = "path traversal through a DVR CGI to reach /etc/passwd, the Zollard entry",
         pattern = "/language/../../../../../../../etc/passwd|POST /language/",
         reference = "Zollard worm, the MVPower DVR traversal it was written for",
      },
      {
         id = "miner-stratum-pool",
         description = "mining pool endpoint, as named in a coin-miner configuration",
         pattern = "stratum+tcp://|cryptonight|cryptonight-lite",
         reference = "the stratum protocol URI every major coin miner is configured with",
      },
      {
         id = "cobalt-strike-default-uri",
         description = "Cobalt Strike default beacon URI, present in the stock malleable profile",
         pattern = "/submit.php?id=|/pixel.gif|Microsoft-CIS",
         reference = "Cobalt Strike default HTTP profile",
      },
   },
}

return pack
