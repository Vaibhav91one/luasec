// The lua-doctor signature pack, as yara rules.
//
// GENERATED CONTENT, CHECKED BY test/spec/signatures_spec.lua: every signature
// id in this file must also be in src/luadoctor/registry/stds/signatures.lua, and
// the two must list the same alternatives. Add a signature to the Lua pack and
// add its rule here, or the spec fails.
//
// pack version: 2026.09.1
//
// Each signature in the Lua pack is one rule here, and the two match the same
// text: a plain substring, case sensitive, with the alternatives of the pack's
// pattern separated by |. See docs/signatures.md.

rule lua_doctor_sig_mirai_default_credentials
{
   meta:
      id = "mirai-default-credentials"
      pack_version = "2026.09.1"
      description = "Mirai scanner default credential from the botnet's credential table"
      reference = "Mirai source, scanner/scanner.c TABLE_SCAN_CREDENTIALS"

   strings:
      $s1 = "vizxv"
      $s2 = "xc3511"
      $s3 = "Zte521"
      $s4 = "hi3518"
      $s5 = "juantech"
      $s6 = "jvbzd"
      $s7 = "anko"
      $s8 = "7ujMko0admin"
      $s9 = "xmhdipc"

   condition:
      any of them
}

rule lua_doctor_sig_mirai_user_agent
{
   meta:
      id = "mirai-user-agent"
      pack_version = "2026.09.1"
      description = "Mirai's default HTTP User-Agent, sent by every scan request"
      reference = "Mirai source, scanner.c TABLE_SCAN_CB_USER_AGENT"

   strings:
      $s1 = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36"

   condition:
      any of them
}

rule lua_doctor_sig_mirai_loader_paths
{
   meta:
      id = "mirai-loader-paths"
      pack_version = "2026.09.1"
      description = "file name or command string used by Mirai variants to install themselves"
      reference = "Mirai source, scanner.c and killer.c"

   strings:
      $s1 = "/bin/busybox MIRAI"
      $s2 = "/tmp/.mirai"
      $s3 = "/var/run/mirai.pid"

   condition:
      any of them
}

rule lua_doctor_sig_shellshock_cgi_environment
{
   meta:
      id = "shellshock-cgi-environment"
      pack_version = "2026.09.1"
      description = "Shellshock (CVE-2014-6271) environment prefix or Bash function export"
      reference = "CVE-2014-6271, the CGI request header form of the exploit"

   strings:
      $s1 = "() { :; };"
      $s2 = "BASH_FUNC_"
      $s3 = "HTTP_PROXY="
      $s4 = "HTTP_USER_AGENT="

   condition:
      any of them
}

rule lua_doctor_sig_cve_2017_17215_huawei_hg532
{
   meta:
      id = "cve-2017-17215-huawei-hg532"
      pack_version = "2026.09.1"
      description = "Huawei HG532 router remote code execution, the DeviceUpgrade endpoint"
      reference = "CVE-2017-17215, the SOAP request the published exploit sends"

   strings:
      $s1 = "/ctrlt/DeviceUpgrade_1"
      $s2 = "setNewpwd"

   condition:
      any of them
}

rule lua_doctor_sig_cve_2018_10561_dlink_gpon
{
   meta:
      id = "cve-2018-10561-dlink-gpon"
      pack_version = "2026.09.1"
      description = "D-Link and GPON router SOAPAction remote code execution"
      reference = "CVE-2018-10561, the SOAPAction and body of the published exploit"

   strings:
      $s1 = "NewStatusURL"
      $s2 = "AddPortMapping"
      $s3 = "urn:dslforum-org:service:WANCommonInterfaceConfig:1"

   condition:
      any of them
}

rule lua_doctor_sig_dvr_cgi_path_traversal
{
   meta:
      id = "dvr-cgi-path-traversal"
      pack_version = "2026.09.1"
      description = "path traversal through a DVR CGI to reach /etc/passwd, the Zollard entry"
      reference = "Zollard worm, the MVPower DVR traversal it was written for"

   strings:
      $s1 = "/language/../../../../../../../etc/passwd"
      $s2 = "POST /language/"

   condition:
      any of them
}

rule lua_doctor_sig_miner_stratum_pool
{
   meta:
      id = "miner-stratum-pool"
      pack_version = "2026.09.1"
      description = "mining pool endpoint, as named in a coin-miner configuration"
      reference = "the stratum protocol URI every major coin miner is configured with"

   strings:
      $s1 = "stratum+tcp://"
      $s2 = "cryptonight"
      $s3 = "cryptonight-lite"

   condition:
      any of them
}

rule lua_doctor_sig_cobalt_strike_default_uri
{
   meta:
      id = "cobalt-strike-default-uri"
      pack_version = "2026.09.1"
      description = "Cobalt Strike default beacon URI, present in the stock malleable profile"
      reference = "Cobalt Strike default HTTP profile"

   strings:
      $s1 = "/submit.php?id="
      $s2 = "/pixel.gif"
      $s3 = "Microsoft-CIS"

   condition:
      any of them
}

// vim: syntax=off