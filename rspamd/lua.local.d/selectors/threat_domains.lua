--[[
rspamd-threat-multimap: the `threat_domains` selector.

Install as $LOCAL_CONFDIR/lua.local.d/selectors/threat_domains.lua
(rspamd 3.12+ loads lua.local.d/selectors/*.lua, lua_extras).

Returns the names a message points at, for one multimap rule
(local.d/multimap.conf, THREAT_DOMAIN) to look up in threat.map:

  urls     every URL host in the message: text and HTML parts, mailto:
           addresses, and the URLs rspamd finds in attachments it reads
           (PDF, Office); not images
  senders  the SMTP sender's domain, the From: and Reply-To: domains

Each host comes with its parents down to the registrable domain, so a
listed evil.example matches www.evil.example and a.b.evil.example, as a
DNS wildcard would; a listed sub.host.example matches only under itself.
The public suffix (com, co.uk, or a hosting suffix such as
blogspot.com) is never looked up.

  threat_domains             urls and senders
  threat_domains('urls')     urls only
  threat_domains('senders')  senders only

MIT licensed, see LICENSE.
]]

local rspamd_util = require "rspamd_util"
local rspamd_logger = require "rspamd_logger"

-- Parent names per host: deeper names are not worth the lookups
local MAX_DEPTH = 8

local function add_host(out, seen, host)
  if type(host) ~= 'string' or host == '' then
    return
  end
  host = host:lower():gsub('%.$', '')
  -- IP literals and single labels are never in the map
  if host:find('[:%[%]]') or host:match('^[%d.]+$') or not host:find('.', 1, true) then
    return
  end
  local tld = rspamd_util.get_tld(host)
  if type(tld) ~= 'string' or tld == '' or #tld > #host then
    tld = host
  end
  local name = host
  for _ = 1, MAX_DEPTH do
    if not seen[name] then
      seen[name] = true
      out[#out + 1] = name
    end
    if #name <= #tld then
      break
    end
    name = name:match('^[^.]+%.(.+)$')
    if not name then
      break
    end
  end
end

local function add_addrs(out, seen, addrs)
  if type(addrs) ~= 'table' then
    return
  end
  for _, a in ipairs(addrs) do
    if type(a) == 'table' and a.domain then
      add_host(out, seen, a.domain)
    end
  end
end

local function get_value(task, args)
  local what = args and args[1] or 'all'
  if what ~= 'all' and what ~= 'urls' and what ~= 'senders' then
    rspamd_logger.errx(task, "threat_domains: unknown argument '%s' (urls, senders)", what)
    return nil
  end
  local out, seen = {}, {}

  if what == 'all' or what == 'urls' then
    -- true: mailto: addresses too; images are left out by default
    local urls = task:get_urls(true)
    if urls then
      for _, u in ipairs(urls) do
        add_host(out, seen, u:get_host())
      end
    end
  end

  if what == 'all' or what == 'senders' then
    add_addrs(out, seen, task:get_from('smtp'))
    add_addrs(out, seen, task:get_from('mime'))
    local reply_to = task:get_header('Reply-To')
    if reply_to then
      add_addrs(out, seen, rspamd_util.parse_mail_address(reply_to, task:get_mempool()))
    end
  end

  if #out == 0 then
    return nil
  end
  return out, 'string_list'
end

return {
  threat_domains = {
    get_value = get_value,
    description = [[URL hosts and sender domains, each with its parents
down to the registrable domain (rspamd-threat-multimap).
Argument: 'urls', 'senders' or none for both]],
  },
}
