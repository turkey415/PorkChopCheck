#!/usr/bin/lua
-- Switches the router between Router and Access point mode with GL.iNet's own call (the one its
-- Network Mode page makes), so every setting is kept. It goes through `ubus call gl-session call`,
-- which runs the call inside GL.iNet's web server: set_mode needs that server's nginx Lua tools.
-- Run by the side switch (/etc/gl-switch.d/netmode.sh), the screen's Mode page and the phone page.
--
--   lua netmode.lua get            prints router, ap, ...
--   lua netmode.lua set router|ap  changes mode; progress goes to /tmp/pcc-netmode.json
--
-- Callers wrap it in `flock -n /var/lock/pcc-netmode.lock` so two changes never overlap.

local cjson = require "cjson"

local STATE = "/tmp/pcc-netmode.json"
local WAN = "eth0"
-- GL.iNet's error codes for set_mode, as its page explains them
local ERRORS = {
    [1] = "Could not connect",
    [2] = "No address from the network on WAN",
    [3] = "That network uses 192.168.8.x too",
}

local function write(t)
    t.t = os.time()
    local f = io.open(STATE .. ".tmp", "w")
    if not f then return end
    f:write(cjson.encode(t))
    f:close()
    os.rename(STATE .. ".tmp", STATE)
end

local function line(path)
    local f = io.open(path)
    if not f then return nil end
    local s = f:read("*l")
    f:close()
    return s
end

-- one GL.iNet call; returns the decoded reply ({result = ...}) or nil and the error text
local function gl(func, params, secs)
    local req = cjson.encode({ module = "netmode", func = func, params = params or {} })
    local p = io.popen("ubus -t " .. (secs or 10) .. " call gl-session call '" .. req .. "' 2>&1")
    local out = p:read("*a")
    p:close()
    local ok, res = pcall(cjson.decode, out)
    if ok and type(res) == "table" then return res end
    return nil, (out:gsub("%s+$", ""))
end

local function mode()
    local r = gl("get_mode")
    return r and type(r.result) == "table" and r.result.mode or nil
end

local cmd, want = arg[1], arg[2]
if cmd == "get" then
    print(mode() or "?")
    return
end
if cmd ~= "set" or (want ~= "router" and want ~= "ap") then
    io.stderr:write("usage: netmode.lua get | set router|ap\n")
    os.exit(2)
end

local now = mode()
if now == want then
    write({ state = "done", mode = now })
    return
end
-- GL.iNet's page refuses AP mode without a cable in WAN: the router needs an address from that network
if want == "ap" and line("/sys/class/net/" .. WAN .. "/carrier") ~= "1" then
    write({ state = "error", mode = now, want = want, error = "Plug a cable into WAN first" })
    os.exit(1)
end

write({ state = "changing", mode = now, want = want, since = os.time() })
-- GL.iNet's page allows a minute; the network restarts underneath, so allow a little more
local res, err = gl("set_mode", { mode = want }, 90)
local got = mode()
for _ = 1, 20 do  -- get_mode can fail for a moment while the network comes back
    if got then break end
    os.execute("sleep 1")
    got = mode()
end
if got == want then
    write({ state = "done", mode = got })
else
    local code = res and (res.err_code or (type(res.result) == "table" and res.result.err_code))
    local why = (code and (ERRORS[code] or ("GL.iNet error " .. tostring(code))))
        or (res and res.err_msg) or err
        or "The router stayed in " .. tostring(got) .. " mode"
    write({ state = "error", mode = got, want = want, error = why })
    os.exit(1)
end
