local update_ips_time		= 10
local ip_whitelist 			= ngx.shared.ip_whitelist
local last_update_time 		= ip_whitelist:get("last_update_time")
local cache_ttl				= 60
local redis_connect_timeout = 1000
local redis_host			= "127.0.0.1"
local redis_port			= 6379
local redis_key             = "white_list_sets"
local new_ip_whitelist_dict = "new_ip_whitelist_dict"
local ngx_re_gmatch         = ngx.re.gmatch
local delimiter             = ":"
local ip_regexp             = "([0-9]+.[0-9]+.[0-9]+.[0-9]+(/[0-9]+)?)"
local iputils 				=  require "resty.iputils"
iputils.enable_lrucache()


local _M = { version = '1.0' }

local mt = {
  __index = _M
}

function _M.update_white_ips()
-- only update ip_whitelist from Redis once every cache_ttl seconds:
	if last_update_time == nil or last_update_time < ( ngx.now() - cache_ttl ) then
	
		local redis = require "resty.redis";
		local red = redis:new();
		
		red:set_timeout(redis_connect_timeout);
		
		local ok, err = red:connect(redis_host, redis_port);
		if not ok then
			ngx.log(ngx.ERR, "Redis connection error while retrieving ip_whitelist: " .. err);
		else
			local new_ip_whitelist, err = red:smembers(redis_key);
            local str_new_ip_whitelist = table.concat(new_ip_whitelist, delimiter)
            -- ngx.log(ngx.ERR, "parse_counts: " .. table.getn(new_ip_whitelist).." new_ip: "..table.concat(new_ip_whitelist, delimiter))
			if not redis_connect_timeout then
				ngx.log(ngx.ERR, "Redis read error while retrieving ip_whitelist: " .. err);
			else
				-- replace the locally stored ip_whitelist with the updated values:
				
				ip_whitelist:flush_all();
			 	local succ, err, forcible = ip_whitelist:set(new_ip_whitelist_dict, str_new_ip_whitelist)
                if not succ then
                    ngx.log(ngx.ERR, "store to shared memery failed: " .. err)
                end
			-- update time
				ip_whitelist:set("last_update_time", end_update_time);
			end
		end
	end
end

_M.handler = function (premature)
    if premature then
        return
    end
    _M.update_white_ips()
    local ok, err = ngx.timer.at(update_ips_time, _M.handler)
    if not ok then
		ngx.log(ngx.ERR, "failed to create then: ", err)
		return
	end
end

function _M.do_task()
	local ok, err = ngx.timer.at(update_ips_time, _M.handler)
	if not ok then
		ngx.log(ngx.ERR, "failed to create the timer: ", err)
		return
	end
end

-- get ip list and transfer to table from ngx.shared.DICT
function _M.str2table(str, delimiter)
    local list_table = {}
    local iter, err = ngx.re.gmatch(str, delimiter, "io")
    while true do
        local m, err = iter()
        if err then
            ngx.log(ngx.ERR, "error: "..err)
            return
        end
        if not m then
            break
        end
        table.insert(list_table, m[0])
    end
    return list_table
end

function _M.get_ip_white_list_table(new_ip_whitelist_dict, regexp)
	local ip_whitelist_sets, flag = ip_whitelist:get(new_ip_whitelist_dict)
    local regexp = regexp or ip_regexp
	local list_table = _M.str2table(ip_whitelist_sets, regexp)
	return list_table
end
-- test table
--for _, i in pairs(white_list_table) do
--    ngx.say(i)
--end


function _M.checkIp(ip, cidr_table_list)
    local parse_whitelist_table = iputils.parse_cidrs(cidr_table_list)
    if not (iputils.ip_in_cidrs(ip, parse_whitelist_table)) then
        ngx.log(ngx.ERR, "Banned IP detected and refused access: " .. ip)
        if ngx.req.get_method() == 'POST' then
            ngx.header.content_type = "text/javascript";
            return ngx.print('{"ec":403,"em":"access denied"}');
        else
            ngx.status = 403;
            ngx.header.content_type = "text/plain";
    -- return ngx.print("access denied");
            return ngx.exit(ngx.HTTP_FORBIDDEN);
        end
    else
        ngx.say("success")
    end
end

-- use
-- checkIp(ip, white_list_table)

return _M

-- use
--[[
local ip = ngx.var.remote_addr
local white_list_table = get_ip_white_list_table(new_ip_whitelist_dict, ip_regexp)
checkIp(ip, white_list_table)
--]]
