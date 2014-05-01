local basexx  = require 'basexx'
local json    = require 'cjson'

local data    = {}

function data:encode(header, claims)
  return basexx.to_base64(json.encode(claims))
end

function data:decode(header, str)
  local dotFirst = str:find("%.")
  str = str:sub(dotFirst+1)
  return json.decode(basexx.from_base64(str))
end

return data
