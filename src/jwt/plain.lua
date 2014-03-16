local basexx  = require 'basexx'
local json    = require 'cjson'

local data    = {}

function data:encode(claims)
  return basexx.to_base64(json.encode(claims))
end

function data:decode(header, str)
  return json.decode(basexx.from_base64(str))
end

return data
