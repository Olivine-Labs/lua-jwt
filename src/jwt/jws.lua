local basexx  = require 'basexx'
local json    = require 'cjson'
local crypto  = require 'crypto'

local data    = {}

data.sign = {
  ['HS256'] = function(data, key) return crypto.hmac.digest('sha256', data, key) end,
  ['HS384'] = function(data, key) return crypto.hmac.digest('sha384', data, key) end,
  ['HS512'] = function(data, key) return crypto.hmac.digest('sha512', data, key) end,
  ['RS256'] = function(data, key) return crypto.sign("sha256", data, key) end,
}

data.verify = {
  ['HS256'] = function(data, signature, key) return signature == crypto.hmac.digest('sha256', data, key) end,
  ['HS384'] = function(data, signature, key) return signature == crypto.hmac.digest('sha384', data, key) end,
  ['HS512'] = function(data, signature, key) return signature == crypto.hmac.digest('sha512', data, key) end,
  ['RS256'] = function(data, signature, key) return crypto.verify("sha256", data, signature, key) end,
}

function data:encode(claims, options)
  if not options then error("options are required") end
  local claims    = json.encode(claims)
  local signature, err = self.sign[options.alg](claims, options.keys.private)
  if not signature then return nil, err end
  return basexx.to_base64(claims).. "." .. basexx.to_base64(signature)
end

function data:decode(header, str, options)
  local dotFirst = str:find("%.")
  local signature
  local bodyStr
  if dotFirst then
    bodyStr       = str:sub(1, dotFirst)
    signature     = basexx.from_base64(str:sub(dotFirst+1))
  else
    bodyStr = str
  end

  local message = basexx.from_base64(bodyStr)

  if signature then
    if not self.verify[header.alg](message, signature, options.keys.public) then
      return nil, "Invalid token"
    end
  end

  return json.decode(message)
end

return data
