local meta = {}
local crypto = require 'crypto'
local basexx  = require 'basexx'
local json    = require 'cjson'

local data = {
  alg_type = {
    ['HS256'] = function(data, key) return crypto.hmac.digest('sha256', data, key) end,
    ['HS384'] = function(data, key) return crypto.hmac.digest('sha384', data, key) end,
    ['HS512'] = function(data, key) return crypto.hmac.digest('sha512', data, key) end,
    ['none']  = function(data) return data end,
  },
}

local function header(alg, enc)
  local cty = nil
  local typ = "JWT"
  if not alg and not enc then cty = "JWT" end
  return {
    typ = typ,
    alg = alg,
  }
end

function meta:__metatable()
  return false
end

function meta:__index(key)
  return data[key]
end

function data.encode(claims, alg, alg_key)
  if alg and not data.alg_type[alg] then return nil, "Parameter 2 must be a registered MAC algorithm" end
  local header    = json.encode(header(mac, enc))
  local claims    = json.encode(claims)
  local signature = nil

  local jwt = basexx.to_base64(header).."."..basexx.to_base64(claims)
  if alg then
    signature = data.alg_type[alg](claims, alg_key)
    jwt = jwt .. "." .. basexx.to_base64(signature)
  end
  return jwt
end

function data.decode(str, key)
  if not str then return nil, "Parameter 1 cannot be nil" end
  local dotFirst = str:find("%.")
  if not dotFirst then return nil, "Invalid token" end
  local header = json.decode(basexx.from_base64(str:sub(1, dotFirst)))

  local dotSecond = str:find("%.", dotFirst+1)
  local claims = basexx.from_base64(str:sub(dotFirst+1,dotSecond))

  local signature
  if alg and dotSecond then
    signature = basexx.from_base64(str:sub(dotSecond+1))
    if signature then
      local data_sig = data.alg_type[alg](claims, key)
      if data_sig ~= signature then
        return nil, "Invalid token"
      end
    end
  end

 return json.decode(claims)
end

function meta:__newindex(key)
  error('Read Only')
end

return setmetatable({}, meta)
