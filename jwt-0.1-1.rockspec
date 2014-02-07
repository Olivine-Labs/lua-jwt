package = "jwt"
version = "0.1-1"
source = {
  url = "https://github.com/Olivine-Labs/lua-jwt/archive/v0.1.tar.gz",
  dir = "lua-jwt-0.1"
}
description = {
  summary = "A library for encoding and decoding json web tokens.",
  detailed = [[
    
  ]],
  homepage = "",
  license = "MIT <http://opensource.org/licenses/MIT>"
}
dependencies = {
  "lua >= 5.1",
  "busted >= 1.7-1"
}
build = {
  type = "builtin",
  modules = {
    ["jwt"]  = "src/jwt.lua"
  }
}
