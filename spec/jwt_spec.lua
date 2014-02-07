describe("JWT spec", function()

  local jwt = require 'jwt'
  local plainJwt = "eyJhbGciOiJub25lIn0.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"

  it("can decode a plain text token", function()
    local token, msg = jwt.decode(plainJwt)
    assert(token or error(msg))
    assert(token.iss == "joe")
    assert(token.exp == 1300819380)
    assert(token["http://example.com/is_root"] == true)
  end)

  it("can decode a plain text token with an extra dot", function()
    local token, msg = jwt.decode(plainJwt..".")
    assert(token or error(msg))
    assert(token.iss == "joe")
    assert(token.exp == 1300819380)
    assert(token["http://example.com/is_root"] == true)
  end)

  it("can encode a plain text token", function()
    local claim = {
      iss = "joe",
      exp = 1300819380,
      ["http://example.com/is_root"] = true
    }
    local token = jwt.encode(claim)
    local token2 = jwt.encode(jwt.decode(plainJwt))
    assert(token == token2)
  end)

  it("it can encode/decode a signed plain text token with alg=HS256", function()
    local claims = {
      test = "test",
    }
    local token = jwt.encode(claims, "HS256", "key")
    local decodedClaims = jwt.decode(token, "key")
    assert.are.same(claims, decodedClaims)
  end)
end)
