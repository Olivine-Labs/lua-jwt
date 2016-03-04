describe("JWT spec", function()

  local jwt  = require 'jwt'
  local pkey = require 'openssl.pkey'
  local plainJwt = "eyJhbGciOiJub25lIn0.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"

  it("can decode a plain text token", function()
    local token, msg = jwt.decode(plainJwt)
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
    local token = jwt.encode(claims, {alg = "HS256", keys = {private = "key"}})
    local decodedClaims = jwt.decode(token, {keys = {public = "key"}})
    assert.are.same(claims, decodedClaims)
  end)

  it("it cannot encode/decode a signed plain text token with alg=HS256 and an incorrect key", function()
    local claims = {
      test = "test",
    }
    local token = jwt.encode(claims, {alg = "HS256", keys = {private = "key"}})
    local decodedClaims = jwt.decode(token, {keys = {public = "notthekey"}})
    assert.has_error(function() assert.are.same(claims, decodedClaims) end)
  end)

  it("it can encode/decode a signed plain text token with alg=RS256", function()
    local claims = {
      test = "test",
      empty={},
    }
    local keyPair = pkey.new{type = "rsa", bits=512}
    local token, err = jwt.encode(claims, {alg = "RS256", keys = {private = keyPair}})
    local decodedClaims = jwt.decode(token, {keys = {public = keyPair}})
    assert.are.same(claims, decodedClaims)
  end)

  it("it cannot encode/decode a signed plain text token with alg=RS256 and an incorrect key", function()
    local claims = {
      test = "test",
    }
    local keyPair = pkey.new{type="rsa", bits=512}
    local badPair = pkey.new{type="rsa", bits=512}
    local token = jwt.encode(claims, {alg = "RS256", keys = {private = keyPair}})
    local decodedClaims = jwt.decode(token, {keys = {public = badPair}})
    assert.has_error(function() assert.are.same(claims, decodedClaims) end)
  end)

  it("can verify a signature", function()
    local token = "eyJhbGciOiJSUzI1NiJ9.eyJqdGkiOiJhOGZjZTFkZi1iNGFlLTRjNDEtYmFjNi1iNWJiZjI4MGMyOWMiLCJzdWIiOiI3YmZjNThlYy03N2RkLTQ4NzQtYmViZC1iYTg0MTAzMDEyNzkiLCJzY29wZSI6WyJvYXV0aC5hcHByb3ZhbHMiLCJvcGVuaWQiXSwiY2xpZW50X2lkIjoibG9naW4iLCJjaWQiOiJsb2dpbiIsImdyYW50X3R5cGUiOiJwYXNzd29yZCIsInVzZXJfaWQiOiI3YmZjNThlYy03N2RkLTQ4NzQtYmViZC1iYTg0MTAzMDEyNzkiLCJ1c2VyX25hbWUiOiJhZG1pbkBmb3Jpby5jb20iLCJlbWFpbCI6ImFkbWluQGZvcmlvLmNvbSIsImlhdCI6MTM5ODkwNjcyNywiZXhwIjoxMzk4OTQ5OTI3LCJpc3MiOiJodHRwOi8vbG9jYWxob3N0Ojk3NjMvdWFhL29hdXRoL3Rva2VuIiwiYXVkIjpbIm9hdXRoIiwib3BlbmlkIl19.xOa5ZpXksgoaA_XJ3yHMjlLcbSoM6XJy-e60zfyP7bRmu0EKEGZdZrl2iJVh6OTIn8z6UuvcY282C1A5LtRgpir4wqhIrphd-Mi9gfxra0pJvtydd4XqVpuNdW7GDaC43VXpvUtetmfn-YAo2jkD9G22mUuT2sFdt5NqFL7Rk4tVRILes73OWxfQpuoReWvRBik-sJXxC9ADmTuzR36OvomIrso42R8aufU2ku_zPve8IhYLvn3vHmYCt0zNZkX-jSV8YtGodr9V-dKs9na41YvGp2UxkBcV7LKoGSRELSSNJ8JLF-bjO3zYSSbT42-yeHeKfoWAeP6R7S_0c_AYRA"
    local key = [[-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3h3hbKXM40yH18djU0eM
asMIJ2jEtRn4DzJEcPvRDu+zFUzzNqSUFbD6pYIv/S+C31edIvyfi9kxMdZOKEIm
AHasLJ6PTBej+ruzIWHNf2Yse7+egXEit5bcKb3J9FOpCDHE+YjM4S9QaQT2hr30
Y7iIVcNURJn0k2T6HL+AVt0oUbupUdJjS9S5GUSQ0F74t74J9g7X4sOSTjl3RBxB
mUzfYor3w1HVwP+R0awAzSlNYZdWWJJM6aZXH76nqfv6blKTW0on12b71YWRWKYP
GxG1KwES6v5+PeLzlJDIDRcI8pl49fJYoXyasF8pskS63o9q8ibQspk+nzL9lD4E
EQIDAQAB
-----END PUBLIC KEY-----]]

    local claims = jwt.decode(token, {keys={public=key}})
    assert(claims)
  end)

  it("Is not fooled by modified tokens that claim to be unsigned", function()
    local encoded = 'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJpc3MiOiJodHRwczovL2p3dC1pZHAuZXhhbXBsZS5jb20iLCJzdWIiOiJtYWlsdG86bWlrZUBleGFtcGxlLmNvbSIsIm5iZiI6MTQ0NTQ3MDA3MywiZXhwIjoxNDQ1NDczNjczLCJpYXQiOjE0NDU0NzAwNzMsImp0aSI6ImlkMTIzNDU2IiwidHlwIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9yZWdpc3RlciJ9.NEbef_xsCzaLMU0Oh-Q_XLQyvF25vSIGlCcupi5-us05HFNhbTG7_2ElRmn0ew4DCBssT14GEU_8TjtcdmBkta7gCqKLF7X07UASVkL7lS_6VAu8lHGD4U4N-35AByu5gO2RQf5V3tt5WSpv2qABF4R_msF_qjZ8Ii8o_Fth6YxH6eDFgNAOCWwWwB3hvK2mJ6te9ZK04C00qc1U4xOFdO8geXaW7ohoXBCv1h8VT7sbsmyZ14ce6ASliHVCGjoXyXRGfFMQPKdJ5t4x_pSdH85MQn08nsYXIPCzMo3Fl2lFJyKbXLl3pMF1pwKpKpSxoCjbsWcjot1RmzpLbTcvfg'
    local token, err = jwt.decode(encoded)
    assert(not token)
    assert(err ~= nil)
  end)

  it("can encode and decode rs256", function()
    local keys = {
      private = pkey.new(
[[-----BEGIN RSA PRIVATE KEY-----
MIIBOwIBAAJBANfnFz7xPmYVdJxZE7sQ5quh/XUzB5y/D5z2A7KPYXUgUP0jd5yL
Z7+pVBcFSUm5AZXJLXH4jPVOXztcmiu4ta0CAwEAAQJBAJYXWNmw7Cgbkk1+v3C0
dyeqHYF0UD5vtHLxs/BWLPI2lZO0e6ixFNI4uIuatBox1Zbzt1TSy8T09Slt4tNL
CAECIQD6PHDGtKXcI2wUSvh4y8y7XfvwlwRPU2AzWZ1zvOCbbQIhANzgMpUNOZL2
vakju4sal1yZeXUWO8FurmsAyotAx9tBAiB2oQKh4PAkXZKWSDhlI9CqHtMaaq17
Yb5geaKARNGCPQIgILYrh5ufzT4xtJ0QJ3fWtuYb8NVMIEeuGTbSyHDdqIECIQDZ
3LNCyR2ykwetc6KqbQh3W4VkuatAQgMv5pNdFLrfmg==
-----END RSA PRIVATE KEY-----]]),
      public = pkey.new(
[[-----BEGIN PUBLIC KEY-----
MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBANfnFz7xPmYVdJxZE7sQ5quh/XUzB5y/
D5z2A7KPYXUgUP0jd5yLZ7+pVBcFSUm5AZXJLXH4jPVOXztcmiu4ta0CAwEAAQ==
-----END PUBLIC KEY-----]]),
    }
    local claims = {
      test = "test",
      longClaim = "iubvn1oubv91henvicuqnw93bn19u  ndij npkhabsdvlb23iou4bijbandlivubhql3ubvliuqwdbnvliuqwhv9ulqbhiulbiluabsdvuhbq9urbv9ubqubxuvbu9qbdshvuhqniuhv9uhbfq9uhr89hqu9ebnv9uqhu9rbvp9843$#BVCo²¸´no414i"
    }
    local token = jwt.encode(claims, {alg = "RS256", keys = keys})
    local decodedClaims, err = jwt.decode(token, {keys = keys})
    if not decodedClaims then error(err) end
    assert.are.same(claims, decodedClaims)
  end)

  it("does not throw an error when key is invalid in rs256", function()
    local keys = {
      private = pkey.new(
[[-----BEGIN RSA PRIVATE KEY-----
MIIBOwIBAAJBANfnFz7xPmYVdJxZE7sQ5quh/XUzB5y/D5z2A7KPYXUgUP0jd5yL
Z7+pVBcFSUm5AZXJLXH4jPVOXztcmiu4ta0CAwEAAQJBAJYXWNmw7Cgbkk1+v3C0
dyeqHYF0UD5vtHLxs/BWLPI2lZO0e6ixFNI4uIuatBox1Zbzt1TSy8T09Slt4tNL
CAECIQD6PHDGtKXcI2wUSvh4y8y7XfvwlwRPU2AzWZ1zvOCbbQIhANzgMpUNOZL2
vakju4sal1yZeXUWO8FurmsAyotAx9tBAiB2oQKh4PAkXZKWSDhlI9CqHtMaaq17
Yb5geaKARNGCPQIgILYrh5ufzT4xtJ0QJ3fWtuYb8NVMIEeuGTbSyHDdqIECIQDZ
3LNCyR2ykwetc6KqbQh3W4VkuatAQgMv5pNdFLrfmg==
-----END RSA PRIVATE KEY-----]]),
      public = pkey.new(
[[-----BEGIN PUBLIC KEY-----
MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBANfnFz7xPmYVdJxZE7sQ5quh/XUzB5y/
D5z2A7KPYXUgUP0jd5yLZ7+pVBcFSUm5AZXJLXH4jPVOXztcmiu4ta0CAwEAAQ==
-----END PUBLIC KEY-----]]),
    }
    local invalid_key = "a really invalid key"
    local data = {
      test = "test",
    }
    local token = jwt.encode(data, {alg = "RS256", keys = keys})
    assert.has.no.error(function ()
      local result, err = jwt.decode(token, {keys = {public = invalid_key }})
      assert.is_nil(result)
      assert.is_not_nil(err)
    end)
  end)
end)
