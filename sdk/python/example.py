import os
import authgo

AUTH_CONFIG = "authgo2.请在构建时替换为后台接入配置"
client = authgo.Client(AUTH_CONFIG)
result = client.check(os.environ["AUTHGO_LICENSE"])
print(result.status)
