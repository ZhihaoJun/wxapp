# wxapp
Wechat mini app oauth client, simple implementation

## api
``` golang
type IWXLoginResponse interface {
	Errcode() int
	Errmsg() string
	OpenId() string
	SessionKey() string
	ExpiresIn() int64
}

type IWXUserInfo interface {
	OpenId() string
	Nickname() string
	Gender() int
	City() string
	Province() string
	Contry() string
	AvatarUrl() string
	UnionId() string
	WaterMark() map[string]interface{}
}

type IWXApp interface {
	Code2Session(code string) (IWXLoginResponse, error)
	DecryptUserInfo(encrypted, key, iv string) (IWXUserInfo, error)
	VerifySignature(raw, signature, key string) bool
	Decrypt(encrypted, key, iv64 string) ([]byte, error)
}
```

## denpendencies
* [https://github.com/dghubble/sling](https://github.com/dghubble/sling)
