package wxapp

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"log"

	"github.com/dghubble/sling"
)

const (
	jscode2session = "https://api.weixin.qq.com/sns/jscode2session"
)

type WXLoginResponse struct {
	Ierrcode    int    `json:"errcode"`
	Ierrmsg     string `json:"errmsg"`
	IopenId     string `json:"openid"`
	IsessionKey string `json:"session_key"`
	IexpiresIn  int64  `json:"expires_in"`
}

func (lr *WXLoginResponse) Errcode() int {
	return lr.Ierrcode
}

func (lr *WXLoginResponse) Errmsg() string {
	return lr.Ierrmsg
}

func (lr *WXLoginResponse) OpenId() string {
	return lr.IopenId
}

func (lr *WXLoginResponse) SessionKey() string {
	return lr.IsessionKey
}

func (lr *WXLoginResponse) ExpiresIn() int64 {
	return lr.IexpiresIn
}

type WXLogin struct {
	appid      string
	appsecret  string
	httpClient *http.Client
}

func NewWXLogin(appId, appSecret string, httpClient *http.Client) *WXLogin {
	return &WXLogin{
		appid:      appId,
		appsecret:  appSecret,
		httpClient: httpClient,
	}
}

func (wxl *WXLogin) Code2Session(code string) (IWXLoginResponse, error) {
	type QueryStruct struct {
		AppId     string `url:"appid"`
		Secret    string `url:"secret"`
		Code      string `url:"js_code"`
		GrantType string `url:"grant_type"`
	}
	query := QueryStruct{
		AppId:     wxl.appid,
		Secret:    wxl.appsecret,
		Code:      code,
		GrantType: "authorization_code",
	}
	resp := &WXLoginResponse{}
	_, err := sling.New().Get(jscode2session).QueryStruct(query).
		Client(wxl.httpClient).Receive(resp, resp)
	if err != nil {
		log.Println("[code2session failed]", code)
		log.Print("[resp] %+v\n", resp)
		log.Println("[error]", err)
		return nil, err
	}
	if resp.Errcode() != 0 {
		log.Println("[code2session errcode]", code)
		log.Print("[resp] %+v\n", resp)
		log.Println("[error]", err)
		return nil, errors.New(fmt.Sprintf("%d:%s", resp.Errcode, resp.Errmsg))
	}
	return resp, nil
}

type WXUserInfoWatermark struct {
	AppId     string `json:"appid"`
	Timestamp int64  `json:"timestamp"`
}

type WXUserInfo struct {
	IopenId    string              `json:"openId"`
	Inickname  string              `json:"nickname"`
	Igender    int                 `json:"gender"`
	Icity      string              `json:"city"`
	Iprovince  string              `json:"province"`
	Icontry    string              `json:"contry"`
	IavatarUrl string              `json:"avatarUrl"`
	IunionId   string              `json:"unionId"`
	IwaterMark WXUserInfoWatermark `json:"watermark"`
}

func (wxui *WXUserInfo) OpenId() string {
	return wxui.IopenId
}

func (wxui *WXUserInfo) Nickname() string {
	return wxui.Inickname
}

func (wxui *WXUserInfo) Gender() int {
	return wxui.Igender
}

func (wxui *WXUserInfo) City() string {
	return wxui.Icity
}

func (wxui *WXUserInfo) Province() string {
	return wxui.Iprovince
}

func (wxui *WXUserInfo) Contry() string {
	return wxui.Icontry
}

func (wxui *WXUserInfo) AvatarUrl() string {
	return wxui.IavatarUrl
}

func (wxui *WXUserInfo) UnionId() string {
	return wxui.IunionId
}

func (wxui *WXUserInfo) WaterMark() map[string]interface{} {
	return nil
}

func (wxl *WXLogin) pkcs7Unpad(data []byte) []byte {
	l := len(data)
	padlen := int(data[l-1])
	return data[:(l - padlen)]
}

func (wxl *WXLogin) Decrypt(encrypted, key, iv64 string) ([]byte, error) {
	// 1. decode base64
	entext, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		return nil, err
	}
	aeskey, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return nil, err
	}
	iv, err := base64.StdEncoding.DecodeString(iv64)
	if err != nil {
		return nil, err
	}
	// 2. create decrypter
	block, err := aes.NewCipher(aeskey)
	if err != nil {
		return nil, err
	}
	aescbc := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(entext))
	aescbc.CryptBlocks(plaintext, entext)

	return wxl.pkcs7Unpad(plaintext), nil
}

func (wxl *WXLogin) DecryptUserInfo(encrypted, key, iv64 string) (IWXUserInfo, error) {
	plaintext, err := wxl.Decrypt(encrypted, key, iv64)
	if err != nil {
		return nil, err
	}
	// 3. unmarshal json
	userInfo := &WXUserInfo{}
	if err := json.Unmarshal(plaintext, userInfo); err != nil {
		return nil, err
	}
	return userInfo, nil
}

func (wxl *WXLogin) VerifySignature(raw, signature, key string) bool {
	combined := fmt.Sprintf("%s%s", raw, key)
	h := sha1.New()
	if _, err := h.Write([]byte(combined)); err != nil {
		log.Println("[sha1 write failed]", err)
		return false
	}
	bin := h.Sum(nil)
	checkSign := fmt.Sprintf("%x", bin)
	log.Println("[verify sign]", checkSign)
	if checkSign == signature {
		return true
	}
	return false
}

type MockWXLogin struct {
	WXLogin
}

func NewMockWXLogin(appId, appSecret string, httpClient *http.Client) *MockWXLogin {
	login := &MockWXLogin{}
	login.appid = appId
	login.appsecret = appSecret
	login.httpClient = httpClient
	return login
}

func (wxl *MockWXLogin) Code2Session(code string) (IWXLoginResponse, error) {
	return &WXLoginResponse{
		Ierrcode:    0,
		Ierrmsg:     "success",
		IopenId:     "mock_user_id1",
		IsessionKey: "mock_session_key",
		IexpiresIn:  7200,
	}, nil
}

func (mwxl *MockWXLogin) DecryptUserInfo(encrypted, key, iv string) (IWXUserInfo, error) {
	return &WXUserInfo{
		IopenId:    "mock_user_id1",
		Inickname:  "mock_user_nickname",
		Igender:    0,
		Icity:      "Shenzhen",
		Iprovince:  "Guangdong",
		Icontry:    "China",
		IavatarUrl: "mock_avatar_url",
		IunionId:   "mock_user_union_id1",
		IwaterMark: WXUserInfoWatermark{
			AppId:     mwxl.appid,
			Timestamp: time.Now().Unix(),
		},
	}, nil
}

func (mwxl *MockWXLogin) VerifySignature(raw, signature, key string) bool {
	return true
}
