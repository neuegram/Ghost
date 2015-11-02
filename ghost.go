// Package ghost provides methods for interacting with the Snapchat API.
package ghost

import (
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	phone "github.com/dicefm/extra-terrestrial/phone"
	"github.com/hako/casper"
)

// Snapchat general constants.
const (
	SnapchatVersion   = "9.18.0.0"
	URL               = "https://app.snapchat.com"
	UserAgent         = "Snapchat/" + SnapchatVersion + " (HTC One; Android 5.0.2#482424.2#21; gzip)"
	AcceptLang        = "en"
	AcceptLocale      = "en_US"
	Pattern           = "0001110111101110001111010101111011010001001110011000110001000110"
	Secret            = "iEk21fuwZApXlz93750dmW22pw389dPwOk"
	StaticToken       = "m198sOkJEn37DjqZ32lpRu76xmw288xSQ9"
	BlobEncryptionKey = "M02cnQ51Ji97vwT4"
	JPEGSignature     = "FFD8FFE0"
	MP4Signature      = "000000186674797033677035"
)

// Snapchat media constants.
const (
	MediaImage SnapchatMediaType = iota
	MediaVideo
	MediaVideoNoAudio

	MediaFriendRequest
	MediaFriendRequestImage
	MediaFriendRequestVideo
	MediaFriendRequestNoAudio
)

// Snapchat Snap statuses.
const (
	StatusNone SnapchatStatus = iota - 1
	StatusSent
	StatusDelivered
	StatusOpened
	StatusScreenShot
)

// Snapchat Friend statuses.
const (
	FriendConfirmed SnapchatFriendStatus = iota
	FriendUnconfirmed
	FriendBlocked
	FriendDeleted
	FriendFollowing = 6
)

// Snapchat Privacy settings
const (
	PrivacyEveryone SnapchatPrivacySetting = iota
	PrivacyFriends
)

// Supported Snaptag formats.
const (
	SnapTagPNG SnapTagImageFormat = "PNG"
	SnapTagSVG SnapTagImageFormat = "SVG"
)

// SnapchatMediaType represents the a Snapchat media type.
type SnapchatMediaType int

// SnapchatStatus represents a Snapchat status type.
type SnapchatStatus int

// SnapchatFriendStatus represents a Snapchat friend status type.
type SnapchatFriendStatus int

// SnapchatPrivacySetting represents a Snapchat privacy setting.
type SnapchatPrivacySetting int

// SnapTagImageFormat represents a downloadable Snaptag image format.
type SnapTagImageFormat string

// Account represents a single Snapchat account.
type Account struct {
	GoogleMail       string
	GooglePassword   string
	CasperClient     *casper.Casper
	Debug            bool
	AndroidAuthToken string
	Token            string
	Username         string
	Password         string
	UserID           string
	ProxyURL         *url.URL
}

// Error handles errors returned by ghost methods.
type Error struct {
	Err SnapchatError
}

func (e Error) Error() string {
	return fmt.Sprintf("Error: Snapchat said: %s, Status code: %d, Logged In: %t", e.Err.Message, e.Err.Status, e.Err.Logged)
}

// NewAccount creates a new Snapchat Account of type *Account.
func NewAccount(gmail, gpassword string, cc *casper.Casper, debug bool) *Account {
	ghostAcc := &Account{
		GoogleMail:       gmail,
		GooglePassword:   gpassword,
		CasperClient:     cc,
		Debug:            debug,
		AndroidAuthToken: "",
	}
	return ghostAcc
}

// NewGhostCasperClient creates a new Casper API client of type *casper.Casper.
func NewGhostCasperClient(apiKey, apiSecret, username, password string, debug bool) *casper.Casper {
	casperClient := &casper.Casper{
		APIKey:    apiKey,
		APISecret: apiSecret,
		Username:  username,
		Password:  password,
		Debug:     debug,
	}
	return casperClient
}

// NewRawCasperClient creates an empty Casper API client of type *casper.Casper.
// Same as NewGhostCasperClient() But configurable.
func NewRawCasperClient(apiKey, apiSecret string) *casper.Casper {
	casperClient := &casper.Casper{
		APIKey:    apiKey,
		APISecret: apiSecret,
	}
	return casperClient
}

// NewRawAccount creates an empty Snapchat Account client of type *Account.
// Same as NewAccount() But configurable.
func NewRawAccount() *Account {
	return &Account{}
}

// DecodeSnaptag decodes Snapchat 'Snaptags'.
func DecodeSnaptag(snaptag string) {
	b, _ := hex.DecodeString(snaptag)
	for _, v := range b {
		fmt.Println(strconv.FormatInt(int64(v), 2))
	}
}

// AddPKCS5 pads plaintext with PKCS5.
func AddPKCS5(plaintext []byte) []byte {
	padding := aes.BlockSize - (len(plaintext) % aes.BlockSize)
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(plaintext, padtext...)
}

// RemovePKCS5 removes padding from plaintext.
func RemovePKCS5(plaintext []byte) []byte {
	unpadding := int(plaintext[len(plaintext)-1])
	return plaintext[:(len(plaintext) - unpadding)]
}

// DecryptECB decrypts data using ECB.
func DecryptECB(key, data []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		fmt.Println(err)
	}

	if len(data) < aes.BlockSize {
		fmt.Println("Ciphertext is too short")
	}

	if len(data)%aes.BlockSize != 0 {
		fmt.Println("Ciphertext is not a multiple of the block size")
	}

	j := len(data) / aes.BlockSize
	var decrypted []byte
	for i := 0; i < j; i++ {
		low := i * aes.BlockSize
		high := low + aes.BlockSize
		out := make([]byte, aes.BlockSize)
		block.Decrypt(out, data[low:high])
		tmp := [][]byte{decrypted, out}
		decrypted = bytes.Join(tmp, nil)
	}

	return decrypted
}

// EncryptECB encrypts data using ECB.
func EncryptECB(key, data []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		fmt.Println(err)
	}

	if len(data)%aes.BlockSize != 0 {
		fmt.Println("Plaintext is not a multiple of the block size")
	}

	j := len(data) / aes.BlockSize
	var encrypted []byte
	for i := 0; i < j; i++ {
		low := i * aes.BlockSize
		high := low + aes.BlockSize
		out := make([]byte, aes.BlockSize)
		block.Encrypt(out, data[low:high])
		tmp := [][]byte{encrypted, out}
		encrypted = bytes.Join(tmp, nil)
	}

	return encrypted
}

// // DecryptCBC decrypts data using CBC.
// func DecryptCBC(key, iv string) {
// }

// IsJPEG checks if data is a JPEG Image.
func IsJPEG(data []byte) bool {
	sig, err := hex.DecodeString(JPEGSignature)
	if err != nil {
		return false
	}
	if bytes.Equal(data[:len(sig)], sig) {
		return true
	}
	return false
}

// IsMP4 checks if data is an MP4 Video.
func IsMP4(data []byte) bool {
	sig, err := hex.DecodeString(MP4Signature)
	if err != nil {
		return false
	}
	if bytes.Equal(data[:len(sig)], sig) {
		return true
	}
	return false
}

// CalculateAge calculates the age of a Snapchat user.
func CalculateAge(date string) (string, error) {
	now := time.Now()
	birthday, err := time.Parse("2006-01-02", date)
	if err != nil {
		return "", err
	}
	return strconv.Itoa(now.Year() - birthday.Year()), nil
}

// structToJSON is a helper method for converting Snapchat structs To JSON.
func structToJSON(jsn interface{}) string {

	bytes, err := json.Marshal(jsn)
	if err != nil {
		fmt.Println(err)
	}
	return string(bytes)
}

// AddJPEGSignature appends a JPEG magic number to data.
func AddJPEGSignature(data []byte) []byte {
	sig, err := hex.DecodeString(JPEGSignature)
	if err != nil {
		fmt.Println(err)
	}
	return append(sig, data...)
}

// AddMP4Signature appends a MP4 magic number to data.
func AddMP4Signature(data []byte) []byte {
	sig, err := hex.DecodeString(MP4Signature)
	if err != nil {
		fmt.Println(err)
	}
	return append(sig, data...)
}

// Timestamp generates timestamps in miliseconds.
func Timestamp() string {
	return strconv.Itoa(int(time.Now().UnixNano() / 1000000))
}

// UUID4 Generates (RFC 4122) compatible UUIDs.
func UUID4() string {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		fmt.Println(err)
	}
	return fmt.Sprintf("%04x-%02x-%02x-%02x-%06x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

// MediaID creates Snapchat Media UUIDs using username.
func MediaID(username string) string {
	return fmt.Sprintf("%s~%s", strings.ToUpper(username), UUID4())
}

// EncryptSnap is a small wrapper around AddPKCS5 & EncryptECB.
func EncryptSnap(file []byte) ([]byte, error) {
	if len(file) == 0 {
		return nil, errors.New("File does not exist.")
	}
	padFile := AddPKCS5(file)
	encryptedFile := EncryptECB([]byte(BlobEncryptionKey), padFile)
	return encryptedFile, nil
}

// DetectMedia is a small wrapper around IsJPEG & IsMP4.
func DetectMedia(file []byte) (string, error) {
	var mt SnapchatMediaType
	if len(file) == 0 {
		return "", errors.New("File does not exist.")
	}
	if IsJPEG(file) == true {
		mt = MediaImage
	} else if IsMP4(file) == true {
		mt = MediaVideo
	} else {
		return "", errors.New("Unknown file type.")
	}
	return strconv.Itoa(int(mt)), nil
}

// RequestToken generates request tokens on each Snapchat API request.
func RequestToken(AuthToken, timestamp string) string {
	hash := sha256.New()
	io.WriteString(hash, Secret+AuthToken)
	first := hex.EncodeToString(hash.Sum(nil))
	hash.Reset()
	io.WriteString(hash, timestamp+Secret)
	second := hex.EncodeToString(hash.Sum(nil))
	var bits string
	for i, c := range Pattern {
		if c == '0' {
			bits += string(first[i])
		} else {
			bits += string(second[i])
		}
	}
	return bits
}

// encryptPasswd is an implemention of Google's EncryptPasswd for encrypting Google account passwords.
func (acc *Account) encryptPasswd() string {
	googleDefaultPubKey := "AAAAgMom/1a/v0lblO2Ubrt60J2gcuXSljGFQXgcyZWveWLEwo6prwgi3iJIZdodyhKZQrNWp5nKJ3srRXcUW+F1BD3baEVGcmEgqaLZUNBjm057pKRI16kB0YppeGx5qIQ5QjKzsR8ETQbKLNWgRY0QRNVz34kMJR3P/LgHax/6rmf5AAAAAwEAAQ=="
	b64DecodedKey, err := base64.StdEncoding.DecodeString(googleDefaultPubKey)
	if err != nil {
		fmt.Println(err)
	}
	bigintMod := new(big.Int)
	bigintExp := new(big.Int)
	binarykey := hex.EncodeToString([]byte(b64DecodedKey))
	half := binarykey[8:264]
	modulus, b := bigintMod.SetString(half, 16)
	if b != true {
		fmt.Println(modulus, b)
	}
	half = binarykey[272:]
	bigExponent, b := bigintExp.SetString(half, 16)
	if b != true {
		fmt.Println(bigExponent, b)
	}
	exponent, err := strconv.Atoi(bigExponent.String())
	if err != nil {
		fmt.Println(err)
	}
	h := sha1.New()
	io.WriteString(h, string(b64DecodedKey))
	hash := h.Sum(nil)

	signature := "00" + hex.EncodeToString(hash[0:4])
	pubkey := &rsa.PublicKey{N: modulus, E: exponent}
	plain := acc.GoogleMail + "\x00" + acc.GooglePassword
	s := sha1.New()
	msg := []byte(plain)
	encrypted, err := rsa.EncryptOAEP(s, rand.Reader, pubkey, msg, []byte(""))
	if err != nil {
		fmt.Println(err)
	}
	hexencrypted := hex.EncodeToString(encrypted)
	output, err := hex.DecodeString(signature + string(hexencrypted))
	if err != nil {
		fmt.Println(err)
	}

	pass1 := strings.Replace(base64.StdEncoding.EncodeToString(output), "+", "-", -1)
	b64encryptedPasswd := strings.Replace(pass1, "/", "_", -1)
	return b64encryptedPasswd
}

// GetGCMToken fetches a GCM token from (You guessed it) Google.
func (acc *Account) GetGCMToken() string {
	var tr *http.Transport

	tr = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	if acc.ProxyURL != nil {
		tr.Proxy = http.ProxyURL(acc.ProxyURL)
	}

	client := &http.Client{Transport: tr}
	clientGCMForm := url.Values{}
	clientGCMForm.Add("device", "3847872624728098287")
	clientGCMForm.Add("sender", "191410808405")
	clientGCMForm.Add("app_ver", "564")
	clientGCMForm.Add("gcm_ver", "7097038")
	clientGCMForm.Add("app", "com.snapchat.android")
	clientGCMForm.Add("iat", Timestamp())
	clientGCMForm.Add("cert", "49f6badb81d89a9e38d65de76f09355071bd67e7")

	req, err := http.NewRequest("POST", "https://android.clients.google.com/c2dm/register3", strings.NewReader(string(clientGCMForm.Encode())))

	req.Header.Set("App", "com.snapchat.android")
	req.Header.Set("User-Agent", "Android-GCM/1.5 (m7 KOT49H)")
	req.Header.Set("Authorization", "AidLogin 3847872624728098287:1187196130325105010")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept-Encoding", "gzip")

	resp, err := client.Do(req)
	gzBody, err := gzip.NewReader(resp.Body)
	decompressedBody, err := ioutil.ReadAll(gzBody)
	if acc.Debug == true {
		fmt.Println(string(decompressedBody))
	}
	if err != nil {
		fmt.Println(err)
	}

	token := string(decompressedBody)[6:]
	return token
}

// GetAuthToken fetches an Android auth token.
func (acc *Account) GetAuthToken() string {
	var tr *http.Transport

	tr = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	if acc.ProxyURL != nil {
		tr.Proxy = http.ProxyURL(acc.ProxyURL)
	}

	encyptedPassword := acc.encryptPasswd()
	client := &http.Client{Transport: tr}

	authForm := url.Values{}
	authForm.Add("device_country", "us")
	authForm.Add("operatorCountry", "us")
	authForm.Add("lang", "en_US")
	authForm.Add("sdk_version", "19")
	authForm.Add("google_play_services_version", "7097038")
	authForm.Add("accountType", "HOSTED_OR_GOOGLE")
	authForm.Add("Email", acc.GoogleMail)
	authForm.Add("service", "audience:server:client_id:694893979329-l59f3phl42et9clpoo296d8raqoljl6p.apps.googleusercontent.com")
	authForm.Add("source", "android")
	authForm.Add("androidId", "378c184c6070c26c")
	authForm.Add("app", "com.snapchat.android")
	authForm.Add("client_sig", "49f6badb81d89a9e38d65de76f09355071bd67e7")
	authForm.Add("callerPkg", "com.snapchat.android")
	authForm.Add("callerSig", "49f6badb81d89a9e38d65de76f09355071bd67e7")
	authForm.Add("EncryptedPasswd", encyptedPassword)

	req, err := http.NewRequest("POST", "https://android.clients.google.com/auth", strings.NewReader(string(authForm.Encode())))
	req.Header.Set("User-Agent", "GoogleAuth/1.4 (mako JDQ39)")
	req.Header.Set("Device", "378c184c6070c26c")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("App", "com.snapchat.android")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Encoding", "gzip")

	resp, err := client.Do(req)
	gzBody, err := gzip.NewReader(resp.Body)
	decompressedBody, err := ioutil.ReadAll(gzBody)
	if err != nil {
		fmt.Println(err)
	}
	if acc.Debug == true {
		fmt.Println(string(decompressedBody))
	}
	splitString := strings.Split(string(decompressedBody), "issueAdvice")
	authToken := splitString[0][5:]
	return authToken
}

// GetDeviceToken fetches the device token to use with Snapchat.
func (acc *Account) GetDeviceToken() map[string]interface{} {
	ts := Timestamp()
	acc.SetAuthToken(acc.GetAuthToken())
	data := map[string]string{
		"timestamp": ts,
		"req_token": RequestToken(StaticToken, ts),
	}

	resp := acc.SendRequest("POST", "/loq/device_id", data)
	body, ioErr := ioutil.ReadAll(resp.Body)
	if ioErr != nil {
		fmt.Println(ioErr)
	}
	if acc.Debug == true {
		fmt.Println(string(body))
	}

	var parsed map[string]interface{}
	json.Unmarshal(body, &parsed)
	return parsed
}

// SetAuthToken sets the auth token auth to current Snapchat account acc.
func (acc *Account) SetAuthToken(auth string) {
	acc.AndroidAuthToken = auth
}

// AuthToken returns the auth token associated with the current Snapchat account acc.
func (acc *Account) AuthToken() string {
	return acc.AndroidAuthToken
}

// SendRequest performs HTTP requests.
func (acc *Account) SendRequest(method, endpoint string, data map[string]string) *http.Response {
	var tr *http.Transport

	tr = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	if acc.ProxyURL != nil {
		tr.Proxy = http.ProxyURL(acc.ProxyURL)
	}

	if acc.Debug == true {
		fmt.Printf(method+"\t%s\n", URL+endpoint)
	}

	form := url.Values{}
	for k, v := range data {
		form.Add(k, v)
		if acc.Debug == true {
			fmt.Printf("%s\t%s\n", k, v)
		}
	}

	client := &http.Client{Transport: tr}

	req, err := http.NewRequest(method, URL+endpoint, strings.NewReader(form.Encode()))

	req.Header.Set("User-Agent", UserAgent)

	if endpoint == "/bq/solve_captcha" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	androidAuthToken := acc.AuthToken()

	if endpoint == "/loq/login" || endpoint == "/loq/device_id" || endpoint == "/bq/solve_captcha" {
		clientAuthToken, err := acc.CasperClient.GetClientAuthToken(acc.Username, acc.Password, data["timestamp"])
		if err != nil {
			fmt.Println(err)
		}
		req.Header.Set("X-Snapchat-Client-Auth-Token", "Bearer "+androidAuthToken)
		req.Header.Set("X-Snapchat-Client-Auth", clientAuthToken)
	} else {
		req.Header.Set("X-Snapchat-Client-Auth-Token", "Bearer "+androidAuthToken)
	}

	req.Header.Set("Accept-Language", AcceptLang)
	req.Header.Set("Accept-Locale", AcceptLocale)
	resp, err := client.Do(req)

	if err != nil {
		fmt.Println(err)
	}

	return resp
}

// Performs multipart HTTP requests. (Not fully implemented)
/*func SendMultipartRequest(endpoint string, data map[string]string, path string) *http.Response {
	// For debugging purposes only!
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	client := &http.Client{Transport: tr}

	ms := multipartstreamer.New()

	err := ms.WriteFields(data)
	if err != nil {
		fmt.Println(err)
	}

	err = ms.WriteFile("data", path)
	if err != nil {
		fmt.Println(err)
	}

	req, err := http.NewRequest("POST", URL+endpoint, ms.GetReader())
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Accept-Language", AcceptLang)
	req.Header.Add("Content-Type", ms.ContentType)
	req.ContentLength = ms.Len()
	var b []byte
	ms.GetReader().Read(b)
	fmt.Println(b)
	if err != nil {
		fmt.Println(err)
	}

	resp, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
	}

	return resp
}*/

// SendMultipartRequest performs multipart HTTP requests.
func (acc *Account) SendMultipartRequest(endpoint string, data map[string]string, path string) *http.Response {
	var tr *http.Transport

	tr = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	file, err := os.Open(path)
	if err != nil {
		fmt.Println(err)
	}

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	err = writer.SetBoundary("Boundary+0xAbCdEfGbOuNdArY")
	if err != nil {
		fmt.Println(err)
	}
	mh := make(textproto.MIMEHeader)
	mh.Set("Content-Disposition", "form-data; name=\"data\"; filename=\"data\"")
	mh.Set("Content-Type", "application/octet-stream")
	partWriter, err := writer.CreatePart(mh)
	if err != nil {
		fmt.Println(err)
	}
	if err != nil {
		fmt.Println(err)
	}
	_, err = io.Copy(partWriter, file)
	if err != nil {
		fmt.Println(err)
	}

	for k, v := range data {
		mh = make(textproto.MIMEHeader)
		dpos := fmt.Sprintf("form-data; name=\"%s\"", k)
		mh.Set("Content-Disposition", dpos)
		partWriter, err = writer.CreatePart(mh)
		if nil != err {
			panic(err)
		}
		mh.Set("Boundary", writer.Boundary())
		io.Copy(partWriter, bytes.NewBufferString(v))
	}

	err = writer.Close()
	if err != nil {
		fmt.Println(err)
	}

	if acc.ProxyURL != nil {
		tr.Proxy = http.ProxyURL(acc.ProxyURL)
	}

	if acc.Debug == true {
		fmt.Printf("POST"+"\t%s\n", URL+endpoint)
	}

	client := &http.Client{Transport: tr}
	req, err := http.NewRequest("POST", URL+endpoint, body)
	req.Header.Set("Content-Type", "multipart/form-data; boundary=Boundary+0xAbCdEfGbOuNdArY")

	androidAuthToken := acc.AuthToken()
	req.Header.Set("Accept-Language", AcceptLang)
	req.Header.Set("Accept-Locale", AcceptLocale)
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("X-Snapchat-Client-Auth-Token", "Bearer "+androidAuthToken)

	if acc.Debug == true {
		for k, v := range req.Header {
			fmt.Println(k, v)
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
	}

	return resp
}

// Register registers a new Snapchat account.
func (acc *Account) Register(username, password, email, birthday string) map[string]interface{} {
	acc.Username = username
	acc.Password = password

	ts := Timestamp()
	deviceToken := acc.GetDeviceToken()
	reqToken := RequestToken(StaticToken, ts)

	dsigStr := []byte(email + "|" + password + "|" + ts + "|" + reqToken)
	h := hmac.New(sha256.New, []byte(deviceToken["dtoken1v"].(string)))
	h.Write(dsigStr)

	dsig := hex.EncodeToString(h.Sum(nil))[:20]
	dtoken1i := deviceToken["dtoken1i"].(string)

	acc.SetAuthToken(acc.GetAuthToken())
	age, err := CalculateAge(birthday)

	attestation, err := acc.CasperClient.GetAttestation(username, password, ts)

	if err != nil {
		fmt.Println(err)
	}

	ssjson := StudySettings{
		RegisterHideSkipPhone: RegisterHideSkipPhone{
			Experimentid: "0",
		},
	}

	studySettings := structToJSON(ssjson)

	data := map[string]string{
		"timestamp":      ts,
		"req_token":      RequestToken(StaticToken, ts),
		"email":          email,
		"password":       password,
		"dsig":           dsig,
		"study_settings": studySettings,
		"dtoken1i":       dtoken1i,
		"attestation":    attestation,
		"age":            age,
		"birthday":       birthday,
	}

	resp := acc.SendRequest("POST", "/loq/register", data)
	body, ioErr := ioutil.ReadAll(resp.Body)
	if ioErr != nil {
		fmt.Println(ioErr)
	}
	if acc.Debug == true {
		fmt.Println(string(body))
	}

	var parsed map[string]interface{}
	json.Unmarshal(body, &parsed)
	return parsed
}

// RegisterUsername registers a new Snapchat username.
func (acc *Account) RegisterUsername(username, email string) map[string]interface{} {
	ts := Timestamp()
	data := map[string]string{
		"timestamp":         ts,
		"req_token":         RequestToken(acc.Token, ts),
		"username":          email,
		"selected_username": username,
	}

	resp := acc.SendRequest("POST", "/loq/register_username", data)
	body, ioErr := ioutil.ReadAll(resp.Body)
	if ioErr != nil {
		fmt.Println(ioErr)
	}
	if acc.Debug == true {
		fmt.Println(string(body))
	}

	var parsed map[string]interface{}
	json.Unmarshal(body, &parsed)
	return parsed
}

// VerifyPhoneNumber sends a phone number to Snapchat for verification.
func (acc *Account) VerifyPhoneNumber(phoneNumber string) map[string]interface{} {
	ts := Timestamp()
	number, err := phone.Normalise(phoneNumber, "")
	if err != nil {
		fmt.Println(err)
	}
	// Get country code out of phone number.
	data := map[string]string{
		"timestamp":        ts,
		"req_token":        RequestToken(acc.Token, ts),
		"username":         acc.Username,
		"countryCode":      number.Country[:2],
		"skipConfirmation": "true",
		"phoneNumber":      phoneNumber,
		"action":           "updatePhoneNumber",
	}

	resp := acc.SendRequest("POST", "/bq/phone_verify", data)
	body, ioErr := ioutil.ReadAll(resp.Body)
	if ioErr != nil {
		fmt.Println(ioErr)
	}
	if acc.Debug == true {
		fmt.Println(string(body))
	}

	var parsed map[string]interface{}
	json.Unmarshal(body, &parsed)
	return parsed
}

// SendSMSCode sends an SMS code to Snapchat.
func (acc *Account) SendSMSCode(code string) map[string]interface{} {
	ts := Timestamp()
	data := map[string]string{
		"timestamp": ts,
		"req_token": RequestToken(acc.Token, ts),
		"username":  acc.Username,
		"action":    "verifyPhoneNumber",
		"code":      code,
		"type":      "DEFAULT_TYPE",
	}

	resp := acc.SendRequest("POST", "/bq/phone_verify", data)
	body, ioErr := ioutil.ReadAll(resp.Body)
	if ioErr != nil {
		fmt.Println(ioErr)
	}
	if acc.Debug == true {
		fmt.Println(string(body))
	}

	var parsed map[string]interface{}
	json.Unmarshal(body, &parsed)
	return parsed
}

// GetCaptcha fetches a captcha puzzle from snapchat.
func (acc *Account) GetCaptcha() string {
	ts := Timestamp()
	data := map[string]string{
		"timestamp": ts,
		"req_token": RequestToken(acc.Token, ts),
		"username":  acc.Username,
	}

	resp := acc.SendRequest("POST", "/bq/get_captcha", data)
	body, ioErr := ioutil.ReadAll(resp.Body)
	if ioErr != nil {
		fmt.Println(ioErr)
	}
	filename := resp.Header["Content-Disposition"][0][20:]
	if acc.Debug == true {
		fmt.Println("< CAPTCHA ZIP: " + filename + " >")
	}
	captchaID := strings.Replace(filename, ".zip", "", 1)
	ioutil.WriteFile(filename, body, 0644)
	return captchaID
}

// SolveCaptcha fetches a captcha puzzle from snapchat.
func (acc *Account) SolveCaptcha(captchaID, solution string) map[string]interface{} {
	ts := Timestamp()
	data := map[string]string{
		"timestamp":        ts,
		"captcha_solution": solution,
		"captcha_id":       captchaID,
		"req_token":        RequestToken(acc.Token, ts),
		"username":         acc.Username,
	}

	resp := acc.SendRequest("POST", "/bq/solve_captcha", data)
	body, ioErr := ioutil.ReadAll(resp.Body)
	if ioErr != nil {
		fmt.Println(ioErr)
	}
	if acc.Debug == true {
		fmt.Println(string(body))
	}

	var parsed map[string]interface{}
	json.Unmarshal(body, &parsed)
	return parsed
}

//	RegisterExpire expires a device id.
//  (This happens when the user presses cancel when signing up.)
// func (acc *Account) RegisterExpire(device_id string) map[string]interface{} {
// 	ts := Timestamp()

// 	data := map[string]string{
// 		"timestamp":        ts,
// 		"req_token":        RequestToken(acc.Token, ts),
// 		"device_unique_id": device_unique_id,
// 	}

// 	resp := acc.SendRequest("POST", "/loq/and/register_exp", data)
// 	body, ioErr := ioutil.ReadAll(resp.Body)
// 	fmt.Println(string(body))
// 	if ioErr != nil {
// 		fmt.Println(ioErr)
// 	}

// 	var parsed map[string]interface{}
// 	json.Unmarshal(body, &parsed)
// 	return parsed
// }

// Login logs the user into Snapchat.
func (acc *Account) Login() error {
	acc.Username = acc.CasperClient.Username
	acc.Password = acc.CasperClient.Password

	deviceToken := acc.GetDeviceToken()

	ts := Timestamp()
	reqToken := RequestToken(StaticToken, ts)

	dsigStr := []byte(acc.Username + "|" + acc.Password + "|" + ts + "|" + reqToken)
	h := hmac.New(sha256.New, []byte(deviceToken["dtoken1v"].(string)))
	h.Write(dsigStr)
	dsig := hex.EncodeToString(h.Sum(nil))[:20]
	dtoken1i := deviceToken["dtoken1i"].(string)

	acc.SetAuthToken(acc.GetAuthToken())
	attestation, err := acc.CasperClient.GetAttestation(acc.Username, acc.Password, ts)
	if err != nil {
		fmt.Println(err)
	}

	data := map[string]string{
		"application_id":   "com.snapchat.android",
		"height":           "1280",
		"width":            "720",
		"max_Video_height": "640",
		"max_Video_width":  "480",
		"dsig":             dsig,
		"dtoken1i":         dtoken1i,
		"attestation":      attestation,
		"sflag":            "1",
		"ptoken":           "ie",
		"username":         acc.Username,
		"timestamp":        ts,
		"req_token":        reqToken,
		"password":         acc.Password,
	}

	resp := acc.SendRequest("POST", "/loq/login", data)
	body, ioErr := ioutil.ReadAll(resp.Body)
	if ioErr != nil {
		fmt.Println(ioErr)
	}
	if acc.Debug == true {
		fmt.Println(string(body))
	}

	var parsed Updates
	json.Unmarshal(body, &parsed)

	if parsed.UpdatesResponse.Logged == true {
		acc.Token = parsed.UpdatesResponse.AuthToken
		acc.UserID = parsed.UpdatesResponse.UserID
		return nil
	}
	var scerror Error
	json.Unmarshal(body, &scerror.Err)
	return scerror
}

// Logout logs the user out of Snapchat.
func (acc *Account) Logout() bool {
	ts := Timestamp()
	data := map[string]string{
		"username":  acc.Username,
		"timestamp": ts,
		"req_token": RequestToken(acc.Token, ts),
	}

	resp := acc.SendRequest("POST", "/ph/logout", data)
	body, ioErr := ioutil.ReadAll(resp.Body)
	if ioErr != nil {
		fmt.Println(ioErr)
	}
	if acc.Debug == true {
		fmt.Println(string(body))
	}
	if resp.StatusCode != 200 {
		return false
	}

	return true
}

// FetchBlob fetches the media blob. (Yet to test.)
func (acc *Account) FetchBlob(username, id string) []byte {
	ts := Timestamp()
	data := map[string]string{
		"username":  username,
		"timestamp": ts,
		"req_token": RequestToken(acc.Token, ts),
		"id":        id,
	}

	resp := acc.SendRequest("POST", "/bq/blob", data)
	body, ioErr := ioutil.ReadAll(resp.Body)
	if ioErr != nil {
		fmt.Println(ioErr)
	}
	if acc.Debug == true {
		fmt.Println(string(body))
	}

	return body
}

// IPRouting gets IP Routing URLs.
func (acc *Account) IPRouting() map[string]interface{} {
	ts := Timestamp()
	data := map[string]string{
		"username":           acc.Username,
		"userId":             acc.Username,
		"timestamp":          ts,
		"req_token":          RequestToken(acc.Token, ts),
		"currentUrlEntities": "",
	}

	resp := acc.SendRequest("POST", "/bq/ip_routing", data)
	body, ioErr := ioutil.ReadAll(resp.Body)
	if ioErr != nil {
		fmt.Println(ioErr)
	}
	if acc.Debug == true {
		fmt.Println(string(body))
	}
	var parsed map[string]interface{}
	json.Unmarshal(body, &parsed)
	return parsed
}

// Updates gets all the Snapchat updates for the authenticated account.
func (acc *Account) Updates() Updates {
	ts := Timestamp()
	data := map[string]string{
		"checksums_dict":   "{}",
		"height":           "1280",
		"width":            "720",
		"max_video_height": "640",
		"max_Video_width":  "480",
		"username":         acc.Username,
		"timestamp":        ts,
		"req_token":        RequestToken(acc.Token, ts),
	}

	resp := acc.SendRequest("POST", "/loq/all_updates", data)
	body, ioErr := ioutil.ReadAll(resp.Body)
	if ioErr != nil {
		fmt.Println(ioErr)
	}
	if acc.Debug == true {
		fmt.Println(string(body))
	}
	var parsed Updates
	json.Unmarshal(body, &parsed)
	return parsed
}

// SuggestedFriends fetches all the Snapchat suggested friends.
func (acc *Account) SuggestedFriends() SuggestedFriends {
	ts := Timestamp()
	data := map[string]string{
		"action":    "list",
		"username":  acc.Username,
		"timestamp": ts,
		"req_token": RequestToken(acc.Token, ts),
	}

	resp := acc.SendRequest("POST", "/bq/suggest_friend", data)
	body, ioErr := ioutil.ReadAll(resp.Body)
	if ioErr != nil {
		fmt.Println(ioErr)
	}
	if acc.Debug == true {
		fmt.Println(string(body))
	}
	var parsed SuggestedFriends
	json.Unmarshal(body, &parsed)
	return parsed
}

// LoadLensSchedule fetches the lens schedule for the authenticated account.
func (acc *Account) LoadLensSchedule() LensSchedule {
	ts := Timestamp()
	data := map[string]string{
		"username":  acc.Username,
		"timestamp": ts,
		"req_token": RequestToken(acc.Token, ts),
	}

	resp := acc.SendRequest("POST", "/lens/load_schedule", data)
	body, ioErr := ioutil.ReadAll(resp.Body)
	if ioErr != nil {
		fmt.Println(ioErr)
	}
	if acc.Debug == true {
		fmt.Println(string(body))
	}
	var parsed LensSchedule
	json.Unmarshal(body, &parsed)
	return parsed
}

// DiscoverChannels fetches Snapchat discover channels.
func (acc *Account) DiscoverChannels() Discover {
	var tr *http.Transport
	var discoverURL = URL + "/discover/channel_list?region=US&country=USA&version=1&language=en"

	tr = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	if acc.ProxyURL != nil {
		tr.Proxy = http.ProxyURL(acc.ProxyURL)
	}

	if acc.Debug == true {
		fmt.Printf("GET"+"\t%s\n", discoverURL)
	}

	client := &http.Client{Transport: tr}

	req, err := http.NewRequest("GET", discoverURL, nil)

	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Accept-Language", AcceptLang)
	req.Header.Set("Accept-Locale", AcceptLocale)

	resp, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
	}

	body, ioErr := ioutil.ReadAll(resp.Body)
	if ioErr != nil {
		fmt.Println(ioErr)
	}
	if acc.Debug == true {
		fmt.Println(string(body))
	}
	var parsed Discover
	json.Unmarshal(body, &parsed)
	return parsed
}

// DownloadSnapTag fetches the authenticated users Snaptag.
func (acc *Account) DownloadSnapTag(sfmt SnapTagImageFormat) (SnapTag, error) {
	ts := Timestamp()
	format := string(sfmt)
	data := map[string]string{
		"username":  acc.Username,
		"timestamp": ts,
		"type":      format,
		"req_token": RequestToken(acc.Token, ts),
		"user_id":   acc.UserID,
	}

	resp := acc.SendRequest("POST", "/bq/snaptag_download", data)
	body, ioErr := ioutil.ReadAll(resp.Body)
	if ioErr != nil {
		return SnapTag{}, ioErr
	}
	if acc.Debug == true {
		fmt.Println(string(body))
	}
	var parsed SnapTag
	json.Unmarshal(body, &parsed)
	return parsed, nil
}

// DownloadFriendSnapTag fetches a friends Snaptag.
// Requires their Snapchat user_id in the form:
// 84ee8839-3911-492d-8b94-72dd80f3713a
func (acc *Account) DownloadFriendSnapTag(userID string, sfmt SnapTagImageFormat) (SnapTag, error) {
	ts := Timestamp()
	format := string(sfmt)
	data := map[string]string{
		"username":  acc.Username,
		"timestamp": ts,
		"type":      format,
		"req_token": RequestToken(acc.Token, ts),
		"user_id":   userID,
	}

	resp := acc.SendRequest("POST", "/bq/snaptag_download", data)
	body, ioErr := ioutil.ReadAll(resp.Body)
	if ioErr != nil {
		return SnapTag{}, ioErr
	}
	if acc.Debug == true {
		fmt.Println(string(body))
	}
	var parsed SnapTag
	json.Unmarshal(body, &parsed)
	return parsed, nil
}

// Upload sends media to Snapchat.
func (acc *Account) Upload(path string) (string, error) {
	ts := Timestamp()
	id := MediaID(acc.Username)

	file, err := ioutil.ReadFile(path)
	if err != nil {
		return "", errors.New("File does not exist.")
	}

	mediaType, err := DetectMedia(file)
	if err != nil {
		return "", err
	}

	data := map[string]string{
		"media_id":  id,
		"req_token": RequestToken(acc.Token, ts),
		"timestamp": ts,
		"type":      mediaType,
		"username":  acc.Username,
		"zipped":    "0",
	}
	resp := acc.SendMultipartRequest("/ph/upload", data, path)
	body, ioErr := ioutil.ReadAll(resp.Body)
	if ioErr != nil {
		fmt.Println(ioErr)
	}
	if acc.Debug == true {
		fmt.Println(string(body))
	}
	if resp.StatusCode != 200 {
		return "", errors.New("An error occured: HTTP Status: " + resp.Status)
	}
	return id, nil
}

// Send sends media to other Snapchat users.
func (acc *Account) Send(mediaID string, recipients []string, time int) (map[string]interface{}, error) {
	ts := Timestamp()
	rp, err := json.Marshal(recipients)
	if err != nil {
		return nil, err
	}
	timeString := strconv.Itoa(int(time))
	data := map[string]string{
		"username":            acc.Username,
		"timestamp":           ts,
		"req_token":           RequestToken(acc.Token, ts),
		"media_id":            mediaID,
		"recipients":          string(rp),
		"reply":               "0",
		"time":                timeString,
		"country_code":        "US",
		"camera_front_facing": "0",
		"zipped":              "0",
	}

	resp := acc.SendRequest("POST", "/loq/send", data)
	body, ioErr := ioutil.ReadAll(resp.Body)
	if ioErr != nil {
		return nil, ioErr
	}
	if acc.Debug == true {
		fmt.Println(string(body))
	}
	if resp.StatusCode != 200 {
		return nil, errors.New(resp.Status)
	}
	var parsed map[string]interface{}
	json.Unmarshal(body, &parsed)
	return parsed, nil
}

// RetrySend retries to resend media to Snapchat users.
func (acc *Account) RetrySend(mediaID string, path string, recipients []string, time int) (map[string]interface{}, error) {
	ts := Timestamp()
	var rp string
	for i, v := range recipients {
		if i > 0 {
			rp += "\",\""
		} else {
			rp += "[\""
		}
		rp += v
		if i == len(recipients)-1 {
			rp += "\"]"
		}
	}
	timeString := strconv.Itoa(time)
	data := map[string]string{
		"username":            acc.Username,
		"timestamp":           ts,
		"req_token":           RequestToken(acc.Token, ts),
		"media_id":            mediaID,
		"recipients":          string(rp),
		"reply":               "0",
		"time":                timeString,
		"camera_front_facing": "0",
		"zipped":              "0",
	}

	resp := acc.SendMultipartRequest("/loq/retry", data, path)
	body, ioErr := ioutil.ReadAll(resp.Body)
	if ioErr != nil {
		return nil, ioErr
	}
	if acc.Debug == true {
		fmt.Println(string(body))
	}
	if resp.StatusCode != 200 {
		return nil, errors.New(resp.Status)
	}
	var parsed map[string]interface{}
	json.Unmarshal(body, &parsed)
	return parsed, nil
}

// PostStory posts media to a users Snapchat story.
func (acc *Account) PostStory(mediaID string, path string, caption string, time int) (map[string]interface{}, error) {
	ts := Timestamp()

	file, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, errors.New("File does not exist.")
	}

	mediaType, err := DetectMedia(file)
	if err != nil {
		return nil, err
	}

	if caption == "" {
		caption = ""
	}

	data := map[string]string{
		"camera_front_facing":  "0",
		"username":             acc.Username,
		"timestamp":            ts,
		"req_token":            RequestToken(acc.Token, ts),
		"media_id":             mediaID,
		"my_story":             "true",
		"client_id":            mediaID,
		"story_timestamp":      ts,
		"shared_ids":           "{}",
		"caption_text_display": caption,
		"type":                 mediaType,
		"time":                 string(time),
	}

	resp := acc.SendRequest("POST", "/bq/post_story", data)
	body, ioErr := ioutil.ReadAll(resp.Body)
	if ioErr != nil {
		return nil, ioErr
	}
	if acc.Debug == true {
		fmt.Println(string(body))
	}
	if resp.StatusCode != 200 {
		return nil, errors.New(resp.Status)
	}
	var parsed map[string]interface{}
	json.Unmarshal(body, &parsed)
	return parsed, nil
}

// RetryPostStory retries to post media to a users Snapchat story.
func (acc *Account) RetryPostStory(mediaID string, path string, caption string, time int) (map[string]interface{}, error) {
	ts := Timestamp()

	file, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, errors.New("File does not exist.")
	}

	mediaType, err := DetectMedia(file)
	if err != nil {
		return nil, err
	}

	if caption == "" {
		caption = ""
	}

	timeString := strconv.Itoa(int(time))
	data := map[string]string{
		"username":             acc.Username,
		"timestamp":            ts,
		"req_token":            RequestToken(acc.Token, ts),
		"media_id":             mediaID,
		"client_id":            mediaID,
		"caption_text_display": caption,
		"type":                 mediaType,
		"time":                 timeString,
	}

	resp := acc.SendMultipartRequest("/bq/retry_post_story", data, path)
	body, ioErr := ioutil.ReadAll(resp.Body)
	if ioErr != nil {
		return nil, ioErr
	}
	if acc.Debug == true {
		fmt.Println(string(body))
	}
	if resp.StatusCode != 200 {
		return nil, errors.New(resp.Status)
	}
	var parsed map[string]interface{}
	json.Unmarshal(body, &parsed)
	return parsed, nil
}

// DeleteStory deletes media from a Snapchat story.
func (acc *Account) DeleteStory(username, AuthToken, id string) bool {
	ts := Timestamp()
	data := map[string]string{
		"username":  username,
		"timestamp": ts,
		"req_token": RequestToken(AuthToken, ts),
		"story_id":  id,
	}

	resp := acc.SendRequest("POST", "/bq/delete_story", data)
	body, ioErr := ioutil.ReadAll(resp.Body)
	if ioErr != nil {
		fmt.Println(ioErr)
	}
	if acc.Debug == true {
		fmt.Println(string(body))
	}
	if resp.StatusCode != 200 {
		return false
	}

	return true
}

// DoublePost posts a snap to a users Snapchat story and to other Snapchat users.
func (acc *Account) DoublePost(username, AuthToken, id string, recipients []string, blobType, time int) map[string]interface{} {
	ts := Timestamp()
	var rp string
	for i, v := range recipients {
		if i > 0 {
			rp += ","
		}
		rp += v
	}
	data := map[string]string{
		"username":             username,
		"timestamp":            ts,
		"req_token":            RequestToken(AuthToken, ts),
		"media_id":             id,
		"client_id":            id,
		"recipient":            rp,
		"caption_text_display": "",
		"type":                 string(blobType),
		"time":                 string(time),
	}

	resp := acc.SendRequest("POST", "/bq/double_post", data)
	body, ioErr := ioutil.ReadAll(resp.Body)
	if ioErr != nil {
		fmt.Println(ioErr)
	}
	if acc.Debug == true {
		fmt.Println(string(body))
	}
	var parsed map[string]interface{}
	json.Unmarshal(body, &parsed)
	return parsed
}

// FindFriends finds friends using a phone number from contacts.
func (acc *Account) FindFriends(username, AuthToken, countryCode string, contacts map[string]string) map[string]interface{} {
	ts := Timestamp()
	nums, err := json.Marshal(contacts)
	if err != nil {
		fmt.Println(err)
	}
	data := map[string]string{
		"username":    username,
		"timestamp":   ts,
		"req_token":   RequestToken(AuthToken, ts),
		"countryCode": countryCode,
		"numbers":     string(nums),
	}

	resp := acc.SendRequest("POST", "/bq/find_friends", data)
	body, ioErr := ioutil.ReadAll(resp.Body)
	if ioErr != nil {
		fmt.Println(ioErr)
	}
	if acc.Debug == true {
		fmt.Println(string(body))
	}
	var parsed map[string]interface{}
	json.Unmarshal(body, &parsed)
	return parsed
}

// AddFriend adds a friend on Snapchat.
func (acc *Account) AddFriend(username, AuthToken, friend string) map[string]interface{} {
	ts := Timestamp()
	data := map[string]string{
		"username":  username,
		"timestamp": ts,
		"req_token": RequestToken(AuthToken, ts),
		"action":    "add",
		"friend":    friend,
	}

	resp := acc.SendRequest("POST", "/bq/friend", data)
	body, ioErr := ioutil.ReadAll(resp.Body)
	if ioErr != nil {
		fmt.Println(ioErr)
	}
	if acc.Debug == true {
		fmt.Println(string(body))
	}
	var parsed map[string]interface{}
	json.Unmarshal(body, &parsed)
	return parsed
}

// DeleteFriend deletes a friend on Snapchat.
func (acc *Account) DeleteFriend(username, AuthToken, friend string) map[string]interface{} {
	ts := Timestamp()
	data := map[string]string{
		"username":  username,
		"timestamp": ts,
		"req_token": RequestToken(AuthToken, ts),
		"action":    "delete",
		"friend":    friend,
	}

	resp := acc.SendRequest("POST", "/bq/friend", data)
	body, ioErr := ioutil.ReadAll(resp.Body)
	if ioErr != nil {
		fmt.Println(ioErr)
	}
	if acc.Debug == true {
		fmt.Println(string(body))
	}
	var parsed map[string]interface{}
	json.Unmarshal(body, &parsed)
	return parsed
}

// BlockFriend blocks a friend on Snapchat.
func (acc *Account) BlockFriend(username, AuthToken, friend string) map[string]interface{} {
	ts := Timestamp()
	data := map[string]string{
		"username":  username,
		"timestamp": ts,
		"req_token": RequestToken(AuthToken, ts),
		"action":    "block",
		"friend":    friend,
	}

	resp := acc.SendRequest("POST", "/bq/friend", data)
	body, ioErr := ioutil.ReadAll(resp.Body)
	if ioErr != nil {
		fmt.Println(ioErr)
	}
	if acc.Debug == true {
		fmt.Println(string(body))
	}
	var parsed map[string]interface{}
	json.Unmarshal(body, &parsed)
	return parsed
}

// UnblockFriend unblocks a friend on Snapchat.
func (acc *Account) UnblockFriend(username, AuthToken, friend string) map[string]interface{} {
	ts := Timestamp()
	data := map[string]string{
		"username":  username,
		"timestamp": ts,
		"req_token": RequestToken(AuthToken, ts),
		"action":    "unblock",
		"friend":    friend,
	}

	resp := acc.SendRequest("POST", "/bq/friend", data)
	body, ioErr := ioutil.ReadAll(resp.Body)
	if ioErr != nil {
		fmt.Println(ioErr)
	}
	if acc.Debug == true {
		fmt.Println(string(body))
	}
	var parsed map[string]interface{}
	json.Unmarshal(body, &parsed)
	return parsed
}

// SetNickname sets a nickname a friend on Snapchat.
func (acc *Account) SetNickname(username, AuthToken, friend, nickname string) map[string]interface{} {
	ts := Timestamp()
	data := map[string]string{
		"username":  username,
		"timestamp": ts,
		"req_token": RequestToken(AuthToken, ts),
		"action":    "display",
		"friend":    friend,
		"display":   nickname,
	}

	resp := acc.SendRequest("POST", "/bq/friend", data)
	body, ioErr := ioutil.ReadAll(resp.Body)
	if ioErr != nil {
		fmt.Println(ioErr)
	}
	if acc.Debug == true {
		fmt.Println(string(body))
	}
	var parsed map[string]interface{}
	json.Unmarshal(body, &parsed)
	return parsed
}

// BestFriends fetches best friends, scores and miscellania on Snapchat.
func (acc *Account) BestFriends(username, AuthToken string, friends []string) map[string]interface{} {
	ts := Timestamp()
	users, err := json.Marshal(friends)
	if err != nil {
		fmt.Println(err)
	}
	data := map[string]string{
		"username":         username,
		"timestamp":        ts,
		"req_token":        RequestToken(AuthToken, ts),
		"friend_usernames": string(users),
	}

	resp := acc.SendRequest("POST", "/bq/bests", data)
	body, ioErr := ioutil.ReadAll(resp.Body)
	if ioErr != nil {
		fmt.Println(ioErr)
	}
	if acc.Debug == true {
		fmt.Println(string(body))
	}
	var parsed map[string]interface{}
	json.Unmarshal(body, &parsed)
	return parsed
}

// SetProxyURL sets given string addr, as a proxy addr. Primarily for debugging purposes.
// Other reasons include bypassing IP banning.
func (acc *Account) SetProxyURL(addr string) error {
	proxyURL, err := url.Parse(addr)
	if err != nil {
		return err
	}
	if proxyURL.Scheme == "" {
		return errors.New("Invalid proxy url.")
	}
	acc.ProxyURL = proxyURL
	acc.CasperClient.ProxyURL = proxyURL
	return nil
}
