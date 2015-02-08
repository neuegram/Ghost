package ghost

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	HOST                = "feelinsonice-hrd.appspot.com"
	URL                 = "https://" + HOST
	USER_AGENT          = "Snapchat/6.0.2 (iPhone; iOS 7.0.4; gzip)"
	ACCEPT_LANG         = "en;q=1, zh-Hans;q=0.9"
	PATTERN             = "0001110111101110001111010101111011010001001110011000110001000110"
	SECRET              = "iEk21fuwZApXlz93750dmW22pw389dPwOk"
	STATIC_TOKEN        = "m198sOkJEn37DjqZ32lpRu76xmw288xSQ9"
	BLOB_ENCRYPTION_KEY = "M02cnQ51Ji97vwT4"
	IMAGE               = 0
	JPEG_SIGNATURE      = "FFD8FFE0"
	VIDEO               = 1
	MP4_SIGNATURE       = "000000186674797033677035"
)

func DecodeSnaptag(snaptag string) {
	b, _ := hex.DecodeString(snaptag)
	for _, v := range b {
		fmt.Println(strconv.FormatInt(int64(v), 2))
	}
}

func AddPKCS5(plaintext []byte) []byte {
	padding := aes.BlockSize - (len(plaintext) % aes.BlockSize)
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(plaintext, padtext...)
}

func RemovePKCS5(plaintext []byte) []byte {
	unpadding := int(plaintext[len(plaintext)-1])
	return plaintext[:(len(plaintext) - unpadding)]
}

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

func IsJPEG(data []byte) bool {
	sig, err := hex.DecodeString(JPEG_SIGNATURE)
	if err != nil {
		fmt.Println(err)
	}
	if bytes.Equal(data[:len(sig)], sig) {
		return true
	} else {
		return false
	}
}

func IsMP4(data []byte) bool {
	sig, err := hex.DecodeString(MP4_SIGNATURE)
	if err != nil {
		fmt.Println(err)
	}
	if bytes.Equal(data[:len(sig)], sig) {
		return true
	} else {
		return false
	}
}

func AddJPEGSignature(data []byte) []byte {
	sig, err := hex.DecodeString(JPEG_SIGNATURE)
	if err != nil {
		fmt.Println(err)
	}
	return append(sig, data...)
}

func AddMP4Signature(data []byte) []byte {
	sig, err := hex.DecodeString(MP4_SIGNATURE)
	if err != nil {
		fmt.Println(err)
	}
	return append(sig, data...)
}

func Timestamp() string {
	return strconv.Itoa(int(time.Now().Unix()))
}

func UUID4() string {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		fmt.Println(err)
	}
	return fmt.Sprintf("%04x-%02x-%02x-%02x-%06x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

func MediaId(username string) string {
	return fmt.Sprintf("%s~%s", strings.ToUpper(username), UUID4())
}

func RequestToken(authToken, timestamp string) string {
	hash := sha256.New()
	io.WriteString(hash, SECRET+authToken)
	first := hex.EncodeToString(hash.Sum(nil))
	hash.Reset()
	io.WriteString(hash, timestamp+SECRET)
	second := hex.EncodeToString(hash.Sum(nil))
	var bits string
	for i, c := range PATTERN {
		if c == '0' {
			bits += string(first[i])
		} else {
			bits += string(second[i])
		}
	}
	return bits
}

func SendRequest(endpoint string, data map[string]string) *http.Response {
	//For testing purposes only!
	/*proxyUrl, err := url.Parse("http://192.168.1.148:8888")
	if err != nil {
		fmt.Println(err)
	}*/

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		//Proxy:           http.ProxyURL(proxyUrl),
	}

	client := &http.Client{Transport: tr}

	fmt.Printf("POST\t%s\n", URL+endpoint)

	form := url.Values{}
	for k, v := range data {
		form.Add(k, v)
		fmt.Printf("%s\t%s\n", k, v)
	}

	req, err := http.NewRequest("POST", URL+endpoint, strings.NewReader(form.Encode()))
	req.Header.Set("User-Agent", USER_AGENT)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept-Language", ACCEPT_LANG)
	if err != nil {
		fmt.Println(err)
	}

	resp, err := client.Do(req)

	if err != nil {
		fmt.Println(err)
	}

	return resp
}

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
	req.Header.Set("User-Agent", USER_AGENT)
	req.Header.Set("Accept-Language", ACCEPT_LANG)
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

func SendMultipartRequest(endpoint string, data map[string]string, path string) *http.Response {
	// For debugging purposes only!
	file, err := os.Open(path)
	if err != nil {
		fmt.Println(err)
	}
	defer file.Close()

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	err = writer.SetBoundary("Boundary+0xAbCdEfGbOuNdArY")
	if err != nil {
		fmt.Println(err)
	}
	mh := make(textproto.MIMEHeader)
	mh.Set("Content-Disposition", "form-data; name=\"data\"; filename=\"data\"")
	mh.Set("Content-Type", "application/octet-stream")
	part_writer, err := writer.CreatePart(mh)
	if err != nil {
		fmt.Println(err)
	}
	if err != nil {
		fmt.Println(err)
	}
	_, err = io.Copy(part_writer, file)
	if err != nil {
		fmt.Println(err)
	}

	for k, v := range data {
		mh = make(textproto.MIMEHeader)
		dpos := fmt.Sprintf("form-data; name=\"%s\"", k)
		mh.Set("Content-Disposition", dpos)
		part_writer, err = writer.CreatePart(mh)
		if nil != err {
			panic(err)
		}
		mh.Set("Boundary", writer.Boundary())
		io.Copy(part_writer, bytes.NewBufferString(v))
	}

	err = writer.Close()
	if err != nil {
		fmt.Println(err)
	}

	//For testing purposes only!
	/*proxyUrl, err := url.Parse("http://192.168.1.148:8888")
	if err != nil {
		fmt.Println(err)
	}*/

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		//Proxy:           http.ProxyURL(proxyUrl),
	}

	client := &http.Client{Transport: tr}

	req, err := http.NewRequest("POST", URL+endpoint, body)
	//req.Header.Set("User-Agent", USER_AGENT)
	req.Header.Set("Content-Type", "multipart/form-data; boundary=Boundary+0xAbCdEfGbOuNdArY")
	req.Header.Set("Accept-Language", ACCEPT_LANG)
	for k, v := range req.Header {
		fmt.Println(k, v)
	}
	fmt.Println(body)

	resp, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
	}

	return resp
}

func Register(email, password, birthday string, age int) map[string]interface{} {
	ts := Timestamp()
	data := map[string]string{
		"timestamp": ts,
		"req_token": RequestToken(STATIC_TOKEN, ts),
		"email":     email,
		"password":  password,
		"age":       string(age),
		"birthday":  birthday,
	}

	resp := SendRequest("/bq/register", data)
	body, ioErr := ioutil.ReadAll(resp.Body)
	fmt.Println(string(body))
	if ioErr != nil {
		fmt.Println(ioErr)
	}

	var parsed map[string]interface{}
	json.Unmarshal(body, &parsed)
	return parsed
}

func RegisterUsername(email, username string) map[string]interface{} {
	ts := Timestamp()
	data := map[string]string{
		"timestamp": ts,
		"req_token": RequestToken(STATIC_TOKEN, ts),
		"email":     email,
		"username":  username,
	}

	resp := SendRequest("/bq/registeru", data)
	body, ioErr := ioutil.ReadAll(resp.Body)
	fmt.Println(string(body))
	if ioErr != nil {
		fmt.Println(ioErr)
	}

	var parsed map[string]interface{}
	json.Unmarshal(body, &parsed)
	return parsed
}

func Login(username, password string) map[string]interface{} {
	ts := Timestamp()
	data := map[string]string{
		"username":  username,
		"timestamp": ts,
		"req_token": RequestToken(STATIC_TOKEN, ts),
		"password":  password,
	}

	resp := SendRequest("/bq/login", data)
	body, ioErr := ioutil.ReadAll(resp.Body)
	//fmt.Println(string(body))
	if ioErr != nil {
		fmt.Println(ioErr)
	}

	var parsed map[string]interface{}
	json.Unmarshal(body, &parsed)
	return parsed
}

func Logout(username, authToken string) bool {
	ts := Timestamp()
	data := map[string]string{
		"username":  username,
		"timestamp": ts,
		"req_token": RequestToken(authToken, ts),
		"json":      "{}",
		"events":    "[]",
	}

	resp := SendRequest("/bq/logout", data)
	fmt.Println(resp.Status)
	if resp.StatusCode != 200 {
		return false
	}
	return true
}

func FetchBlob(username, authToken, id string) []byte {
	ts := Timestamp()
	data := map[string]string{
		"username":  username,
		"timestamp": ts,
		"req_token": RequestToken(authToken, ts),
		"id":        id,
	}

	resp := SendRequest("/bq/blob", data)
	body, ioErr := ioutil.ReadAll(resp.Body)
	fmt.Println(string(body))
	if ioErr != nil {
		fmt.Println(ioErr)
	}

	return body
}

func Upload(username, authToken string, blobType int, path string) string { //map[string]interface{} {
	ts := Timestamp()
	id := MediaId(username)
	data := map[string]string{
		"media_id":  id,
		"req_token": RequestToken(authToken, ts),
		"timestamp": ts,
		"type":      "0",
		"username":  username,
		"zipped":    "0",
	}

	resp := SendMultipartRequest("/bq/upload", data, path)
	fmt.Println(resp.Status)
	if resp.StatusCode != 200 {
		return resp.Status
	}
	return id
}

func SendBlob(username, authToken, id string, recipients []string, time int) string {
	ts := Timestamp()
	rp, err := json.Marshal(recipients)
	if err != nil {
		fmt.Println(err)
	}
	data := map[string]string{
		"username":            username,
		"timestamp":           ts,
		"req_token":           RequestToken(authToken, ts),
		"media_id":            id,
		"recipients":          string(rp),
		"reply":               "1",
		"time":                "5",
		"country_code":        "US",
		"camera_front_facing": "0",
		"zipped":              "0",
	}

	resp := SendRequest("/loq/send", data)
	fmt.Println(resp.Status)
	if resp.StatusCode != 200 {
		return resp.Status
	}
	return id
}

func RetryBlob(username, authToken string, blobType int, encryptedBlob []byte, recipients []string, time int) string {
	ts := Timestamp()
	var rp string
	for i, v := range recipients {
		if i > 0 {
			rp += ","
		}
		rp += v
	}
	data := map[string]string{
		"username":  username,
		"timestamp": ts,
		"req_token": RequestToken(authToken, ts),
		"media_id":  MediaId(username),
		"type":      string(blobType),
		"data":      string(encryptedBlob),
		"recipient": rp,
		"time":      string(time),
	}

	resp := SendRequest("/bq/retry", data)
	return resp.Status
}

func PostStory(username, authToken, id string, blobType, time int) map[string]interface{} {
	ts := Timestamp()
	data := map[string]string{
		"username":             username,
		"timestamp":            ts,
		"auth_token":           RequestToken(authToken, ts),
		"media_id":             id,
		"client_id":            id,
		"caption_text_display": "",
		"type":                 string(blobType),
		"time":                 string(time),
	}

	resp := SendRequest("/bq/post_story", data)
	body, ioErr := ioutil.ReadAll(resp.Body)
	fmt.Println(string(body))
	if ioErr != nil {
		fmt.Println(ioErr)
	}

	var parsed map[string]interface{}
	json.Unmarshal(body, &parsed)
	return parsed
}

func DeleteStory(username, authToken, id string) bool {
	ts := Timestamp()
	data := map[string]string{
		"username":  username,
		"timestamp": ts,
		"req_token": RequestToken(authToken, ts),
		"story_id":  id,
	}

	resp := SendRequest("/bq/delete_story", data)
	if resp.StatusCode != 200 {
		return false
	}
	return true
}

func RetryPostStory(username, authToken string, blobType, time int, encryptedBlob []byte) map[string]interface{} {
	ts := Timestamp()
	id := MediaId(username)
	data := map[string]string{
		"username":             username,
		"timestamp":            ts,
		"req_token":            RequestToken(authToken, ts),
		"media_id":             id,
		"client_id":            id,
		"caption_text_display": "",
		"type":                 string(blobType),
		"time":                 string(time),
		"data":                 string(encryptedBlob),
	}

	resp := SendRequest("/bq/retry_post_story", data)
	body, ioErr := ioutil.ReadAll(resp.Body)
	fmt.Println(string(body))
	if ioErr != nil {
		fmt.Println(ioErr)
	}

	var parsed map[string]interface{}
	json.Unmarshal(body, &parsed)
	return parsed
}

func DoublePost(username, authToken, id string, recipients []string, blobType, time int) map[string]interface{} {
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
		"req_token":            RequestToken(authToken, ts),
		"media_id":             id,
		"client_id":            id,
		"recipient":            rp,
		"caption_text_display": "",
		"type":                 string(blobType),
		"time":                 string(time),
	}

	resp := SendRequest("/bq/double_post", data)
	body, ioErr := ioutil.ReadAll(resp.Body)
	fmt.Println(string(body))
	if ioErr != nil {
		fmt.Println(ioErr)
	}

	var parsed map[string]interface{}
	json.Unmarshal(body, &parsed)
	return parsed
}

func FindFriends(username, authToken, countryCode string, contacts map[string]string) map[string]interface{} {
	ts := Timestamp()
	nums, err := json.Marshal(contacts)
	if err != nil {
		fmt.Println(err)
	}
	data := map[string]string{
		"username":    username,
		"timestamp":   ts,
		"req_token":   RequestToken(authToken, ts),
		"countryCode": countryCode,
		"numbers":     string(nums),
	}

	resp := SendRequest("/bq/find_friends", data)
	body, ioErr := ioutil.ReadAll(resp.Body)
	fmt.Println(string(body))
	if ioErr != nil {
		fmt.Println(ioErr)
	}

	var parsed map[string]interface{}
	json.Unmarshal(body, &parsed)
	return parsed
}

func AddFriend(username, authToken, friend string) map[string]interface{} {
	ts := Timestamp()
	data := map[string]string{
		"username":  username,
		"timestamp": ts,
		"req_token": RequestToken(authToken, ts),
		"action":    "add",
		"friend":    friend,
	}

	resp := SendRequest("/bq/friend", data)
	body, ioErr := ioutil.ReadAll(resp.Body)
	fmt.Println(string(body))
	if ioErr != nil {
		fmt.Println(ioErr)
	}

	var parsed map[string]interface{}
	json.Unmarshal(body, &parsed)
	return parsed
}

func DeleteFriend(username, authToken, friend string) map[string]interface{} {
	ts := Timestamp()
	data := map[string]string{
		"username":  username,
		"timestamp": ts,
		"req_token": RequestToken(authToken, ts),
		"action":    "delete",
		"friend":    friend,
	}

	resp := SendRequest("/bq/friend", data)
	body, ioErr := ioutil.ReadAll(resp.Body)
	fmt.Println(string(body))
	if ioErr != nil {
		fmt.Println(ioErr)
	}

	var parsed map[string]interface{}
	json.Unmarshal(body, &parsed)
	return parsed
}

func BlockFriend(username, authToken, friend string) map[string]interface{} {
	ts := Timestamp()
	data := map[string]string{
		"username":  username,
		"timestamp": ts,
		"req_token": RequestToken(authToken, ts),
		"action":    "block",
		"friend":    friend,
	}

	resp := SendRequest("/bq/friend", data)
	body, ioErr := ioutil.ReadAll(resp.Body)
	fmt.Println(string(body))
	if ioErr != nil {
		fmt.Println(ioErr)
	}

	var parsed map[string]interface{}
	json.Unmarshal(body, &parsed)
	return parsed
}

func UnblockFriend(username, authToken, friend string) map[string]interface{} {
	ts := Timestamp()
	data := map[string]string{
		"username":  username,
		"timestamp": ts,
		"req_token": RequestToken(authToken, ts),
		"action":    "unblock",
		"friend":    friend,
	}

	resp := SendRequest("/bq/friend", data)
	body, ioErr := ioutil.ReadAll(resp.Body)
	fmt.Println(string(body))
	if ioErr != nil {
		fmt.Println(ioErr)
	}

	var parsed map[string]interface{}
	json.Unmarshal(body, &parsed)
	return parsed
}

func SetNickname(username, authToken, friend, nickname string) map[string]interface{} {
	ts := Timestamp()
	data := map[string]string{
		"username":  username,
		"timestamp": ts,
		"req_token": RequestToken(authToken, ts),
		"action":    "display",
		"friend":    friend,
		"display":   nickname,
	}

	resp := SendRequest("/bq/friend", data)
	body, ioErr := ioutil.ReadAll(resp.Body)
	fmt.Println(string(body))
	if ioErr != nil {
		fmt.Println(ioErr)
	}

	var parsed map[string]interface{}
	json.Unmarshal(body, &parsed)
	return parsed
}

func BestFriends(username, authToken string, friends []string) map[string]interface{} {
	ts := Timestamp()
	users, err := json.Marshal(friends)
	if err != nil {
		fmt.Println(err)
	}
	data := map[string]string{
		"username":         username,
		"timestamp":        ts,
		"req_token":        RequestToken(authToken, ts),
		"friend_usernames": string(users),
	}

	resp := SendRequest("/bq/bests", data)
	body, ioErr := ioutil.ReadAll(resp.Body)
	fmt.Println(string(body))
	if ioErr != nil {
		fmt.Println(ioErr)
	}

	var parsed map[string]interface{}
	json.Unmarshal(body, &parsed)
	return parsed
}
