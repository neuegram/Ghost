# Ghost
A Go library for Snapchat's API

### Example
```go
// Login
loginResult := Login("myUsername", "myPassword")
authToken = loginResult["auth_token"].(string)
// Encrypt
file, _ := ioutil.ReadFile("filePathIn.jpg")
encryptedFile := EncryptECB([]byte(BLOB_ENCRYPTION_KEY), file)
ioutil.WriteFile("filePathOut.jpg", encryptedFile, 0644)
// Upload
id := Upload("myUsername", authToken, IMAGE, "ImageECB.jpg")
SendBlob("myUsername", authToken, id, []string{"recipientUsername"}, 10)
```

### Status
Because some parts have needed more work than others, I have yet to test about half of the code. I haven't had enough time to go through all of Snapchat's API changes since I last documented it. If something doesn't work, opening an issue (and email me if you feel the need). More coming, including additions to my Snapchat API [documentation](https://github.com/neuegram/SnAPI) (it needs a lot of updating :grimacing:).

### Special Thanks :poop:
To whoever at Snapchat came up with this header:
> “X-Snapchat-Notice: Snapchat Private APIs - Unauthorized use is prohibited.”

And to whoever at Snapchat came up with this message:
> We've noticed that you're using a third-party application to access Snapchat, putting yourself (and possibly your friends) at risk. Please change your password and stop using third-party applications when you access Snapchat.
