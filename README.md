# ghost
A Go library for Snapchat's API

### Sending a Snap example
```go
 casperClient := &casper.Casper{
    APIKey:    "yourapikey",
    APISecret: "yourapisecret",
    Username:  "yoursnapchatusername",
    Password:  "yoursnapchatpassword",
    Debug:     false,
}
snapchat := ghost.NewAccount("yourgmailaccount@gmail.com", "yourgmailpassword", casperClient, false)
err := snapchat.Login()
if err != nil {
	fmt.Println(err)
}
snapchat.Updates()
mediaID, _ := snapchat.Upload("yoursnap.jpg")
result, _ := snapchat.Send(mediaID, []string{"teamsnapchat"}, 10)
fmt.Println(result)
```
#### Installation
`$ go get github.com/hako/ghost`

#### Update
This library has been updated to keep up with Snapchat's changes. To use this library you need to install the Casper API. 

There is a Go library of the API [here](https://github.com/hako/casper)

Run `go get github.com/hako/casper` then enter your API keys and you can start using this library.

You can take a look at the documentation [here](https://github.com/mgp25/SC-API/wiki/API-v2-Research) and [here](https://github.com/cuonic/SnapchatDevWiki/wiki).

#### Snapchat Registration CLI
You can register a Snapchat account through the CLI.

Run `$ go get github.com/hako/ghost/srcli`

Run `$ srcli -help` for more details.

### Warning

**This library is in alpha** at the moment, not everything has been tested (yet) but the basics still work. Feel free to contribute, this library is actively maintained and is making fast progress! :)

But use at your own risk.

### Special Thanks

- [mgp25](https://github.com/hako/SC-API)
- [neuegram](https://github.com/neuegram)
- [teknogeek](https://github.com/teknogeek)
- [hako](https://github.com/hako)
- [liamcottle](https://github.com/liamcottle) (creator of [Casper](https://casper.io/))
- [kyleboyer](https://github.com/kyleboyer)

### Extra Special Thanks :poop:
To whoever at Snapchat came up with this header:
> “X-Snapchat-Notice: Snapchat Private APIs - Unauthorized use is prohibited.”

And to whoever at Snapchat came up with this message:
> We've noticed that you're using a third-party application to access Snapchat, putting yourself (and possibly your friends) at risk. Please change your password and stop using third-party applications when you access Snapchat.

### License
This project is licensed under the MIT license, see the LICENSE file for more details.
