# ghost
A Go library for Snapchat's API

#### Installation
`$ go get github.com/neuegram/ghost`

This library has been updated to keep up with Snapchat's changes. To use this library you need to signup to use the Casper API.

[Register a casper account](https://clients.casper.io/register.php), and you can start using this library.

### Warning

**This library is in alpha** at the moment, not everything has been tested (yet) but the basics still work. Feel free to contribute, this library is actively maintained and is making fast progress! :)

**Use at your own risk.**

### Examples

### Fetch all updates
```go
package main

import (
	"fmt"
	"github.com/neuegram/ghost"
)

func main() {
	casperClient := ghost.NewRawCasperClient("yourapikey","yourapisecret")
	casperClient.Username = "yoursnapchatusername"
	casperClient.Password = "yoursnapchatpassword"
	casperClient.Debug = false
	snapchat := ghost.NewAccount("yourgmailaccount@gmail.com", "yourgmailpassword", casperClient, false)
	err := snapchat.Login()
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(snapchat.Updates())
}

```

### Sending a Snap
```go
package main

import (
	"fmt"
	"github.com/neuegram/ghost"
)

func main() {
	casperClient := ghost.NewRawCasperClient("yourapikey","yourapisecret")
	casperClient.Username = "yoursnapchatusername"
	casperClient.Password = "yoursnapchatpassword"
	casperClient.Debug = false
	snapchat := ghost.NewAccount("yourgmailaccount@gmail.com", "yourgmailpassword", casperClient, false)
	err := snapchat.Login()
	mediaID, err := snapchat.Upload("yoursnap.jpg")
	result, err := snapchat.Send(mediaID, []string{"teamsnapchat"}, 10)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(result)
}
```

#### Snapchat Registration CLI
You can register a Snapchat account through the CLI.

Run `$ go get github.com/neuegram/ghost/srcli`

Run `$ srcli -help` for more details.

### Special Thanks

- [mgp25](https://github.com/mgp25)
- [neuegram](https://github.com/neuegram)
- [teknogeek](https://github.com/teknogeek)
- [hako](https://github.com/hako)
- [liamcottle](https://github.com/liamcottle) (creator of [Casper](https://casper.io/))
- [kyleboyer](https://github.com/kyleboyer)

If you would like to contribute, you can take a look at the documentation [here](https://github.com/mgp25/SC-API/wiki/API-v2-Research) and [here](https://github.com/cuonic/SnapchatDevWiki/wiki).

### Extra Special Thanks :poop:
To whoever at Snapchat came up with this header:
> “X-Snapchat-Notice: Snapchat Private APIs - Unauthorized use is prohibited.”

And to whoever at Snapchat came up with this message:
> We've noticed that you're using a third-party application to access Snapchat, putting yourself (and possibly your friends) at risk. Please change your password and stop using third-party applications when you access Snapchat.

### License
This project is licensed under the MIT license, see the LICENSE file for more details.
