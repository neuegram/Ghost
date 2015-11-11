package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"sort"
	"strings"

	"github.com/docopt/docopt-go"
	"github.com/enodata/faker"
	"github.com/hako/casper"
	"github.com/neuegram/ghost"
	"gopkg.in/readline.v1"
)

var (
	debug    bool
	proxy    string
	finalMap map[string]string
	data     GeneratedSCAccount

	version       = "0.5.2"
	autocompleter = readline.NewPrefixCompleter(
		readline.PcItem("Y"),
		readline.PcItem("N"),
	)

	usage = `Snapchat Registration CLI ` + version + ` by Wesley Hill

Usage:
  srcli generate <gmail> <gpassword> <key> <secret> [-p <PROXY> | --proxy=<PROXY>]
  srcli register -f <FILE> (--captcha | --phone <number>) [-d | --debug] [-p <PROXY>]
  srcli register -i <username> <password> <email> <birthday> <gmail> <gpassword> <key> <secret> (--captcha | --phone <number>) [-d | --debug] [-p <PROXY>]
  srcli register (--captcha | --phone <number>) [-d | --debug] [-p <PROXY>]
  srcli teehee
  srcli about
  srcli -h | --help
  srcli -a | --about
  srcli --version

Commands:
  generate    Generate a new snapchat user and save it in a .json file.
  register    Debug output. (Requires proxy server)
  teehee      Just...

Options:
  -a --about       About this program.
  -d --debug       Debug output. (Requires proxy server)
  -f <FILE> 	   A registration file (.json)
  -h --help        Show this screen.
  -p <PROXY>       Proxy URL.

  --captcha        Use captcha verification. (default)
  --phone <number> Use phone verification.
  --version        Show version.
 `

	notice = `
				       oxxooooxxo.              
			            .x-o        ox-.            
			           o-.            .-o           
			           -                -.          
			          .-                -o          
			          .-                -o          
			      .-xxx-                -xxxxo      
			      o-xxo                  oxx-o      
			         .--                x-.         
			         o-.                .-x         
			       oxx                    x-o       
			   oxxxx.                      .oxxoo   
			   oxxxx.                      .xxxxx   
			       .-ooooxo          .ooooo-o       
			        ..   .xxxo    .x-x.   ..        
			                .ooooxo.                

			Welcome to the Snapchat Registration CLI.
	        You are currently manually setting up a Snapchat Account.

	  		Please follow the instructions below.
	`
)

// GeneratedSCAccount holds data of a single Snapchat registration account.
// Which was either generated or manually entered in by a human.
type GeneratedSCAccount struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Email    string `json:"email"`
	Birthday string `json:"birthday"`
	Age      string `json:"age"`

	Gmail           string `json:"gmail"`
	GmailPassword   string `json:"gmail_password"`
	CasperAPIKey    string `json:"casper_api_key"`
	CasperAPISecret string `json:"capser_api_secret"`
}

func main() {
	opts, _ := docopt.Parse(usage, nil, true, "version "+version, false)

	if opts["--debug"] == true || opts["-d"] == true {
		debug = true
	} else {
		debug = false
	}

	if opts["-p"] != nil {
		proxy = opts["-p"].(string)
	} else {
		proxy = ""
	}

	if opts["about"] == true || opts["--about"] == true || opts["-a"] == true {
		fmt.Println("Snapchat Registration CLI " + version + " by Wesley Hill (@hako/@hakobyte)")
		return
	}

	if opts["teehee"] == true {
		fmt.Println("\033[37mteehee!\033[39m")
		return
	}

	if opts["generate"] == true {
		key := opts["<key>"].(string)
		secret := opts["<secret>"].(string)
		gmail := opts["<gmail>"].(string)
		gpassword := opts["<gpassword>"].(string)

		snapchat := generateAccount(gmail, gpassword, key, secret)

		jsonbytes, err := json.Marshal(snapchat)
		if err != nil {
			fmt.Println(err)
		}
		ioutil.WriteFile(snapchat.Username+".json", jsonbytes, 0644)
		fmt.Println("Generated account \"" + snapchat.Username + "\" and saved to " + snapchat.Username + ".json")
		return
	}

	if opts["-f"] != nil {
		filename := opts["-f"].(string)

		b, err := ioutil.ReadFile(filename)
		if err != nil {
			fmt.Println("Unable to parse the given file.")
			os.Exit(1)
		}

		if err := json.Unmarshal(b, &data); err != nil {
			fmt.Println("Unable to parse the given file.")
			os.Exit(1)
		}

		finalMap = map[string]string{
			"username":          data.Username,
			"password":          data.Password,
			"email":             data.Email,
			"birthday":          data.Birthday,
			"age":               data.Age,
			"gmail":             data.Gmail,
			"gmail_password":    data.GmailPassword,
			"casper_api_key":    data.CasperAPIKey,
			"casper_api_secret": data.CasperAPISecret,
		}
		registerAccount(opts)
	} else if opts["-i"] == true {
		// CLI input setup.
		age, err := ghost.CalculateAge(opts["<birthday>"].(string))
		if err != nil {
			fmt.Println(errors.New("[ X ] Sorry! " + "\"" + opts["<birthday>"].(string) + "\"" + " is not a valid birthday date!"))
			os.Exit(1)
		}
		uncheckedMap := map[string]string{
			"username":          opts["<username>"].(string),
			"password":          opts["<password>"].(string),
			"email":             opts["<email>"].(string),
			"birthday":          opts["<birthday>"].(string),
			"age":               age,
			"gmail":             opts["<gmail>"].(string),
			"gmail_password":    opts["<gpassword>"].(string),
			"casper_api_key":    opts["<key>"].(string),
			"casper_api_secret": opts["<secret>"].(string),
		}
		// Check the uncheckedMap, (Just in case.)
		checkedMap, err := checkKeys(uncheckedMap)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		finalMap = checkedMap
		registerAccount(opts)
	} else {
		// Manual setup.
		choice, err := manualSetup(opts)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		// TODO decouple huge if statement. WTH
		if choice == "Y" {
			var verificationOption string

			data.Username = finalMap["username"]
			data.Password = finalMap["password"]
			data.Email = finalMap["email"]
			data.Birthday = finalMap["birthday"]
			data.Age = finalMap["age"]
			data.Gmail = finalMap["gmail"]
			data.GmailPassword = finalMap["gmail_password"]
			data.CasperAPIKey = finalMap["casper_api_key"]
			data.CasperAPISecret = finalMap["casper_api_secret"]

			jsonbytes, err := json.MarshalIndent(data, "", " ")
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
			ioutil.WriteFile(data.Username+".json", jsonbytes, 0644)
			fmt.Println("Account \"" + data.Username + "\" and saved to " + data.Username + ".json")

			rl, err := readline.NewEx(&readline.Config{
				AutoComplete: autocompleter,
			})

			fmt.Println(string(jsonbytes))

			// Get the registration option.
			if opts["--captcha"] == true {
				verificationOption = "This is your registration data. Register now with captcha verification? [Y / N] "
			}
			if opts["--phone"] == true {
				verificationOption = "This is your registration data. Register now with phone verification? [Y / N] "
			}

			rl.SetPrompt(verificationOption)

			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}

			var regChoice string
			for {
				decision, err := rl.Readline()
				if err != nil {
					fmt.Println(err)
				}
				checkChoice, err := checkYesNo(decision)
				if err != nil {
					fmt.Println(err)
				} else {
					regChoice = checkChoice
					break
				}
			}

			defer rl.Close()

			if regChoice == "Y" {
				registerAccount(opts)
			} else {
				fmt.Println("You can register later using srcli register -f " + data.Username + ".json" + " --captcha | --phone=<number>")
				return
			}

		} else {
			fmt.Println("Cancelled.")
			os.Exit(0)
		}
	}
}

// registerAccount is the crux of the program that registers a new Snapchat account.
func registerAccount(opts map[string]interface{}) {

	rl, err := readline.New("")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer rl.Close()

	snapchatUsername := finalMap["username"]
	snapchatPassword := finalMap["password"]
	gmail := finalMap["gmail"]
	gmailPassword := finalMap["gmail_password"]
	email := finalMap["email"]
	birthday := finalMap["birthday"]

	casperClient := &casper.Casper{
		APIKey:    finalMap["casper_api_key"],
		APISecret: finalMap["casper_api_secret"],
		Username:  snapchatUsername,
		Password:  snapchatPassword,
		Debug:     debug,
	}

	// Setup the snapchat account, drop in a proxy if specified.
	snapchat := ghost.NewAccount(gmail, gmailPassword, casperClient, debug)
	if proxy != "" {
		err := snapchat.SetProxyURL(proxy)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	}

	// Register the account.
	fmt.Println("Registering account...")
	registered := snapchat.Register(snapchatUsername, snapchatPassword, email, birthday)
	snapchat.Token = registered["auth_token"].(string)
	registerResponse := snapchat.RegisterUsername(snapchatUsername, email)

	if registerResponse["logged"] != nil {
		fmt.Println("Message from Snapchat: " + registerResponse["message"].(string))
		return
	}

	// Verify the user using captcha verification (Apparently not working yet.)
	if opts["--captcha"] == true {
		captchaID := snapchat.GetCaptcha()
		rl.SetPrompt("Enter captcha pattern: ")
		solution, _ := rl.Readline()
		snapchat.SolveCaptcha(captchaID, solution)
	}

	// Verify the user using phone number verification.
	if opts["--phone"] == true {
		phoneNum := opts["<number>"].(string)
		verifyResponse := snapchat.VerifyPhoneNumber(phoneNum)
		if verifyResponse["logged"] != nil {
			fmt.Println("Message from Snapchat: " + verifyResponse["message"].(string))
			fmt.Println("Number: " + verifyResponse["param"].(string))

			rl.SetPrompt("Enter verification code: ")
			code, _ := rl.Readline()
			smsCodeResponse := snapchat.SendSMSCode(code)
			if smsCodeResponse["logged"] != nil {
				fmt.Println("Message from Snapchat: " + smsCodeResponse["message"].(string))
				fmt.Println("At this point you should be registered into Snapchat.")
			} else {
				fmt.Println("Message from Snapchat: " + smsCodeResponse["message"].(string))
				return
			}
		} else {
			fmt.Println("Message from Snapchat: " + verifyResponse["message"].(string))
			return
		}
	}
}

// generateAccount creates a new Snapchat account based on Snapchat's registration requirements.
// NOTE: This will save sensitive credentials. Use with caution.
func generateAccount(gmail, gpassword, key, secret string) *GeneratedSCAccount {
	genSnapchatAccount := &GeneratedSCAccount{
		CasperAPIKey:    key,
		CasperAPISecret: secret,
	}

	fakedate := faker.Date().Birthday(13, 34).Format("2006-01-02")
	age, err := ghost.CalculateAge(fakedate)
	if err != nil {
		fmt.Println(err)
	}

	genSnapchatAccount.Username = faker.Internet().UserName() + faker.Number().Hexadecimal(4)
	genSnapchatAccount.Email = faker.Internet().Email()
	genSnapchatAccount.Age = age
	genSnapchatAccount.Password = faker.Internet().Password(10, 20)
	genSnapchatAccount.Gmail = gmail
	genSnapchatAccount.Birthday = fakedate
	genSnapchatAccount.GmailPassword = gpassword

	return genSnapchatAccount
}

// enterPassword allows the user to enter a password with a custom prompt message.
func enterPassword(msg string) (string, error) {

	rl, err := readline.New("")
	if err != nil {
		return "", errors.New("Unable to initalise terminal input.")
	}

	passwd, err := rl.ReadPassword(msg)
	if err != nil {
		return "", errors.New("Unable to process password input.")
	}

	defer rl.Close()
	return string(passwd), nil
}

// manualSetup is a function to manually setup a Snapchat account.
func manualSetup(opts map[string]interface{}) (string, error) {
	var uncheckedMap map[string]string

	// Show the fancy notice graphic.
	fmt.Println(notice)

	rl, err := readline.NewEx(&readline.Config{
		AutoComplete: autocompleter,
	})
	if err != nil {
		return "", err
	}

	// Enter your desired username.
	rl.SetPrompt("Enter your desired Snapchat username: ")
	username, err := rl.Readline()
	if err != nil {
		return "", errors.New("Cancelled.")
	}

	// Enter your desired password.
	password, err := enterPassword("Enter your desired Snapchat password: ")
	if err != nil {
		return "", errors.New("Cancelled.")
	}

	// Enter your email address.
	rl.SetPrompt("Enter your email address: ")
	email, err := rl.Readline()
	if err != nil {
		return "", errors.New("Cancelled.")
	}

	// Enter your birthday.
	rl.SetPrompt("Enter your birthday (YYYY-MM-DD): ")
	birthday, err := rl.Readline()
	if err != nil {
		return "", errors.New("Cancelled.")
	}

	age, err := ghost.CalculateAge(birthday)
	if err != nil {
		return "", errors.New("Sorry! " + "\"" + birthday + "\"" + " is not a valid birthday date!")
	}

	// Enter your Gmail address.
	rl.SetPrompt("Enter your Gmail address: ")
	gmail, err := rl.Readline()
	if err != nil {
		return "", errors.New("Cancelled.")
	}

	// Enter your Gmail password.
	gmailPassword, err := enterPassword("Enter your Gmail password: ")
	if err != nil {
		return "", errors.New("Cancelled.")
	}

	// Enter your Casper API Key.
	rl.SetPrompt("Enter your Casper API Key: ")
	casperAPIKey, err := rl.Readline()
	if err != nil {
		return "", errors.New("Cancelled.")
	}

	// Enter your Casper API Secret.
	rl.SetPrompt("Enter your Casper API Secret: ")
	casperAPISecret, err := rl.Readline()
	if err != nil {
		return "", errors.New("Cancelled.")
	}

	// Unchecked setup map.
	uncheckedMap = map[string]string{
		"username":          username,
		"password":          password,
		"email":             email,
		"birthday":          birthday,
		"age":               age,
		"gmail":             gmail,
		"gmail_password":    gmailPassword,
		"casper_api_key":    casperAPIKey,
		"casper_api_secret": casperAPISecret,
	}

	// Check the setup map.
	checkedMap, checkedMapErr := checkKeys(uncheckedMap)
	if checkedMapErr != nil {
		return "", checkedMapErr
	}

	// Ask if the user wants to save to file.
	rl.SetPrompt("Registration file will be saved as " + checkedMap["username"] + ".json. Continue? [ Y / N ] ")
	var choice string
	for {
		decision, err := rl.Readline()
		if err != nil {
			return "", err
		}
		checkChoice, err := checkYesNo(decision)
		if err != nil {
			fmt.Println(err)
		} else {
			choice = checkChoice
			finalMap = checkedMap
			break
		}
	}

	defer rl.Close()
	return choice, nil
}

// checkKeys checks the if the map keyMap has empty keys.
func checkKeys(keyMap map[string]string) (map[string]string, error) {
	var emptyKeys []string
	var emptyKeysExist, whiteSpace bool
	var errorString string

	// Check the data.
	for k, v := range keyMap {
		if strings.Contains("", v) && len(v) <= 1 {
			emptyKeys = append(emptyKeys, k)
			emptyKeysExist = true
		} else if strings.ContainsAny(" ", v) {
			keyMap[k] = strings.Replace(v, " ", "", -1)
			whiteSpace = true
		}
	}
	sort.Strings(emptyKeys)

	// Check purely empty keys, return an error if missing information is found.
	if emptyKeysExist == true {
		errorString = "[ X ] The following information is required: " + "\n"
		for _, v := range emptyKeys {
			errorString += "\n"
			errorString += string(v)
		}
		return nil, errors.New(errorString)
	}
	// Check for any whitespace.
	if whiteSpace == true {
		fmt.Println("[ ! ] Warning: Some data contained whitespace, I've removed this whitespace for you.")
	}

	return keyMap, nil
}

// checkYesNo checks if the user typed yes or no from a string.
// It returns a standard Y/N if a similar string exists in an array.
func checkYesNo(choice string) (string, error) {
	var exists = false

	// Check for Yeses.
	for _, c := range []string{"Y", "y", "Yes", "YES", "yes"} {
		if choice == c {
			exists = true
			choice = "Y"
			break
		}
	}
	// Check for Nos.
	for _, c := range []string{"N", "n", "No", "NO", "no"} {
		if choice == c {
			exists = true
			choice = "N"
			break
		}
	}
	// If the string exists, return Y/N, otherwise an error.
	if exists == true {
		return choice, nil
	}
	return "", errors.New("Enter either Y or N.")
}
