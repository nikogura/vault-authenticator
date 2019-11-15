package vaultlibs

import (
	"bufio"
	"encoding/json"
	"fmt"
	"github.com/mitchellh/go-homedir"
	"github.com/pkg/errors"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/user"
	"path"
	"regexp"
	"strings"
)

const DEFAULT_KEY_FILE = ".ssh/id_rsa"
const DBT_USER_CONFIG_FILE = ".dbt/conf/user.json"

// LocalUsername returns the current user's username.
func LocalUsername() (username string, err error) {
	userObj, err := user.Current()
	if err != nil {
		err = errors.Wrapf(err, "failed to get current user object")
		return username, err
	}

	username = userObj.Username
	return username, err
}

// Dir copies a whole directory recursively
func DirCopy(src string, dst string) error {
	var err error
	var fds []os.FileInfo
	var srcinfo os.FileInfo

	if srcinfo, err = os.Stat(src); err != nil {
		return err
	}

	if err = os.MkdirAll(dst, srcinfo.Mode()); err != nil {
		return err
	}

	if fds, err = ioutil.ReadDir(src); err != nil {
		return err
	}
	for _, fd := range fds {
		srcfp := path.Join(src, fd.Name())
		dstfp := path.Join(dst, fd.Name())

		if fd.IsDir() {
			if err = DirCopy(srcfp, dstfp); err != nil {
				fmt.Println(err)
			}
		} else {
			if err = FileCopy(srcfp, dstfp); err != nil {
				fmt.Println(err)
			}
		}
	}
	return nil
}

// File copies a single file from src to dst
func FileCopy(src, dst string) error {
	var err error
	var srcfd *os.File
	var dstfd *os.File
	var srcinfo os.FileInfo

	if srcfd, err = os.Open(src); err != nil {
		return err
	}
	defer srcfd.Close()

	if dstfd, err = os.Create(dst); err != nil {
		return err
	}
	defer dstfd.Close()

	if _, err = io.Copy(dstfd, srcfd); err != nil {
		return err
	}
	if srcinfo, err = os.Stat(src); err != nil {
		return err
	}
	return os.Chmod(dst, srcinfo.Mode())
}

func verboseOutput(verbose bool, message string, args ...interface{}) {
	if verbose {
		if len(args) == 0 {
			fmt.Printf("%s\n", message)
			return
		}

		msg := fmt.Sprintf(message, args...)
		fmt.Printf("%s\n", msg)
	}
}

// UserConfig a struct for storing per-user config when a user's laptop info (username, key location) differs from the defaults
type UserConfig struct {
	Username       string `json:"username"`
	PrivateKeyFile string `json:"privateKeyFile"`
}

// LoadUserConfig loads the per-user config file from ~/.dbt/conf/user.json
func LoadUserConfig() (config UserConfig, err error) {
	homeDir, err := homedir.Dir()
	if err != nil {
		err = errors.Wrap(err, "failed to determine home dir")
		return config, err
	}

	configFile := fmt.Sprintf("%s/%s", homeDir, DBT_USER_CONFIG_FILE)
	if _, err := os.Stat(configFile); !os.IsNotExist(err) {

		configBytes, err := ioutil.ReadFile(configFile)
		if err != nil {
			err = errors.Wrapf(err, "failed to read config file %s", configFile)
			return config, err
		}

		err = json.Unmarshal(configBytes, &config)
		if err != nil {
			err = errors.Wrapf(err, "failed to unmarshal data in file %s", configFile)
			return config, err
		}

		return config, err
	}

	config.PrivateKeyFile = fmt.Sprintf("%s/%s", homeDir, DEFAULT_KEY_FILE)
	username, err := LocalUsername()
	if err != nil {
		err = errors.Wrapf(err, "failed to get local user name")
		return config, err
	}

	config.Username = username
	return config, err
}

// SaveUserConfig saves a UserConfig Object back to disk
func SaveUserConfig(config UserConfig) (err error) {
	jsonBytes, err := json.Marshal(config)
	if err != nil {
		err = errors.Wrapf(err, "failed to marshal user config into json")
		return err
	}

	homeDir, err := homedir.Dir()
	if err != nil {
		log.Fatal("failed to determine home dir")
	}

	configFile := fmt.Sprintf("%s/%s", homeDir, DBT_USER_CONFIG_FILE)

	err = ioutil.WriteFile(configFile, jsonBytes, 0644)
	if err != nil {
		err = errors.Wrapf(err, "failed to write config file %s", err)
		return err
	}

	return err
}

// UsernameFromConfig Returns the username from the dbt config
func UsernameFromConfig() (username string, err error) {
	userConfig, err := LoadUserConfig()
	if err != nil {
		err = errors.Wrap(err, "failed to load user config")
		return username, err
	}

	username = userConfig.Username

	if !VerifyUsername(username) {
		fmt.Println("\nEnter your Scribd username: (your email address before the '@')")
		fmt.Println()

		var inputUsername string

		_, _ = fmt.Scanln(&inputUsername)

		username = strings.TrimRight(inputUsername, "\n")

		fmt.Println("Would you like to save this username as your default? ")
		reader := bufio.NewReader(os.Stdin)

		input, err := reader.ReadString('\n')
		if err != nil {
			err = errors.Wrapf(err, "failed to read response")
			return username, err
		}

		answer := strings.TrimRight(input, "\n")

		ok, err := regexp.MatchString(`[yY]`, answer)
		if err != nil {
			err = errors.Wrapf(err, "Failed to parse answer")
		}

		if ok {
			userConfig, err := LoadUserConfig()
			if err != nil {
				err = errors.Wrapf(err, "failed to load user config: %s", err)
				return username, err
			}

			userConfig.Username = username

			err = SaveUserConfig(userConfig)
			if err != nil {
				err = errors.Wrapf(err, "failed to save user config: %s", err)
				return username, err
			}

			return username, err
		}
	}

	return username, err
}

// VerifyUsername prompts the username to ensure the username derived from the shell environment is correct.  Usually this is the case, but requiring the user to visually confirm cuts down on mystery errors
func VerifyUsername(username string) bool {
	fmt.Println(fmt.Sprintf("\nLooks like your Scribd username is %q.", username))
	fmt.Println()
	fmt.Println("If this correct, press 'y' to continue")
	fmt.Println()

	var confirm string

	_, _ = fmt.Scanln(&confirm)

	match, _ := regexp.MatchString("[yY]", confirm)

	if match {
		return true
	} else {
		return false
	}
}
