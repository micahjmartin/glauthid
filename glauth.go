package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/glauth/glauth/pkg/config"
	gologgingr "github.com/glauth/glauth/pkg/gologgingr"
	"github.com/glauth/glauth/pkg/server"
	"github.com/go-logr/logr"
	logging "github.com/op/go-logging"
)

const programName = "glauth"

var usage = `glauth: expose caddy-auth-portal config for LDAP auth

Usage:
  glauth [options] -c <file>
  glauth -h --help
  glauth -version

Options:
`

type caddyAuthUser struct {
	Username       string
	Id             string
	EmailAddresses []struct {
		Address string
		Domain  string
	} `json:"email_addresses"`
	Passwords []struct {
		Algorithm string
		Hash      string
		// TODO: Expired and disabled
	}

	Roles []struct {
		Name string
	}
}

type caddyAuthConfig struct {
	Revision int
	Users    []caddyAuthUser
}

var (
	log          logr.Logger
	stderr       *logging.LogBackend
	activeConfig = &config.Config{}
)

// Reads builtime vars and returns a full string containing info about
// the currently running version of the software. Primarily used by the
// --version flag at runtime.
func getVersionString() string {
	return "GLauth\nNon-release build for caddy-auth-portal\n\n"
}

func main() {
	stderr = initLogging()
	log.V(6).Info("AP start")

	flag.StringVar(&activeConfig.ConfigFile, "c", "", "Config file.")
	flag.StringVar(&activeConfig.Backend.BaseDN, "basedn", "dc=glauth,dc=local", "LDAP Base domain")
	flag.StringVar(&activeConfig.LDAP.Listen, "ldap", "", "ldap bind address")
	flag.StringVar(&activeConfig.LDAPS.Listen, "ldaps", "", "ldaps bind address")
	flag.StringVar(&activeConfig.LDAPS.Cert, "ldaps-cert", "", "ldaps certificate")
	flag.StringVar(&activeConfig.LDAPS.Key, "ldaps-key", "", "ldaps key")
	flag.BoolVar(&activeConfig.Debug, "v", false, "Debug logging")
	version := flag.Bool("version", false, "ldaps key")

	flag.Usage = func() {
		fmt.Fprint(os.Stderr, usage)
		flag.PrintDefaults()
	}

	flag.Parse()

	if *version {
		fmt.Fprintln(os.Stderr, getVersionString())
		os.Exit(0)
	}

	// Setup a default backend
	// activeConfig.Backend.BaseDN
	activeConfig.Backend.Datastore = "config"
	activeConfig.Backend.NameFormat = "cn"
	activeConfig.Backend.GroupFormat = "ou"
	activeConfig.Backend.SSHKeyAttr = "sshPublicKey"
	activeConfig.Backends = append(activeConfig.Backends, activeConfig.Backend)

	// The listen fields are configured from the cli
	activeConfig.LDAP.Enabled = len(activeConfig.LDAP.Listen) != 0
	activeConfig.LDAPS.Enabled = len(activeConfig.LDAPS.Listen) != 0

	if len(activeConfig.ConfigFile) == 0 {
		log.Error(fmt.Errorf("configuration file not specified"), "Configuration file error")
		os.Exit(1)
	}
	if !activeConfig.LDAP.Enabled && !activeConfig.LDAPS.Enabled {
		log.Error(fmt.Errorf("no server configuration found: please provide either LDAP or LDAPS configuration"), "Configuration file error")
		os.Exit(1)
	}

	// Load the JSON config
	if err := updateConfig(); err != nil {
		log.Error(err, "Configuration file error")
		os.Exit(1)
	}
	log.V(3).Info("Loaded users and groups from config")

	stderr = initLogging()

	startService()
}

func startService() {
	startConfigWatcher()

	s, err := server.NewServer(
		server.Logger(log),
		server.Config(activeConfig),
	)
	if err != nil {
		log.Error(err, "Could not create server")
		os.Exit(1)
	}

	if activeConfig.LDAP.Enabled {
		// Don't block if also starting a LDAPS server afterwards
		shouldBlock := !activeConfig.LDAPS.Enabled

		if shouldBlock {
			if err := s.ListenAndServe(); err != nil {
				log.Error(err, "Could not start LDAP server")
				os.Exit(1)
			}
		} else {
			go func() {
				if err := s.ListenAndServe(); err != nil {
					log.Error(err, "Could not start LDAP server")
					os.Exit(1)
				}
			}()
		}
	}

	if activeConfig.LDAPS.Enabled {
		// Always block here
		if err := s.ListenAndServeTLS(); err != nil {
			log.Error(err, "Could not start LDAPS server")
			os.Exit(1)
		}
	}

	log.V(0).Info("AP exit")
	os.Exit(1)
}

func startConfigWatcher() {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Error(err, "Could not start config-watcher")
		return
	}

	ticker := time.NewTicker(1 * time.Second)
	go func() {
		isChanged, isRemoved := false, false
		for {
			select {
			case event := <-watcher.Events:
				log.V(6).Info("watcher got event", "e", event.Op.String())
				if event.Op&fsnotify.Write == fsnotify.Write {
					isChanged = true
				} else if event.Op&fsnotify.Remove == fsnotify.Remove { // vim edit file with rename/remove
					isChanged, isRemoved = true, true
				}
			case err := <-watcher.Errors:
				log.Error(err, "Error!")
			case <-ticker.C:
				// wakeup, try finding removed config
			}
			if _, err := os.Stat(activeConfig.ConfigFile); !os.IsNotExist(err) && (isRemoved || isChanged) {
				if isRemoved {
					log.V(6).Info("rewatching config", "file", activeConfig.ConfigFile)
					watcher.Add(activeConfig.ConfigFile) // overwrite
					isChanged, isRemoved = true, false
				}
				if isChanged {
					if err := updateConfig(); err != nil {
						log.V(2).Info("Could not reload config. Holding on to old config", "error", err.Error())
					} else {
						log.V(3).Info("Config was reloaded")
					}
					isChanged = false
				}
			}
		}
	}()

	watcher.Add(activeConfig.ConfigFile)
}

/* Update the in-memory users and groups from the JSON file on disk.
If errors occur, it will return before changing the users/groups
*/
func updateConfig() error {
	c := &caddyAuthConfig{} // JSON file from caddy auth portal
	bytes, err := ioutil.ReadFile(activeConfig.ConfigFile)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(bytes, c); err != nil {
		return err
	}

	nextGid := 1001
	// Convert the caddyAuth config into a glauth config

	configUsers := make([]config.User, 0, len(c.Users))

	// Make a default group and set it as the primary group for all users
	groups := map[string]int{
		"user": 1000,
	}

	groupsInverse := map[int]string{
		1000: "user",
	}

	for i, user := range c.Users {
		u := config.User{
			Name:         user.Username,
			UIDNumber:    1000 + i, // Doesnt really matter
			PrimaryGroup: 1000,
			OtherGroups:  make([]int, 0),
		}
		if len(user.EmailAddresses) > 0 {
			u.Mail = user.EmailAddresses[0].Address
		}

		if len(user.Passwords) == 0 {
			continue
		}
		pw := user.Passwords[0]
		if pw.Algorithm != "bcrypt" {
			return fmt.Errorf("invalid password type %s for user %s", pw.Algorithm, user.Username)
		}
		u.PassBcrypt = hex.EncodeToString([]byte(pw.Hash))
		// Add the roles
		for _, r := range user.Roles {
			// use the existing group or make a new one
			if id, ok := groups[r.Name]; ok {
				u.OtherGroups = append(u.OtherGroups, id)
			} else {
				groups[r.Name] = nextGid
				u.OtherGroups = append(u.OtherGroups, nextGid)
				groupsInverse[nextGid] = r.Name
				nextGid++
			}
		}

		configUsers = append(configUsers, u)
	}

	activeConfig.Users = configUsers
	activeConfig.Groups = make([]config.Group, 0, len(groups))
	for group, gid := range groups {
		activeConfig.Groups = append(activeConfig.Groups, config.Group{
			Name:      group,
			GIDNumber: gid,
		})
	}

	// log the users
	if activeConfig.Debug {
		for _, u := range activeConfig.Users {
			groups := make([]string, 0, len(u.OtherGroups))
			for _, g := range u.OtherGroups {
				groups = append(groups, groupsInverse[g])
			}
			fmt.Println(u.Name, groups)
		}
	}
	return nil
}

// initLogging sets up logging to stderr
func initLogging() *logging.LogBackend {
	l := logging.MustGetLogger(programName)
	l.ExtraCalldepth = 2 // add extra call depth for the logr wrapper

	log = gologgingr.New(
		gologgingr.Logger(l),
	)
	gologgingr.SetVerbosity(10) // do not filter by verbosity. glauth uses the go-logging lib to filter the levels

	format := "%{color}%{time:15:04:05.000000} %{shortfunc} ▶ %{level:.4s} %{id:03x}%{color:reset} %{message}"
	logBackend := logging.NewLogBackend(os.Stderr, "", 0)

	logging.SetBackend(logBackend)
	logging.SetLevel(logging.NOTICE, programName)
	logging.SetFormatter(logging.MustStringFormatter(format))
	if activeConfig.Debug {
		logging.SetLevel(logging.DEBUG, programName)
		log.V(6).Info("Debugging enabled")
	}
	return logBackend
}
