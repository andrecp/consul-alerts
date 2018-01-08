package notifier

import (
	"bytes"
	"encoding/json"
	"fmt"
	log "github.com/AcalephStorage/consul-alerts/Godeps/_workspace/src/github.com/Sirupsen/logrus"
	"net/http"
	"strconv"
	"strings"
)

type StringMap map[string]string

type RocketChatLoginInfo struct {
	Username  string `json:"username"`
	Password string `json:"password"`
}

type RocketChatAuthData struct {
	AuthToken string `json:"authToken"`
	UserId string `json:"userId"`
}

type RocketChatAuthInfo struct {
	Status string    `json:"status"`
	Data RocketChatAuthData `json:"data"`
}

type RocketChatUserInfo struct {
	UserID             string    `json:"id"`
	CreateAt           int64     `json:"create_at"`
	UpdateAt           int64     `json:"update_at"`
	DeleteAt           int64     `json:"delete_at"`
	Username           string    `json:"username"`
	FirstName          string    `json:"first_name"`
	LastName           string    `json:"last_name"`
	Nickname           string    `json:"nickname"`
	Email              string    `json:"email"`
	EmailVerified      bool      `json:"email_verified"`
	Password           string    `json:"password"`
	AuthData           *string   `json:"auth_data"`
	AuthService        string    `json:"auth_service"`
	Roles              string    `json:"roles"`
	NotifyProps        StringMap `json:"notify_props"`
	Props              StringMap `json:"props,omitempty"`
	LastPasswordUpdate int64     `json:"last_password_update"`
	LastPictureUpdate  int64     `json:"last_picture_update"`
	FailedAttempts     int       `json:"failed_attempts"`
	MfaActive          bool      `json:"mfa_active"`
	MfaSecret          string    `json:"mfa_secret"`
}

type RocketChatTeamInfo struct {
	TeamID          string `json:"id"`
	CreateAt        int64  `json:"create_at"`
	UpdateAt        int64  `json:"update_at"`
	DeleteAt        int64  `json:"delete_at"`
	DisplayName     string `json:"display_name"`
	Name            string `json:"name"`
	Email           string `json:"email"`
	Type            string `json:"type"`
	AllowedDomains  string `json:"allowed_domains"`
	InviteID        string `json:"invite_id"`
	AllowOpenInvite bool   `json:"allow_open_invite"`
}

type RocketChatChannelInfo struct {
	ChannelID     string `json:"id"`
	CreateAt      int64  `json:"create_at"`
	UpdateAt      int64  `json:"update_at"`
	DeleteAt      int64  `json:"delete_at"`
	TeamID        string `json:"team_id"`
	Type          string `json:"type"`
	DisplayName   string `json:"display_name"`
	Name          string `json:"name"`
	Header        string `json:"header"`
	Purpose       string `json:"purpose"`
	LastPostAt    int64  `json:"last_post_at"`
	TotalMsgCount int64  `json:"total_msg_count"`
	ExtraUpdateAt int64  `json:"extra_update_at"`
	CreatorID     string `json:"creator_id"`
}

type RocketChatChannelList struct {
	Channels []RocketChatChannelInfo
}

type RocketChatPostInfo struct {
	PostID        string    `json:"id"`
	CreateAt      int64     `json:"create_at"`
	UpdateAt      int64     `json:"update_at"`
	DeleteAt      int64     `json:"delete_at"`
	UserID        string    `json:"user_id"`
	ChannelID     string    `json:"channel_id"`
	RootID        string    `json:"root_id"`
	ParentID      string    `json:"parent_id"`
	OriginalID    string    `json:"original_id"`
	Message       string    `json:"message"`
	Type          string    `json:"type"`
	Props         StringMap `json:"props"`
	Hashtags      string    `json:"hashtags"`
	Filenames     StringMap `json:"filenames"`
	PendingPostID string    `json:"pending_post_id"`
}

type RocketChatNotifier struct {
	ClusterName string
	Url         string
	UserName    string
	Password    string
	Team        string
	Channel     string
	Detailed    bool
	NotifName   string
	Enabled     bool

	/* Filled in after authentication */
	Initialized bool
	Token       string
	TeamID      string
	UserID      string
	ChannelID   string
	Text        string
}

func (rocketchat *RocketChatNotifier) GetURL() string {

	proto := "http"
	u := strings.TrimSpace(strings.ToLower(rocketchat.Url))
	if u[:5] == "https" && u[5] == ':' {
		proto = "https"
	}

	host := ""
	port := 0
	buf := strings.Split(u, ":")
	if (u[:4] == "http" && u[4] == ':') ||
		(u[:5] == "https" && u[5] == ':') {

		host = strings.Trim(buf[1], "/")
		if len(buf) == 3 {
			port, _ = strconv.Atoi(strings.TrimSpace(buf[2]))
		}

	} else if len(buf) == 2 {
		host = strings.Trim(buf[0], "/")
		port, _ = strconv.Atoi(strings.TrimSpace(buf[1]))

	} else {
		host = strings.TrimSpace(buf[0])
	}

	portstr := ""
	if port > 0 {
		portstr = fmt.Sprintf(":%d", port)
	}

	return fmt.Sprintf("%s://%s%s/api/v1", proto, host, portstr)
}

func (rocketchat *RocketChatNotifier) Authenticate() bool {

	loginURL := fmt.Sprintf("%s/login", rocketchat.GetURL())
	loginInfo := RocketChatLoginInfo{Username: rocketchat.UserName,
		Password: rocketchat.Password}

	buf := new(bytes.Buffer)
	json.NewEncoder(buf).Encode(loginInfo)

	req, err := http.NewRequest("POST", loginURL, buf)
	if err != nil {
		log.Error("NewRequest: ", err)
		return false
	}

	req.Header.Set("Content-Type", "application/json; charset=utf-8")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Error("Do: ", err)
		return false
	}

	defer resp.Body.Close()

	decoder := json.NewDecoder(resp.Body)
	var authInfo RocketChatAuthInfo
	err = decoder.Decode(&authInfo)
	if err != nil {
		log.Error("Decode: ", err)
		return false
	}

	if authInfo.status != "success" {
		log.Error("Problem login in to rocket chat: ", resp.Body)
		return false
	}
	rocketchat.Token = authInfo.data.AuthToken
	rocketchat.UserId = authInfo.data.UserId

	return true
}

func (rocketchat *RocketChatNotifier) GetAllTeams(teams *[]RocketChatTeamInfo) bool {

	teamURL := fmt.Sprintf("%s/teams/all", rocketchat.GetURL())
	req, err := http.NewRequest("GET", teamURL, nil)
	if err != nil {
		log.Error("NewRequest: ", err)
		return false
	}

	authorization := fmt.Sprintf("Bearer %s", rocketchat.Token)
	req.Header.Set("Authorization", authorization)
	req.Header.Set("Content-Type", "application/json; charset=utf-8")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Error("Do: ", err)
		return false
	}

	defer resp.Body.Close()

	decoder := json.NewDecoder(resp.Body)
	var buf map[string]*RocketChatTeamInfo
	err = decoder.Decode(&buf)
	if err != nil {
		log.Error("Decode: ", err)
		return false
	}

	if len(buf) > 0 {
		for _, value := range buf {
			*teams = append(*teams, *value)
		}
		return true
	}

	return false
}

func (rocketchat *RocketChatNotifier) GetUser(userID string, userInfo *RocketChatUserInfo) bool {

	if userID == "" || userInfo == nil {
		return false
	}

	userURL := fmt.Sprintf("%s/users/%s/get", rocketchat.GetURL(), userID)

	req, err := http.NewRequest("GET", userURL, nil)
	if err != nil {
		log.Error("NewRequest: ", err)
		return false
	}

	authorization := fmt.Sprintf("Bearer %s", rocketchat.Token)
	req.Header.Set("Authorization", authorization)
	req.Header.Set("Content-Type", "application/json; charset=utf-8")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Error("Do: ", err)
		return false
	}

	defer resp.Body.Close()

	decoder := json.NewDecoder(resp.Body)
	err = decoder.Decode(userInfo)
	if err != nil {
		log.Error("Decode: ", err)
		return false
	}

	return true
}

func (rocketchat *RocketChatNotifier) GetMe(me *RocketChatUserInfo) bool {

	if me == nil {
		return false
	}

	userURL := fmt.Sprintf("%s/users/me", rocketchat.GetURL())

	req, err := http.NewRequest("GET", userURL, nil)
	if err != nil {
		log.Error("NewRequest: ", err)
		return false
	}

	authorization := fmt.Sprintf("Bearer %s", rocketchat.Token)
	req.Header.Set("Authorization", authorization)
	req.Header.Set("Content-Type", "application/json; charset=utf-8")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Error("Do: ", err)
		return false
	}

	defer resp.Body.Close()

	decoder := json.NewDecoder(resp.Body)
	err = decoder.Decode(me)
	if err != nil {
		log.Error("Decode: ", err)
		return false
	}

	return true
}

func (rocketchat *RocketChatNotifier) GetTeam(teamID string, teamInfo *RocketChatTeamInfo) bool {

	if teamID == "" || teamInfo == nil {
		return false
	}

	teamURL := fmt.Sprintf("%s/teams/%s/me", rocketchat.GetURL(), teamID)

	req, err := http.NewRequest("GET", teamURL, nil)
	if err != nil {
		log.Error("NewRequest: ", err)
		return false
	}

	authorization := fmt.Sprintf("Bearer %s", rocketchat.Token)
	req.Header.Set("Authorization", authorization)
	req.Header.Set("Content-Type", "application/json; charset=utf-8")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Error("Do: ", err)
		return false
	}

	defer resp.Body.Close()

	decoder := json.NewDecoder(resp.Body)
	err = decoder.Decode(teamInfo)
	if err != nil {
		log.Error("Decode: ", err)
		return false
	}

	return true
}

func (rocketchat *RocketChatNotifier) GetChannels(teamID string, channels *[]RocketChatChannelInfo) bool {

	if teamID == "" || channels == nil {
		return false
	}

	channelURL := fmt.Sprintf("%s/teams/%s/channels/", rocketchat.GetURL(), teamID)
	req, err := http.NewRequest("GET", channelURL, nil)
	if err != nil {
		log.Error("NewRequest: ", err)
		return false
	}

	authorization := fmt.Sprintf("Bearer %s", rocketchat.Token)
	req.Header.Set("Authorization", authorization)
	req.Header.Set("Content-Type", "application/json; charset=utf-8")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Error("Do: ", err)
		return false
	}

	defer resp.Body.Close()

	decoder := json.NewDecoder(resp.Body)
	fc := &RocketChatChannelList{}
	err = decoder.Decode(&fc)
	if err != nil {
		log.Error("Decode: ", err)
		return false
	}
	*channels = fc.Channels

	return true
}

func (rocketchat *RocketChatNotifier) PostMessage(teamID string, channelID string, postInfo *RocketChatPostInfo) bool {

	if teamID == "" || channelID == "" || postInfo == nil {
		return false
	}

	postURL := fmt.Sprintf("%s/teams/%s/channels/%s/posts/create",
		rocketchat.GetURL(), teamID, channelID)

	buf := new(bytes.Buffer)
	encoder := json.NewEncoder(buf)
	err := encoder.Encode(*postInfo)

	req, err := http.NewRequest("POST", postURL, buf)
	if err != nil {
		log.Error("NewRequest: ", err)
		return false
	}

	authorization := fmt.Sprintf("Bearer %s", rocketchat.Token)
	req.Header.Set("Authorization", authorization)
	req.Header.Set("Content-Type", "application/json; charset=utf-8")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Error("Do: ", err)
		return false
	}

	defer resp.Body.Close()

	decoder := json.NewDecoder(resp.Body)
	var p RocketChatPostInfo
	err = decoder.Decode(&p)
	if err != nil {
		log.Error("Decode: ", err)
		return false
	}
	*postInfo = p

	return false
}

func (rocketchat *RocketChatNotifier) Init() bool {
	if rocketchat.Initialized == true {
		return true
	}

	if rocketchat.Token == "" && !rocketchat.Authenticate() {
		log.Println("RocketChat: Unable to authenticate!")
		return false
	}

	if rocketchat.TeamID == "" {
		var teams []RocketChatTeamInfo

		if !rocketchat.GetAllTeams(&teams) {
			log.Println("RocketChat: Unable to get teams!")
			return false
		}

		for i := 0; i < len(teams); i++ {
			if teams[i].Name == rocketchat.Team {
				rocketchat.TeamID = teams[i].TeamID
				break
			}
		}

		if rocketchat.TeamID == "" {
			log.Println("RocketChat: Unable to find team!")
			return false
		}
	}

	if rocketchat.UserID == "" {
		var me RocketChatUserInfo

		if !rocketchat.GetMe(&me) {
			log.Println("RocketChat: Unable to get user!")
			return false
		}

		if me.UserID == "" {
			log.Println("RocketChat: Unable to get user ID!")
			return false
		}

		rocketchat.UserID = me.UserID
	}

	if rocketchat.ChannelID == "" {
		var channels []RocketChatChannelInfo

		if !rocketchat.GetChannels(rocketchat.TeamID, &channels) {
			log.Println("RocketChat: Unable to get channels!")
			return false
		}

		for i := 0; i < len(channels); i++ {
			if channels[i].Name == rocketchat.Channel {
				rocketchat.ChannelID = channels[i].ChannelID
				break
			}
		}

		if rocketchat.ChannelID == "" {
			log.Println("RocketChat: Unable to find channel!")
			return false
		}
	}

	rocketchat.Initialized = true
	return true
}

// NotifierName provides name for notifier selection
func (rocketchat *RocketChatNotifier) NotifierName() string {
	return "rocketchat"
}

func (rocketchat *RocketChatNotifier) Copy() Notifier {
	notifier := *rocketchat
	return &notifier
}

//Notify sends messages to the endpoint notifier
func (rocketchat *RocketChatNotifier) Notify(messages Messages) bool {
	if !rocketchat.Init() {
		return false
	}

	if rocketchat.Detailed {
		return rocketchat.notifyDetailed(messages)
	}

	return rocketchat.notifySimple(messages)
}

func (rocketchat *RocketChatNotifier) notifySimple(messages Messages) bool {
	overallStatus, pass, warn, fail := messages.Summary()

	text := fmt.Sprintf(header, rocketchat.ClusterName, overallStatus, fail, warn, pass)

	for _, message := range messages {
		text += fmt.Sprintf("\n%s:%s:%s is %s.",
			message.Node, message.Service, message.Check, message.Status)
		text += fmt.Sprintf("\n%s\n\n", message.Output)
	}

	rocketchat.Text = text

	return rocketchat.postToRocketChat()
}

func (rocketchat *RocketChatNotifier) notifyDetailed(messages Messages) bool {

	overallStatus, pass, warn, fail := messages.Summary()

	var emoji string
	switch overallStatus {
	case SYSTEM_HEALTHY:
		emoji = ":white_check_mark:"
	case SYSTEM_UNSTABLE:
		emoji = ":question:"
	case SYSTEM_CRITICAL:
		emoji = ":x:"
	default:
		emoji = ":question:"
	}
	title := "Consul monitoring report"
	pretext := fmt.Sprintf("%s %s is *%s*", emoji, rocketchat.ClusterName, overallStatus)

	detailedBody := ""
	detailedBody += fmt.Sprintf("*Changes:* Fail = %d, Warn = %d, Pass = %d",
		fail, warn, pass)
	detailedBody += fmt.Sprintf("\n")

	for _, message := range messages {
		detailedBody += fmt.Sprintf("\n*[%s:%s]* %s is *%s.*",
			message.Node, message.Service, message.Check, message.Status)
		detailedBody += fmt.Sprintf("\n`%s`", strings.TrimSpace(message.Output))
	}

	rocketchat.Text = fmt.Sprintf("%s\n%s\n%s\n\n", title, pretext, detailedBody)

	return rocketchat.postToRocketChat()

}

func (rocketchat *RocketChatNotifier) postToRocketChat() bool {
	var postInfo = RocketChatPostInfo{
		ChannelID: rocketchat.ChannelID,
		Message:   rocketchat.Text}

	return rocketchat.PostMessage(rocketchat.TeamID, rocketchat.ChannelID, &postInfo)
}
