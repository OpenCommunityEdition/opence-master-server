package discord

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// OAuth is Discord's OAuth2, for the player links (the identify scope
// alone), and the guild membership check, over Discord's HTTPS API with
// net/http (gateway.go alone uses discordgo).
type OAuth struct {
	// Discord's API ("https://discord.com/api/v10") and its authorisation
	// page ("https://discord.com/oauth2/authorize"); tests point them at a
	// fake
	API, Authorize string
	Client         *http.Client
}

// NewOAuth is Discord's OAuth2, through a client.
func NewOAuth(client *http.Client) *OAuth {
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	return &OAuth{API: "https://discord.com/api/v10", Authorize: "https://discord.com/oauth2/authorize",
		Client: client}
}

// AuthorizeURL is the authorisation page a player is sent to: the identify
// scope, the state bound to the link page's cookie, and the master's
// redirect URI.
func (o *OAuth) AuthorizeURL(clientID, redirectURI, state string) string {
	query := url.Values{"response_type": {"code"}, "client_id": {clientID}, "scope": {"identify"},
		"state": {state}, "redirect_uri": {redirectURI}}
	return o.Authorize + "?" + query.Encode()
}

// discordError reads Discord's refusal, without a secret in it.
func discordError(response *http.Response, secrets ...string) error {
	body, _ := io.ReadAll(io.LimitReader(response.Body, 2048))
	var refusal struct {
		Error       string `json:"error"`
		Description string `json:"error_description"`
		Message     string `json:"message"`
	}
	text := response.Status
	if json.Unmarshal(body, &refusal) == nil {
		for _, part := range []string{refusal.Error, refusal.Description, refusal.Message} {
			if part != "" {
				text += ": " + part
			}
		}
	}
	for _, s := range secrets {
		text = redact(text, s)
	}
	return &Error{Status: response.StatusCode, Message: "Discord answered " + text}
}

// Identify exchanges an authorisation code for its token, asks Discord whose
// it is (GET /users/@me), and forgets the token: the account's id and
// username.
func (o *OAuth) Identify(ctx context.Context, clientID, secret, code, redirectURI string) (User, error) {
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirectURI}}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, o.API+"/oauth2/token",
		strings.NewReader(form.Encode()))
	if err != nil {
		return User{}, err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.SetBasicAuth(clientID, secret)
	response, err := o.Client.Do(request)
	if err != nil {
		return User{}, errors.New(redact(err.Error(), secret))
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return User{}, discordError(response, secret, code)
	}
	var token struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 64<<10)).Decode(&token); err != nil ||
		token.AccessToken == "" {
		return User{}, errors.New("Discord's token answer did not read")
	}
	request, err = http.NewRequestWithContext(ctx, http.MethodGet, o.API+"/users/@me", nil)
	if err != nil {
		return User{}, err
	}
	request.Header.Set("Authorization", "Bearer "+token.AccessToken)
	response, err = o.Client.Do(request)
	if err != nil {
		return User{}, errors.New(redact(err.Error(), token.AccessToken))
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return User{}, discordError(response, token.AccessToken)
	}
	var me struct {
		ID       string `json:"id"`
		Username string `json:"username"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 64<<10)).Decode(&me); err != nil ||
		!snowflakePattern.MatchString(me.ID) || me.Username == "" {
		return User{}, errors.New("Discord's /users/@me answer did not read")
	}
	return User{ID: me.ID, Name: me.Username}, nil
}

// Member tells whether a user is a member of a guild, asked with the bot's
// token (GET /guilds/{guild}/members/{user}: 200 a member, 404 not).
func (o *OAuth) Member(ctx context.Context, botToken, guild, user string) (bool, error) {
	if !snowflakePattern.MatchString(guild) || !snowflakePattern.MatchString(user) {
		return false, errors.New("a guild or user id that is not a Discord id")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, o.API+"/guilds/"+guild+"/members/"+user, nil)
	if err != nil {
		return false, err
	}
	request.Header.Set("Authorization", "Bot "+botToken)
	response, err := o.Client.Do(request)
	if err != nil {
		return false, errors.New(redact(err.Error(), botToken))
	}
	defer response.Body.Close()
	switch response.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusNotFound:
		return false, nil
	}
	return false, fmt.Errorf("the membership check: %w", discordError(response, botToken))
}
