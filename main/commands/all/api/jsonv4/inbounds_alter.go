package jsonv4

import (
	"encoding/json"
	"fmt"
	"github.com/v2fly/v2ray-core/v5/infra/conf/v4"
	"github.com/v2fly/v2ray-core/v5/main/commands/all/api"
	"github.com/v2fly/v2ray-core/v5/main/commands/helpers"
	"github.com/v2fly/v2ray-core/v5/proxy/trojan"
	"github.com/v2fly/v2ray-core/v5/proxy/vless"

	"github.com/golang/protobuf/proto"
	handlerService "github.com/v2fly/v2ray-core/v5/app/proxyman/command"
	"github.com/v2fly/v2ray-core/v5/common/protocol"
	"github.com/v2fly/v2ray-core/v5/common/serial"
	"github.com/v2fly/v2ray-core/v5/common/uuid"
	"github.com/v2fly/v2ray-core/v5/main/commands/base"
)

var cmdAlterInbounds = &base.Command{
	CustomFlags: true,
	UsageLine:   "{{.Exec}} api ati [--server=127.0.0.1:8080] [c1.json] [dir1]...",
	Short:       "alter inbounds",
	Long: `
Alter inbounds to V2Ray.

> Make sure you have "HandlerService" set in "config.api.services" 
of server config.

Arguments:

	-format <format>
		The input format.
		Available values: "auto", "json", "toml", "yaml"
		Default: "auto"

	-r
		Load folders recursively.

	-remove
		remove user.

	-tags
		The input are tags instead of config files.

	-email <email>
		email of user. Required when input are tags.

	-level <level>
		id of user.
		Default: 0

	-id <id>
		id(vmess/vless) or password(trojan) of user.
		Default new creates a UUID with random value

	-alter <alter>
		alterId(vmess) of user.
		Default 0

	-protocol <protocol>
		protocol of tag.
		Available values: "vmess", "vless", "trojan"
		Default: "vmess"

	-s, -server <server:port>
		The API server address. Default 127.0.0.1:8080

	-t, -timeout <seconds>
		Timeout seconds to call API. Default 3

Example:

    {{.Exec}} {{.LongName}} dir
    {{.Exec}} {{.LongName}} -remove c1.json c2.yaml
    {{.Exec}} {{.LongName}} -tags -email test@v2fly.org -level 0 -id 27848739-7e62-4138-9fd3-098a63964b6b -alter 0 -protocol vmess tag1
    {{.Exec}} {{.LongName}} -tags -email test@v2fly.org -remove tag1 tag2
`,
	Run: executeAlterInbounds,
}

func executeAlterInbounds(cmd *base.Command, args []string) {
	api.SetSharedFlags(cmd)
	api.SetSharedConfigFlags(cmd)
	var (
		email        string
		level        int
		id           string
		alterId      int
		protocolType string
		isRemove     bool
		isTags       bool
	)
	cmd.Flag.StringVar(&email, "email", "", "")
	cmd.Flag.IntVar(&level, "level", 0, "")
	cmd.Flag.StringVar(&id, "id", "", "")
	cmd.Flag.IntVar(&alterId, "alter", 0, "")
	cmd.Flag.StringVar(&protocolType, "protocol", "vmess", "")
	cmd.Flag.BoolVar(&isRemove, "remove", false, "")
	cmd.Flag.BoolVar(&isTags, "tags", false, "")
	cmd.Flag.Parse(args)

	conn, ctx, close := api.DialAPIServer()
	defer close()

	client := handlerService.NewHandlerServiceClient(conn)

	messagesMap := make(map[string][]proto.Message)
	if isTags {
		tags := cmd.Flag.Args()
		if email == "" {
			base.Fatalf("email not found")
		}
		if len(tags) == 0 {
			base.Fatalf("tags not found")
		}
		if id == "" {
			u := uuid.New()
			id = u.String()
			fmt.Println("email:", email, "id:", id)
		}
		for _, tag := range tags {
			messages, err := processInput(tag, protocolType, id, alterId, email, level, isRemove)
			if err != nil {
				base.Fatalf("failed to processInput: %s", err)
			}
			messagesMap[tag] = messages
		}
	} else {
		c, err := helpers.LoadConfig(cmd.Flag.Args(), api.APIConfigFormat, api.APIConfigRecursively)
		if err != nil {
			base.Fatalf("failed to load: %s", err)
		}
		if len(c.InboundConfigs) == 0 {
			base.Fatalf("no valid inbound found")
		}
		for _, in := range c.InboundConfigs {
			messages, err := processInboundConfig(in, isRemove)
			if err != nil {
				base.Fatalf("failed to processInboundConfig: %s", err)
			}
			messagesMap[in.Tag] = messages
		}
	}
	for tag := range messagesMap {
		fmt.Println("altering:", tag)
		for _, message := range messagesMap[tag] {
			r := &handlerService.AlterInboundRequest{
				Tag:       tag,
				Operation: serial.ToTypedMessage(message),
			}
			_, err := client.AlterInbound(ctx, r)
			if err != nil {
				base.Fatalf("failed to alter inbound: %s", err)
			}
		}
	}
}

func processInput(tag string, protocolType string, id string, alterId int, email string, level int, isRemove bool) ([]proto.Message, error) {
	if protocolType == "vmess" {
		user := new(protocol.User)
		account := &v4.VMessAccount{
			ID:       id,
			AlterIds: uint16(alterId),
		}

		user.Email = email
		user.Level = uint32(level)
		user.Account = serial.ToTypedMessage(account.Build())

		var message proto.Message
		if isRemove {
			message = &handlerService.RemoveUserOperation{Email: user.Email}
		} else {
			message = &handlerService.AddUserOperation{User: user}
		}
		return []proto.Message{message}, nil
	} else if protocolType == "vless" {
		user := new(protocol.User)
		account := &vless.Account{
			Id: id,
		}

		user.Email = email
		user.Level = uint32(level)
		user.Account = serial.ToTypedMessage(account)

		var message proto.Message
		if isRemove {
			message = &handlerService.RemoveUserOperation{Email: user.Email}
		} else {
			message = &handlerService.AddUserOperation{User: user}
		}
		return []proto.Message{message}, nil
	} else if protocolType == "trojan" {
		user := new(protocol.User)
		account := &trojan.Account{
			Password: id,
		}

		user.Email = email
		user.Level = uint32(level)
		user.Account = serial.ToTypedMessage(account)

		var message proto.Message
		if isRemove {
			message = &handlerService.RemoveUserOperation{Email: user.Email}
		} else {
			message = &handlerService.AddUserOperation{User: user}
		}
		return []proto.Message{message}, nil
	}
	base.Fatalf("tag: %s with unsupported protocol: %s", tag, protocolType)
	return make([]proto.Message, 0, 0), nil
}

func processInboundConfig(in v4.InboundDetourConfig, isRemove bool) ([]proto.Message, error) {
	rawConfig, err := in.BuildRawConfig()
	if err != nil {
		base.Fatalf("failed to build conf: %s", err)
	}
	if vMessInboundConfig, ok := rawConfig.(*v4.VMessInboundConfig); ok {
		messages := make([]proto.Message, 0, len(vMessInboundConfig.Users))
		for idx, rawData := range vMessInboundConfig.Users {
			user := new(protocol.User)
			if err := json.Unmarshal(rawData, user); err != nil {
				base.Fatalf("invalid VMess user: %s", err)
			}
			account := new(v4.VMessAccount)
			if err := json.Unmarshal(rawData, account); err != nil {
				base.Fatalf("invalid VMess user: %s", err)
			}
			user.Account = serial.ToTypedMessage(account.Build())

			var message proto.Message
			if isRemove {
				message = &handlerService.RemoveUserOperation{Email: user.Email}
			} else {
				message = &handlerService.AddUserOperation{User: user}
			}
			messages[idx] = message
		}
		return messages, err
	} else if vLessInboundConfig, ok := rawConfig.(*v4.VLessInboundConfig); ok {
		messages := make([]proto.Message, 0, len(vLessInboundConfig.Clients))
		for idx, rawUser := range vLessInboundConfig.Clients {
			user := new(protocol.User)
			if err := json.Unmarshal(rawUser, user); err != nil {
				base.Fatalf("VLESS clients: invalid user: %s", err)
			}
			account := new(vless.Account)
			if err := json.Unmarshal(rawUser, account); err != nil {
				base.Fatalf("VLESS clients: invalid user: %s", err)
			}

			if account.Encryption != "" {
				base.Fatalf("VLESS clients: \"encryption\" should not in inbound settings")
			}

			user.Account = serial.ToTypedMessage(account)

			var message proto.Message
			if isRemove {
				message = &handlerService.RemoveUserOperation{Email: user.Email}
			} else {
				message = &handlerService.AddUserOperation{User: user}
			}
			messages[idx] = message
		}
		return messages, err
	} else if trojanServerConfig, ok := rawConfig.(*v4.TrojanServerConfig); ok {
		messages := make([]proto.Message, 0, len(trojanServerConfig.Clients))
		for idx, rawUser := range trojanServerConfig.Clients {
			user := new(protocol.User)
			account := &trojan.Account{
				Password: rawUser.Password,
			}

			user.Email = rawUser.Email
			user.Level = uint32(rawUser.Level)
			user.Account = serial.ToTypedMessage(account)

			var message proto.Message
			if isRemove {
				message = &handlerService.RemoveUserOperation{Email: user.Email}
			} else {
				message = &handlerService.AddUserOperation{User: user}
			}
			messages[idx] = message
		}
		return messages, err
	}
	base.Fatalf("tag: %s with unsupported protocol: %s", in.Tag, in.Protocol)
	return make([]proto.Message, 0, 0), err
}
