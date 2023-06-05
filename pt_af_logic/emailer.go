package pt_af_logic

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/casdoor/casdoor/object"
	af_client "github.com/casdoor/casdoor/pt_af_sdk"
	"strings"
)

type Message struct {
	Action                string            `json:"action"`
	ClientShortName       string            `json:"clientShortName"`
	ClientProperties      map[string]string `json:"clientProperties"`
	ClientContact         ContactData       `json:"clientContact"`
	Product               string            `json:"product"`
	Plan                  string            `json:"plan"`
	PartnerShortName      string            `json:"partnerShortName"`
	PartnerManagerContact ContactData       `json:"partnerManagerContact"`
}

type ContactData struct {
	Email string `json:"email"`
	Phone string `json:"phone"`
	Name  string `json:"name"`
}

const builtInOrgCode = "built-in"

func Email(subscription *object.Subscription) error {
	provider := getBuiltInEmailProvider()
	if provider == nil {
		return errors.New("no email provider registered")
	}
	if subscription.User == "" {
		return errors.New("no client detected in subscription")
	}

	orgId := fmt.Sprintf("admin/%s", subscription.Owner)
	organization := object.GetOrganization(orgId)
	partnerManager := getPartnerManager(subscription.Owner)
	if partnerManager == nil {
		return errors.New("no partner manager detected")
	}
	client := object.GetUser(subscription.User)

	var clientProps = make(map[string]string)
	for prop := range client.Properties {
		if !strings.HasPrefix(prop, af_client.PtPropPref) {
			clientProps[prop] = client.Properties[prop]
		}
	}

	msg := Message{
		PartnerShortName: organization.Name,
		Plan:             subscription.Plan,
		ClientShortName:  client.Name,
		ClientContact: ContactData{
			Email: client.Email,
			Phone: client.Phone,
			Name:  client.DisplayName,
		},
		ClientProperties: clientProps,
		PartnerManagerContact: ContactData{
			Email: partnerManager.Email,
			Phone: partnerManager.Phone,
			Name:  partnerManager.DisplayName,
		},
		Product: "PT Application Firewall",
	}

	var recipients []string
	var subject string
	switch subscription.State {
	case "Pending":
		{
			recipients = getBuiltInAdmins()
			subject = "Subscription created"
			msg.Action = "Create"
		}
	case "Pre-authorized":
		{
			recipients = getAdmins(subscription.Owner)
			partnerAdmin := getPartnerManager(subscription.Owner)
			if partnerAdmin != nil {
				recipients = append(recipients, partnerAdmin.Email)
			}
			subject = "Subscription pre-authorized"
			msg.Action = "Pre-authorized"
		}
	case "Unauthorized":
		{
			recipients = getAdmins(subscription.Owner)
			partnerAdmin := getPartnerManager(subscription.Owner)
			if partnerAdmin != nil {
				recipients = append(recipients, partnerAdmin.Email)
			}
			subject = "Subscription unauthorized"
			msg.Action = "Approve"
		}
	case "Authorized":
		{
			recipients = getAdmins(subscription.Owner)
			partnerUser := getPartnerUser(subscription.Owner)
			if partnerUser != nil {
				recipients = append(recipients, partnerUser.Email)
			}
			subject = "Subscription authorized"
			msg.Action = "Authorized"
		}
	case "Started":
		{
			recipients = getAdmins(subscription.Owner)
			partnerAdmin := getPartnerManager(subscription.Owner)
			if partnerAdmin != nil {
				recipients = append(recipients, partnerAdmin.Email)
			}
			subject = "Subscription started"
			msg.Action = "Started"
		}
	case "Cancelled":
		{
			recipients = getAdmins(subscription.Owner)
			subject = "Subscription cancelled"
			msg.Action = "Cancelled"
		}
	case "Finished":
		{
			recipients = getAdmins(subscription.Owner)
			subject = "Subscription finished"
			msg.Action = "Finished"
		}
	default:
		return fmt.Errorf("could not handle subscription status: %s", subscription.State)
	}

	data, err := json.Marshal(msg)
	content := string(data)
	if err != nil {
		return err
	}

	errors := make(chan error, 256)
	defer close(errors)
	for _, email := range recipients {
		go func(dst string) {
			errors <- object.SendEmail(provider, subject, content, dst, provider.DisplayName)
		}(email)
	}

	for range recipients {
		if e := <-errors; e != nil {
			if err != nil {
				err = fmt.Errorf("%w; %w", err, e)
			} else {
				err = e
			}
		}
	}

	return err
}

func getBuiltInEmailProvider() *object.Provider {
	providers := object.GetProviders(builtInOrgCode)
	for _, provider := range providers {
		if provider.Category == "Email" {
			return provider
		}
	}
	return nil
}

func getAdmins(organization string) []string {
	users := object.GetUsers(organization)
	var emails []string
	for _, user := range users {
		if user.IsAdmin {
			emails = append(emails, user.Email)
		}
	}
	return emails
}

func getPartnerManager(organization string) *object.User {
	users := object.GetUsers(organization)
	for _, user := range users {
		if user.IsAdmin {
			return user
		}
	}
	return nil
}

func getPartnerUser(organization string) *object.User {
	users := object.GetUsers(organization)
	for _, user := range users {
		if !user.IsAdmin {
			return user
		}
	}
	return nil
}

func getBuiltInAdmins() []string {
	users := object.GetUsers(builtInOrgCode)
	var emails []string
	for _, user := range users {
		if user.IsGlobalAdmin {
			emails = append(emails, user.Email)
		}
	}
	return emails
}
