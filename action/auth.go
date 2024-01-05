// Copyright (c) Topicus Security B.V.
// SPDX-License-Identifier: APSL-2.0

package action

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	keyhub "github.com/topicuskeyhub/sdk-go"
	keyhubaccount "github.com/topicuskeyhub/sdk-go/account"
	"github.com/topicuskeyhub/sdk-go/models"
	keyhubvaultrecord "github.com/topicuskeyhub/sdk-go/vaultrecord"
)

type AuthenticationConfig struct {
	Issuer                  string
	ClientID                string
	ClientSecret            string
	Scopes                  []string
	VaultRecoveryRecordUUID string
}

func NewAuthenticationConfig(issuer string, clientID string, clientSecret string) AuthenticationConfig {
	return AuthenticationConfig{
		Issuer:       issuer,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Scopes: []string{
			"openid",
			"profile",
			"email",
			"manage_account",
			"provisioning",
			"access_vault",
			"group_admin",
			"global_admin",
		},
	}
}

func authenticateWithDeviceFlow(ctx context.Context, config AuthenticationConfig) (*AuthenticatedAccount, error) {
	adapter, err := keyhub.NewKeyHubRequestAdapterForDeviceCode(&http.Client{}, config.Issuer, config.ClientID, config.ClientSecret, config.Scopes)
	if err != nil {
		return nil, fmt.Errorf("unable to create Topicus KeyHub API client: %s", err)
	}

	client := keyhub.NewKeyHubClient(adapter)
	account, err := client.Account().Me().Get(ctx, nil)

	ret := &AuthenticatedAccount{
		Client:  client,
		Account: account,
	}

	if err != nil {
		return nil, fmt.Errorf("unable to fetch account: %s", KeyHubError(err))
	}
	err = checkKeyHubAdmin(ctx, ret)
	if err != nil {
		return nil, fmt.Errorf("user fails sanity checks: %s", err)
	}

	return ret, nil
}

func checkKeyHubAdmin(ctx context.Context, account *AuthenticatedAccount) error {
	settings, err := account.Client.Account().Me().Settings().Get(ctx, nil)
	if err != nil {
		return fmt.Errorf("unable to fetch account settings: %s", KeyHubError(err))
	}
	if !*settings.GetKeyHubAdmin() {
		return errors.New("user is not a Topicus KeyHub Administrator")
	}

	ownAccount, err := account.Client.Account().ByAccountidInt64(*Self(account.Account).GetId()).Get(ctx, &keyhubaccount.WithAccountItemRequestBuilderGetRequestConfiguration{
		QueryParameters: &keyhubaccount.WithAccountItemRequestBuilderGetQueryParameters{
			Additional: []string{"groups"},
		},
	})
	if err != nil {
		return fmt.Errorf("unable to fetch own account: %s", KeyHubError(err))
	}
	groups := ownAccount.GetAdditionalObjects().GetGroups().GetItems()
	if len(ownAccount.GetAdditionalObjects().GetGroups().GetItems()) > 1 {
		names := make([]string, len(groups))
		for i, g := range groups {
			names[i] = *g.GetName()
		}
		return fmt.Errorf("user is member of groups other than KeyHub Administrator: %s", strings.Join(names, ", "))
	}

	return nil
}

func SetupEnvironment(ctx context.Context, config AuthenticationConfig) (*Environment, error) {
	account1, err := authenticateWithDeviceFlow(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("unable to authenticate first user: %s", err)
	}

	account2, err := authenticateWithDeviceFlow(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("unable to authenticate second user: %s", err)
	}

	if *account1.Account.GetUuid() == *account2.Account.GetUuid() {
		return nil, fmt.Errorf("authenticated as the same user twice: %s", *account1.Account.GetUsername())
	}

	ret := &Environment{
		Account1: account1,
		Account2: account2,
	}

	if config.VaultRecoveryRecordUUID != "" {
		record, err := First[models.VaultVaultRecordable](ret.Account1.Client.Vaultrecord().Get(ctx, &keyhubvaultrecord.VaultrecordRequestBuilderGetRequestConfiguration{
			QueryParameters: &keyhubvaultrecord.VaultrecordRequestBuilderGetQueryParameters{
				Uuid:       []string{config.VaultRecoveryRecordUUID},
				Additional: []string{"secret"},
			},
		}))
		if err != nil {
			return nil, fmt.Errorf("unable to fetch vault recovery record with uuid %s: %s", config.VaultRecoveryRecordUUID, err)
		}
		ret.VaultRecoveryKey = *record.GetAdditionalObjects().GetSecret().GetFile()
	}
	return ret, nil
}

func AuthenticateAccount3(ctx context.Context, config AuthenticationConfig, env *Environment) error {
	account3, err := authenticateWithDeviceFlow(ctx, config)
	if err != nil {
		return fmt.Errorf("unable to authenticate third user: %s", err)
	}

	if *account3.Account.GetUuid() == *env.Account1.Account.GetUuid() ||
		*account3.Account.GetUuid() == *env.Account2.Account.GetUuid() {
		return fmt.Errorf("authenticated as the same user twice: %s", *account3.Account.GetUsername())
	}

	env.Account3 = account3
	return nil
}
