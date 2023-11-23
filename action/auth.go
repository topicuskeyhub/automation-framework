// Copyright (c) Topicus Security B.V.
// SPDX-License-Identifier: APSL-2.0

package action

import (
	"context"
	"fmt"
	"net/http"

	keyhub "github.com/topicuskeyhub/sdk-go"
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
	if err != nil {
		return nil, fmt.Errorf("unable to fetch account: %s", err)
	}
	return &AuthenticatedAccount{
		Client:  client,
		Account: account,
	}, nil
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
