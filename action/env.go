// Copyright (c) Topicus Security B.V.
// SPDX-License-Identifier: APSL-2.0

package action

import (
	keyhub "github.com/topicuskeyhub/sdk-go"
	"github.com/topicuskeyhub/sdk-go/models"
)

type AuthenticatedAccount struct {
	Client  *keyhub.KeyHubClient
	Account models.AuthAccountable
}

type Environment struct {
	Account1         *AuthenticatedAccount
	Account2         *AuthenticatedAccount
	VaultRecoveryKey string
}
