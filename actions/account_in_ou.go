// Copyright (c) Topicus Security B.V.
// SPDX-License-Identifier: APSL-2.0

package actions

import (
	"context"
	"fmt"

	"github.com/topicuskeyhub/automation-framework/action"
	keyhubaccount "github.com/topicuskeyhub/sdk-go/account"
	"github.com/topicuskeyhub/sdk-go/models"
	keyhuborganizationalunit "github.com/topicuskeyhub/sdk-go/organizationalunit"
)

type accountInOU struct {
	accountUUID string
	orgUnitUUID string
	member      bool
	account     models.AuthAccountable
	orgUnit     models.OrganizationOrganizationalUnitable
}

func NewAccountInOU(accountUUID string, orgUnitUUID string) action.AutomationAction {
	return &accountInOU{
		accountUUID: accountUUID,
		orgUnitUUID: orgUnitUUID,
	}
}

func (a *accountInOU) TypeID() string {
	return "accountInOU"
}

func (a *accountInOU) Parameters() []*string {
	return []*string{&a.accountUUID, &a.orgUnitUUID}
}

func (a *accountInOU) Init(ctx context.Context, env *action.Environment) {
	account, err := action.First[models.AuthAccountable](
		env.Account1.Client.Account().Get(ctx, &keyhubaccount.AccountRequestBuilderGetRequestConfiguration{
			QueryParameters: &keyhubaccount.AccountRequestBuilderGetQueryParameters{
				Uuid: []string{a.accountUUID},
			},
		}))
	if err != nil {
		action.Abort(a, "unable to read account with UUID %s: %s", a.accountUUID, action.KeyHubError(err))
	}
	orgUnit, err := action.First[models.OrganizationOrganizationalUnitable](
		env.Account1.Client.Organizationalunit().Get(ctx, &keyhuborganizationalunit.OrganizationalunitRequestBuilderGetRequestConfiguration{
			QueryParameters: &keyhuborganizationalunit.OrganizationalunitRequestBuilderGetQueryParameters{
				Uuid: []string{a.orgUnitUUID},
			},
		}))
	if err != nil {
		action.Abort(a, "unable to read organisational unit with UUID %s: %s", a.orgUnitUUID, action.KeyHubError(err))
	}

	a.account = account
	a.orgUnit = orgUnit

	orgUnitAccounts, err := env.Account1.Client.Organizationalunit().ByOrganizationalunitidInt64(*action.Self(orgUnit).GetId()).
		Account().Get(ctx, &keyhuborganizationalunit.ItemAccountRequestBuilderGetRequestConfiguration{
		QueryParameters: &keyhuborganizationalunit.ItemAccountRequestBuilderGetQueryParameters{
			Account: []int64{*action.Self(account).GetId()},
		},
	})
	if err != nil {
		action.Abort(a, "unable to read organisational unit memberships for account %s, unit %s: %s", a.accountUUID, a.orgUnitUUID, action.KeyHubError(err))
	}
	a.member = len(orgUnitAccounts.GetItems()) == 1
}

func (a *accountInOU) IsSatisfied() bool {
	return a.member
}

func (a *accountInOU) Requires3() bool {
	return false
}

func (a *accountInOU) AllowGlobalOptimization() bool {
	return false
}

func (a *accountInOU) Execute(ctx context.Context, env *action.Environment) error {
	newOrgUnitAccount := models.NewOrganizationOrganizationalUnitAccount()
	newOrgUnitAccount.SetLinks([]models.RestLinkable{action.Self(a.account)})
	wrapper := models.NewOrganizationOrganizationalUnitAccountLinkableWrapper()
	wrapper.SetItems([]models.OrganizationOrganizationalUnitAccountable{newOrgUnitAccount})

	_, err := action.First[models.OrganizationOrganizationalUnitAccountable](
		env.Account1.Client.Organizationalunit().ByOrganizationalunitidInt64(*action.Self(a.orgUnit).GetId()).
			Account().Post(ctx, wrapper, nil))
	if err != nil {
		return fmt.Errorf("cannot add account to organisational unit in '%s': %s", a.String(), action.KeyHubError(err))
	}
	return nil
}

func (a *accountInOU) Setup(env *action.Environment) []action.AutomationAction {
	ret := make([]action.AutomationAction, 0)
	ret = append(ret, NewAccountInGroup(*env.Account1.Account.GetUuid(), *a.orgUnit.GetOwner().GetUuid(), action.Ptr(models.MANAGER_GROUPGROUPRIGHTS)))
	return ret
}

func (a *accountInOU) Perform(env *action.Environment) []action.AutomationAction {
	return make([]action.AutomationAction, 0)
}

func (a *accountInOU) Revert() action.AutomationAction {
	return nil
}

func (a *accountInOU) Progress() string {
	accountName := a.accountUUID
	if a.account != nil {
		accountName = *a.account.GetUsername()
	}
	return fmt.Sprintf("Adding %s", accountName)
}

func (a *accountInOU) String() string {
	accountName := a.accountUUID
	if a.account != nil {
		accountName = *a.account.GetUsername()
	} else if a.accountUUID == action.Account3UUIDPlaceholder {
		accountName = "account #3"
	}
	ouName := a.orgUnitUUID
	if a.orgUnit != nil {
		ouName = *a.orgUnit.GetName()
	}
	return fmt.Sprintf("Add %s to '%s'", accountName, ouName)
}
