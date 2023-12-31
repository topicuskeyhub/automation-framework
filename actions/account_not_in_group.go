// Copyright (c) Topicus Security B.V.
// SPDX-License-Identifier: APSL-2.0

package actions

import (
	"context"
	"fmt"

	"github.com/topicuskeyhub/automation-framework/action"
	keyhubaccount "github.com/topicuskeyhub/sdk-go/account"
	keyhubgroup "github.com/topicuskeyhub/sdk-go/group"
	"github.com/topicuskeyhub/sdk-go/models"
)

type accountNotInGroup struct {
	accountUUID string
	groupUUID   string
	account     models.AuthAccountable
	group       models.GroupGroupable
	membership  models.GroupGroupAccountable
}

func NewAccountNotInGroup(accountUUID string, groupUUID string) action.AutomationAction {
	return &accountNotInGroup{
		accountUUID: accountUUID,
		groupUUID:   groupUUID,
	}
}

func (a *accountNotInGroup) TypeID() string {
	return "accountNotInGroup"
}

func (a *accountNotInGroup) Parameters() []*string {
	return []*string{&a.accountUUID, &a.groupUUID}
}

func (a *accountNotInGroup) Init(ctx context.Context, env *action.Environment) {
	group, err := action.First[models.GroupGroupable](env.Account1.Client.Group().Get(ctx, &keyhubgroup.GroupRequestBuilderGetRequestConfiguration{
		QueryParameters: &keyhubgroup.GroupRequestBuilderGetQueryParameters{
			Uuid:       []string{a.groupUUID},
			Additional: []string{"accounts"},
		},
	}))
	if err != nil {
		action.Abort(a, "unable to read group with uuid %s: %s", a.groupUUID, action.KeyHubError(err))
	}
	a.group = group

	if a.accountUUID == action.Account3UUIDPlaceholder && env.Account3 != nil {
		a.accountUUID = *env.Account3.Account.GetUuid()
	}
	if a.accountUUID != action.Account3UUIDPlaceholder {
		for _, m := range group.GetAdditionalObjects().GetAccounts().GetItems() {
			if *m.GetUuid() == a.accountUUID {
				a.membership = m
				break
			}
		}

		account, err := action.First[models.AuthAccountable](env.Account1.Client.Account().Get(ctx, &keyhubaccount.AccountRequestBuilderGetRequestConfiguration{
			QueryParameters: &keyhubaccount.AccountRequestBuilderGetQueryParameters{
				Uuid: []string{a.accountUUID},
			},
		}))
		if err != nil {
			action.Abort(a, "unable to read account with uuid %s: %s", a.accountUUID, action.KeyHubError(err))
		}
		a.account = account
	}
}

func (a *accountNotInGroup) IsSatisfied() bool {
	return a.membership == nil
}

func (a *accountNotInGroup) Requires3() bool {
	return a.accountUUID == action.Account3UUIDPlaceholder
}

func (a *accountNotInGroup) AllowGlobalOptimization() bool {
	return true
}

func (a *accountNotInGroup) Execute(ctx context.Context, env *action.Environment) error {
	auth := *env.Account1
	if a.accountUUID == *env.Account2.Account.GetUuid() {
		auth = *env.Account2
	} else if env.Account3 != nil && a.accountUUID == *env.Account3.Account.GetUuid() {
		auth = *env.Account3
	}

	member, err := action.First[models.GroupGroupAccountable](auth.Client.Group().ByGroupidInt64(*action.Self(a.group).GetId()).Account().Get(ctx, &keyhubgroup.ItemAccountRequestBuilderGetRequestConfiguration{
		QueryParameters: &keyhubgroup.ItemAccountRequestBuilderGetQueryParameters{
			Account: []int64{*a.account.GetLinks()[0].GetId()},
		},
	}))
	if err != nil {
		return fmt.Errorf("cannot fetch group membership in '%s': %s", a.String(), action.KeyHubError(err))
	}
	err = auth.Client.Group().ByGroupidInt64(*action.Self(a.group).GetId()).Account().ByAccountidInt64(*action.Koppeling(member).GetId()).Delete(ctx, nil)
	if err != nil {
		return fmt.Errorf("cannot remove user from group in '%s': %s", a.String(), action.KeyHubError(err))
	}
	return nil
}

func (a *accountNotInGroup) Setup(env *action.Environment) []action.AutomationAction {
	account1UUID := *env.Account1.Account.GetUuid()
	account2UUID := *env.Account2.Account.GetUuid()
	if a.accountUUID == account1UUID || a.accountUUID == account2UUID || a.accountUUID == action.Account3UUIDPlaceholder {
		return make([]action.AutomationAction, 0)
	}
	return []action.AutomationAction{NewAccountInGroup(account1UUID, a.groupUUID, action.Ptr(models.MANAGER_GROUPGROUPRIGHTS))}
}

func (*accountNotInGroup) Perform(env *action.Environment) []action.AutomationAction {
	return make([]action.AutomationAction, 0)
}

func (a *accountNotInGroup) Revert() action.AutomationAction {
	var rights *models.GroupGroupRights
	if a.membership != nil {
		rights = a.membership.GetRights()
	}
	return NewAccountInGroup(a.accountUUID, a.groupUUID, rights)
}

func (a *accountNotInGroup) Progress() string {
	accountName := a.accountUUID
	if a.account != nil {
		accountName = *a.account.GetUsername()
	}
	return fmt.Sprintf("Removing %s", accountName)
}

func (a *accountNotInGroup) String() string {
	accountName := a.accountUUID
	if a.account != nil {
		accountName = *a.account.GetUsername()
	} else if a.accountUUID == action.Account3UUIDPlaceholder {
		accountName = "account #3"
	}
	groupName := a.groupUUID
	if a.group != nil {
		groupName = *a.group.GetName()
	}
	return fmt.Sprintf("Remove %s from '%s'", accountName, groupName)
}
