// Copyright (c) Topicus Security B.V.
// SPDX-License-Identifier: APSL-2.0

package actions

import (
	"context"
	"fmt"
	"log"

	"github.com/topicuskeyhub/automation-framework/action"
	keyhubaccount "github.com/topicuskeyhub/sdk-go/account"
	keyhubgroup "github.com/topicuskeyhub/sdk-go/group"
	"github.com/topicuskeyhub/sdk-go/models"
)

type ensureAccountNotInGroup struct {
	accountUUID string
	groupUUID   string
	account     models.AuthAccountable
	group       models.GroupGroupable
	membership  models.GroupGroupAccountable
}

func NewEnsureAccountNotInGroup(accountUUID string, groupUUID string) action.AutomationAction {
	return &ensureAccountNotInGroup{
		accountUUID: accountUUID,
		groupUUID:   groupUUID,
	}
}

func (a *ensureAccountNotInGroup) TypeID() string {
	return "ensureAccountNotInGroup"
}

func (a *ensureAccountNotInGroup) Parameters() []string {
	return []string{a.accountUUID, a.groupUUID}
}

func (a *ensureAccountNotInGroup) Init(ctx context.Context, env action.Environment) {
	group, err := action.First[models.GroupGroupable](env.Account1.Client.Group().Get(ctx, &keyhubgroup.GroupRequestBuilderGetRequestConfiguration{
		QueryParameters: &keyhubgroup.GroupRequestBuilderGetQueryParameters{
			Uuid:       []string{a.groupUUID},
			Additional: []string{"accounts"},
		},
	}))
	if err != nil {
		log.Fatalf("unable to read group with uuid %s: %s", a.groupUUID, err)
	}
	a.group = group

	for _, m := range group.GetAdditionalObjects().GetAccounts().GetItems() {
		if m.GetUuid() == &a.accountUUID {
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
		log.Fatalf("unable to read account with uuid %s: %s", a.accountUUID, err)
	}
	a.account = account
}

func (a *ensureAccountNotInGroup) IsSatisfied() bool {
	return a.membership == nil
}

func (a *ensureAccountNotInGroup) Execute(ctx context.Context, env action.Environment) {
	auth := *env.Account1
	if a.accountUUID == *auth.Account.GetUuid() {
		auth = *env.Account2
	}

	member, err := action.First[models.GroupGroupAccountable](auth.Client.Group().ByGroupidInt64(*action.Self(a.group).GetId()).Account().Get(ctx, &keyhubgroup.ItemAccountRequestBuilderGetRequestConfiguration{
		QueryParameters: &keyhubgroup.ItemAccountRequestBuilderGetQueryParameters{
			Account: []int64{*a.account.GetLinks()[0].GetId()},
		},
	}))
	if err != nil {
		log.Fatalf("cannot fetch group membership in '%s': %s", a.String(), err)
	}
	err = auth.Client.Group().ByGroupidInt64(*action.Self(member).GetId()).Account().ByAccountidInt64(*action.Koppeling(member).GetId()).Delete(ctx, nil)
	if err != nil {
		log.Fatalf("cannot remove user from group in '%s': %s", a.String(), err)
	}
}

func (a *ensureAccountNotInGroup) Setup(env action.Environment) []action.AutomationAction {
	accountUUID := *env.Account1.Account.GetUuid()
	if a.accountUUID == accountUUID {
		accountUUID = *env.Account2.Account.GetUuid()
	}
	return []action.AutomationAction{NewEnsureAccountInGroup(accountUUID, a.groupUUID, action.Ptr(models.MANAGER_GROUPGROUPRIGHTS))}
}

func (*ensureAccountNotInGroup) Perform(env action.Environment) []action.AutomationAction {
	return make([]action.AutomationAction, 0)
}

func (a *ensureAccountNotInGroup) Revert() action.AutomationAction {
	return NewEnsureAccountInGroup(a.groupUUID, a.accountUUID, a.membership.GetRights())
}

func (a *ensureAccountNotInGroup) String() string {
	accountName := "unknown"
	if a.account != nil {
		accountName = *a.account.GetUsername()
	}
	groupName := "unknown"
	if a.account != nil {
		groupName = *a.group.GetName()
	}
	return fmt.Sprintf("Ensure account %s (%s) is not in group %s (%s)", a.accountUUID, accountName, a.groupUUID, groupName)
}
