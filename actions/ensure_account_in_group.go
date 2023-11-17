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

type ensureAccountInGroup struct {
	accountUUID string
	groupUUID   string
	rights      *models.GroupGroupRights
	account     models.AuthAccountable
	group       models.GroupGroupable
	membership  models.GroupGroupAccountable
}

func NewEnsureAccountInGroup(accountUUID string, groupUUID string, rights *models.GroupGroupRights) action.AutomationAction {
	return &ensureAccountInGroup{
		accountUUID: accountUUID,
		groupUUID:   groupUUID,
		rights:      rights,
	}
}

func (a *ensureAccountInGroup) TypeID() string {
	return "ensureAccountInGroup"
}

func (a *ensureAccountInGroup) Parameters() []string {
	var rel string
	if a.rights == nil {
		rel = "in"
	} else if *a.rights == models.MANAGER_GROUPGROUPRIGHTS {
		rel = "manager"
	} else {
		rel = "member"
	}
	return []string{a.accountUUID, a.groupUUID, rel}
}

func (a *ensureAccountInGroup) Init(ctx context.Context, env action.Environment) {
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

func (a *ensureAccountInGroup) IsSatisfied() bool {
	if a.membership == nil {
		return false
	}
	if a.rights == nil {
		return true
	}
	isManager := *a.membership.GetRights() == models.MANAGER_GROUPGROUPRIGHTS
	mustBeManager := *a.rights == models.MANAGER_GROUPGROUPRIGHTS
	return isManager == mustBeManager
}

func (a *ensureAccountInGroup) Execute(ctx context.Context, env action.Environment) {
	if a.membership == nil || (a.rights != nil && *a.rights == models.MANAGER_GROUPGROUPRIGHTS) {
		auth1 := env.Account1
		auth2 := env.Account2
		if a.accountUUID == *env.Account2.Account.GetUuid() {
			auth1 = env.Account2
			auth2 = env.Account1
		}

		newAddAdmin := models.NewRequestAddGroupAdminRequest()
		newAddAdmin.SetNewAdmin(a.account)
		newAddAdmin.SetGroup(a.group)
		newAddAdmin.SetPrivateKey(&env.VaultRecoveryKey)
		newAddAdmin.SetComment(action.Ptr("automation ensureAccountInGroup"))
		wrapper := models.NewRequestModificationRequestLinkableWrapper()
		wrapper.SetItems([]models.RequestModificationRequestable{newAddAdmin})
		auth1.Client.Request().Post(ctx, wrapper, nil)
		addAdmin, err := action.First[models.RequestModificationRequestable](auth1.Client.Request().Post(ctx, wrapper, nil))
		if err != nil {
			log.Fatalf("cannot request to add manager to group in '%s': %s", a.String(), err)
		}

		addAdmin.SetStatus(action.Ptr(models.ALLOWED_REQUESTMODIFICATIONREQUESTSTATUS))
		addAdmin.SetFeedback(action.Ptr("automation ensureAccountInGroup"))
		addAdmin, err = auth2.Client.Request().ByRequestidInt64(*action.Self(addAdmin).GetId()).Put(ctx, addAdmin, nil)
		if err != nil {
			log.Fatalf("cannot confirm to add manager to group in '%s': %s", a.String(), err)
		}
	}
	if a.rights != nil && *a.rights == models.NORMAL_GROUPGROUPRIGHTS {
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
		member.SetRights(action.Ptr(models.NORMAL_GROUPGROUPRIGHTS))
		member, err = auth.Client.Group().ByGroupidInt64(*action.Self(member).GetId()).Account().ByAccountidInt64(*action.Koppeling(member).GetId()).Put(ctx, member, nil)
		if err != nil {
			log.Fatalf("cannot convert user to normal in '%s': %s", a.String(), err)
		}
	}
}

func (a *ensureAccountInGroup) Setup(env action.Environment) []action.AutomationAction {
	if a.rights != nil && *a.rights == models.NORMAL_GROUPGROUPRIGHTS {
		accountUUID := *env.Account1.Account.GetUuid()
		if a.accountUUID == accountUUID {
			accountUUID = *env.Account2.Account.GetUuid()
		}
		return []action.AutomationAction{NewEnsureAccountInGroup(accountUUID, a.groupUUID, action.Ptr(models.MANAGER_GROUPGROUPRIGHTS))}
	}
	return make([]action.AutomationAction, 0)
}

func (*ensureAccountInGroup) Perform(env action.Environment) []action.AutomationAction {
	return make([]action.AutomationAction, 0)
}

func (a *ensureAccountInGroup) Revert() action.AutomationAction {
	if a.membership == nil {
		return NewEnsureAccountNotInGroup(a.groupUUID, a.accountUUID)
	}
	return NewEnsureAccountInGroup(a.groupUUID, a.accountUUID, a.membership.GetRights())
}

func (a *ensureAccountInGroup) String() string {
	accountName := "unknown"
	if a.account != nil {
		accountName = *a.account.GetUsername()
	}
	groupName := "unknown"
	if a.account != nil {
		groupName = *a.group.GetName()
	}
	var rel string
	if a.rights == nil {
		rel = "in"
	} else if *a.rights == models.MANAGER_GROUPGROUPRIGHTS {
		rel = "manager of"
	} else {
		rel = "normal member of"
	}
	return fmt.Sprintf("Ensure account %s (%s) is %s group %s (%s)", a.accountUUID, accountName, rel, a.groupUUID, groupName)
}
