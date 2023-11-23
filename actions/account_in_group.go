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

type accountInGroup struct {
	accountUUID string
	groupUUID   string
	rights      *models.GroupGroupRights
	account     models.AuthAccountable
	group       models.GroupGroupable
	membership  models.GroupGroupAccountable
}

func NewAccountInGroup(accountUUID string, groupUUID string, rights *models.GroupGroupRights) action.AutomationAction {
	return &accountInGroup{
		accountUUID: accountUUID,
		groupUUID:   groupUUID,
		rights:      rights,
	}
}

func (a *accountInGroup) TypeID() string {
	return "accountInGroup"
}

func (a *accountInGroup) Parameters() []*string {
	var rel *string
	if a.rights != nil {
		if *a.rights == models.MANAGER_GROUPGROUPRIGHTS {
			rel = action.Ptr("manager")
		} else {
			rel = action.Ptr("member")
		}
	}
	return []*string{&a.accountUUID, &a.groupUUID, rel}
}

func (a *accountInGroup) Init(ctx context.Context, env *action.Environment) {
	group, err := action.First[models.GroupGroupable](env.Account1.Client.Group().Get(ctx, &keyhubgroup.GroupRequestBuilderGetRequestConfiguration{
		QueryParameters: &keyhubgroup.GroupRequestBuilderGetQueryParameters{
			Uuid:       []string{a.groupUUID},
			Additional: []string{"accounts"},
		},
	}))
	if err != nil {
		action.Abort(a, "unable to read group with uuid %s: %s", a.groupUUID, err)
	}
	a.group = group

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
		action.Abort(a, "unable to read account with uuid %s: %s", a.accountUUID, err)
	}
	a.account = account
}

func (a *accountInGroup) IsSatisfied() bool {
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

func (a *accountInGroup) Execute(ctx context.Context, env *action.Environment) error {
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
		newAddAdmin.SetComment(action.Ptr("automation accountInGroup"))
		wrapper := models.NewRequestModificationRequestLinkableWrapper()
		wrapper.SetItems([]models.RequestModificationRequestable{newAddAdmin})
		req, err := action.First[models.RequestModificationRequestable](auth1.Client.Request().Post(ctx, wrapper, nil))
		if err != nil {
			return fmt.Errorf("cannot request to add manager to group in '%s': %s", a.String(), err)
		}

		addAdmin := req.(models.RequestAddGroupAdminRequestable)
		addAdmin.SetPrivateKey(&env.VaultRecoveryKey)
		addAdmin.SetStatus(action.Ptr(models.ALLOWED_REQUESTMODIFICATIONREQUESTSTATUS))
		addAdmin.SetFeedback(action.Ptr("automation accountInGroup"))
		_, err = auth2.Client.Request().ByRequestidInt64(*action.Self(addAdmin).GetId()).Put(ctx, addAdmin, nil)
		if err != nil {
			return fmt.Errorf("cannot confirm to add manager to group in '%s': %s", a.String(), err)
		}
	}
	if a.rights != nil && *a.rights == models.NORMAL_GROUPGROUPRIGHTS {
		auth := *env.Account1
		if a.accountUUID == *env.Account2.Account.GetUuid() {
			auth = *env.Account2
		}

		member, err := action.First[models.GroupGroupAccountable](auth.Client.Group().ByGroupidInt64(*action.Self(a.group).GetId()).Account().Get(ctx, &keyhubgroup.ItemAccountRequestBuilderGetRequestConfiguration{
			QueryParameters: &keyhubgroup.ItemAccountRequestBuilderGetQueryParameters{
				Account: []int64{*a.account.GetLinks()[0].GetId()},
			},
		}))
		if err != nil {
			return fmt.Errorf("cannot fetch group membership in '%s': %s", a.String(), err)
		}
		member.SetRights(action.Ptr(models.NORMAL_GROUPGROUPRIGHTS))
		_, err = auth.Client.Group().ByGroupidInt64(*action.Self(member).GetId()).Account().ByAccountidInt64(*action.Koppeling(member).GetId()).Put(ctx, member, nil)
		if err != nil {
			return fmt.Errorf("cannot convert user to normal in '%s': %s", a.String(), err)
		}
	}
	return nil
}

func (a *accountInGroup) Setup(env *action.Environment) []action.AutomationAction {
	if a.rights != nil && *a.rights == models.NORMAL_GROUPGROUPRIGHTS {
		account1UUID := *env.Account1.Account.GetUuid()
		account2UUID := *env.Account2.Account.GetUuid()
		if a.accountUUID == account1UUID || a.accountUUID == account2UUID {
			return make([]action.AutomationAction, 0)
		}
		return []action.AutomationAction{NewAccountInGroup(account1UUID, a.groupUUID, action.Ptr(models.MANAGER_GROUPGROUPRIGHTS))}
	}
	return make([]action.AutomationAction, 0)
}

func (*accountInGroup) Perform(env *action.Environment) []action.AutomationAction {
	return make([]action.AutomationAction, 0)
}

func (a *accountInGroup) Revert() action.AutomationAction {
	if a.membership == nil {
		return NewAccountNotInGroup(a.accountUUID, a.groupUUID)
	}
	return NewAccountInGroup(a.accountUUID, a.groupUUID, a.membership.GetRights())
}

func (a *accountInGroup) String() string {
	accountName := a.accountUUID
	if a.account != nil {
		accountName = *a.account.GetUsername()
	}
	groupName := a.groupUUID
	if a.group != nil {
		groupName = *a.group.GetName()
	}
	var rel string
	if a.rights == nil {
		rel = ""
	} else if *a.rights == models.MANAGER_GROUPGROUPRIGHTS {
		rel = " as manager"
	} else {
		rel = " as normal member"
	}
	return fmt.Sprintf("Add %s to '%s'%s", accountName, groupName, rel)
}
