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
	keyhubrequest "github.com/topicuskeyhub/sdk-go/request"
)

type accountInGroup struct {
	accountUUID string
	groupUUID   string
	rights      *models.GroupGroupRights
	account     models.AuthAccountable
	group       models.GroupGroupable
	membership  models.GroupGroupAccountable
	vaultAccess bool
}

func NewAccountInGroup(accountUUID string, groupUUID string, rights *models.GroupGroupRights) action.AutomationAction {
	return &accountInGroup{
		accountUUID: accountUUID,
		groupUUID:   groupUUID,
		rights:      rights,
		vaultAccess: false,
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

	if a.accountUUID == action.Account3UUIDPlaceholder && env.Account3 != nil {
		a.accountUUID = *env.Account3.Account.GetUuid()
	}
	if a.accountUUID != action.Account3UUIDPlaceholder {
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
	if a.membership != nil {
		memberships, err := env.Account1.Client.Account().ByAccountidInt64(*action.Self(a.account).GetId()).Group().Get(ctx, &keyhubaccount.ItemGroupRequestBuilderGetRequestConfiguration{
			QueryParameters: &keyhubaccount.ItemGroupRequestBuilderGetQueryParameters{
				Group:       []int64{*action.Self(group).GetId()},
				VaultAccess: []bool{true},
			},
		})
		if err != nil {
			action.Abort(a, "unable to read group memberships for account with uuid %s: %s", a.accountUUID, action.KeyHubError(err))
		}
		a.vaultAccess = len(memberships.GetItems()) > 0
	}
}

func (a *accountInGroup) IsSatisfied() bool {
	if a.membership == nil {
		return false
	}
	if a.rights == nil {
		return true
	}
	if !a.vaultAccess {
		return false
	}
	isManager := *a.membership.GetRights() == models.MANAGER_GROUPGROUPRIGHTS
	mustBeManager := *a.rights == models.MANAGER_GROUPGROUPRIGHTS
	return isManager == mustBeManager
}

func (a *accountInGroup) Requires3() bool {
	return a.accountUUID == action.Account3UUIDPlaceholder
}

func (a *accountInGroup) AllowGlobalOptimization() bool {
	return false
}

func (a *accountInGroup) Execute(ctx context.Context, env *action.Environment) error {
	vaultAccessGiven := false
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
			return fmt.Errorf("cannot request to add manager to group in '%s': %s", a.String(), action.KeyHubError(err))
		}

		addAdmin := req.(models.RequestAddGroupAdminRequestable)
		addAdmin.SetPrivateKey(&env.VaultRecoveryKey)
		addAdmin.SetStatus(action.Ptr(models.ALLOWED_REQUESTMODIFICATIONREQUESTSTATUS))
		addAdmin.SetFeedback(action.Ptr("automation accountInGroup"))
		_, err = auth2.Client.Request().ByRequestidInt64(*action.Self(addAdmin).GetId()).Put(ctx, addAdmin, nil)
		if err != nil {
			return fmt.Errorf("cannot confirm to add manager to group in '%s': %s", a.String(), action.KeyHubError(err))
		}
		vaultAccessGiven = true
	}
	if a.group.GetAuthorizingGroupMembership() == nil {
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
				return fmt.Errorf("cannot fetch group membership in '%s': %s", a.String(), action.KeyHubError(err))
			}
			member.SetRights(action.Ptr(models.NORMAL_GROUPGROUPRIGHTS))
			_, err = auth.Client.Group().ByGroupidInt64(*action.Self(member).GetId()).Account().ByAccountidInt64(*action.Koppeling(member).GetId()).Put(ctx, member, nil)
			if err != nil {
				return fmt.Errorf("cannot convert user to normal in '%s': %s", a.String(), action.KeyHubError(err))
			}
		}
	} else {
		request, err := action.First[models.RequestModificationRequestable](env.Account3.Client.Request().Get(ctx, &keyhubrequest.RequestRequestBuilderGetRequestConfiguration{
			QueryParameters: &keyhubrequest.RequestRequestBuilderGetQueryParameters{
				UpdateGroupMembershipType: []string{
					models.ADD_REQUESTUPDATEGROUPMEMBERSHIPTYPE.String(),
					models.MODIFY_REQUESTUPDATEGROUPMEMBERSHIPTYPE.String()},
				Status:          []string{models.REQUESTED_REQUESTMODIFICATIONREQUESTSTATUS.String()},
				Group:           []int64{*action.Self(a.group).GetId()},
				AccountToUpdate: []int64{*action.Self(a.account).GetId()},
			},
		}))
		if err != nil {
			return fmt.Errorf("cannot fetch update group membership request in '%s': %s", a.String(), action.KeyHubError(err))
		}
		request.SetStatus(action.Ptr(models.ALLOWED_REQUESTMODIFICATIONREQUESTSTATUS))
		request.SetFeedback(action.Ptr("automation accountInGroup"))
		_, err = env.Account3.Client.Request().ByRequestidInt64(*action.Self(request).GetId()).Put(ctx, request, nil)
		if err != nil {
			return fmt.Errorf("cannot confirm to update group membership in '%s': %s", a.String(), action.KeyHubError(err))
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
				return fmt.Errorf("cannot fetch group membership in '%s': %s", a.String(), action.KeyHubError(err))
			}

			newUpdateReq := models.NewRequestUpdateGroupMembershipRequest()
			newUpdateReq.SetAccountToUpdate(a.account)
			newUpdateReq.SetGroup(a.group)
			newUpdateReq.SetRights(action.Ptr(models.NORMAL_GROUPGROUPRIGHTS))
			newUpdateReq.SetEndDate(member.GetEndDate())
			newUpdateReq.SetComment(action.Ptr("automation accountInGroup"))
			newUpdateReq.SetUpdateGroupMembershipType(action.Ptr(models.MODIFY_REQUESTUPDATEGROUPMEMBERSHIPTYPE))
			err = submitAndAccept(ctx, newUpdateReq, &auth, env.Account3)
			if err != nil {
				return fmt.Errorf("cannot request to change membership to normal in '%s': %s", a.String(), action.KeyHubError(err))
			}
		}
	}
	if !vaultAccessGiven {
		memberships, err := env.Account1.Client.Account().ByAccountidInt64(*action.Self(a.account).GetId()).Group().Get(ctx, &keyhubaccount.ItemGroupRequestBuilderGetRequestConfiguration{
			QueryParameters: &keyhubaccount.ItemGroupRequestBuilderGetQueryParameters{
				VaultAccess: []bool{true},
				Group:       []int64{*action.Self(a.group).GetId()},
			},
		})
		if err != nil {
			action.Abort(a, "unable to read group memberships for account with uuid %s: %s", a.accountUUID, action.KeyHubError(err))
		}
		if len(memberships.GetItems()) == 0 {
			auth := env.Account1
			if a.accountUUID == *env.Account1.Account.GetUuid() {
				auth = env.Account2
			}

			recovery := models.NewVaultVaultRecovery()
			recovery.SetAccount(a.account)
			recovery.SetPrivateKey(&env.VaultRecoveryKey)
			err := auth.Client.Group().ByGroupidInt64(*action.Self(a.group).GetId()).Vault().Recover().Post(ctx, recovery, nil)
			if err != nil {
				return fmt.Errorf("cannot recover vault access in '%s': %s", a.String(), action.KeyHubError(err))
			}
		}
	}
	return nil
}

func (a *accountInGroup) Setup(env *action.Environment) []action.AutomationAction {
	ret := make([]action.AutomationAction, 0)
	if a.rights != nil && *a.rights == models.NORMAL_GROUPGROUPRIGHTS {
		account1UUID := *env.Account1.Account.GetUuid()
		account2UUID := *env.Account2.Account.GetUuid()
		if a.accountUUID != account1UUID && a.accountUUID != account2UUID {
			ret = append(ret, NewAccountInGroup(account1UUID, a.groupUUID, action.Ptr(models.MANAGER_GROUPGROUPRIGHTS)))
		}
	}
	if a.group.GetAuthorizingGroupMembership() != nil {
		ret = append(ret, NewAccountInGroup(action.Account3UUIDPlaceholder, *a.group.GetAuthorizingGroupMembership().GetUuid(), nil))
	}
	return ret
}

func (a *accountInGroup) Perform(env *action.Environment) []action.AutomationAction {
	return make([]action.AutomationAction, 0)
}

func (a *accountInGroup) Revert() action.AutomationAction {
	if a.membership == nil {
		return NewAccountNotInGroup(a.accountUUID, a.groupUUID)
	}
	if a.rights != nil && *a.membership.GetRights() != *a.rights {
		return NewAccountInGroup(a.accountUUID, a.groupUUID, a.membership.GetRights())
	}
	return nil
}

func (a *accountInGroup) Progress() string {
	accountName := a.accountUUID
	if a.account != nil {
		accountName = *a.account.GetUsername()
	}
	return fmt.Sprintf("Adding %s", accountName)
}

func (a *accountInGroup) String() string {
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
