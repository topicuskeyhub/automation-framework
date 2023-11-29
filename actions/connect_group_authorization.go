// Copyright (c) Topicus Security B.V.
// SPDX-License-Identifier: APSL-2.0

package actions

import (
	"context"
	"fmt"
	"unicode"
	"unicode/utf8"

	"github.com/topicuskeyhub/automation-framework/action"
	keyhubgroup "github.com/topicuskeyhub/sdk-go/group"
	"github.com/topicuskeyhub/sdk-go/models"
)

type connectGroupAuthorization struct {
	subjectGroupUUID     string
	authorizingGroupUUID string
	authorizationType    models.RequestAuthorizingGroupType
	subjectGroup         models.GroupGroupable
	authorizingGroup     models.GroupGroupable
}

func NewConnectGroupAuthorization(subjectGroupUUID string, authorizingGroupUUID string,
	authorizationType models.RequestAuthorizingGroupType) action.AutomationAction {
	return &connectGroupAuthorization{
		subjectGroupUUID:     subjectGroupUUID,
		authorizingGroupUUID: authorizingGroupUUID,
		authorizationType:    authorizationType,
	}
}

func (a *connectGroupAuthorization) TypeID() string {
	return "connectGroupAuthorization"
}

func (a *connectGroupAuthorization) Parameters() []*string {
	return []*string{&a.subjectGroupUUID, &a.authorizingGroupUUID, action.Ptr(a.authorizationType.String())}
}

func (a *connectGroupAuthorization) Init(ctx context.Context, env *action.Environment) {
	subjectGroup, err := action.First[models.GroupGroupable](env.Account1.Client.Group().Get(ctx, &keyhubgroup.GroupRequestBuilderGetRequestConfiguration{
		QueryParameters: &keyhubgroup.GroupRequestBuilderGetQueryParameters{
			Uuid: []string{a.subjectGroupUUID},
		},
	}))
	if err != nil {
		action.Abort(a, "unable to read group with uuid %s: %s", a.subjectGroupUUID, action.KeyHubError(err))
	}
	a.subjectGroup = subjectGroup

	authorizingGroup, err := action.First[models.GroupGroupable](env.Account1.Client.Group().Get(ctx, &keyhubgroup.GroupRequestBuilderGetRequestConfiguration{
		QueryParameters: &keyhubgroup.GroupRequestBuilderGetQueryParameters{
			Uuid: []string{a.authorizingGroupUUID},
		},
	}))
	if err != nil {
		action.Abort(a, "unable to read group with uuid %s: %s", a.authorizingGroupUUID, action.KeyHubError(err))
	}
	a.authorizingGroup = authorizingGroup
}

func firstCharToUpper(input string) string {
	r, i := utf8.DecodeRuneInString(input)
	return string(unicode.ToUpper(r)) + input[i:]
}

func (a *connectGroupAuthorization) IsSatisfied() bool {
	groupSet := findCurrentAuthorizingGroup(a.subjectGroup, a.authorizationType)
	return groupSet != nil && action.Self(groupSet).GetId() == action.Self(a.authorizingGroup).GetId()
}

func (a *connectGroupAuthorization) Requires3() bool {
	return false
}

func (a *connectGroupAuthorization) AllowGlobalOptimization() bool {
	return false
}

func (a *connectGroupAuthorization) Execute(ctx context.Context, env *action.Environment) error {
	groupSet := findCurrentAuthorizingGroup(a.subjectGroup, a.authorizationType)
	if groupSet != nil {
		disconnectReq := models.NewRequestSetupAuthorizingGroupRequest()
		disconnectReq.SetConnect(action.Ptr(false))
		disconnectReq.SetAuthorizingGroupType(&a.authorizationType)
		disconnectReq.SetRequestingGroup(groupSet)
		disconnectReq.SetGroup(a.subjectGroup)
		disconnectReq.SetComment(action.Ptr("automation connectGroupAuthorization"))
		err := submitAndAccept(ctx, disconnectReq, env.Account2, env.Account1)
		if err != nil {
			return fmt.Errorf("cannot request to disconnect %s authorization in '%s': %s", describe(a.authorizationType), a.String(), action.KeyHubError(err))
		}
	}

	connectReq := models.NewRequestSetupAuthorizingGroupRequest()
	connectReq.SetConnect(action.Ptr(true))
	connectReq.SetAuthorizingGroupType(&a.authorizationType)
	connectReq.SetRequestingGroup(a.authorizingGroup)
	connectReq.SetGroup(a.subjectGroup)
	connectReq.SetComment(action.Ptr("automation connectGroupAuthorization"))
	err := submitAndAccept(ctx, connectReq, env.Account2, env.Account1)
	if err != nil {
		return fmt.Errorf("cannot request to disconnect %s authorization in '%s': %s", describe(a.authorizationType), a.String(), action.KeyHubError(err))
	}
	return nil
}

func (a *connectGroupAuthorization) Setup(env *action.Environment) []action.AutomationAction {
	ret := make([]action.AutomationAction, 0)
	groupSet := findCurrentAuthorizingGroup(a.subjectGroup, a.authorizationType)
	if groupSet != nil {
		ret = append(ret, NewAccountInGroup(*env.Account2.Account.GetUuid(), *groupSet.GetUuid(), action.Ptr(models.MANAGER_GROUPGROUPRIGHTS)))
	}
	ret = append(ret, NewAccountInGroup(*env.Account2.Account.GetUuid(), a.authorizingGroupUUID, action.Ptr(models.MANAGER_GROUPGROUPRIGHTS)))
	ret = append(ret, NewAccountInGroup(*env.Account1.Account.GetUuid(), a.subjectGroupUUID, action.Ptr(models.MANAGER_GROUPGROUPRIGHTS)))
	return ret
}

func (*connectGroupAuthorization) Perform(env *action.Environment) []action.AutomationAction {
	return make([]action.AutomationAction, 0)
}

func (a *connectGroupAuthorization) Revert() action.AutomationAction {
	groupSet := findCurrentAuthorizingGroup(a.subjectGroup, a.authorizationType)
	if groupSet == nil {
		return NewDisconnectGroupAuthorization(a.subjectGroupUUID, a.authorizationType)
	} else {
		return NewConnectGroupAuthorization(a.subjectGroupUUID, *groupSet.GetUuid(), a.authorizationType)
	}
}

func (a *connectGroupAuthorization) Progress() string {
	subjectGroupName := a.subjectGroupUUID
	if a.subjectGroup != nil {
		subjectGroupName = *a.subjectGroup.GetName()
	}
	return fmt.Sprintf("%s auth. on %s", firstCharToUpper(describe(a.authorizationType)), subjectGroupName)
}

func (a *connectGroupAuthorization) String() string {
	subjectGroupName := a.subjectGroupUUID
	if a.subjectGroup != nil {
		subjectGroupName = *a.subjectGroup.GetName()
	}
	authorizingGroupName := a.authorizingGroupUUID
	if a.authorizingGroup != nil {
		authorizingGroupName = *a.authorizingGroup.GetName()
	}

	return fmt.Sprintf("Setup %s authorization on '%s' by '%s'", describe(a.authorizationType), subjectGroupName, authorizingGroupName)
}
