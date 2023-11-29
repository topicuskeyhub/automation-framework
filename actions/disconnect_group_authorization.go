// Copyright (c) Topicus Security B.V.
// SPDX-License-Identifier: APSL-2.0

package actions

import (
	"context"
	"fmt"

	"github.com/topicuskeyhub/automation-framework/action"
	keyhubgroup "github.com/topicuskeyhub/sdk-go/group"
	"github.com/topicuskeyhub/sdk-go/models"
)

type disconnectGroupAuthorization struct {
	subjectGroupUUID  string
	authorizationType models.RequestAuthorizingGroupType
	subjectGroup      models.GroupGroupable
}

func NewDisconnectGroupAuthorization(subjectGroupUUID string, authorizationType models.RequestAuthorizingGroupType) action.AutomationAction {
	return &disconnectGroupAuthorization{
		subjectGroupUUID:  subjectGroupUUID,
		authorizationType: authorizationType,
	}
}

func (a *disconnectGroupAuthorization) TypeID() string {
	return "disconnectGroupAuthorization"
}

func (a *disconnectGroupAuthorization) Parameters() []*string {
	return []*string{&a.subjectGroupUUID, action.Ptr(a.authorizationType.String())}
}

func (a *disconnectGroupAuthorization) Init(ctx context.Context, env *action.Environment) {
	subjectGroup, err := action.First[models.GroupGroupable](env.Account1.Client.Group().Get(ctx, &keyhubgroup.GroupRequestBuilderGetRequestConfiguration{
		QueryParameters: &keyhubgroup.GroupRequestBuilderGetQueryParameters{
			Uuid: []string{a.subjectGroupUUID},
		},
	}))
	if err != nil {
		action.Abort(a, "unable to read group with uuid %s: %s", a.subjectGroupUUID, action.KeyHubError(err))
	}
	a.subjectGroup = subjectGroup
}

func (a *disconnectGroupAuthorization) IsSatisfied() bool {
	return findCurrentAuthorizingGroup(a.subjectGroup, a.authorizationType) == nil
}

func (a *disconnectGroupAuthorization) Requires3() bool {
	return false
}

func (a *disconnectGroupAuthorization) AllowGlobalOptimization() bool {
	return false
}

func (a *disconnectGroupAuthorization) Execute(ctx context.Context, env *action.Environment) error {
	groupSet := findCurrentAuthorizingGroup(a.subjectGroup, a.authorizationType)
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
	return nil
}

func (a *disconnectGroupAuthorization) Setup(env *action.Environment) []action.AutomationAction {
	groupSet := findCurrentAuthorizingGroup(a.subjectGroup, a.authorizationType)
	return []action.AutomationAction{
		NewAccountInGroup(*env.Account2.Account.GetUuid(), *groupSet.GetUuid(), action.Ptr(models.MANAGER_GROUPGROUPRIGHTS)),
		NewAccountInGroup(*env.Account1.Account.GetUuid(), a.subjectGroupUUID, action.Ptr(models.MANAGER_GROUPGROUPRIGHTS)),
	}
}

func (*disconnectGroupAuthorization) Perform(env *action.Environment) []action.AutomationAction {
	return make([]action.AutomationAction, 0)
}

func (a *disconnectGroupAuthorization) Revert() action.AutomationAction {
	groupSet := findCurrentAuthorizingGroup(a.subjectGroup, a.authorizationType)
	return NewConnectGroupAuthorization(a.subjectGroupUUID, *groupSet.GetUuid(), a.authorizationType)
}

func (a *disconnectGroupAuthorization) Progress() string {
	subjectGroupName := a.subjectGroupUUID
	if a.subjectGroup != nil {
		subjectGroupName = *a.subjectGroup.GetName()
	}
	return fmt.Sprintf("Stop %s auth. on %s", describe(a.authorizationType), subjectGroupName)
}

func (a *disconnectGroupAuthorization) String() string {
	subjectGroupName := a.subjectGroupUUID
	if a.subjectGroup != nil {
		subjectGroupName = *a.subjectGroup.GetName()
	}

	return fmt.Sprintf("Stop %s authorization on '%s'", describe(a.authorizationType), subjectGroupName)
}
