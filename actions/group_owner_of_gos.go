// Copyright (c) Topicus Security B.V.
// SPDX-License-Identifier: APSL-2.0

package actions

import (
	"context"
	"fmt"
	"log"

	"github.com/topicuskeyhub/automation-framework/action"
	keyhubgroup "github.com/topicuskeyhub/sdk-go/group"
	"github.com/topicuskeyhub/sdk-go/models"
	keyhubsystem "github.com/topicuskeyhub/sdk-go/system"
)

type groupOwnerOfGOS struct {
	systemUUID      string
	gosNameInSystem string
	groupUUID       string
	system          models.ProvisioningProvisionedSystemable
	gos             models.ProvisioningGroupOnSystemable
	group           models.GroupGroupable
}

func NewGroupOwnerOfGOS(systemUUID string, gosNameInSystem string, groupUUID string) action.AutomationAction {
	return &groupOwnerOfGOS{
		systemUUID:      systemUUID,
		gosNameInSystem: gosNameInSystem,
		groupUUID:       groupUUID,
	}
}

func (a *groupOwnerOfGOS) TypeID() string {
	return "groupOwnerOfGOS"
}

func (a *groupOwnerOfGOS) Parameters() []string {
	return []string{a.systemUUID, a.gosNameInSystem, a.groupUUID}
}

func (a *groupOwnerOfGOS) Init(ctx context.Context, env *action.Environment) {
	system, err := action.First[models.ProvisioningProvisionedSystemable](env.Account1.Client.System().Get(ctx, &keyhubsystem.SystemRequestBuilderGetRequestConfiguration{
		QueryParameters: &keyhubsystem.SystemRequestBuilderGetQueryParameters{
			Uuid: []string{a.systemUUID},
		},
	}))
	if err != nil {
		log.Fatalf("unable to read system with uuid %s: %s", a.systemUUID, err)
	}
	a.system = system

	gos, err := action.First[models.ProvisioningGroupOnSystemable](env.Account1.Client.System().
		BySystemidInt64(*action.Self(system).GetId()).Group().Get(ctx, &keyhubsystem.ItemGroupRequestBuilderGetRequestConfiguration{
		QueryParameters: &keyhubsystem.ItemGroupRequestBuilderGetQueryParameters{
			NameInSystem: []string{a.gosNameInSystem},
		},
	}))
	if err != nil {
		log.Fatalf("unable to read group on system with name %s: %s", a.gosNameInSystem, err)
	}
	a.gos = gos

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

}

func (a *groupOwnerOfGOS) IsSatisfied() bool {
	return *a.gos.GetOwner().GetUuid() == a.groupUUID
}

func (a *groupOwnerOfGOS) Execute(ctx context.Context, env *action.Environment) error {
	newTransferOwner := models.NewRequestTransferGroupOnSystemOwnershipRequest()
	newTransferOwner.SetGroupOnSystem(a.gos)
	newTransferOwner.SetGroup(a.group)
	newTransferOwner.SetComment(action.Ptr("automation groupOwnerOfGOS"))
	wrapper := models.NewRequestModificationRequestLinkableWrapper()
	wrapper.SetItems([]models.RequestModificationRequestable{newTransferOwner})
	env.Account1.Client.Request().Post(ctx, wrapper, nil)
	transferOwner, err := action.First[models.RequestModificationRequestable](env.Account1.Client.Request().Post(ctx, wrapper, nil))
	if err != nil {
		return fmt.Errorf("cannot request to transfer group on system ownership in '%s': %s", a.String(), err)
	}

	transferOwner.SetStatus(action.Ptr(models.ALLOWED_REQUESTMODIFICATIONREQUESTSTATUS))
	transferOwner.SetFeedback(action.Ptr("automation groupOwnerOfGOS"))
	transferOwner, err = env.Account2.Client.Request().ByRequestidInt64(*action.Self(transferOwner).GetId()).Put(ctx, transferOwner, nil)
	if err != nil {
		return fmt.Errorf("cannot confirm to transfer group on system ownership in '%s': %s", a.String(), err)
	}
	return nil
}

func (a *groupOwnerOfGOS) Setup(env *action.Environment) []action.AutomationAction {
	return []action.AutomationAction{
		NewAccountInGroup(*env.Account1.Account.GetUuid(), *a.gos.GetOwner().GetUuid(), action.Ptr(models.MANAGER_GROUPGROUPRIGHTS)),
		NewAccountInGroup(*env.Account2.Account.GetUuid(), a.groupUUID, action.Ptr(models.MANAGER_GROUPGROUPRIGHTS)),
	}
}

func (*groupOwnerOfGOS) Perform(env *action.Environment) []action.AutomationAction {
	return make([]action.AutomationAction, 0)
}

func (a *groupOwnerOfGOS) Revert() action.AutomationAction {
	return NewGroupOwnerOfGOS(a.systemUUID, a.gosNameInSystem, *a.gos.GetOwner().GetUuid())
}

func (a *groupOwnerOfGOS) String() string {
	systemName := "unknown"
	if a.system != nil {
		systemName = *a.system.GetName()
	}
	gosName := "unknown"
	if a.gos != nil && a.gos.GetDisplayName() != nil {
		gosName = *a.gos.GetDisplayName()
	}

	groupName := "unknown"
	if a.group != nil {
		groupName = *a.group.GetName()
	}

	return fmt.Sprintf("Ensure ownership of %s (%s) within the system %s (%s) is set to group %s (%s)", a.gosNameInSystem, gosName, a.systemUUID, systemName, a.groupUUID, groupName)
}