package actions

import (
	"context"
	"fmt"

	"github.com/topicuskeyhub/automation-framework/action"
	"github.com/topicuskeyhub/sdk-go/models"
)

func submitAndAccept(ctx context.Context, request models.RequestModificationRequestable, requester *action.AuthenticatedAccount, accepter *action.AuthenticatedAccount) error {
	wrapper := models.NewRequestModificationRequestLinkableWrapper()
	wrapper.SetItems([]models.RequestModificationRequestable{request})
	r, err := action.First[models.RequestModificationRequestable](requester.Client.Request().Post(ctx, wrapper, nil))
	if err != nil {
		return fmt.Errorf("cannot submit request: %s", action.KeyHubError(err))
	}

	r.SetStatus(action.Ptr(models.ALLOWED_REQUESTMODIFICATIONREQUESTSTATUS))
	r.SetFeedback(request.GetComment())
	_, err = accepter.Client.Request().ByRequestidInt64(*action.Self(r).GetId()).Put(ctx, r, nil)
	if err != nil {
		return fmt.Errorf("cannot handle request: %s", action.KeyHubError(err))
	}
	return nil
}

func findCurrentAuthorizingGroup(subject models.GroupGroupable, authType models.RequestAuthorizingGroupType) models.GroupGroupPrimerable {
	switch authType {
	case models.AUDITING_REQUESTAUTHORIZINGGROUPTYPE:
		return subject.GetAuthorizingGroupAuditing()
	case models.DELEGATION_REQUESTAUTHORIZINGGROUPTYPE:
		return subject.GetAuthorizingGroupDelegation()
	case models.MEMBERSHIP_REQUESTAUTHORIZINGGROUPTYPE:
		return subject.GetAuthorizingGroupMembership()
	case models.PROVISIONING_REQUESTAUTHORIZINGGROUPTYPE:
		return subject.GetAuthorizingGroupProvisioning()
	}
	panic("Invalid value")
}

func describe(authType models.RequestAuthorizingGroupType) string {
	switch authType {
	case models.AUDITING_REQUESTAUTHORIZINGGROUPTYPE:
		return "auditing"
	case models.DELEGATION_REQUESTAUTHORIZINGGROUPTYPE:
		return "delegation"
	case models.MEMBERSHIP_REQUESTAUTHORIZINGGROUPTYPE:
		return "membership"
	case models.PROVISIONING_REQUESTAUTHORIZINGGROUPTYPE:
		return "provisioning"
	}
	panic("Invalid value")
}
