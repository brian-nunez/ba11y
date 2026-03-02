package authorization

import (
	"github.com/brian-nunez/ba11y/internal/auth"
	baccess "github.com/brian-nunez/baccess"
)

type Subject struct {
	UserID string
	Roles  []string
}

func (s Subject) GetRoles() []string {
	return s.Roles
}

type ScanResource struct {
	OwnerUserID string
}

type ScanAuthorizer struct {
	evaluator *baccess.Evaluator[Subject, ScanResource]
}

func NewScanAuthorizer() *ScanAuthorizer {
	evaluator := baccess.NewEvaluator[Subject, ScanResource]()
	rbac := baccess.NewRBAC[Subject, ScanResource]()

	adminRole := rbac.HasRole("admin")
	userRole := rbac.HasRole("user")
	ownerOnly := baccess.FieldEquals(
		func(subject Subject) string { return subject.UserID },
		func(resource ScanResource) string { return resource.OwnerUserID },
	)

	evaluator.AddPolicy("scans.create", adminRole.Or(userRole))
	evaluator.AddPolicy("scans.list", adminRole.Or(userRole))
	evaluator.AddPolicy("scans.read", adminRole.Or(userRole.And(ownerOnly)))
	evaluator.AddPolicy("scans.cancel", adminRole.Or(userRole.And(ownerOnly)))
	evaluator.AddPolicy("scans.report", adminRole.Or(userRole.And(ownerOnly)))

	return &ScanAuthorizer{evaluator: evaluator}
}

func (a *ScanAuthorizer) Can(user auth.User, resource ScanResource, action string) bool {
	subject := Subject{
		UserID: user.ID,
		Roles:  user.Roles,
	}

	return a.evaluator.Evaluate(baccess.AccessRequest[Subject, ScanResource]{
		Subject:  subject,
		Resource: resource,
		Action:   action,
	})
}
