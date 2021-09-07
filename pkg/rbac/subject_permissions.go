package rbac

import (
	"sort"
	"strings"

	v1 "k8s.io/api/rbac/v1"
	"k8s.io/klog"
)

type DetailedPolicyRule struct {
	// Holds the rule itself
	PolicyRule v1.PolicyRule
	//One of theses variables will be set and the other will be empty
	//Can maybe use one variable instead and use a prefix to say it's a ClusterRole but this will require parsing later on to know if its a role or a clusterrole
	Role        string
	ClusterRole string
}

type SubjectPermissions struct {
	Subject v1.Subject

	//Rules Per Namespace ... "" means cluster-wide
	Rules map[string][]DetailedPolicyRule
}

func NewSubjectPermissions(perms *Permissions) []SubjectPermissions {
	subjects := map[string]*SubjectPermissions{}

	for _, bindings := range perms.RoleBindings {
		for _, binding := range bindings {
			for _, subject := range binding.Subjects {
				var exist bool
				var subPerms *SubjectPermissions

				ns := binding.Namespace
				if strings.ToLower(binding.RoleRef.Kind) == "clusterrole" {
					ns = ""
				}

				roles, exist := perms.Roles[ns]
				if !exist {
					klog.V(6).Infof("%+v didn't find roles for namespace '%v'", binding, ns)
					continue
				}

				role, exist := roles[binding.RoleRef.Name]
				if !exist {
					klog.V(6).Infof("%+v didn't find role '%v' in '%v'", binding, binding.RoleRef.Name, ns)
					continue
				}

				sub := subject.String()
				subPerms, exist = subjects[sub]

				if !exist {
					subPerms = &SubjectPermissions{
						Subject: subject,
						Rules:   map[string][]DetailedPolicyRule{},
					}
				}

				rules, exist := subPerms.Rules[binding.Namespace]
				if !exist {
					rules = []DetailedPolicyRule{}
				}

				//klog.V(6).Infof("%+v --add-- %v %v", subject, len(rules), len(role.Rules))

				for _, rule := range role.Rules {
					if ns == "" {
						rules = append(rules, DetailedPolicyRule{PolicyRule: rule, ClusterRole: role.Name})
					} else {
						rules = append(rules, DetailedPolicyRule{PolicyRule: rule, Role: role.Name})
					}
				}

				subPerms.Rules[binding.Namespace] = rules
				subjects[sub] = subPerms
			}
		}
	}

	res := []SubjectPermissions{}
	for _, v := range subjects {
		res = append(res, *v)
	}

	return res
}

func ReplaceToWildCard(l []string) {
	for i, _ := range l {
		if l[i] == "" {
			l[i] = "*"
		}
	}
}

func ReplaceToCore(l []string) {
	for i, _ := range l {
		if l[i] == "" {
			l[i] = "core"
		}
	}
}

type NamespacedPolicyRule struct {
	Namespace string `json:"namespace,omitempty"`

	// Verbs is a list of Verbs that apply to ALL the ResourceKinds and AttributeRestrictions contained in this rule.  VerbAll represents all kinds.
	Verb string `json:"verb"`

	// The name of the APIGroup that contains the resources.
	APIGroup string `json:"apiGroup,omitempty"`

	// Resources is a list of resources this rule applies to.  ResourceAll represents all resources.
	Resource string `json:"resource,omitempty"`

	// ResourceNames is an optional white list of names that the rule applies to.  An empty set means that everything is allowed.
	ResourceNames []string `json:"resourceNames,omitempty"`

	// NonResourceURLs is a set of partial urls that a user should have access to.  *s are allowed, but only as the full, final step in the path
	// Since non-resource URLs are not namespaced, this field is only applicable for ClusterRoles referenced from a ClusterRoleBinding.
	NonResourceURLs []string `json:"nonResourceURLs,omitempty"`

	// Source Roles: list of roles that give this permission.
	// When initialized it contains 0 or 1 element. More elements can be added through compaction like in policy-rules
	Roles []string `json:"roles,omitempty"`

	// Source ClusterRoles: list of roles that give this permission.
	// When initialized it contains 0 or 1 element. More elements can be added through compaction like in policy-rules
	ClusterRoles []string `json:"clusterRoles,omitempty"`
}

type SubjectPolicyList struct {
	v1.Subject

	AllowedTo []NamespacedPolicyRule `json:"allowedTo,omitempty"`
}

func NewSubjectPermissionsList(policies []SubjectPermissions) []SubjectPolicyList {
	subjectPolicyList := []SubjectPolicyList{}

	for _, p := range policies {
		nsrules := []NamespacedPolicyRule{}
		for namespace, rules := range p.Rules {
			if namespace == "" {
				namespace = "*"
			}

			for _, rule := range rules {
				//Normalize the strings
				ReplaceToCore(rule.PolicyRule.APIGroups)
				ReplaceToWildCard(rule.PolicyRule.Resources)
				ReplaceToWildCard(rule.PolicyRule.ResourceNames)
				ReplaceToWildCard(rule.PolicyRule.Verbs)
				ReplaceToWildCard(rule.PolicyRule.NonResourceURLs)

				sort.Strings(rule.PolicyRule.APIGroups)
				sort.Strings(rule.PolicyRule.Resources)
				sort.Strings(rule.PolicyRule.ResourceNames)
				sort.Strings(rule.PolicyRule.Verbs)
				sort.Strings(rule.PolicyRule.NonResourceURLs)
				for _, verb := range rule.PolicyRule.Verbs {

					if len(rule.PolicyRule.NonResourceURLs) == 0 {
						// The common case ... let's flatten the rule
						for _, apiGroup := range rule.PolicyRule.APIGroups {
							for _, resource := range rule.PolicyRule.Resources {
								subjectPolicy := NamespacedPolicyRule{
									Namespace:       namespace,
									Verb:            verb,
									APIGroup:        apiGroup,
									Resource:        resource,
									ResourceNames:   rule.PolicyRule.ResourceNames,
									NonResourceURLs: rule.PolicyRule.NonResourceURLs,
								}
								// testing if it's empty prevents from adding empty values that will later need removal
								if rule.Role != "" {
									subjectPolicy.Roles = []string{rule.Role}
								}
								if rule.ClusterRole != "" {
									subjectPolicy.ClusterRoles = []string{rule.ClusterRole}
								}
								nsrules = append(nsrules, subjectPolicy)
							}

						}
					} else {
						// NonResourceURL ... not namespaced
						subjectPolicy := NamespacedPolicyRule{
							Namespace:       namespace,
							Verb:            verb,
							NonResourceURLs: rule.PolicyRule.NonResourceURLs,
						}
						if rule.Role != "" {
							subjectPolicy.Roles = []string{rule.Role}
						}
						if rule.ClusterRole != "" {
							subjectPolicy.ClusterRoles = []string{rule.ClusterRole}
						}
						nsrules = append(nsrules, subjectPolicy)
					}
				}
			}
		}
		subjectPolicyList = append(
			subjectPolicyList, SubjectPolicyList{
				Subject:   p.Subject,
				AllowedTo: nsrules,
			})
	}

	return subjectPolicyList
}
