package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"regexp"
	"sort"
	"strings"

	"sigs.k8s.io/yaml"

	"github.com/alcideio/rbac-tool/pkg/kube"
	"github.com/alcideio/rbac-tool/pkg/rbac"
	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"
)

type DetailedPolicyRule struct {
	// Like ServiceAccount
	UserKind string
	// Value of UserKind
	UserName             string
	NamespacedPolicyRule rbac.NamespacedPolicyRule
}

// SamePermissionExists checks whether the same permission has been defined for the same user more than once
// Returns boolean to indicate whether it does exist or not and returns the index of the PolicyRule where it was found
// The index is used later to add an element to the Roles or ClusterRoles array
func SamePermissionExists(rows []*DetailedPolicyRule, newRow DetailedPolicyRule) (bool, int) {
	// we sort so we can use DeepEqual on []string
	sort.Strings(newRow.NamespacedPolicyRule.NonResourceURLs)
	sort.Strings(newRow.NamespacedPolicyRule.ResourceNames)
	for i, row := range rows {
		sort.Strings(row.NamespacedPolicyRule.NonResourceURLs)
		sort.Strings(row.NamespacedPolicyRule.ResourceNames)
		if row.NamespacedPolicyRule.APIGroup == newRow.NamespacedPolicyRule.APIGroup &&
			row.NamespacedPolicyRule.Namespace == newRow.NamespacedPolicyRule.Namespace &&
			reflect.DeepEqual(row.NamespacedPolicyRule.NonResourceURLs, newRow.NamespacedPolicyRule.NonResourceURLs) &&
			row.NamespacedPolicyRule.Resource == newRow.NamespacedPolicyRule.Resource &&
			reflect.DeepEqual(row.NamespacedPolicyRule.ResourceNames, newRow.NamespacedPolicyRule.ResourceNames) &&
			row.NamespacedPolicyRule.Verb == newRow.NamespacedPolicyRule.Verb &&
			row.UserName == newRow.UserName && row.UserKind == newRow.UserKind {
			return true, i
		}
	}
	return false, -1
}

func NewCommandPolicyRules() *cobra.Command {

	clusterContext := ""
	regex := ""
	inverse := false
	output := "table"
	// Support overrides
	cmd := &cobra.Command{
		Use:     "policy-rules",
		Aliases: []string{"rules", "rule", "policy", "pr"},
		Short:   "RBAC List Policy Rules For subject (user/group/serviceaccount) name",
		Long: `
List Kubernetes RBAC policy rules for a given User/ServiceAccount/Group

Examples:

# Search All Service Accounts
rbac-tool policy-rules -e '.*'

# Search All Service Accounts that contain myname
rbac-tool policy-rules -e '.*myname.*'

# Lookup System Accounts (all accounts that start with system: )
rbac-tool policy-rules -e '^system:.*'

# Lookup all accounts that DO NOT start with system: )
rbac-tool policy-rules -ne '^system:.*'

# Leveraging jmespath for further filtering and implementing who-can
rbac-tool policy-rules -o json  | jp "[? @.allowedTo[? (verb=='get' || verb=='*') && (apiGroup=='core' || apiGroup=='*') && (resource=='secrets' || resource == '*')  ]].{name: name, namespace: namespace, kind: kind}"

`,
		Hidden: false,
		RunE: func(c *cobra.Command, args []string) error {
			var re *regexp.Regexp
			var err error

			if regex != "" {
				re, err = regexp.Compile(regex)
			} else {
				if len(args) != 1 {
					re, err = regexp.Compile(fmt.Sprintf(`.*`))
				} else {
					re, err = regexp.Compile(fmt.Sprintf(`(?mi)%v`, args[0]))
				}
			}

			if err != nil {
				return err
			}

			client, err := kube.NewClient(clusterContext)
			if err != nil {
				return fmt.Errorf("Failed to create kubernetes client - %v", err)
			}

			perms, err := rbac.NewPermissionsFromCluster(client)
			if err != nil {
				return err
			}

			policies := rbac.NewSubjectPermissions(perms)
			filteredPolicies := []rbac.SubjectPermissions{}
			for _, policy := range policies {
				match := re.MatchString(policy.Subject.Name)

				//  match    inverse
				//  -----------------
				//  true     true   --> skip
				//  true     false  --> keep
				//  false    true   --> keep
				//  false    false  --> skip
				if match {
					if inverse {
						continue
					}
				} else {
					if !inverse {
						continue
					}
				}

				filteredPolicies = append(filteredPolicies, policy)
			}

			switch output {
			case "table":
				rows := [][]string{}

				policies := rbac.NewSubjectPermissionsList(filteredPolicies)
				// added accumulates PolicyRules and Roles/ClusterRoles
				added := []*DetailedPolicyRule{}
				for _, p := range policies {
					for _, allowedTo := range p.AllowedTo {
						notNew, index := SamePermissionExists(added, DetailedPolicyRule{UserKind: p.Kind, UserName: p.Name, NamespacedPolicyRule: allowedTo})
						if notNew {
							// if SamePermission exist -> add value to Roles or ClusterRoles (effectively only one will be added in an iteration)
							added[index].NamespacedPolicyRule.Roles = append(added[index].NamespacedPolicyRule.Roles, allowedTo.Roles...)
							added[index].NamespacedPolicyRule.ClusterRoles = append(added[index].NamespacedPolicyRule.ClusterRoles, allowedTo.ClusterRoles...)
							continue
						}
						added = append(added, &DetailedPolicyRule{NamespacedPolicyRule: allowedTo, UserName: p.Name, UserKind: p.Kind})
					}
				}
				// added is used to build the rows table that will be used in rendering
				for _, add := range added {
					row := []string{
						add.UserKind,
						add.UserName,
						add.NamespacedPolicyRule.Verb,
						add.NamespacedPolicyRule.Namespace,
						add.NamespacedPolicyRule.APIGroup,
						add.NamespacedPolicyRule.Resource,
						strings.Join(add.NamespacedPolicyRule.ResourceNames, ","),
						strings.Join(add.NamespacedPolicyRule.NonResourceURLs, ","),
						strings.Join(add.NamespacedPolicyRule.Roles, ","),
						strings.Join(add.NamespacedPolicyRule.ClusterRoles, ","),
					}

					rows = append(rows, row)
				}

				sort.Slice(rows, func(i, j int) bool {
					if strings.Compare(rows[i][0], rows[j][0]) == 0 {
						return (strings.Compare(rows[i][1], rows[j][1]) < 0)
					}

					return (strings.Compare(rows[i][0], rows[j][0]) < 0)
				})

				table := tablewriter.NewWriter(os.Stdout)
				table.SetHeader([]string{"TYPE", "SUBJECT", "VERBS", "NAMESPACE", "API GROUP", "KIND", "NAMES", "NonResourceURI", "Roles", "ClusterRoles"})
				table.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
				table.SetBorder(false)
				table.SetAlignment(tablewriter.ALIGN_LEFT)
				//table.SetAutoMergeCells(true)

				table.AppendBulk(rows)
				table.Render()

				return nil
			case "yaml":
				policies := rbac.NewSubjectPermissionsList(filteredPolicies)
				data, err := yaml.Marshal(&policies)
				if err != nil {
					return fmt.Errorf("Processing error - %v", err)
				}
				fmt.Println(string(data))
				return nil

			case "json":
				policies := rbac.NewSubjectPermissionsList(filteredPolicies)

				data, err := json.Marshal(&policies)
				if err != nil {
					return fmt.Errorf("Processing error - %v", err)
				}

				fmt.Println(string(data))
				return nil

			default:
				return fmt.Errorf("Unsupported output format")
			}
		},
	}

	flags := cmd.Flags()
	flags.StringVar(&clusterContext, "cluster-context", "", "Cluster Context .use 'kubectl config get-contexts' to list available contexts")
	flags.StringVarP(&output, "output", "o", "table", "Output type: table | json | yaml")

	flags.StringVarP(&regex, "regex", "e", "", "Specify whether run the lookup using a regex match")
	flags.BoolVarP(&inverse, "not", "n", false, "Inverse the regex matching. Use to search for users that do not match '^system:.*'")
	return cmd
}
