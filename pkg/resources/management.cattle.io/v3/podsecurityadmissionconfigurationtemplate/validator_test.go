package podsecurityadmissionconfigurationtemplate

import (
	"encoding/json"
	"fmt"
	"testing"

	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	provv1 "github.com/rancher/rancher/pkg/apis/provisioning.cattle.io/v1"
	"github.com/rancher/webhook/pkg/admission"
	"github.com/rancher/wrangler/v3/pkg/generic/fake"
	"go.uber.org/mock/gomock"
	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/pod-security-admission/api"
)

type validationTest struct {
	testName    string
	template    *v3.PodSecurityAdmissionConfigurationTemplate
	wantAllowed bool
}

type deleteTest struct {
	testName    string
	template    *v3.PodSecurityAdmissionConfigurationTemplate
	wantAllowed bool
}

var (
	validationTests []validationTest
	deleteTests     []deleteTest
	validator       Validator
)

func TestAdmit(t *testing.T) {
	ctrl := gomock.NewController(t)
	mgmtCache := fake.NewMockNonNamespacedCacheInterface[*v3.Cluster](ctrl)
	provCache := fake.NewMockCacheInterface[*provv1.Cluster](ctrl)

	mgmtCache.EXPECT().GetByIndex(gomock.Any(), gomock.AssignableToTypeOf("")).DoAndReturn(func(_, key string) ([]*v3.Cluster, error) {
		x := []*v3.Cluster{
			{
				Spec: v3.ClusterSpec{
					DisplayName: "validationTest-cluster",
					ClusterSpecBase: v3.ClusterSpecBase{
						DefaultPodSecurityAdmissionConfigurationTemplateName: "mgmttesting",
					},
				},
			},
		}
		if key != "mgmttesting" {
			return nil, nil
		}
		return x, nil
	}).AnyTimes()

	provCache.EXPECT().GetByIndex(gomock.Any(), gomock.AssignableToTypeOf("")).DoAndReturn(func(_, key string) ([]*provv1.Cluster, error) {
		x := []*provv1.Cluster{
			{
				Spec: provv1.ClusterSpec{
					DefaultPodSecurityAdmissionConfigurationTemplateName: "provtesting",
				},
			},
		}
		if key != "provtesting" {
			return nil, nil
		}
		return x, nil
	}).AnyTimes()

	validator = Validator{
		admitter: admitter{
			ManagementClusterCache:   mgmtCache,
			provisioningClusterCache: provCache,
		},
	}
	validConfiguration := v3.PodSecurityAdmissionConfigurationTemplateSpec{
		Defaults: v3.PodSecurityAdmissionConfigurationTemplateDefaults{
			Enforce:        string(api.LevelPrivileged),
			EnforceVersion: "v1.25",
			Audit:          string(api.LevelBaseline),
			AuditVersion:   "v1.25",
			Warn:           string(api.LevelBaseline),
			WarnVersion:    "v1.25",
		},
		Exemptions: v3.PodSecurityAdmissionConfigurationTemplateExemptions{
			Usernames:      nil,
			RuntimeClasses: nil,
			Namespaces:     nil,
		},
	}

	deleteTests = []deleteTest{
		{
			testName: "cannot delete built-in template",
			template: &v3.PodSecurityAdmissionConfigurationTemplate{
				TypeMeta: metav1.TypeMeta{},
				ObjectMeta: metav1.ObjectMeta{
					Name: rancherRestrictedPSACTName,
				},
				Description:   "",
				Configuration: validConfiguration,
			},
			wantAllowed: false,
		},
		{
			testName: "cannot delete built-in template",
			template: &v3.PodSecurityAdmissionConfigurationTemplate{
				TypeMeta: metav1.TypeMeta{},
				ObjectMeta: metav1.ObjectMeta{
					Name: rancherPrivilegedPSACTName,
				},
				Description:   "",
				Configuration: validConfiguration,
			},
			wantAllowed: false,
		},
		{
			testName: "cannot delete template used by management cluster",
			template: &v3.PodSecurityAdmissionConfigurationTemplate{
				TypeMeta: metav1.TypeMeta{},
				ObjectMeta: metav1.ObjectMeta{
					Name: "mgmttesting",
				},
				Description:   "",
				Configuration: validConfiguration,
			},
			wantAllowed: false,
		},
		{
			testName: "cannot delete template used by provisioning cluster",
			template: &v3.PodSecurityAdmissionConfigurationTemplate{
				TypeMeta: metav1.TypeMeta{},
				ObjectMeta: metav1.ObjectMeta{
					Name: "provtesting",
				},
				Description:   "",
				Configuration: validConfiguration,
			},
			wantAllowed: false,
		},
		{
			testName: "successfully delete a template",
			template: &v3.PodSecurityAdmissionConfigurationTemplate{
				TypeMeta: metav1.TypeMeta{},
				ObjectMeta: metav1.ObjectMeta{
					Name: "testing",
				},
				Description:   "",
				Configuration: validConfiguration,
			},
			wantAllowed: true,
		},
	}
	validationTests = []validationTest{
		{
			testName: "Completely Valid Template Test",
			template: &v3.PodSecurityAdmissionConfigurationTemplate{
				Description: "a valid test template",
				Configuration: v3.PodSecurityAdmissionConfigurationTemplateSpec{
					Defaults: v3.PodSecurityAdmissionConfigurationTemplateDefaults{
						Enforce:        string(api.LevelPrivileged),
						EnforceVersion: "v1.25",
						Audit:          string(api.LevelBaseline),
						AuditVersion:   "v1.25",
						Warn:           string(api.LevelBaseline),
						WarnVersion:    "v1.25",
					},
					Exemptions: v3.PodSecurityAdmissionConfigurationTemplateExemptions{
						Usernames:      nil,
						RuntimeClasses: nil,
						Namespaces:     nil,
					},
				},
			},
			wantAllowed: true,
		},
		{
			testName: "Completely Valid Template Test With a Level And Version Omitted",
			template: &v3.PodSecurityAdmissionConfigurationTemplate{
				Description: "a valid test template",
				Configuration: v3.PodSecurityAdmissionConfigurationTemplateSpec{
					Defaults: v3.PodSecurityAdmissionConfigurationTemplateDefaults{
						Enforce:        "",
						EnforceVersion: "",
						Audit:          string(api.LevelBaseline),
						AuditVersion:   "v1.25",
						Warn:           string(api.LevelBaseline),
						WarnVersion:    "v1.25",
					},
					Exemptions: v3.PodSecurityAdmissionConfigurationTemplateExemptions{
						Usernames:      nil,
						RuntimeClasses: nil,
						Namespaces:     nil,
					},
				},
			},
			wantAllowed: true,
		},
		{
			testName: "Completely Valid Template Test With a Level Omitted",
			template: &v3.PodSecurityAdmissionConfigurationTemplate{
				Description: "a valid test template",
				Configuration: v3.PodSecurityAdmissionConfigurationTemplateSpec{
					Defaults: v3.PodSecurityAdmissionConfigurationTemplateDefaults{
						Enforce:        "",
						EnforceVersion: "v1.25",
						Audit:          string(api.LevelBaseline),
						AuditVersion:   "v1.25",
						Warn:           string(api.LevelBaseline),
						WarnVersion:    "v1.25",
					},
					Exemptions: v3.PodSecurityAdmissionConfigurationTemplateExemptions{
						Usernames:      nil,
						RuntimeClasses: nil,
						Namespaces:     nil,
					},
				},
			},
			wantAllowed: true,
		},
		{
			testName: "Completely Valid Template Test With a Version Omitted",
			template: &v3.PodSecurityAdmissionConfigurationTemplate{
				Description: "a valid test template",
				Configuration: v3.PodSecurityAdmissionConfigurationTemplateSpec{
					Defaults: v3.PodSecurityAdmissionConfigurationTemplateDefaults{
						Enforce:        string(api.LevelBaseline),
						EnforceVersion: "",
						Audit:          string(api.LevelBaseline),
						AuditVersion:   "v1.25",
						Warn:           string(api.LevelBaseline),
						WarnVersion:    "v1.25",
					},
					Exemptions: v3.PodSecurityAdmissionConfigurationTemplateExemptions{
						Usernames:      nil,
						RuntimeClasses: nil,
						Namespaces:     nil,
					},
				},
			},
			wantAllowed: true,
		},
		{
			testName: "Ensure a bad enforce level is caught",
			template: &v3.PodSecurityAdmissionConfigurationTemplate{
				Description: "a test template",
				Configuration: v3.PodSecurityAdmissionConfigurationTemplateSpec{
					Defaults: v3.PodSecurityAdmissionConfigurationTemplateDefaults{
						Enforce:        "badlevel",
						EnforceVersion: "v1.25",
						Audit:          string(api.LevelBaseline),
						AuditVersion:   "v1.25",
						Warn:           string(api.LevelBaseline),
						WarnVersion:    "v1.25",
					},
					Exemptions: v3.PodSecurityAdmissionConfigurationTemplateExemptions{
						Usernames:      nil,
						RuntimeClasses: nil,
						Namespaces:     nil,
					},
				},
			},
			wantAllowed: false,
		},
		{
			testName: "Ensure a bad enforce version is caught",
			template: &v3.PodSecurityAdmissionConfigurationTemplate{
				Description: "a test template",
				Configuration: v3.PodSecurityAdmissionConfigurationTemplateSpec{
					Defaults: v3.PodSecurityAdmissionConfigurationTemplateDefaults{
						Enforce:        string(api.LevelBaseline),
						EnforceVersion: "not-a-valid-version",
						Audit:          string(api.LevelBaseline),
						AuditVersion:   "v1.25",
						Warn:           string(api.LevelBaseline),
						WarnVersion:    "v1.25",
					},
					Exemptions: v3.PodSecurityAdmissionConfigurationTemplateExemptions{
						Usernames:      nil,
						RuntimeClasses: nil,
						Namespaces:     nil,
					},
				},
			},
			wantAllowed: false,
		},
		{
			testName: "Ensure a bad audit level is caught",
			template: &v3.PodSecurityAdmissionConfigurationTemplate{
				Description: "a test template",
				Configuration: v3.PodSecurityAdmissionConfigurationTemplateSpec{
					Defaults: v3.PodSecurityAdmissionConfigurationTemplateDefaults{
						Enforce:        string(api.LevelBaseline),
						EnforceVersion: "v1.25",
						Audit:          "badlevel",
						AuditVersion:   "v1.25",
						Warn:           string(api.LevelBaseline),
						WarnVersion:    "v1.25",
					},
					Exemptions: v3.PodSecurityAdmissionConfigurationTemplateExemptions{
						Usernames:      nil,
						RuntimeClasses: nil,
						Namespaces:     nil,
					},
				},
			},
			wantAllowed: false,
		},
		{
			testName: "Ensure a bad enforce version is caught",
			template: &v3.PodSecurityAdmissionConfigurationTemplate{
				Description: "a test template",
				Configuration: v3.PodSecurityAdmissionConfigurationTemplateSpec{
					Defaults: v3.PodSecurityAdmissionConfigurationTemplateDefaults{
						Enforce:        string(api.LevelBaseline),
						EnforceVersion: "v1.25",
						Audit:          string(api.LevelBaseline),
						AuditVersion:   "not-a-valid-version",
						Warn:           string(api.LevelBaseline),
						WarnVersion:    "v1.25",
					},
					Exemptions: v3.PodSecurityAdmissionConfigurationTemplateExemptions{
						Usernames:      nil,
						RuntimeClasses: nil,
						Namespaces:     nil,
					},
				},
			},
			wantAllowed: false,
		},
		{
			testName: "Ensure a bad warn level is caught",
			template: &v3.PodSecurityAdmissionConfigurationTemplate{
				Description: "a test template",
				Configuration: v3.PodSecurityAdmissionConfigurationTemplateSpec{
					Defaults: v3.PodSecurityAdmissionConfigurationTemplateDefaults{
						Enforce:        string(api.LevelBaseline),
						EnforceVersion: "v1.25",
						Audit:          string(api.LevelBaseline),
						AuditVersion:   "v1.25",
						Warn:           "bad version",
						WarnVersion:    "v1.25",
					},
					Exemptions: v3.PodSecurityAdmissionConfigurationTemplateExemptions{
						Usernames:      nil,
						RuntimeClasses: nil,
						Namespaces:     nil,
					},
				},
			},
			wantAllowed: false,
		},
		{
			testName: "Ensure a bad enforce version is caught",
			template: &v3.PodSecurityAdmissionConfigurationTemplate{
				Description: "a test template",
				Configuration: v3.PodSecurityAdmissionConfigurationTemplateSpec{
					Defaults: v3.PodSecurityAdmissionConfigurationTemplateDefaults{
						Enforce:        string(api.LevelBaseline),
						EnforceVersion: "v1.25",
						Audit:          string(api.LevelBaseline),
						AuditVersion:   "v1.25",
						Warn:           string(api.LevelBaseline),
						WarnVersion:    "not-a-valid-version",
					},
					Exemptions: v3.PodSecurityAdmissionConfigurationTemplateExemptions{
						Usernames:      nil,
						RuntimeClasses: nil,
						Namespaces:     nil,
					},
				},
			},
			wantAllowed: false,
		},
		{
			testName: "Ensure a duplicate username is caught",
			template: &v3.PodSecurityAdmissionConfigurationTemplate{
				Description: "a test template",
				Configuration: v3.PodSecurityAdmissionConfigurationTemplateSpec{
					Defaults: v3.PodSecurityAdmissionConfigurationTemplateDefaults{
						Enforce:        string(api.LevelBaseline),
						EnforceVersion: "v1.25",
						Audit:          string(api.LevelBaseline),
						AuditVersion:   "v1.25",
						Warn:           string(api.LevelBaseline),
						WarnVersion:    "v1.25",
					},
					Exemptions: v3.PodSecurityAdmissionConfigurationTemplateExemptions{
						Usernames: []string{
							"user1",
							"user1",
						},
						RuntimeClasses: nil,
						Namespaces:     nil,
					},
				},
			},
			wantAllowed: false,
		},
		{
			testName: "Ensure an empty username is caught",
			template: &v3.PodSecurityAdmissionConfigurationTemplate{
				Description: "a test template",
				Configuration: v3.PodSecurityAdmissionConfigurationTemplateSpec{
					Defaults: v3.PodSecurityAdmissionConfigurationTemplateDefaults{
						Enforce:        string(api.LevelBaseline),
						EnforceVersion: "v1.25",
						Audit:          string(api.LevelBaseline),
						AuditVersion:   "v1.25",
						Warn:           string(api.LevelBaseline),
						WarnVersion:    "v1.25",
					},
					Exemptions: v3.PodSecurityAdmissionConfigurationTemplateExemptions{
						Usernames:      []string{""},
						RuntimeClasses: nil,
						Namespaces:     nil,
					},
				},
			},
			wantAllowed: false,
		},
		{
			testName: "Ensure a bad runtimeClass is caught",
			template: &v3.PodSecurityAdmissionConfigurationTemplate{
				Description: "a test template",
				Configuration: v3.PodSecurityAdmissionConfigurationTemplateSpec{
					Defaults: v3.PodSecurityAdmissionConfigurationTemplateDefaults{
						Enforce:        string(api.LevelBaseline),
						EnforceVersion: "v1.25",
						Audit:          string(api.LevelBaseline),
						AuditVersion:   "v1.25",
						Warn:           string(api.LevelBaseline),
						WarnVersion:    "v1.25",
					},
					Exemptions: v3.PodSecurityAdmissionConfigurationTemplateExemptions{
						Usernames:      nil,
						RuntimeClasses: []string{"-notadnssubdomain"},
						Namespaces:     nil,
					},
				},
			},
			wantAllowed: false,
		},
		{
			testName: "Ensure a duplicate runtimeClass is caught",
			template: &v3.PodSecurityAdmissionConfigurationTemplate{
				Description: "a test template",
				Configuration: v3.PodSecurityAdmissionConfigurationTemplateSpec{
					Defaults: v3.PodSecurityAdmissionConfigurationTemplateDefaults{
						Enforce:        string(api.LevelBaseline),
						EnforceVersion: "v1.25",
						Audit:          string(api.LevelBaseline),
						AuditVersion:   "v1.25",
						Warn:           string(api.LevelBaseline),
						WarnVersion:    "v1.25",
					},
					Exemptions: v3.PodSecurityAdmissionConfigurationTemplateExemptions{
						Usernames:      nil,
						RuntimeClasses: []string{"testruntime", "testruntime"},
						Namespaces:     nil,
					},
				},
			},
			wantAllowed: false,
		},
		{
			testName: "Ensure a valid runtimeClass is accepted",
			template: &v3.PodSecurityAdmissionConfigurationTemplate{
				Description: "a test template",
				Configuration: v3.PodSecurityAdmissionConfigurationTemplateSpec{
					Defaults: v3.PodSecurityAdmissionConfigurationTemplateDefaults{
						Enforce:        string(api.LevelBaseline),
						EnforceVersion: "v1.25",
						Audit:          string(api.LevelBaseline),
						AuditVersion:   "v1.25",
						Warn:           string(api.LevelBaseline),
						WarnVersion:    "v1.25",
					},
					Exemptions: v3.PodSecurityAdmissionConfigurationTemplateExemptions{
						Usernames:      nil,
						RuntimeClasses: []string{"runtime.class"},
						Namespaces:     nil,
					},
				},
			},
			wantAllowed: true,
		},
		{
			testName: "Ensure empty namespaces slice is caught",
			template: &v3.PodSecurityAdmissionConfigurationTemplate{
				Description: "a test template",
				Configuration: v3.PodSecurityAdmissionConfigurationTemplateSpec{
					Defaults: v3.PodSecurityAdmissionConfigurationTemplateDefaults{
						Enforce:        string(api.LevelBaseline),
						EnforceVersion: "v1.25",
						Audit:          string(api.LevelBaseline),
						AuditVersion:   "v1.25",
						Warn:           string(api.LevelBaseline),
						WarnVersion:    "v1.25",
					},
					Exemptions: v3.PodSecurityAdmissionConfigurationTemplateExemptions{
						Usernames:      nil,
						RuntimeClasses: nil,
						Namespaces:     []string{""},
					},
				},
			},
			wantAllowed: false,
		},
		{
			testName: "Ensure invalid namespace is caught",
			template: &v3.PodSecurityAdmissionConfigurationTemplate{
				Description: "a test template",
				Configuration: v3.PodSecurityAdmissionConfigurationTemplateSpec{
					Defaults: v3.PodSecurityAdmissionConfigurationTemplateDefaults{
						Enforce:        string(api.LevelBaseline),
						EnforceVersion: "v1.25",
						Audit:          string(api.LevelBaseline),
						AuditVersion:   "v1.25",
						Warn:           string(api.LevelBaseline),
						WarnVersion:    "v1.25",
					},
					Exemptions: v3.PodSecurityAdmissionConfigurationTemplateExemptions{
						Usernames:      nil,
						RuntimeClasses: nil,
						Namespaces:     []string{"-badnamespace"},
					},
				},
			},
			wantAllowed: false,
		},
		{
			testName: "Ensure duplicate namespaces are caught",
			template: &v3.PodSecurityAdmissionConfigurationTemplate{
				Description: "a test template",
				Configuration: v3.PodSecurityAdmissionConfigurationTemplateSpec{
					Defaults: v3.PodSecurityAdmissionConfigurationTemplateDefaults{
						Enforce:        string(api.LevelBaseline),
						EnforceVersion: "v1.25",
						Audit:          string(api.LevelBaseline),
						AuditVersion:   "v1.25",
						Warn:           string(api.LevelBaseline),
						WarnVersion:    "v1.25",
					},
					Exemptions: v3.PodSecurityAdmissionConfigurationTemplateExemptions{
						Usernames:      nil,
						RuntimeClasses: nil,
						Namespaces:     []string{"namespaceone", "namespaceone"},
					},
				},
			},
			wantAllowed: false,
		},
		{
			testName: "Catch many errors",
			template: &v3.PodSecurityAdmissionConfigurationTemplate{
				Description: "a test template",
				Configuration: v3.PodSecurityAdmissionConfigurationTemplateSpec{
					Defaults: v3.PodSecurityAdmissionConfigurationTemplateDefaults{
						Enforce:        "notvalid",
						EnforceVersion: "reallynotvalid",
						Audit:          string(api.LevelBaseline),
						AuditVersion:   "v1.25",
						Warn:           string(api.LevelBaseline),
						WarnVersion:    "v1.25",
					},
					Exemptions: v3.PodSecurityAdmissionConfigurationTemplateExemptions{
						Usernames:      []string{""},
						RuntimeClasses: []string{"supernotvalid"},
						Namespaces:     []string{"namespaceone", "namespaceone", "--!incrediblyInvalid"},
					},
				},
			},
			wantAllowed: false,
		},
	}

	for _, testcase := range deleteTests {
		t.Run(testcase.testName, func(t *testing.T) {
			req, err := createRequest(testcase.template, admissionv1.Delete)
			if err != nil {
				t.Log(fmt.Errorf("failed to create DELETE request for PodSecurityAdmissionConfigurationTemplate object: %w", err))
				t.Fail()
			}
			admitters := validator.Admitters()
			if len(admitters) != 1 {
				t.Logf("wanted only one admitter but got = %d", len(admitters))
			}
			resp, _ := admitters[0].Admit(&req)
			if resp.Allowed != testcase.wantAllowed {
				t.Logf("wanted allowed = %t, got allowed = %t", testcase.wantAllowed, resp.Allowed)
				t.Fail()
			}
		})
	}

	for _, testcase := range validationTests {
		t.Run(testcase.testName, func(t *testing.T) {
			req, err := createRequest(testcase.template, admissionv1.Create)
			if err != nil {
				t.Log(fmt.Errorf("failed to create CREATE request for PodSecurityAdmissionConfigurationTemplate object: %w", err))
				t.Fail()
			}
			admitters := validator.Admitters()
			if len(admitters) != 1 {
				t.Logf("wanted only one admitter but got = %d", len(admitters))
			}
			resp, _ := admitters[0].Admit(&req)
			if resp.Allowed != testcase.wantAllowed {
				t.Logf("wanted allowed = %t, got allowed = %t", testcase.wantAllowed, resp.Allowed)
				t.Fail()
			}

		})
	}
}

func createRequest(obj *v3.PodSecurityAdmissionConfigurationTemplate, operation admissionv1.Operation) (admission.Request, error) {
	req := admission.Request{
		AdmissionRequest: admissionv1.AdmissionRequest{
			Operation: operation,
		},
		Context: nil,
	}
	j, err := json.Marshal(obj)
	if err != nil {
		return req, err
	}
	req.Object.Raw = j
	req.OldObject.Raw = j
	return req, nil
}
