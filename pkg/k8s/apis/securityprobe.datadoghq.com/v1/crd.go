package v1

import (
	"github.com/pkg/errors"
	apiextv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiextv1client "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset/typed/apiextensions/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"

	securityprobedatadoghqcom "github.com/Gui774ume/network-security-probe/pkg/k8s/apis/securityprobe.datadoghq.com"
)

var (
	// SecurityProfileCRD - Custom resource definition for SecurityProfile.
	SecurityProfileCRD = &apiextv1.CustomResourceDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name: "securityprofiles.securityprobe.datadoghq.com",
		},
		Spec: apiextv1.CustomResourceDefinitionSpec{
			Group: securityprobedatadoghqcom.GroupName,
			Names: apiextv1.CustomResourceDefinitionNames{
				Singular: "securityprofile",
				Plural:   "securityprofiles",
				Kind:     "SecurityProfile",
				ListKind: "SecurityProfileList",
				ShortNames: []string{
					"sp",
					"sps",
				},
			},
			Versions: []apiextv1.CustomResourceDefinitionVersion{
				{
					Name:    Version,
					Served:  true,
					Storage: true,
					Schema: &apiextv1.CustomResourceValidation{
						OpenAPIV3Schema: SecurityProfileCRDSchema,
					},
				},
			},
			Scope: apiextv1.NamespaceScoped,
		},
	}

	// SecurityProfileCRDSchema - OpenAPI schema to the SecurityProfileCRD.
	SecurityProfileCRDSchema = &apiextv1.JSONSchemaProps{
		Type: "object",
		Properties: map[string]apiextv1.JSONSchemaProps{
			"spec": apiextv1.JSONSchemaProps{
				Type: "object",
				Properties: map[string]apiextv1.JSONSchemaProps{
					"labelSelector": apiextv1.JSONSchemaProps{
						Type: "object",
						Properties: map[string]apiextv1.JSONSchemaProps{
							"matchLabels": apiextv1.JSONSchemaProps{
								Type:                   "object",
								XPreserveUnknownFields: boolPtr(true),
							},
						},
					},
					"actions": apiextv1.JSONSchemaProps{
						Type: "array",
						Items: &apiextv1.JSONSchemaPropsOrArray{
							Schema: &apiextv1.JSONSchemaProps{
								Type: "string",
							},
						},
					},
					"attacks": apiextv1.JSONSchemaProps{
						Type: "array",
						Items: &apiextv1.JSONSchemaPropsOrArray{
							Schema: &apiextv1.JSONSchemaProps{
								Type: "string",
							},
						},
					},
					"default": NetworkPolicyCRDSchema,
					"processes": apiextv1.JSONSchemaProps{
						Type: "array",
						Items: &apiextv1.JSONSchemaPropsOrArray{
							Schema: &apiextv1.JSONSchemaProps{
								Type: "object",
								Properties: map[string]apiextv1.JSONSchemaProps{
									"path": apiextv1.JSONSchemaProps{
										Type: "string",
									},
									"network": NetworkPolicyCRDSchema,
								},
							},
						},
					},
				},
			},
		},
	}

	// NetworkPolicyCRDSchema - OpenAPI schema for NetworkPolicies.
	NetworkPolicyCRDSchema = apiextv1.JSONSchemaProps{
		Type: "object",
		Properties: map[string]apiextv1.JSONSchemaProps{
			"egress": apiextv1.JSONSchemaProps{
				Type: "object",
				Properties: map[string]apiextv1.JSONSchemaProps{
					"fqdns": apiextv1.JSONSchemaProps{
						Type: "array",
						Items: &apiextv1.JSONSchemaPropsOrArray{
							Schema: &apiextv1.JSONSchemaProps{
								Type: "string",
							},
						},
					},
					"cidr4": apiextv1.JSONSchemaProps{
						Type: "array",
						Items: &apiextv1.JSONSchemaPropsOrArray{
							Schema: &apiextv1.JSONSchemaProps{
								Type: "string",
							},
						},
					},
					"cidr6": apiextv1.JSONSchemaProps{
						Type: "array",
						Items: &apiextv1.JSONSchemaPropsOrArray{
							Schema: &apiextv1.JSONSchemaProps{
								Type: "string",
							},
						},
					},
					"l3": apiextv1.JSONSchemaProps{
						Type: "object",
						Properties: map[string]apiextv1.JSONSchemaProps{
							"protocols": apiextv1.JSONSchemaProps{
								Type: "array",
								Items: &apiextv1.JSONSchemaPropsOrArray{
									Schema: &apiextv1.JSONSchemaProps{
										Type: "string",
									},
								},
							},
						},
					},
					"l4": apiextv1.JSONSchemaProps{
						Type: "object",
						Properties: map[string]apiextv1.JSONSchemaProps{
							"protocols": apiextv1.JSONSchemaProps{
								Type: "array",
								Items: &apiextv1.JSONSchemaPropsOrArray{
									Schema: &apiextv1.JSONSchemaProps{
										Type: "string",
									},
								},
							},
							"protocolPorts": apiextv1.JSONSchemaProps{
								Type: "array",
								Items: &apiextv1.JSONSchemaPropsOrArray{
									Schema: &apiextv1.JSONSchemaProps{
										Type: "object",
										Properties: map[string]apiextv1.JSONSchemaProps{
											"protocol": apiextv1.JSONSchemaProps{
												Type: "string",
											},
											"port": apiextv1.JSONSchemaProps{
												Type: "integer",
											},
										},
									},
								},
							},
						},
					},
					"l7": apiextv1.JSONSchemaProps{
						Type: "object",
						Properties: map[string]apiextv1.JSONSchemaProps{
							"protocols": apiextv1.JSONSchemaProps{
								Type: "array",
								Items: &apiextv1.JSONSchemaPropsOrArray{
									Schema: &apiextv1.JSONSchemaProps{
										Type: "string",
									},
								},
							},
							"dns": apiextv1.JSONSchemaProps{
								Type: "array",
								Items: &apiextv1.JSONSchemaPropsOrArray{
									Schema: &apiextv1.JSONSchemaProps{
										Type: "string",
									},
								},
							},
							"http": apiextv1.JSONSchemaProps{
								Type: "array",
								Items: &apiextv1.JSONSchemaPropsOrArray{
									Schema: &apiextv1.JSONSchemaProps{
										Type: "object",
										Properties: map[string]apiextv1.JSONSchemaProps{
											"method": apiextv1.JSONSchemaProps{
												Type: "string",
											},
											"uri": apiextv1.JSONSchemaProps{
												Type: "string",
											},
										},
									},
								},
							},
						},
					},
				},
			},
			"ingress": apiextv1.JSONSchemaProps{
				Type: "object",
				Properties: map[string]apiextv1.JSONSchemaProps{
					"cidr4": apiextv1.JSONSchemaProps{
						Type: "array",
						Items: &apiextv1.JSONSchemaPropsOrArray{
							Schema: &apiextv1.JSONSchemaProps{
								Type: "string",
							},
						},
					},
					"cidr6": apiextv1.JSONSchemaProps{
						Type: "array",
						Items: &apiextv1.JSONSchemaPropsOrArray{
							Schema: &apiextv1.JSONSchemaProps{
								Type: "string",
							},
						},
					},
					"l3": apiextv1.JSONSchemaProps{
						Type: "object",
						Properties: map[string]apiextv1.JSONSchemaProps{
							"protocols": apiextv1.JSONSchemaProps{
								Type: "array",
								Items: &apiextv1.JSONSchemaPropsOrArray{
									Schema: &apiextv1.JSONSchemaProps{
										Type: "string",
									},
								},
							},
						},
					},
					"l4": apiextv1.JSONSchemaProps{
						Type: "object",
						Properties: map[string]apiextv1.JSONSchemaProps{
							"protocols": apiextv1.JSONSchemaProps{
								Type: "array",
								Items: &apiextv1.JSONSchemaPropsOrArray{
									Schema: &apiextv1.JSONSchemaProps{
										Type: "string",
									},
								},
							},
							"protocolPorts": apiextv1.JSONSchemaProps{
								Type: "array",
								Items: &apiextv1.JSONSchemaPropsOrArray{
									Schema: &apiextv1.JSONSchemaProps{
										Type: "object",
										Properties: map[string]apiextv1.JSONSchemaProps{
											"protocol": apiextv1.JSONSchemaProps{
												Type: "string",
											},
											"port": apiextv1.JSONSchemaProps{
												Type: "integer",
											},
										},
									},
								},
							},
						},
					},
					"l7": apiextv1.JSONSchemaProps{
						Type: "object",
						Properties: map[string]apiextv1.JSONSchemaProps{
							"protocols": apiextv1.JSONSchemaProps{
								Type: "array",
								Items: &apiextv1.JSONSchemaPropsOrArray{
									Schema: &apiextv1.JSONSchemaProps{
										Type: "string",
									},
								},
							},
							"dns": apiextv1.JSONSchemaProps{
								Type: "array",
								Items: &apiextv1.JSONSchemaPropsOrArray{
									Schema: &apiextv1.JSONSchemaProps{
										Type: "string",
									},
								},
							},
							"http": apiextv1.JSONSchemaProps{
								Type: "array",
								Items: &apiextv1.JSONSchemaPropsOrArray{
									Schema: &apiextv1.JSONSchemaProps{
										Type: "object",
										Properties: map[string]apiextv1.JSONSchemaProps{
											"method": apiextv1.JSONSchemaProps{
												Type: "string",
											},
											"uri": apiextv1.JSONSchemaProps{
												Type: "string",
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}
)

func boolPtr(b bool) *bool {
	return &b
}

// CreateSecurityProfileCRD - Creates SecurityProfile v1 CRDs
func CreateSecurityProfileCRD(config *rest.Config) error {
	client, err := apiextv1client.NewForConfig(config)
	if err != nil {
		return errors.Wrap(err, "error creating apiextensions/v1 client")
	}

	crdClient := client.CustomResourceDefinitions()

	_, err = crdClient.Create(SecurityProfileCRD)
	if err != nil && apierrors.IsAlreadyExists(err) {
		return nil
	} else if err != nil {
		return errors.Wrap(err, "error creating CRD")
	}

	return nil
}
