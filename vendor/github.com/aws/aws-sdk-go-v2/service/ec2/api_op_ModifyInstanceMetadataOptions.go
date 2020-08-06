// Code generated by private/model/cli/gen-api/main.go. DO NOT EDIT.

package ec2

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/internal/awsutil"
)

type ModifyInstanceMetadataOptionsInput struct {
	_ struct{} `type:"structure"`

	// Checks whether you have the required permissions for the action, without
	// actually making the request, and provides an error response. If you have
	// the required permissions, the error response is DryRunOperation. Otherwise,
	// it is UnauthorizedOperation.
	DryRun *bool `type:"boolean"`

	// This parameter enables or disables the HTTP metadata endpoint on your instances.
	// If the parameter is not specified, the existing state is maintained.
	//
	// If you specify a value of disabled, you will not be able to access your instance
	// metadata.
	HttpEndpoint InstanceMetadataEndpointState `type:"string" enum:"true"`

	// The desired HTTP PUT response hop limit for instance metadata requests. The
	// larger the number, the further instance metadata requests can travel. If
	// no parameter is specified, the existing state is maintained.
	//
	// Possible values: Integers from 1 to 64
	HttpPutResponseHopLimit *int64 `type:"integer"`

	// The state of token usage for your instance metadata requests. If the parameter
	// is not specified in the request, the default state is optional.
	//
	// If the state is optional, you can choose to retrieve instance metadata with
	// or without a signed token header on your request. If you retrieve the IAM
	// role credentials without a token, the version 1.0 role credentials are returned.
	// If you retrieve the IAM role credentials using a valid signed token, the
	// version 2.0 role credentials are returned.
	//
	// If the state is required, you must send a signed token header with any instance
	// metadata retrieval requests. In this state, retrieving the IAM role credential
	// always returns the version 2.0 credentials; the version 1.0 credentials are
	// not available.
	HttpTokens HttpTokensState `type:"string" enum:"true"`

	// The ID of the instance.
	//
	// InstanceId is a required field
	InstanceId *string `type:"string" required:"true"`
}

// String returns the string representation
func (s ModifyInstanceMetadataOptionsInput) String() string {
	return awsutil.Prettify(s)
}

// Validate inspects the fields of the type to determine if they are valid.
func (s *ModifyInstanceMetadataOptionsInput) Validate() error {
	invalidParams := aws.ErrInvalidParams{Context: "ModifyInstanceMetadataOptionsInput"}

	if s.InstanceId == nil {
		invalidParams.Add(aws.NewErrParamRequired("InstanceId"))
	}

	if invalidParams.Len() > 0 {
		return invalidParams
	}
	return nil
}

type ModifyInstanceMetadataOptionsOutput struct {
	_ struct{} `type:"structure"`

	// The ID of the instance.
	InstanceId *string `locationName:"instanceId" type:"string"`

	// The metadata options for the instance.
	InstanceMetadataOptions *InstanceMetadataOptionsResponse `locationName:"instanceMetadataOptions" type:"structure"`
}

// String returns the string representation
func (s ModifyInstanceMetadataOptionsOutput) String() string {
	return awsutil.Prettify(s)
}

const opModifyInstanceMetadataOptions = "ModifyInstanceMetadataOptions"

// ModifyInstanceMetadataOptionsRequest returns a request value for making API operation for
// Amazon Elastic Compute Cloud.
//
// Modify the instance metadata parameters on a running or stopped instance.
// When you modify the parameters on a stopped instance, they are applied when
// the instance is started. When you modify the parameters on a running instance,
// the API responds with a state of “pending”. After the parameter modifications
// are successfully applied to the instance, the state of the modifications
// changes from “pending” to “applied” in subsequent describe-instances
// API calls. For more information, see Instance metadata and user data (https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html).
//
//    // Example sending a request using ModifyInstanceMetadataOptionsRequest.
//    req := client.ModifyInstanceMetadataOptionsRequest(params)
//    resp, err := req.Send(context.TODO())
//    if err == nil {
//        fmt.Println(resp)
//    }
//
// Please also see https://docs.aws.amazon.com/goto/WebAPI/ec2-2016-11-15/ModifyInstanceMetadataOptions
func (c *Client) ModifyInstanceMetadataOptionsRequest(input *ModifyInstanceMetadataOptionsInput) ModifyInstanceMetadataOptionsRequest {
	op := &aws.Operation{
		Name:       opModifyInstanceMetadataOptions,
		HTTPMethod: "POST",
		HTTPPath:   "/",
	}

	if input == nil {
		input = &ModifyInstanceMetadataOptionsInput{}
	}

	req := c.newRequest(op, input, &ModifyInstanceMetadataOptionsOutput{})

	return ModifyInstanceMetadataOptionsRequest{Request: req, Input: input, Copy: c.ModifyInstanceMetadataOptionsRequest}
}

// ModifyInstanceMetadataOptionsRequest is the request type for the
// ModifyInstanceMetadataOptions API operation.
type ModifyInstanceMetadataOptionsRequest struct {
	*aws.Request
	Input *ModifyInstanceMetadataOptionsInput
	Copy  func(*ModifyInstanceMetadataOptionsInput) ModifyInstanceMetadataOptionsRequest
}

// Send marshals and sends the ModifyInstanceMetadataOptions API request.
func (r ModifyInstanceMetadataOptionsRequest) Send(ctx context.Context) (*ModifyInstanceMetadataOptionsResponse, error) {
	r.Request.SetContext(ctx)
	err := r.Request.Send()
	if err != nil {
		return nil, err
	}

	resp := &ModifyInstanceMetadataOptionsResponse{
		ModifyInstanceMetadataOptionsOutput: r.Request.Data.(*ModifyInstanceMetadataOptionsOutput),
		response:                            &aws.Response{Request: r.Request},
	}

	return resp, nil
}

// ModifyInstanceMetadataOptionsResponse is the response type for the
// ModifyInstanceMetadataOptions API operation.
type ModifyInstanceMetadataOptionsResponse struct {
	*ModifyInstanceMetadataOptionsOutput

	response *aws.Response
}

// SDKResponseMetdata returns the response metadata for the
// ModifyInstanceMetadataOptions request.
func (r *ModifyInstanceMetadataOptionsResponse) SDKResponseMetdata() *aws.Response {
	return r.response
}
