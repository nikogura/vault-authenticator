package authenticator

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/hashicorp/vault/api"
	"github.com/pkg/errors"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"
)

// Time out for all AWS Metadata endpoint reads.  Half a second seems to work.  Unknown if there's an expected latency, or how close this falls to the average case.  Because AWS is preferred, this value becomes minimum overhead for non-aws authentication.
const CLIENT_TIMEOUT = 700 * time.Millisecond

// IAMLogin actually performs the AWS IAM login to vault, and returns a logged in vault client
func IAMLogin(authenticator *Authenticator) (client *api.Client, err error) {
	verboseOutput(authenticator.Verbose, "Attempting IAM Login...\n")

	if os.Getenv("AWS_REGION") == "" {
		region := GetAwsRegion(authenticator.Verbose)

		os.Setenv("AWS_REGION", region)
	}

	if os.Getenv("AWS_REGION") == "" {
		err = errors.New("Not running in AWS")
		return client, err
	}

	apiConfig, err := ApiConfig(authenticator.Address, authenticator.CACertificate)
	if err != nil {
		err = errors.Wrap(err, "failed creating vault api config")
	}

	stsSvc := sts.New(session.New())
	req, _ := stsSvc.GetCallerIdentityRequest(&sts.GetCallerIdentityInput{})

	err = req.Sign()
	if err != nil {
		err = errors.Wrap(err, "failed to sign auth request")
		return client, err
	}

	rHeader, err := json.Marshal(req.HTTPRequest.Header)
	if err != nil {
		err = errors.Wrap(err, "failed to marshal request headers for auth request")
		return client, err
	}

	rBody, err := ioutil.ReadAll(req.HTTPRequest.Body)
	if err != nil {
		err = errors.Wrap(err, "failed to read auth request body")
		return client, err
	}

	data := map[string]string{
		"role":                    authenticator.Role,
		"iam_request_body":        base64.StdEncoding.EncodeToString(rBody),
		"iam_request_url":         base64.StdEncoding.EncodeToString([]byte(req.HTTPRequest.URL.String())),
		"iam_request_headers":     base64.StdEncoding.EncodeToString(rHeader),
		"iam_http_request_method": req.HTTPRequest.Method,
	}

	postdata, err := json.Marshal(data)
	if err != nil {
		err = errors.Wrapf(err, "failed to marshal data in auth request")
		return client, err
	}

	vaultAddress := apiConfig.Address
	// protect potential double slashes
	vaultAddress = strings.TrimRight(vaultAddress, "/")

	vaultUrl := fmt.Sprintf("%s/v1/auth/aws/login", vaultAddress)

	verboseOutput(authenticator.Verbose, "  vault url is %s", vaultUrl)
	verboseOutput(authenticator.Verbose, "  making request...")

	resp, err := http.Post(vaultUrl, "application/json", bytes.NewBuffer(postdata))
	if err != nil {
		err = errors.Wrapf(err, "failed to post auth data to vault")
		return client, err
	}

	verboseOutput(authenticator.Verbose, "  Response code: %d", resp.StatusCode)

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		err = errors.Wrapf(err, "failed to read auth response body")
		return client, err
	}

	var authData map[string]interface{}

	err = json.Unmarshal(body, &authData)
	if err != nil {
		err = errors.Wrapf(err, "failed to unmarshal data in response body")
		return client, err
	}

	authError, ok := authData["errors"].([]interface{})
	if ok {
		if len(authError) > 0 {
			err = errors.New(fmt.Sprintf("error authenticating to vault: %s", authError[0]))
			return client, err
		}

		err = errors.New("unknown err authenticating to vault")
		return client, err
	}

	auth, ok := authData["auth"].(map[string]interface{})
	if !ok {
		err = errors.New("failed to get auth data from response")
		return client, err
	}

	verboseOutput(authenticator.Verbose, "  auth data successfully parsed")

	token, ok := auth["client_token"].(string)
	if !ok {
		err = errors.New("returned client token is not a string")
		return client, err
	}

	verboseOutput(authenticator.Verbose, "  vault token extracted")

	client, err = api.NewClient(apiConfig)
	if err != nil {
		err = errors.Wrapf(err, "failed to create vault client from authenticator")
		return client, err
	}

	client.SetToken(token)

	verboseOutput(authenticator.Verbose, "Success!\n\n")

	return client, err
}

// DetectAWS See if we can find the AWS metadata service necessary for IAM auth
func DetectAws(c chan bool, verbose bool) {
	region := GetAwsRegion(verbose)

	if region != "" {
		c <- true
	}

	c <- false
}

// GetAwsRegion Attemts to find the Availability Zone for the running instance, and derives the Region by truncating the trailing letters off that AZ.  i.e. 'us-east-2a' becomes 'us-east-2'.  There doesn't appear to be an official means to get the Region, which is required by the STS signing request, but the AZ appears to be of a fairly constant form.
func GetAwsRegion(verbose bool) (region string) {
	c := make(chan string)

	// Simultaneously try 3 ways to get the AZ
	go GetAzEc2(c, verbose)
	go GetAzEcs(c, verbose)
	go GetAzFargate(c, verbose)

	// don't want to block forever
	timeout := make(chan bool, 1)
	go func() {
		time.Sleep(CLIENT_TIMEOUT)
		timeout <- true
	}()

	select {
	case az := <-c:
		// trim the suffix off the AZ to get the region
		region := strings.TrimRight(az, "abcdefghijklmnopqrstuvwxyz")
		return region
	case <-timeout:
		return region
	}
}

// GetAwsRegionFargate  Attempts to get the AZ info from the url listed in the ENV var ECS_CONTAINER_METADATA_URI.
func GetAzFargate(c chan string, verbose bool) {
	// Fargate needs ECS_CONTAINER_METADATA_URI for task metadata v3 and fargate
	metadataUrl := os.Getenv("ECS_CONTAINER_METADATA_URI")

	if metadataUrl == "" {
		return
	}

	client := http.Client{
		Timeout: CLIENT_TIMEOUT,
	}

	resp, err := client.Get(metadataUrl)
	if err != nil {
		err = errors.Wrap(err, "failed to query task metadata v3 service")
		verboseOutput(verbose, err.Error())
		return
	}

	if resp.StatusCode != 200 {
		err = errors.Wrapf(err, "non-success response code from %s", metadataUrl)
		verboseOutput(verbose, err.Error())
		return
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		err = errors.Wrap(err, "failed to read response body")
		verboseOutput(verbose, err.Error())
		return
	}

	data := make(map[string]interface{})

	err = json.Unmarshal(body, &data)
	if err != nil {
		err = errors.Wrap(err, "failed to unmarshal json from response")
		verboseOutput(verbose, err.Error())
		return
	}

	availabilityZone, ok := data["AvailabilityZone"]
	if ok {
		az, ok := availabilityZone.(string)
		if ok {
			c <- az
		}
	}
}

// GetAwsRegionEcs Hits the Task metadata endpoint for ECS and returns the AvailabilityZone.
func GetAzEcs(c chan string, verbose bool) {
	// ECS on EC2 needs http://169.254.170.2/v2/metadata | jq .AvailabilityZone for ecs. Will timeout when run from ec2.
	metadataUrl := "http://169.254.170.2/v2/metadata"

	client := http.Client{
		Timeout: CLIENT_TIMEOUT,
	}

	resp, err := client.Get(metadataUrl)
	if err != nil {
		err = errors.Wrap(err, "failed to query ECS task metadata service")
		verboseOutput(verbose, err.Error())
		return
	}

	if resp.StatusCode != 200 {
		err = errors.Wrapf(err, "non-success response code from %s", metadataUrl)
		verboseOutput(verbose, err.Error())
		return
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		err = errors.Wrap(err, "failed to read response body")
		verboseOutput(verbose, err.Error())
		return
	}

	data := make(map[string]interface{})

	err = json.Unmarshal(body, &data)
	if err != nil {
		err = errors.Wrap(err, "failed to unmarshal json from response")
		verboseOutput(verbose, err.Error())
		return
	}

	availabilityZone, ok := data["AvailabilityZone"]
	if ok {
		az, ok := availabilityZone.(string)
		if ok {
			c <- az
		}
	}
}

// GetAwsRegionEc2 gets the AZ from the metadata service and returns it
func GetAzEc2(c chan string, verbose bool) {
	metadataUrl := "http://169.254.169.254/latest/meta-data/placement/availability-zone"

	client := http.Client{
		Timeout: CLIENT_TIMEOUT,
	}

	resp, err := client.Get(metadataUrl)
	if err != nil {
		err = errors.Wrap(err, "failed to query EC2 metadata service")
		verboseOutput(verbose, err.Error())
		return
	}

	if resp.StatusCode != 200 {
		err = errors.Wrapf(err, "non-success response code from %s", metadataUrl)
		verboseOutput(verbose, err.Error())
		return
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		err = errors.Wrap(err, "failed to read response body")
		verboseOutput(verbose, err.Error())
		return
	}

	c <- string(body)
}
