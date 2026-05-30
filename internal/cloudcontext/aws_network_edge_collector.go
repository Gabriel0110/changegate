package cloudcontext

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/apigatewayv2"
	apigwv2types "github.com/aws/aws-sdk-go-v2/service/apigatewayv2/types"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
	cftypes "github.com/aws/aws-sdk-go-v2/service/cloudfront/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	elbtypes "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
)

const (
	relationshipSourceEC2        = "aws_ec2"
	relationshipSourceELBV2      = "aws_elbv2"
	relationshipSourceCloudFront = "aws_cloudfront"
	relationshipSourceAPIGWV2    = "aws_apigatewayv2"
	internetResourceID           = "internet"
)

func (c *sdkAWSClientSet) NetworkInventory(ctx context.Context, region string, accountID string) (AWSInventory, error) {
	ec2Client := c.ec2ForRegion(region)
	inventory := AWSInventory{Network: ResourceSet{Resources: map[string]Resource{}}}
	if err := c.collectVPCs(ctx, ec2Client, region, accountID, &inventory); err != nil {
		return AWSInventory{}, err
	}
	if err := c.collectSubnets(ctx, ec2Client, region, accountID, &inventory); err != nil {
		return AWSInventory{}, err
	}
	if err := c.collectInternetGateways(ctx, ec2Client, region, accountID, &inventory); err != nil {
		return AWSInventory{}, err
	}
	if err := c.collectNATGateways(ctx, ec2Client, region, accountID, &inventory); err != nil {
		return AWSInventory{}, err
	}
	if err := c.collectRouteTables(ctx, ec2Client, region, accountID, &inventory); err != nil {
		return AWSInventory{}, err
	}
	if err := c.collectSecurityGroups(ctx, ec2Client, region, accountID, &inventory); err != nil {
		return AWSInventory{}, err
	}
	if err := c.collectNetworkInterfaces(ctx, ec2Client, region, accountID, &inventory); err != nil {
		return AWSInventory{}, err
	}
	return inventory, nil
}

func (c *sdkAWSClientSet) EdgeInventory(ctx context.Context, region string, accountID string) (AWSInventory, error) {
	inventory := AWSInventory{Edge: ResourceSet{Resources: map[string]Resource{}}}
	if err := c.collectLoadBalancers(ctx, c.elbv2ForRegion(region), region, accountID, &inventory); err != nil {
		return AWSInventory{}, err
	}
	if err := c.collectAPIGatewayV2(ctx, c.apigwV2ForRegion(region), region, accountID, &inventory); err != nil {
		return AWSInventory{}, err
	}
	if region == "us-east-1" {
		if err := c.collectCloudFront(ctx, accountID, &inventory); err != nil {
			return AWSInventory{}, err
		}
	}
	return inventory, nil
}

func (c *sdkAWSClientSet) ec2ForRegion(region string) *ec2.Client {
	cfg := c.cfg.Copy()
	cfg.Region = region
	return ec2.NewFromConfig(cfg)
}

func (c *sdkAWSClientSet) elbv2ForRegion(region string) *elasticloadbalancingv2.Client {
	cfg := c.cfg.Copy()
	cfg.Region = region
	return elasticloadbalancingv2.NewFromConfig(cfg)
}

func (c *sdkAWSClientSet) apigwV2ForRegion(region string) *apigatewayv2.Client {
	cfg := c.cfg.Copy()
	cfg.Region = region
	return apigatewayv2.NewFromConfig(cfg)
}

func (c *sdkAWSClientSet) collectVPCs(ctx context.Context, client *ec2.Client, region string, accountID string, inventory *AWSInventory) error {
	paginator := ec2.NewDescribeVpcsPaginator(client, &ec2.DescribeVpcsInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("describe VPCs: %w", err)
		}
		for _, vpc := range page.Vpcs {
			id := aws.ToString(vpc.VpcId)
			if id == "" {
				continue
			}
			attrs := map[string]string{
				"cidr_block": aws.ToString(vpc.CidrBlock),
				"is_default": strconv.FormatBool(aws.ToBool(vpc.IsDefault)),
				"state":      string(vpc.State),
			}
			inventory.Network.Resources[id] = awsResource(id, ec2ARN(region, accountID, "vpc", id), id, accountID, "aws_vpc", region, ec2Tags(vpc.Tags), attrs)
		}
	}
	return nil
}

func (c *sdkAWSClientSet) collectSubnets(ctx context.Context, client *ec2.Client, region string, accountID string, inventory *AWSInventory) error {
	paginator := ec2.NewDescribeSubnetsPaginator(client, &ec2.DescribeSubnetsInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("describe subnets: %w", err)
		}
		for _, subnet := range page.Subnets {
			id := aws.ToString(subnet.SubnetId)
			if id == "" {
				continue
			}
			attrs := map[string]string{
				"vpc_id":                  aws.ToString(subnet.VpcId),
				"cidr_block":              aws.ToString(subnet.CidrBlock),
				"availability_zone":       aws.ToString(subnet.AvailabilityZone),
				"map_public_ip_on_launch": strconv.FormatBool(aws.ToBool(subnet.MapPublicIpOnLaunch)),
			}
			resource := awsResource(id, ec2ARN(region, accountID, "subnet", id), id, accountID, "aws_subnet", region, ec2Tags(subnet.Tags), attrs)
			resource.Public = boolPtr(aws.ToBool(subnet.MapPublicIpOnLaunch))
			inventory.Network.Resources[id] = resource
			addRelationship(inventory, aws.ToString(subnet.VpcId), id, "contains", relationshipSourceEC2, "high")
		}
	}
	return nil
}

func (c *sdkAWSClientSet) collectInternetGateways(ctx context.Context, client *ec2.Client, region string, accountID string, inventory *AWSInventory) error {
	paginator := ec2.NewDescribeInternetGatewaysPaginator(client, &ec2.DescribeInternetGatewaysInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("describe internet gateways: %w", err)
		}
		for _, gateway := range page.InternetGateways {
			id := aws.ToString(gateway.InternetGatewayId)
			if id == "" {
				continue
			}
			inventory.Network.Resources[id] = awsResource(id, ec2ARN(region, accountID, "internet-gateway", id), id, accountID, "aws_internet_gateway", region, ec2Tags(gateway.Tags), nil)
			for _, attachment := range gateway.Attachments {
				addRelationship(inventory, id, aws.ToString(attachment.VpcId), "attached_to", relationshipSourceEC2, "high")
			}
		}
	}
	return nil
}

func (c *sdkAWSClientSet) collectNATGateways(ctx context.Context, client *ec2.Client, region string, accountID string, inventory *AWSInventory) error {
	paginator := ec2.NewDescribeNatGatewaysPaginator(client, &ec2.DescribeNatGatewaysInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("describe NAT gateways: %w", err)
		}
		for _, gateway := range page.NatGateways {
			id := aws.ToString(gateway.NatGatewayId)
			if id == "" {
				continue
			}
			attrs := map[string]string{
				"vpc_id":     aws.ToString(gateway.VpcId),
				"subnet_id":  aws.ToString(gateway.SubnetId),
				"state":      string(gateway.State),
				"public_ips": strings.Join(natPublicIPs(gateway), ","),
			}
			inventory.Network.Resources[id] = awsResource(id, ec2ARN(region, accountID, "natgateway", id), id, accountID, "aws_nat_gateway", region, ec2Tags(gateway.Tags), attrs)
			addRelationship(inventory, aws.ToString(gateway.SubnetId), id, "contains", relationshipSourceEC2, "high")
		}
	}
	return nil
}

func (c *sdkAWSClientSet) collectRouteTables(ctx context.Context, client *ec2.Client, region string, accountID string, inventory *AWSInventory) error {
	paginator := ec2.NewDescribeRouteTablesPaginator(client, &ec2.DescribeRouteTablesInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("describe route tables: %w", err)
		}
		for _, table := range page.RouteTables {
			id := aws.ToString(table.RouteTableId)
			if id == "" {
				continue
			}
			public := routeTablePublic(table)
			attrs := map[string]string{
				"vpc_id": aws.ToString(table.VpcId),
			}
			resource := awsResource(id, ec2ARN(region, accountID, "route-table", id), id, accountID, "aws_route_table", region, ec2Tags(table.Tags), attrs)
			resource.Public = boolPtr(public)
			inventory.Network.Resources[id] = resource
			addRelationship(inventory, aws.ToString(table.VpcId), id, "contains", relationshipSourceEC2, "high")
			for _, association := range table.Associations {
				addRelationship(inventory, id, aws.ToString(association.SubnetId), "associated_with", relationshipSourceEC2, "high")
				if public {
					markResourcePublic(inventory.Network.Resources, aws.ToString(association.SubnetId))
				}
			}
			for _, route := range table.Routes {
				target := firstNonEmpty(aws.ToString(route.GatewayId), aws.ToString(route.NatGatewayId), aws.ToString(route.TransitGatewayId), aws.ToString(route.VpcPeeringConnectionId))
				if target != "" {
					addRelationship(inventory, id, target, "routes_to", relationshipSourceEC2, "high")
				}
				if routePublic(route) {
					addRelationship(inventory, internetResourceID, id, "routes_to", relationshipSourceEC2, "high")
				}
			}
		}
	}
	return nil
}

func (c *sdkAWSClientSet) collectSecurityGroups(ctx context.Context, client *ec2.Client, region string, accountID string, inventory *AWSInventory) error {
	paginator := ec2.NewDescribeSecurityGroupsPaginator(client, &ec2.DescribeSecurityGroupsInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("describe security groups: %w", err)
		}
		for _, group := range page.SecurityGroups {
			id := aws.ToString(group.GroupId)
			if id == "" {
				continue
			}
			publicPorts := publicIngressPorts(group.IpPermissions)
			attrs := map[string]string{
				"vpc_id":               aws.ToString(group.VpcId),
				"name":                 aws.ToString(group.GroupName),
				"description":          aws.ToString(group.Description),
				"public_ingress":       strconv.FormatBool(len(publicPorts) > 0),
				"public_ingress_ports": strings.Join(publicPorts, ","),
			}
			resource := awsResource(id, firstNonEmpty(aws.ToString(group.SecurityGroupArn), ec2ARN(region, accountID, "security-group", id)), id, accountID, "aws_security_group", region, ec2Tags(group.Tags), attrs)
			resource.Public = boolPtr(len(publicPorts) > 0)
			inventory.Network.Resources[id] = resource
			addRelationship(inventory, aws.ToString(group.VpcId), id, "contains", relationshipSourceEC2, "high")
			for _, permission := range append(group.IpPermissions, group.IpPermissionsEgress...) {
				for _, pair := range permission.UserIdGroupPairs {
					addRelationship(inventory, id, aws.ToString(pair.GroupId), "allows_security_group", relationshipSourceEC2, "high")
				}
			}
		}
	}
	return nil
}

func (c *sdkAWSClientSet) collectNetworkInterfaces(ctx context.Context, client *ec2.Client, region string, accountID string, inventory *AWSInventory) error {
	paginator := ec2.NewDescribeNetworkInterfacesPaginator(client, &ec2.DescribeNetworkInterfacesInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("describe network interfaces: %w", err)
		}
		for _, iface := range page.NetworkInterfaces {
			id := aws.ToString(iface.NetworkInterfaceId)
			if id == "" {
				continue
			}
			attrs := map[string]string{
				"vpc_id":             aws.ToString(iface.VpcId),
				"subnet_id":          aws.ToString(iface.SubnetId),
				"interface_type":     string(iface.InterfaceType),
				"private_ip_address": aws.ToString(iface.PrivateIpAddress),
				"public_ip_address":  "",
			}
			if iface.Association != nil {
				attrs["public_ip_address"] = aws.ToString(iface.Association.PublicIp)
			}
			resource := awsResource(id, ec2ARN(region, accountID, "network-interface", id), id, accountID, "aws_network_interface", region, ec2Tags(iface.TagSet), attrs)
			resource.Public = boolPtr(attrs["public_ip_address"] != "")
			inventory.Network.Resources[id] = resource
			addRelationship(inventory, aws.ToString(iface.SubnetId), id, "contains", relationshipSourceEC2, "high")
			for _, group := range iface.Groups {
				addRelationship(inventory, aws.ToString(group.GroupId), id, "attached_to", relationshipSourceEC2, "high")
			}
			if iface.Attachment != nil {
				addRelationship(inventory, id, aws.ToString(iface.Attachment.InstanceId), "attached_to", relationshipSourceEC2, "high")
			}
		}
	}
	return nil
}

func (c *sdkAWSClientSet) collectLoadBalancers(ctx context.Context, client *elasticloadbalancingv2.Client, region string, accountID string, inventory *AWSInventory) error {
	lbs, err := describeAllLoadBalancers(ctx, client)
	if err != nil {
		return err
	}
	targetGroups, err := describeAllTargetGroups(ctx, client)
	if err != nil {
		return err
	}
	for _, lb := range lbs {
		arn := aws.ToString(lb.LoadBalancerArn)
		if arn == "" {
			continue
		}
		public := lb.Scheme == elbtypes.LoadBalancerSchemeEnumInternetFacing
		attrs := map[string]string{
			"name":     aws.ToString(lb.LoadBalancerName),
			"dns_name": aws.ToString(lb.DNSName),
			"scheme":   string(lb.Scheme),
			"type":     string(lb.Type),
			"vpc_id":   aws.ToString(lb.VpcId),
		}
		resource := awsResource(arn, arn, aws.ToString(lb.LoadBalancerName), accountID, "aws_lb", region, nil, attrs)
		resource.Public = boolPtr(public)
		inventory.Edge.Resources[arn] = resource
		if public {
			addRelationship(inventory, internetResourceID, arn, "routes_to", relationshipSourceELBV2, "high")
		}
		for _, sg := range lb.SecurityGroups {
			addRelationship(inventory, sg, arn, "protects", relationshipSourceELBV2, "high")
		}
		for _, zone := range lb.AvailabilityZones {
			addRelationship(inventory, arn, aws.ToString(zone.SubnetId), "attached_to", relationshipSourceELBV2, "high")
		}
		listeners, err := describeAllListeners(ctx, client, arn)
		if err != nil {
			return err
		}
		for _, listener := range listeners {
			listenerARN := aws.ToString(listener.ListenerArn)
			addRelationship(inventory, arn, listenerARN, "has_listener", relationshipSourceELBV2, "high")
			for _, action := range listener.DefaultActions {
				addRelationship(inventory, listenerARN, aws.ToString(action.TargetGroupArn), "routes_to", relationshipSourceELBV2, "high")
			}
			rules, err := describeAllRules(ctx, client, listenerARN)
			if err != nil {
				return err
			}
			for _, rule := range rules {
				for _, action := range rule.Actions {
					addRelationship(inventory, listenerARN, aws.ToString(action.TargetGroupArn), "routes_to", relationshipSourceELBV2, "high")
				}
			}
		}
	}
	for _, tg := range targetGroups {
		arn := aws.ToString(tg.TargetGroupArn)
		if arn == "" {
			continue
		}
		attrs := map[string]string{
			"name":        aws.ToString(tg.TargetGroupName),
			"target_type": string(tg.TargetType),
			"protocol":    string(tg.Protocol),
			"vpc_id":      aws.ToString(tg.VpcId),
		}
		if tg.Port != nil {
			attrs["port"] = strconv.Itoa(int(aws.ToInt32(tg.Port)))
		}
		inventory.Edge.Resources[arn] = awsResource(arn, arn, aws.ToString(tg.TargetGroupName), accountID, "aws_lb_target_group", region, nil, attrs)
		for _, lbARN := range tg.LoadBalancerArns {
			addRelationship(inventory, lbARN, arn, "routes_to", relationshipSourceELBV2, "high")
		}
		targets, err := client.DescribeTargetHealth(ctx, &elasticloadbalancingv2.DescribeTargetHealthInput{TargetGroupArn: tg.TargetGroupArn})
		if err != nil {
			return fmt.Errorf("describe target health for %s: %w", arn, err)
		}
		for _, health := range targets.TargetHealthDescriptions {
			targetID := targetResourceID(tg.TargetType, region, accountID, health)
			addRelationship(inventory, arn, targetID, "routes_to", relationshipSourceELBV2, "high")
		}
	}
	return nil
}

func (c *sdkAWSClientSet) collectCloudFront(ctx context.Context, accountID string, inventory *AWSInventory) error {
	paginator := cloudfront.NewListDistributionsPaginator(c.cloudfront, &cloudfront.ListDistributionsInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("list CloudFront distributions: %w", err)
		}
		if page.DistributionList == nil {
			continue
		}
		for _, distribution := range page.DistributionList.Items {
			arn := aws.ToString(distribution.ARN)
			if arn == "" {
				continue
			}
			attrs := map[string]string{
				"id":          aws.ToString(distribution.Id),
				"domain_name": aws.ToString(distribution.DomainName),
				"status":      aws.ToString(distribution.Status),
				"enabled":     strconv.FormatBool(aws.ToBool(distribution.Enabled)),
				"web_acl_id":  aws.ToString(distribution.WebACLId),
			}
			resource := awsResource(arn, arn, aws.ToString(distribution.Id), accountID, "aws_cloudfront_distribution", "global", nil, attrs)
			resource.Public = boolPtr(aws.ToBool(distribution.Enabled))
			if distribution.WebACLId != nil && aws.ToString(distribution.WebACLId) != "" {
				resource.CompensatingControls = append(resource.CompensatingControls, "waf")
			}
			inventory.Edge.Resources[arn] = resource
			if aws.ToBool(distribution.Enabled) {
				addRelationship(inventory, internetResourceID, arn, "routes_to", relationshipSourceCloudFront, "high")
			}
			for _, origin := range cloudFrontOrigins(distribution) {
				addRelationship(inventory, arn, origin, "routes_to", relationshipSourceCloudFront, "medium")
			}
		}
	}
	return nil
}

func (c *sdkAWSClientSet) collectAPIGatewayV2(ctx context.Context, client *apigatewayv2.Client, region string, accountID string, inventory *AWSInventory) error {
	var nextToken *string
	for {
		page, err := client.GetApis(ctx, &apigatewayv2.GetApisInput{NextToken: nextToken})
		if err != nil {
			return fmt.Errorf("get API Gateway v2 APIs: %w", err)
		}
		for _, api := range page.Items {
			id := aws.ToString(api.ApiId)
			if id == "" {
				continue
			}
			arn := fmt.Sprintf("arn:aws:apigateway:%s::/apis/%s", region, id)
			public := !aws.ToBool(api.DisableExecuteApiEndpoint)
			attrs := map[string]string{
				"name":          aws.ToString(api.Name),
				"endpoint":      aws.ToString(api.ApiEndpoint),
				"protocol_type": string(api.ProtocolType),
			}
			resource := awsResource(id, arn, id, accountID, "aws_apigatewayv2_api", region, api.Tags, attrs)
			resource.Public = boolPtr(public)
			inventory.Edge.Resources[id] = resource
			if public {
				addRelationship(inventory, internetResourceID, id, "routes_to", relationshipSourceAPIGWV2, "high")
			}
			routes, err := collectAPIGatewayRoutes(ctx, client, id)
			if err != nil {
				return err
			}
			for _, route := range routes {
				routeID := id + "/routes/" + aws.ToString(route.RouteId)
				routeResource := awsResource(routeID, arn+"/routes/"+aws.ToString(route.RouteId), routeID, accountID, "aws_apigatewayv2_route", region, nil, map[string]string{
					"route_key": aws.ToString(route.RouteKey),
					"target":    aws.ToString(route.Target),
				})
				routeResource.Public = boolPtr(public)
				inventory.Edge.Resources[routeID] = routeResource
				addRelationship(inventory, id, routeID, "routes_to", relationshipSourceAPIGWV2, "high")
			}
		}
		if page.NextToken == nil || aws.ToString(page.NextToken) == "" {
			break
		}
		nextToken = page.NextToken
	}
	return nil
}

func collectAPIGatewayRoutes(ctx context.Context, client *apigatewayv2.Client, apiID string) ([]apigwv2types.Route, error) {
	var routes []apigwv2types.Route
	var nextToken *string
	for {
		page, err := client.GetRoutes(ctx, &apigatewayv2.GetRoutesInput{ApiId: aws.String(apiID), NextToken: nextToken})
		if err != nil {
			return nil, fmt.Errorf("get API Gateway v2 routes for %s: %w", apiID, err)
		}
		routes = append(routes, page.Items...)
		if page.NextToken == nil || aws.ToString(page.NextToken) == "" {
			break
		}
		nextToken = page.NextToken
	}
	return routes, nil
}

func describeAllLoadBalancers(ctx context.Context, client *elasticloadbalancingv2.Client) ([]elbtypes.LoadBalancer, error) {
	paginator := elasticloadbalancingv2.NewDescribeLoadBalancersPaginator(client, &elasticloadbalancingv2.DescribeLoadBalancersInput{})
	var out []elbtypes.LoadBalancer
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("describe load balancers: %w", err)
		}
		out = append(out, page.LoadBalancers...)
	}
	return out, nil
}

func describeAllTargetGroups(ctx context.Context, client *elasticloadbalancingv2.Client) ([]elbtypes.TargetGroup, error) {
	paginator := elasticloadbalancingv2.NewDescribeTargetGroupsPaginator(client, &elasticloadbalancingv2.DescribeTargetGroupsInput{})
	var out []elbtypes.TargetGroup
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("describe target groups: %w", err)
		}
		out = append(out, page.TargetGroups...)
	}
	return out, nil
}

func describeAllListeners(ctx context.Context, client *elasticloadbalancingv2.Client, lbARN string) ([]elbtypes.Listener, error) {
	paginator := elasticloadbalancingv2.NewDescribeListenersPaginator(client, &elasticloadbalancingv2.DescribeListenersInput{LoadBalancerArn: aws.String(lbARN)})
	var out []elbtypes.Listener
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("describe listeners for %s: %w", lbARN, err)
		}
		out = append(out, page.Listeners...)
	}
	return out, nil
}

func describeAllRules(ctx context.Context, client *elasticloadbalancingv2.Client, listenerARN string) ([]elbtypes.Rule, error) {
	paginator := elasticloadbalancingv2.NewDescribeRulesPaginator(client, &elasticloadbalancingv2.DescribeRulesInput{ListenerArn: aws.String(listenerARN)})
	var out []elbtypes.Rule
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("describe listener rules for %s: %w", listenerARN, err)
		}
		out = append(out, page.Rules...)
	}
	return out, nil
}

func awsResource(key string, arn string, id string, accountID string, typ string, region string, tags map[string]string, attrs map[string]string) Resource {
	return Resource{
		TerraformAddress: key,
		ARN:              arn,
		ID:               id,
		AccountID:        accountID,
		Type:             typ,
		Region:           region,
		Tags:             tags,
		Attributes:       compactMap(attrs),
	}
}

func addRelationship(inventory *AWSInventory, from string, to string, typ string, source string, confidence string) {
	if from == "" || to == "" {
		return
	}
	inventory.Relationships = append(inventory.Relationships, Relationship{
		From:       from,
		To:         to,
		Type:       typ,
		Source:     source,
		Confidence: confidence,
	})
}

func ec2Tags(tags []ec2types.Tag) map[string]string {
	out := make(map[string]string, len(tags))
	for _, tag := range tags {
		key := aws.ToString(tag.Key)
		if key == "" {
			continue
		}
		out[key] = aws.ToString(tag.Value)
	}
	return compactMap(out)
}

func compactMap(values map[string]string) map[string]string {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]string, len(values))
	for key, value := range values {
		if key == "" || value == "" {
			continue
		}
		out[key] = value
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func ec2ARN(region string, accountID string, typ string, id string) string {
	if region == "" || accountID == "" || typ == "" || id == "" {
		return ""
	}
	return fmt.Sprintf("arn:aws:ec2:%s:%s:%s/%s", region, accountID, typ, id)
}

func boolPtr(value bool) *bool {
	return &value
}

func routeTablePublic(table ec2types.RouteTable) bool {
	for _, route := range table.Routes {
		if routePublic(route) {
			return true
		}
	}
	return false
}

func routePublic(route ec2types.Route) bool {
	target := aws.ToString(route.GatewayId)
	if !strings.HasPrefix(target, "igw-") {
		return false
	}
	return publicCIDR(aws.ToString(route.DestinationCidrBlock)) || publicCIDR(aws.ToString(route.DestinationIpv6CidrBlock))
}

func publicCIDR(cidr string) bool {
	switch cidr {
	case "0.0.0.0/0", "::/0":
		return true
	default:
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			return false
		}
		ones, bits := network.Mask.Size()
		return ones == 0 && bits > 0
	}
}

func markResourcePublic(resources map[string]Resource, id string) {
	resource, ok := resources[id]
	if !ok {
		return
	}
	resource.Public = boolPtr(true)
	resources[id] = resource
}

func publicIngressPorts(permissions []ec2types.IpPermission) []string {
	ports := make([]string, 0)
	for _, permission := range permissions {
		if !permissionAllowsPublic(permission) {
			continue
		}
		from := aws.ToInt32(permission.FromPort)
		to := aws.ToInt32(permission.ToPort)
		switch {
		case permission.IpProtocol != nil && aws.ToString(permission.IpProtocol) == "-1":
			ports = append(ports, "all")
		case from == to:
			ports = append(ports, strconv.Itoa(int(from)))
		default:
			ports = append(ports, fmt.Sprintf("%d-%d", from, to))
		}
	}
	sort.Strings(ports)
	return ports
}

func permissionAllowsPublic(permission ec2types.IpPermission) bool {
	for _, ipRange := range permission.IpRanges {
		if publicCIDR(aws.ToString(ipRange.CidrIp)) {
			return true
		}
	}
	for _, ipRange := range permission.Ipv6Ranges {
		if publicCIDR(aws.ToString(ipRange.CidrIpv6)) {
			return true
		}
	}
	return false
}

func natPublicIPs(gateway ec2types.NatGateway) []string {
	ips := make([]string, 0, len(gateway.NatGatewayAddresses))
	for _, address := range gateway.NatGatewayAddresses {
		if address.PublicIp != nil {
			ips = append(ips, aws.ToString(address.PublicIp))
		}
	}
	sort.Strings(ips)
	return ips
}

func targetResourceID(targetType elbtypes.TargetTypeEnum, region string, accountID string, health elbtypes.TargetHealthDescription) string {
	if health.Target == nil {
		return ""
	}
	id := aws.ToString(health.Target.Id)
	switch targetType {
	case elbtypes.TargetTypeEnumInstance:
		return id
	case elbtypes.TargetTypeEnumLambda:
		return id
	case elbtypes.TargetTypeEnumAlb:
		return id
	case elbtypes.TargetTypeEnumIp:
		if health.Target.Port == nil {
			return id
		}
		return id + ":" + strconv.Itoa(int(aws.ToInt32(health.Target.Port)))
	default:
		return firstNonEmpty(id, ec2ARN(region, accountID, "target", id))
	}
}

func cloudFrontOrigins(distribution cftypes.DistributionSummary) []string {
	if distribution.Origins == nil {
		return nil
	}
	origins := make([]string, 0, len(distribution.Origins.Items))
	for _, origin := range distribution.Origins.Items {
		target := firstNonEmpty(aws.ToString(origin.DomainName), aws.ToString(origin.Id))
		if target != "" {
			origins = append(origins, target)
		}
	}
	sort.Strings(origins)
	return origins
}
