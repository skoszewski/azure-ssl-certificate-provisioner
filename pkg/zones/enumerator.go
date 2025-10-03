package zones

import (
	"context"
	"log"
	"strings"

	"azure-ssl-certificate-provisioner/pkg/azure"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/dns/armdns"
	"github.com/go-acme/lego/v4/platform/config/env"
	"github.com/go-acme/lego/v4/providers/dns/azuredns"
)

// ProcessorFunc defines the function signature for processing FQDNs
type ProcessorFunc func(ctx context.Context, fqdn string)

// EnumerateAndProcess enumerates DNS zones and records, calling the processor function for each valid FQDN
func EnumerateAndProcess(ctx context.Context, processor ProcessorFunc) error {

	zones := []string{}
	resourceGroupName := env.GetOrFile(azuredns.EnvResourceGroup)

	// Determine which zones to process
	zonesToProcess, err := determineZonesToProcess(ctx, zones)
	if err != nil {
		return err
	}

	if len(zonesToProcess) == 0 {
		log.Printf("No DNS zones found: resource_group=%s", resourceGroupName)
		return nil
	}

	// Process zones
	for _, zone := range zonesToProcess {
		if err := processZone(ctx, zone, processor); err != nil {
			log.Printf("Zone processing failed: zone=%s, error=%v", zone, err)
			continue
		}
	}

	return nil
}

// determineZonesToProcess determines which zones to process based on input
func determineZonesToProcess(ctx context.Context, zones []string) ([]string, error) {
	var zonesToProcess []string
	resourceGroupName := env.GetOrFile(azuredns.EnvResourceGroup)

	if len(zones) == 0 {
		// If no zones specified, get all zones from the resource group
		log.Printf("No zones specified, scanning all DNS zones in resource group: %s", resourceGroupName)
		zonesPager := azure.GetDnsZonesClient().NewListByResourceGroupPager(resourceGroupName, nil)

		for zonesPager.More() {
			zonesPage, err := zonesPager.NextPage(ctx)
			if err != nil {
				log.Printf("DNS zone listing failed: resource_group=%s, error=%v", resourceGroupName, err)
				return nil, err
			}

			for _, zone := range zonesPage.Value {
				if zone != nil && zone.Name != nil {
					zonesToProcess = append(zonesToProcess, *zone.Name)
				}
			}
		}

		log.Printf("Found %d DNS zone(s) to process: %v", len(zonesToProcess), zonesToProcess)
	} else {
		zonesToProcess = zones
		log.Printf("Processing specified zones: %v", zonesToProcess)
	}

	return zonesToProcess, nil
}

// processZone processes a single DNS zone
func processZone(ctx context.Context, zone string, processor ProcessorFunc) error {
	log.Printf("Processing DNS zone: %s", zone)
	resourceGroupName := env.GetOrFile(azuredns.EnvResourceGroup)
	pager := azure.GetDnsClient().NewListAllByDNSZonePager(resourceGroupName, zone, nil)

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			log.Printf("Record set listing failed: zone=%s, error=%v", zone, err)
			return err
		}

		for _, rs := range page.Value {
			if rs == nil {
				continue
			}

			// Check if this record should be processed
			if !shouldProcessRecord(rs) {
				continue
			}

			fqdn := *rs.Name + "." + zone
			rsType := strings.TrimPrefix(*rs.Type, "Microsoft.Network/dnszones/")

			log.Printf("Found record %s (%s).", fqdn, rsType)
			processor(ctx, fqdn)
		}
	}

	return nil
}

// shouldProcessRecord determines if a DNS record should be processed
func shouldProcessRecord(rs *armdns.RecordSet) bool {
	if rs.Properties == nil || rs.Properties.Metadata == nil {
		return false
	}

	val, ok := rs.Properties.Metadata["acme"]
	if val == nil || !ok || strings.ToLower(*val) != "true" {
		return false
	}

	if rs.Name == nil || rs.Type == nil {
		return false
	}

	rsType := strings.TrimPrefix(*rs.Type, "Microsoft.Network/dnszones/")
	if rsType != "A" && rsType != "CNAME" {
		return false
	}

	return true
}
