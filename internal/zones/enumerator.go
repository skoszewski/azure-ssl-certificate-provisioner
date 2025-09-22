package zones

import (
	"context"
	"log"
	"strings"

	"azure-ssl-certificate-provisioner/pkg/azure"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/dns/armdns"
)

// ProcessorFunc defines the function signature for processing FQDNs
type ProcessorFunc func(ctx context.Context, fqdn string, expireThreshold int)

// Enumerator handles DNS zone and record enumeration
type Enumerator struct {
	azureClients *azure.Clients
}

// NewEnumerator creates a new zones enumerator
func NewEnumerator(azureClients *azure.Clients) *Enumerator {
	return &Enumerator{
		azureClients: azureClients,
	}
}

// EnumerateAndProcess enumerates DNS zones and records, calling the processor function for each valid FQDN
func (e *Enumerator) EnumerateAndProcess(ctx context.Context, zones []string, resourceGroupName string, expireThreshold int, processor ProcessorFunc) error {
	// Determine which zones to process
	zonesToProcess, err := e.determineZonesToProcess(ctx, zones, resourceGroupName)
	if err != nil {
		return err
	}

	if len(zonesToProcess) == 0 {
		log.Printf("No DNS zones found in resource group: %s", resourceGroupName)
		return nil
	}

	// Process zones
	for _, zone := range zonesToProcess {
		if err := e.processZone(ctx, zone, resourceGroupName, expireThreshold, processor); err != nil {
			log.Printf("Error processing zone %s: %v", zone, err)
			continue
		}
	}

	return nil
}

// determineZonesToProcess determines which zones to process based on input
func (e *Enumerator) determineZonesToProcess(ctx context.Context, zones []string, resourceGroupName string) ([]string, error) {
	var zonesToProcess []string

	if len(zones) == 0 {
		// If no zones specified, get all zones from the resource group
		log.Printf("No zones specified, scanning all DNS zones in resource group: %s", resourceGroupName)
		zonesPager := e.azureClients.DNSZones.NewListByResourceGroupPager(resourceGroupName, nil)

		for zonesPager.More() {
			zonesPage, err := zonesPager.NextPage(ctx)
			if err != nil {
				log.Printf("failed to list DNS zones in resource group %s: %v", resourceGroupName, err)
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
func (e *Enumerator) processZone(ctx context.Context, zone string, resourceGroupName string, expireThreshold int, processor ProcessorFunc) error {
	log.Printf("Processing DNS zone: %s", zone)
	pager := e.azureClients.DNS.NewListAllByDNSZonePager(resourceGroupName, zone, nil)

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			log.Printf("failed to list record sets for zone %s: %v", zone, err)
			return err
		}

		for _, rs := range page.Value {
			if rs == nil {
				continue
			}

			// Check if this record should be processed
			if !e.shouldProcessRecord(rs) {
				continue
			}

			fqdn := *rs.Name + "." + zone
			rsType := strings.TrimPrefix(*rs.Type, "Microsoft.Network/dnszones/")

			log.Printf("Found record %s (%s).", fqdn, rsType)
			processor(ctx, fqdn, expireThreshold)
		}
	}

	return nil
}

// shouldProcessRecord determines if a DNS record should be processed
func (e *Enumerator) shouldProcessRecord(rs *armdns.RecordSet) bool {
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
