//  Copyright (c) 2022 Cisco Systems, Inc. and others.  All rights reserved.
package config

import "fmt"

/*
 * Global Configuration variables
 */
var (
	LogFile       string
	ListeningPort int
	MaxThreads    int

	// Postgres settings
	PgHost     string
	PgPort     int
	PgUser     string
	PgPassword string
	PgDbname   string
)

/*
 * Constants that could be moved to dynamic/user defined configuration
 */
const (
	NoPrefixesfound     = "% No prefixes found.\r\n"
	ErrorOutOfResources = "% ERROR: Out of resources, try again later.\r\n"
	ErrorInvalidRequest = "% ERROR: Invalid request.\r\n"
	ErrorDbConnectError = "% ERROR: Cannot process request at this time\r\n"
	ErrorDbQueryError   = "% No entries found for prefix.\r\n"

	HelpUsage = "Usage: whois -h <server> -p <port> <command>\r\n" +
		"\r\nCOMMAND:\r\n\r\n" +
		"   ip[/bits] [peer like string] -- Lookup IPv4/IPv6 address or network\r\n" +
		"                       Optionally add peer name prefix string (e.g., jfk01) to scope query to specific peer(s)\r\n"
)

func GetPgInfo() string {
	return fmt.Sprintf("host=%s port=%d user=%s "+
		"password=%s dbname=%s sslmode=require connect_timeout=4 "+
		"fallback_application_name=obmp-whoisd",
		PgHost, PgPort, PgUser, PgPassword, PgDbname)
}
