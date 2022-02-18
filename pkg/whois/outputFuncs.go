//  Copyright (c) 2022 Cisco Systems, Inc. and others.  All rights reserved.
package whois

import (
	"fmt"
	"strings"
)

func fmtResultItem(label string, value interface{}) string {

	valueStr := fmt.Sprintf("%v", value)
	if len(valueStr) <= 0 {
		return ""
	} else {
		return fmt.Sprintf("%-20s %s\r\n", label+":", strings.TrimSpace(valueStr))
	}
}

func appendItem(sb *strings.Builder, value string) {

	if len(value) > 0 {
		sb.WriteString(value)
	}

}
