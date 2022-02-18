//  Copyright (c) 2022 Cisco Systems, Inc. and others.  All rights reserved.
package whois

import "database/sql"

// All handlers implement the handler interface
type Handler interface {
	process(db *sql.DB, client_info string,
		request []byte, stopCh <-chan struct{}) []byte
}
