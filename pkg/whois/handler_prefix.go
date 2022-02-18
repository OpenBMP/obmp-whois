//  Copyright (c) 2022 Cisco Systems, Inc. and others.  All rights reserved.
package whois

import (
	"database/sql"
	"fmt"
	"github.com/openbmp/obmp-whois/config"
	log "github.com/sirupsen/logrus"
	"strings"
	"time"
)

type PrefixRecord struct {
	firstSeenTimestamp  time.Time
	lastModified        time.Time
	routerName          string
	peerName            string
	peerAddr            string
	prefix              string
	bgpPathId           int
	bgpLabels           string
	bgpOriginAsn        int
	bgpMed              int
	bgpLocalPref        int
	bgpNextHop          string
	bgpAsPath           string
	bgpCommunities      string
	bgpExtCommunities   string
	bgpLargeCommunities string
	bgpClusterList      string
	bgpAggregator       sql.NullString

	prefixCity      sql.NullString
	prefixStateprov sql.NullString
	prefixCountry   sql.NullString

	AsnName      sql.NullString
	AsnOrgName   sql.NullString
	AsnOrgId     sql.NullString
	AsnStateProv sql.NullString
	AsnCountry   sql.NullString
	AsnSource    sql.NullString

	RpkiOriginAsn sql.NullInt64

	IrrOriginAsn sql.NullInt64
	IrrDescr     sql.NullString
	IrrSource    sql.NullString

	LsRouter sql.NullString
}

var ()

const (
	peerQuery = `AND peer_hash_id in ( (select hash_id from bgp_peers where name ilike '%s%%') )`

	// Format requires (prefix query, peer name like query)
	prefixQuery = `
	select distinct ip.*,
    	FIRST_VALUE(geo_ip.city) OVER (PARTITION BY ip.prefix ORDER BY geo_ip.ip DESC) as city,
    	FIRST_VALUE(geo_ip.stateprov) OVER (PARTITION BY ip.prefix ORDER BY geo_ip.ip DESC) as stateprov,
    	FIRST_VALUE(geo_ip.country) OVER (PARTITION BY ip.prefix ORDER BY geo_ip.ip DESC) as country,
        ia.as_name asn_name, ia.org_name as asn_org_name, ia.org_id as asn_org_id,
        ia.state_prov as asn_state_prov, ia.country as asn_country,ia.source as asn_source,
        rpki_origin_as,irr_origin_as,irr_source,irr_descr,
    	FIRST_VALUE(ls.local_router_name) OVER (PARTITION BY ip.prefix ORDER BY ls.prefix DESC) as ls_router
	FROM (SELECT firstaddedtimestamp,lastmodified,routername,peername,peeraddress,prefix,
        	path_id,labels,origin_as,med,localpref,nh,as_path,
	        communities,extcommunities,largecommunities,clusterlist,aggregator
		 from v_ip_routes
    		where prefix %s and iswithdrawn = False and prefixlen > 0
    		  %s
	    order by prefix desc
        limit 200
    	) ip
    LEFT JOIN geo_ip on (geo_ip.ip >>= ip.prefix AND geo_ip.ip != '0.0.0.0/0')
	LEFT JOIN global_ip_rib gr ON (gr.prefix = ip.prefix)
	LEFT JOIN info_asn ia ON (ia.asn = ip.origin_as)
    LEFT JOIN v_ls_prefixes ls ON (ls.prefix >>= ip.nh and length(ls.local_router_name) > 0)
	order by prefix desc,peername;
	`
)

type PrefixHandler struct {
}

func (h PrefixHandler) process(db *sql.DB,
	remote_info string, request []byte, stopCh <-chan struct{}) []byte {
	log.Infof("%s: requests lookup for IP %s", remote_info, request)

	var resp strings.Builder

	args := strings.SplitN(string(request), " ", 2)
	prefix := strings.SplitN(args[0], "/", 2)

	peer_like := ""
	if len(args) > 1 {
		log.Debugf("Peer name like '%s' requested", args[1])
		peer_like = fmt.Sprintf(peerQuery, args[1])
	}

	var query string

	// Perform exact query or range if bits were given
	if len(prefix) > 1 && len(prefix[1]) > 0 {
		log.Debugf("Requesting exact query %s/%s", prefix[0], prefix[1])
		fmt.Sprintf("= '%s'", args[0])

	} else {
		query = fmt.Sprintf(prefixQuery, fmt.Sprintf("&& '%s'", args[0]), peer_like)
	}

	rows, err := db.Query(query)
	log.Debugf("Query: %s", query)

	if err != nil {
		log.Errorf("%s: Error running query: ", err)
		return []byte(config.ErrorDbQueryError)
	}

	count := 0
	var prev_prefix string
	var prev_peerName string

	for rows.Next() {
		count++

		var pr PrefixRecord

		err = rows.Scan(
			&pr.firstSeenTimestamp,
			&pr.lastModified,
			&pr.routerName,
			&pr.peerName,
			&pr.peerAddr,
			&pr.prefix,
			&pr.bgpPathId,
			&pr.bgpLabels,
			&pr.bgpOriginAsn,
			&pr.bgpMed,
			&pr.bgpLocalPref,
			&pr.bgpNextHop,
			&pr.bgpAsPath,
			&pr.bgpCommunities,
			&pr.bgpExtCommunities,
			&pr.bgpLargeCommunities,
			&pr.bgpClusterList,
			&pr.bgpAggregator,
			&pr.prefixCity,
			&pr.prefixStateprov,
			&pr.prefixCountry,
			&pr.AsnName,
			&pr.AsnOrgName,
			&pr.AsnOrgId,
			&pr.AsnStateProv,
			&pr.AsnCountry,
			&pr.AsnSource,
			&pr.RpkiOriginAsn,
			&pr.IrrOriginAsn,
			&pr.IrrSource,
			&pr.IrrDescr,
			&pr.LsRouter,
		)

		if err != nil {
			log.Errorf("%s: Error processing query result: ", err)
			return []byte(config.ErrorDbQueryError)
		}

		// Dedup records
		if prev_peerName == pr.peerName && prev_prefix == pr.prefix {
			continue
		}

		prev_peerName = pr.peerName
		prev_prefix = pr.prefix

		resp.WriteString(fmtResultItem("BMPRouter", pr.routerName))
		resp.WriteString(fmtResultItem("Peer", fmt.Sprintf("%s [%s]", pr.peerName, pr.peerAddr)))
		resp.WriteString(fmtResultItem("Prefix", pr.prefix))

		if pr.IrrDescr.Valid && len(pr.IrrDescr.String) > 0 {
			firstnl := strings.Index(pr.IrrDescr.String, "\n")
			var descr string
			if firstnl > 0 {
				descr = pr.IrrDescr.String[0:firstnl]
			} else {
				descr = pr.IrrDescr.String
			}

			resp.WriteString(fmtResultItem("PrefixDescr", descr+" ("+pr.IrrSource.String+")"))
		}

		appendItem(&resp, fmtResultItem("PrefixCity", pr.prefixCity.String))
		appendItem(&resp, fmtResultItem("PrefixStateProv", pr.prefixStateprov.String))
		appendItem(&resp, fmtResultItem("PrefixCountry", pr.prefixCountry.String))

		appendItem(&resp, fmtResultItem("FirstSeenTs", pr.firstSeenTimestamp))
		appendItem(&resp, fmtResultItem("LastModifiedTs", pr.lastModified))
		appendItem(&resp, fmtResultItem("LSRouter", pr.LsRouter.String))

		appendItem(&resp, fmtResultItem("OriginAsn", fmt.Sprintf("AS%d", pr.bgpOriginAsn)))

		if pr.AsnName.Valid && len(pr.AsnName.String) > 0 {
			as_info := fmt.Sprintf("%s, %s, %s", pr.AsnName.String, pr.AsnOrgId.String, pr.AsnOrgName.String)
			appendItem(&resp, fmtResultItem("AsnInfo", as_info))
		}

		if pr.AsnStateProv.Valid && len(pr.AsnStateProv.String) > 0 {
			appendItem(&resp, fmtResultItem("AsnLocation", pr.AsnStateProv.String+", "+pr.AsnCountry.String))
		} else {
			appendItem(&resp, fmtResultItem("AsnLocation", pr.AsnCountry.String))
		}

		appendItem(&resp, fmtResultItem("BgpMed", pr.bgpMed))
		appendItem(&resp, fmtResultItem("BgpLocalPref", pr.bgpLocalPref))
		appendItem(&resp, fmtResultItem("BgpAsPath", pr.bgpAsPath))
		appendItem(&resp, fmtResultItem("BgpNextHop", pr.bgpNextHop))
		appendItem(&resp, fmtResultItem("BgpCommunities", pr.bgpCommunities))
		appendItem(&resp, fmtResultItem("BgpExtCommunities", pr.bgpExtCommunities))
		appendItem(&resp, fmtResultItem("BgpLargeCommunities", pr.bgpLargeCommunities))
		appendItem(&resp, fmtResultItem("BgpClusterList", pr.bgpClusterList))
		appendItem(&resp, fmtResultItem("BggAggregator", pr.bgpAggregator.String))
		appendItem(&resp, fmtResultItem("BgpLabels", pr.bgpLabels))

		resp.WriteByte('\n')

	}

	log.Infof("%s: done with lookup for IP %s", remote_info, request)

	if count <= 0 {
		return []byte(config.NoPrefixesfound)

	} else {
		resp.WriteString("\r\n")
		return []byte(resp.String())
	}
}
