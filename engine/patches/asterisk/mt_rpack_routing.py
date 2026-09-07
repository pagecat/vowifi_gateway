import re, sys

# PATCH_RPACK_ROUTING4: fix MT (mobile-terminated) SMS RP-ACK so the carrier accepts it.
#
# The stock sysmocom send_rpack() sends the RP-ACK to endpoint->smsc_uri and lets PJSIP
# resolve/open a transport. Against a real ePDG this fails several ways (all verified on live
# networks by SIP wire capture):
#   1. Wrong target: the RP-ACK must go to the SMSC signalling address that DELIVERED the
#      SMS = the P-Asserted-Identity of the incoming MESSAGE, not the SMSC E.164 URI.
#      Sending to smsc_uri gets "400 SIP Parser Error" (Telus).
#   2. EADDRINUSE (120098): with a raw-IP request-URI, PJSIP opens a NEW connection from the
#      IMS local port, colliding with the registered IMS socket. Must pin the tdata to the
#      transport the SMS arrived on (pjsip_tx_data_set_transport) so it reuses the open socket.
#   3. FQDN P-Asserted-Identity (EE UK, CTExcel UK and similar): the SMSC identity is an
#      IMS-INTERNAL FQDN (e.g. smg102cro.ims.mnc030.mcc234.3gppnetwork.org) that only resolves
#      inside the carrier IMS. Asterisk's res_pjsip resolver queries it for real -- and only for
#      AAAA when the IMS transport is IPv6 -- and logs "Resolution completed - 0 viable targets",
#      so the RP-ACK is NEVER transmitted -> no delivery confirmation -> the SMSC re-pushes the
#      unacked backlog on every new inbound (the "same SMS repeats" symptom).
#
#      PATCH_RPACK_ROUTING2 tried to fix this by pre-seeding tdata->dest_info with the arrival
#      transport's peer. That does not work: ast_sip_send_request() sends STATEFULLY
#      (pjsip_endpt_send_request -> UAC transaction) and the transaction picks its destination
#      with pjsip_get_request_dest(), which consults ONLY the topmost TYPED Route header
#      (pjsip_msg_find_hdr(.., PJSIP_H_ROUTE, ..)) and otherwise falls back to the request-URI;
#      tdata->dest_info is ignored on that path. Worse, the Service-Route entries this function
#      adds go in through ast_sip_add_header(), which builds a pjsip_generic_string_hdr
#      (PJSIP_H_OTHER) whose name merely reads "Route" -- invisible to that typed lookup. So the
#      RP-ACK was never actually loose-routed at all; PJSIP always routed it by request-URI, i.e.
#      by the unresolvable SMSC FQDN. Telus only ever worked because its PAI is a raw IP.
#
#      Fix (v3): when the PAI host is NOT an IP literal, insert a REAL typed Route header
#      (ast_sip_set_outbound_proxy) pointing at the P-CSCF -- the connected peer of the transport
#      the SMS arrived on, always an IP literal handed to us by the ePDG. pjsip_get_request_dest()
#      then returns that IP ("Target is an IP address, skipping resolution"), the request-URI
#      stays the SMSC PAI, and the RP-ACK goes back on the incoming IMS link to the P-CSCF, which
#      loose-routes it onward to the SMSC -- exactly how a native UE writes the RP-ACK back.
#      Raw-IP PAIs (Telus) keep the existing path untouched.
#   4. Two bugs that made 3. a no-op on some hosts (both fixed here, v4):
#      a. The "is the PAI host an IP literal?" test used pj_sockaddr_parse(). That function is NOT
#         a pure parser: for a non-numeric host it falls through to pj_sockaddr_init() ->
#         pj_gethostbyname(), i.e. a real DNS lookup. On a host whose resolver answers every name
#         (a fake-IP resolver, a wildcard/captive DNS, a search-domain that always matches) the
#         lookup SUCCEEDS, the FQDN is misclassified as an IP literal, and the entire FQDN branch
#         is skipped -- silently, with no log line. Use pj_inet_pton() instead: numeric-only, no
#         resolver involvement, which is what "is this an IP literal" actually means.
#      b. The Route value was built without angle brackets ("sip:host;lr"). RFC 3261 wants
#         name-addr for Route, and in addr-spec form pjsip_parse_hdr() binds ";lr" as a HEADER
#         parameter, not a URI parameter -- so sip_uri->lr_param stays 0 and pjsip_get_request_dest()
#         takes the STRICT-routing branch, swapping the request-URI. Emit "<sip:host;lr>" so lr
#         lands on the URI and loose routing applies.
#      The confirmation lines are LOG_NOTICE (one per inbound SMS) rather than ast_debug so this
#      path can be verified without turning Asterisk debug up.
# With these fixes the carrier returns 200 OK / 202 Accepted and stops re-pushing the queue.

FIXED_FN = r'''static pj_status_t send_rpack(pjsip_rx_data *rdata, unsigned char ack_ref)
{
	/* PATCH_RPACK_ROUTING4 */
	pj_status_t status;
	char buf[7];
	char pai_buf[512];
	char reqm_buf[600];
	buf[0] = 2; /* RPACK mobile-to-network.  */
	buf[1] = ack_ref;
	buf[2] = 0x41;
	buf[3] = 0x02;
	buf[4] = 0x00;
	buf[5] = 0x00;

	struct ast_sip_endpoint *endpoint = ast_pjsip_rdata_get_endpoint(rdata);
	ast_assert(endpoint != NULL);
	pjsip_tx_data *tdata;

	struct ast_sip_transport_state *transport_state = ast_sip_get_transport_state(endpoint->transport);
	if (!transport_state) {
		ast_log(LOG_ERROR, "Failed to get transport state\n");
		return PJ_ENOMEM;
	}

	/* Target = P-Asserted-Identity of the incoming MESSAGE (the SMSC signalling address),
	 * routed via the Service-Route. Fall back to the From URI. Append ;transport=tcp so
	 * PJSIP reuses the established IMS TCP transport. */
	static const pj_str_t PAI = { "P-Asserted-Identity", 19 };
	pjsip_generic_string_hdr *pai_hdr = (pjsip_generic_string_hdr *)
		pjsip_msg_find_hdr_by_name(rdata->msg_info.msg, &PAI, NULL);
	const char *base_uri = NULL;
	if (pai_hdr) {
		int n = (int)pai_hdr->hvalue.slen;
		const char *s = pai_hdr->hvalue.ptr;
		while (n > 0 && (*s == ' ' || *s == '<')) { s++; n--; }
		while (n > 0 && (s[n-1] == ' ' || s[n-1] == '>')) { n--; }
		if (n > 0 && n < (int)sizeof(pai_buf)) {
			memcpy(pai_buf, s, n);
			pai_buf[n] = '\0';
			base_uri = pai_buf;
		}
	}
	if (!base_uri) {
		ssize_t size = pjsip_uri_print(PJSIP_URI_IN_REQ_URI,
			pjsip_uri_get_uri(rdata->msg_info.from->uri), pai_buf, sizeof(pai_buf) - 1);
		if (size <= 0 || size >= (ssize_t)sizeof(pai_buf)) {
			return PJ_ENOMEM;
		}
		pai_buf[size] = '\0';
		base_uri = pai_buf;
	}
	if (strstr(base_uri, "transport=")) {
		snprintf(reqm_buf, sizeof(reqm_buf), "%s", base_uri);
	} else {
		snprintf(reqm_buf, sizeof(reqm_buf), "%s;transport=tcp", base_uri);
	}

	status = ast_sip_create_request("MESSAGE", NULL, endpoint, reqm_buf, NULL, &tdata);
	if (status) {
		ast_log(LOG_WARNING, "PJSIP MESSAGE - Could not create RP-ACK request\n");
		return status;
	}

	/* Pin to the transport the SMS arrived on -> reuse the open IMS socket (no EADDRINUSE). */
	{
		pjsip_tpselector tp_sel;
		memset(&tp_sel, 0, sizeof(tp_sel));
		tp_sel.type = PJSIP_TPSELECTOR_TRANSPORT;
		tp_sel.u.transport = rdata->tp_info.transport;
		pjsip_tx_data_set_transport(tdata, &tp_sel);
	}

	/* If the SMSC identity (P-Asserted-Identity) is an FQDN it is IMS-internal and does not
	 * resolve on our resolver -- res_pjsip logs "Resolution completed - 0 viable targets" and the
	 * RP-ACK is never transmitted, so the SMSC re-pushes the unacked backlog on every new inbound
	 * (the "same SMS repeats" bug). The destination of a stateful send is chosen by
	 * pjsip_get_request_dest(), which looks at the topmost TYPED Route header and otherwise falls
	 * back to the request-URI; tdata->dest_info is NOT consulted there, and the Service-Route
	 * entries added below are generic string headers (PJSIP_H_OTHER) that the typed lookup cannot
	 * see. So insert a real Route header pointing at the P-CSCF -- the connected peer of the
	 * transport this SMS arrived on, always an IP literal -- and PJSIP skips resolution entirely
	 * and writes the RP-ACK back on the incoming IMS link, which loose-routes it onward to the
	 * SMSC, exactly how a native UE does it. The request-URI stays the SMSC PAI. Raw-IP PAIs
	 * (e.g. Telus) are left on the previously verified path, untouched. */
	{
		pj_bool_t pai_is_ip = PJ_FALSE;
		pjsip_uri *pu = pjsip_parse_uri(tdata->pool, (char *)base_uri,
			strlen(base_uri), 0);
		if (pu && (PJSIP_URI_SCHEME_IS_SIP(pu) || PJSIP_URI_SCHEME_IS_SIPS(pu))) {
			pjsip_sip_uri *su = (pjsip_sip_uri *)pjsip_uri_get_uri(pu);
			pj_str_t h = su->host;
			pj_in_addr v4;
			pj_in6_addr v6;

			/* An IPv6 literal may still carry its brackets here; pj_inet_pton wants it bare. */
			if (h.slen >= 2 && h.ptr[0] == '[' && h.ptr[h.slen - 1] == ']') {
				h.ptr++;
				h.slen -= 2;
			}
			/* pj_inet_pton is numeric-only. Do NOT use pj_sockaddr_parse here: it resolves
			 * non-numeric hosts via pj_gethostbyname, so a wildcard/fake-IP resolver makes
			 * every FQDN look like an IP literal and silently disables this whole branch. */
			if (h.slen > 0) {
				pai_is_ip = (pj_inet_pton(pj_AF_INET(), &h, &v4) == PJ_SUCCESS) ||
					(pj_inet_pton(pj_AF_INET6(), &h, &v6) == PJ_SUCCESS);
			}
		}
		if (!pai_is_ip && rdata->tp_info.transport) {
			pjsip_transport *itp = rdata->tp_info.transport;
			char pcscf[PJ_INET6_ADDRSTRLEN + 16];
			char proxy[PJ_INET6_ADDRSTRLEN + 64];

			/* flags 1|2 = append ":port" and bracket an IPv6 literal -> "[2a01:..::1]:5063".
			 * Angle brackets are required: in addr-spec form pjsip binds ";lr" as a header
			 * parameter, leaving lr_param unset and sending us down the strict-routing path. */
			if (pj_sockaddr_print(&itp->key.rem_addr, pcscf, sizeof(pcscf), 3)) {
				snprintf(proxy, sizeof(proxy), "<sip:%s;lr;transport=tcp>", pcscf);
				if (ast_sip_set_outbound_proxy(tdata, proxy)) {
					ast_log(LOG_WARNING, "RP-ACK: could not build P-CSCF route %s "
						"for FQDN SMSC '%s' -- delivery confirmation will not "
						"reach the SMSC\n", proxy, base_uri);
				} else {
					ast_log(LOG_NOTICE, "RP-ACK for FQDN SMSC '%s' routed via "
						"P-CSCF %s (DNS bypassed)\n", base_uri, proxy);
				}
			} else {
				ast_log(LOG_WARNING, "RP-ACK: could not read the P-CSCF address off the "
					"arrival transport for FQDN SMSC '%s'\n", base_uri);
			}

			/* Belt and braces for any path that ends up sending statelessly: pre-resolve to
			 * the same peer so no resolver call can creep back in. */
			tdata->dest_info.name = itp->remote_name.host;
			tdata->dest_info.cur_addr = 0;
			tdata->dest_info.addr.count = 1;
			tdata->dest_info.addr.entry[0].type = (pjsip_transport_type_e) itp->key.type;
			tdata->dest_info.addr.entry[0].priority = 0;
			tdata->dest_info.addr.entry[0].weight = 0;
			pj_sockaddr_cp(&tdata->dest_info.addr.entry[0].addr, &itp->key.rem_addr);
			tdata->dest_info.addr.entry[0].addr_len = itp->addr_len;
		} else if (pai_is_ip) {
			ast_log(LOG_NOTICE, "RP-ACK: SMSC identity '%s' is an IP literal; using the "
				"pinned-transport path\n", base_uri);
		}
	}

	ao2_lock(transport_state);
	if (transport_state->service_routes) {
		int idx;
		for (idx = 0; idx < AST_VECTOR_SIZE(transport_state->service_routes); ++idx) {
			char *service_route = AST_VECTOR_GET(transport_state->service_routes, idx);
			ast_sip_add_header(tdata, "Route", service_route);
		}
	}
	ast_sip_add_header(tdata, "Security-Verify", transport_state->volte.security_server);
	if (transport_state->volte.p_access_network_info[0]) {
		ast_sip_add_header(tdata, "P-Access-Network-Info", transport_state->volte.p_access_network_info);
	}
	ao2_unlock(transport_state);

	ast_sip_add_header(tdata, "Require", "sec-agree");
	ast_sip_add_header(tdata, "Proxy-Require", "sec-agree");
	ast_sip_add_header(tdata, "Supported", "path, sec-agree");

	set_preferred_identity(tdata, transport_state->volte.p_associated_uri);
	ast_sip_update_from(tdata, transport_state->volte.p_associated_uri);
	volte_add_contact_params(tdata, PJ_TRUE, endpoint->contact_user,
				 volte_msg_contact_params);

	pjsip_cid_hdr *call_id_hdr = (pjsip_cid_hdr*) pjsip_msg_find_hdr(rdata->msg_info.msg, PJSIP_H_CALL_ID, NULL);
	if (call_id_hdr) {
		status = add_value_string_hdr(tdata, &STR_IN_REPLY_TO, &call_id_hdr->id);
		if (status)
			return status;
	}

	ast_sip_add_header(tdata, "Accept-Contact", "*;+g.3gpp.smsip");
	ast_sip_add_header(tdata, "Allow", "MESSAGE");
	ast_sip_add_header(tdata, "Request-Disposition", "no-fork");

	struct ast_sip_body body = {
		.type = "application",
		.subtype = "vnd.3gpp.sms",
		.body_text = buf
	};

	status = ast_sip_add_binary_body(tdata, &body, 6);
	if (status) {
		pjsip_tx_data_dec_ref(tdata);
		ast_log(LOG_ERROR, "PJSIP MESSAGE - Could not add body to RP-ACK\n");
		return status;
	}

	status = ast_sip_send_request(tdata, NULL, endpoint, NULL, NULL);
	if (status) {
		ast_log(LOG_ERROR, "PJSIP MESSAGE - Could not send RP-ACK\n");
		return status;
	}

	return PJ_SUCCESS;
}'''

f = '/home/asterisk-build/asterisk/res/res_pjsip_messaging.c'
s = open(f).read()
if 'PATCH_RPACK_ROUTING4' in s:
    print("already patched"); sys.exit(0)

start = s.find('static pj_status_t send_rpack(pjsip_rx_data *rdata, unsigned char ack_ref)')
if start < 0:
    print("PATTERN NOT FOUND: send_rpack signature"); sys.exit(1)
# brace-match to find the end of the function
i = s.find('{', start)
depth = 0
end = -1
for j in range(i, len(s)):
    if s[j] == '{': depth += 1
    elif s[j] == '}':
        depth -= 1
        if depth == 0:
            end = j + 1
            break
if end < 0:
    print("BRACE MATCH FAILED"); sys.exit(1)

s2 = s[:start] + FIXED_FN + s[end:]
open(f, 'w').write(s2)
print("patched OK (send_rpack replaced, %d -> %d bytes)" % (end - start, len(FIXED_FN)))
