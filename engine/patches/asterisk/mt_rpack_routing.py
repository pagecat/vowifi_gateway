import re, sys

# PATCH_RPACK_ROUTING2: fix MT (mobile-terminated) SMS RP-ACK so the carrier accepts it.
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
#   3. FQDN P-Asserted-Identity (EE UK and similar): the SMSC identity is an IMS-INTERNAL FQDN
#      (e.g. smg101wvn.ims.mnc030.mcc234.3gppnetwork.org) that only resolves inside the carrier
#      IMS -> NXDOMAIN on our resolver. PJSIP tries to DNS-resolve the request-URI host BEFORE
#      the pinned transport can carry it, resolution fails, and the RP-ACK is NEVER transmitted
#      -> no delivery confirmation -> the SMSC re-pushes the unacked backlog on every new inbound
#      (the "same SMS repeats" symptom). Fix: when the PAI host is NOT an IP literal, pre-seed
#      tdata->dest_info with the arrival transport's connected peer (the P-CSCF) so
#      pjsip_endpt_send_request skips DNS entirely and sends the RP-ACK back on the incoming IMS
#      link to the P-CSCF, which then loose-routes it onward to the SMSC -- exactly how a native
#      UE writes the RP-ACK back. Raw-IP PAIs (Telus) keep the existing path untouched.
# With these fixes the carrier returns 200 OK / 202 Accepted and stops re-pushing the queue.

FIXED_FN = r'''static pj_status_t send_rpack(pjsip_rx_data *rdata, unsigned char ack_ref)
{
	/* PATCH_RPACK_ROUTING2 */
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

	/* If the SMSC identity (P-Asserted-Identity) is an FQDN (IMS-internal, unresolvable on our
	 * resolver -> NXDOMAIN), do NOT let PJSIP DNS-resolve the request-URI host: that fails and the
	 * RP-ACK never leaves, so the SMSC re-pushes the unacked backlog on every new inbound (the
	 * "same SMS repeats" bug). Instead pre-seed tdata->dest_info with the arrival transport's
	 * connected peer (the P-CSCF) so pjsip_endpt_send_request skips resolution and sends the RP-ACK
	 * back on the incoming IMS link to the P-CSCF, which loose-routes it onward to the SMSC --
	 * exactly how a native UE writes the RP-ACK back. Raw-IP PAIs (e.g. Telus) are left untouched. */
	{
		pj_bool_t pai_is_ip = PJ_FALSE;
		pjsip_uri *pu = pjsip_parse_uri(tdata->pool, (char *)base_uri,
			strlen(base_uri), 0);
		if (pu && (PJSIP_URI_SCHEME_IS_SIP(pu) || PJSIP_URI_SCHEME_IS_SIPS(pu))) {
			pjsip_sip_uri *su = (pjsip_sip_uri *)pjsip_uri_get_uri(pu);
			pj_sockaddr tmp;
			pai_is_ip = (pj_sockaddr_parse(pj_AF_UNSPEC(), 0, &su->host, &tmp) == PJ_SUCCESS);
		}
		if (!pai_is_ip && rdata->tp_info.transport) {
			pjsip_transport *itp = rdata->tp_info.transport;
			tdata->dest_info.name = itp->remote_name.host;
			tdata->dest_info.cur_addr = 0;
			tdata->dest_info.addr.count = 1;
			tdata->dest_info.addr.entry[0].type = (pjsip_transport_type_e) itp->key.type;
			tdata->dest_info.addr.entry[0].priority = 0;
			tdata->dest_info.addr.entry[0].weight = 0;
			pj_sockaddr_cp(&tdata->dest_info.addr.entry[0].addr, &itp->key.rem_addr);
			tdata->dest_info.addr.entry[0].addr_len = itp->addr_len;
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
if 'PATCH_RPACK_ROUTING2' in s:
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
