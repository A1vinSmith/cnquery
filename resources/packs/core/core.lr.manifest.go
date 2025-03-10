// Code generated by resources. DO NOT EDIT.
package core

import (
	"go.mondoo.com/cnquery/resources/lr/docs"
)

var ResourceDocs = docs.LrDocs{
	Resources: map[string]*docs.LrDocsEntry{
		"platform.exploits": {
			IsPrivate:        false,
			MinMondooVersion: "5.15.0",
			Fields: map[string]*docs.LrDocsField{
				"cvss": {
					MinMondooVersion: "5.15.0",
				},
				"stats": {
					MinMondooVersion: "5.15.0",
				},
			},
		},
		"ipmi.chassis": {
			IsPrivate:        false,
			MinMondooVersion: "5.15.0",
			Maturity:         "experimental",
			Fields: map[string]*docs.LrDocsField{
				"status": {
					MinMondooVersion: "5.15.0",
				},
				"systemBootOptions": {
					MinMondooVersion: "5.15.0",
				},
			},
		},
		"mondoo.asset": {
			IsPrivate:        false,
			MinMondooVersion: "5.15.0",
			Fields: map[string]*docs.LrDocsField{
				"platformIDs": {
					MinMondooVersion: "5.15.0",
				},
			},
		},
		"os": {
			IsPrivate:        false,
			MinMondooVersion: "5.15.0",
			Fields: map[string]*docs.LrDocsField{
				"machineid": {
					MinMondooVersion: "5.15.0",
				},
				"name": {
					MinMondooVersion: "5.15.0",
				},
				"path": {
					MinMondooVersion: "5.15.0",
				},
				"rebootpending": {
					MinMondooVersion: "5.15.0",
				},
				"updates": {
					MinMondooVersion: "5.15.0",
				},
				"uptime": {
					MinMondooVersion: "5.15.0",
				},
				"env": {
					MinMondooVersion: "5.15.0",
				},
				"hostname": {
					MinMondooVersion: "5.15.0",
				},
			}, Snippets: []docs.LrDocsSnippet{
				{
					Title: "Show all environment variables",
					Query: "os.env",
				},
				{
					Title: "Retrieve a single environment variable",
					Query: "os.env['windir']",
				},
			},
		},
		"os.rootcertificates": {
			IsPrivate:        false,
			MinMondooVersion: "5.15.0",
		},
		"platform.cves": {
			IsPrivate:        false,
			MinMondooVersion: "5.15.0",
			Fields: map[string]*docs.LrDocsField{
				"cvss": {
					MinMondooVersion: "5.15.0",
				},
				"stats": {
					MinMondooVersion: "5.15.0",
				},
			},
		},
		"mondoo.eol": {
			IsPrivate:        false,
			MinMondooVersion: "5.15.0",
			Fields: map[string]*docs.LrDocsField{
				"version": {
					MinMondooVersion: "5.15.0",
				},
				"date": {
					MinMondooVersion: "5.15.0",
				},
				"product": {
					MinMondooVersion: "5.15.0",
				},
			},
		},
		"ipmi": {
			IsPrivate:        false,
			MinMondooVersion: "5.15.0",
			Maturity:         "experimental",
			Fields: map[string]*docs.LrDocsField{
				"deviceID": {
					MinMondooVersion: "5.15.0",
				},
				"guid": {
					MinMondooVersion: "5.15.0",
				},
			},
		},
		"pkix.extension": {
			IsPrivate:        false,
			MinMondooVersion: "5.15.0",
			Fields: map[string]*docs.LrDocsField{
				"critical": {
					MinMondooVersion: "5.15.0",
				},
				"identifier": {
					MinMondooVersion: "5.15.0",
				},
				"value": {
					MinMondooVersion: "5.15.0",
				},
			},
		},
		"user": {
			IsPrivate:        false,
			MinMondooVersion: "5.15.0",
			Fields: map[string]*docs.LrDocsField{
				"authorizedkeys": {
					MinMondooVersion: "5.15.0",
				},
				"home": {
					MinMondooVersion: "5.15.0",
				},
				"sid": {
					MinMondooVersion: "5.15.0",
				},
				"uid": {
					MinMondooVersion: "5.15.0",
				},
				"enabled": {
					MinMondooVersion: "5.15.0",
				},
				"gid": {
					MinMondooVersion: "5.15.0",
				},
				"group": {
					MinMondooVersion: "5.15.0",
				},
				"name": {
					MinMondooVersion: "5.15.0",
				},
				"shell": {
					MinMondooVersion: "5.15.0",
				},
				"sshkeys": {
					MinMondooVersion: "5.15.0",
				},
			}, Snippets: []docs.LrDocsSnippet{
				{
					Title: "Display a specific user's home directory and UID",
					Query: "user(name: \"vagrant\") { home uid }\n",
				},
			},
		},
		"os.update": {
			IsPrivate:        false,
			MinMondooVersion: "5.15.0",
			Fields: map[string]*docs.LrDocsField{
				"category": {
					MinMondooVersion: "5.15.0",
				},
				"format": {
					MinMondooVersion: "5.15.0",
				},
				"name": {
					MinMondooVersion: "5.15.0",
				},
				"restart": {
					MinMondooVersion: "5.15.0",
				},
				"severity": {
					MinMondooVersion: "5.15.0",
				},
			},
		},
		"parse": {
			IsPrivate:        false,
			MinMondooVersion: "5.15.0",
		},
		"parse.json": {
			IsPrivate:        false,
			MinMondooVersion: "5.15.0",
			Fields: map[string]*docs.LrDocsField{
				"content": {
					MinMondooVersion: "5.15.0",
				},
				"file": {
					MinMondooVersion: "5.15.0",
				},
				"params": {
					MinMondooVersion: "5.15.0",
				},
			}, Snippets: []docs.LrDocsSnippet{
				{
					Title: "Parse JSON from string content",
					Query: "parse.json(content: '{ \"a\": \"b\"  }').params",
				},
				{
					Title: "Parse JSON from file",
					Query: "parse.json(\"/path/to/test.json\").params",
				},
			},
		},
		"socket": {
			IsPrivate:        false,
			MinMondooVersion: "5.15.0",
			Fields: map[string]*docs.LrDocsField{
				"address": {
					MinMondooVersion: "5.15.0",
				},
				"port": {
					MinMondooVersion: "5.15.0",
				},
				"protocol": {
					MinMondooVersion: "5.15.0",
				},
			},
		},
		"audit.cvss": {
			IsPrivate:        true,
			MinMondooVersion: "5.15.0",
			Fields: map[string]*docs.LrDocsField{
				"score": {
					MinMondooVersion: "5.15.0",
				},
				"vector": {
					MinMondooVersion: "5.15.0",
				},
			},
		},
		"audit.exploit": {
			IsPrivate:        true,
			MinMondooVersion: "5.15.0",
			Fields: map[string]*docs.LrDocsField{
				"id": {
					MinMondooVersion: "5.15.0",
				},
				"modified": {
					MinMondooVersion: "5.15.0",
				},
				"mrn": {
					MinMondooVersion: "5.15.0",
				},
				"worstScore": {
					MinMondooVersion: "5.15.0",
				},
			},
		},
		"parse.ini": {
			IsPrivate:        false,
			MinMondooVersion: "5.15.0",
			Fields: map[string]*docs.LrDocsField{
				"content": {
					MinMondooVersion: "5.15.0",
				},
				"delimiter": {
					MinMondooVersion: "5.15.0",
				},
				"file": {
					MinMondooVersion: "5.15.0",
				},
				"params": {
					MinMondooVersion: "5.15.0",
				},
				"sections": {
					MinMondooVersion: "5.15.0",
				},
			},
		},
		"port": {
			IsPrivate:        false,
			MinMondooVersion: "5.15.0",
			Fields: map[string]*docs.LrDocsField{
				"process": {
					MinMondooVersion: "5.15.0",
				},
				"protocol": {
					MinMondooVersion: "5.15.0",
				},
				"remoteAddress": {
					MinMondooVersion: "5.15.0",
				},
				"remotePort": {
					MinMondooVersion: "5.15.0",
				},
				"state": {
					MinMondooVersion: "5.15.0",
				},
				"user": {
					MinMondooVersion: "5.15.0",
				},
				"address": {
					MinMondooVersion: "5.15.0",
				},
				"port": {
					MinMondooVersion: "5.15.0",
				},
			},
		},
		"users": {
			IsPrivate:        false,
			MinMondooVersion: "5.15.0",
			Snippets: []docs.LrDocsSnippet{
				{
					Title: "Display all users and their UID",
					Query: "users { uid name }",
				},
				{
					Title: "Ensure user exists",
					Query: "users.one( name == 'root')",
				},
				{
					Title: "Ensure user does not exist",
					Query: "users.none(name == \"vagrant\")",
				},
				{
					Title: "Search for a specific SID and check for its values",
					Query: "users.where( sid == /S-1-5-21-\\d+-\\d+-\\d+-501/ ) {\n  name != \"Guest\"\n}\n",
				},
			},
		},
		"dns.dkimRecord": {
			IsPrivate:        false,
			MinMondooVersion: "5.15.0",
			Fields: map[string]*docs.LrDocsField{
				"publicKeyData": {
					MinMondooVersion: "5.15.0",
				},
				"serviceTypes": {
					MinMondooVersion: "5.15.0",
				},
				"valid": {
					MinMondooVersion: "5.15.0",
				},
				"dnsTxt": {
					MinMondooVersion: "5.15.0",
				},
				"domain": {
					MinMondooVersion: "5.15.0",
				},
				"flags": {
					MinMondooVersion: "5.15.0",
				},
				"keyType": {
					MinMondooVersion: "5.15.0",
				},
				"hashAlgorithms": {
					MinMondooVersion: "5.15.0",
				},
				"notes": {
					MinMondooVersion: "5.15.0",
				},
				"version": {
					MinMondooVersion: "5.15.0",
				},
			},
		},
		"file": {
			IsPrivate:        false,
			MinMondooVersion: "5.0.0",
			Fields: map[string]*docs.LrDocsField{
				"empty": {
					MinMondooVersion: "5.18.0",
				},
				"exists": {
					MinMondooVersion: "5.0.0",
				},
				"group": {
					MinMondooVersion: "5.0.0",
				},
				"path": {
					MinMondooVersion: "5.0.0",
				},
				"permissions": {
					MinMondooVersion: "5.0.0",
				},
				"user": {
					MinMondooVersion: "5.0.0",
				},
				"dirname": {
					MinMondooVersion: "5.0.0",
				},
				"content": {
					MinMondooVersion: "5.0.0",
				},
				"size": {
					MinMondooVersion: "5.0.0",
				},
				"basename": {
					MinMondooVersion: "5.0.0",
				},
			}, Snippets: []docs.LrDocsSnippet{
				{
					Title: "Test if a directory exists",
					Query: "file('/etc') {\n  exists\n  permissions.isDirectory\n}\n",
				},
			},
		},
		"group": {
			IsPrivate:        false,
			MinMondooVersion: "5.15.0",
			Fields: map[string]*docs.LrDocsField{
				"gid": {
					MinMondooVersion: "5.15.0",
				},
				"members": {
					MinMondooVersion: "5.15.0",
				},
				"name": {
					MinMondooVersion: "5.15.0",
				},
				"sid": {
					MinMondooVersion: "5.15.0",
				},
			},
		},
		"parse.certificates": {
			IsPrivate:        false,
			MinMondooVersion: "5.15.0",
			Fields: map[string]*docs.LrDocsField{
				"content": {
					MinMondooVersion: "5.15.0",
				},
				"file": {
					MinMondooVersion: "5.15.0",
				},
				"path": {
					MinMondooVersion: "5.15.0",
				},
			}, Snippets: []docs.LrDocsSnippet{
				{
					Title: "Parse Certificates from target file system",
					Query: "parse.certificates('/etc/ssl/cert.pem') { issuer.dn }",
				},
				{
					Title: "Parse Certificates from content",
					Query: "parse.certificates(content: 'PEM CONTENT') { issuer.dn }",
				},
			},
		},
		"tls": {
			IsPrivate:        false,
			MinMondooVersion: "5.15.0",
			Fields: map[string]*docs.LrDocsField{
				"socket": {
					MinMondooVersion: "5.15.0",
				},
				"versions": {
					MinMondooVersion: "5.15.0",
				},
				"certificates": {
					MinMondooVersion: "5.15.0",
				},
				"ciphers": {
					MinMondooVersion: "5.15.0",
				},
				"domainName": {
					MinMondooVersion: "5.15.0",
				},
				"extensions": {
					MinMondooVersion: "5.15.0",
				},
				"nonSniCertificates": {
					MinMondooVersion: "5.15.0",
				},
				"params": {
					MinMondooVersion: "5.15.0",
				},
			},
		},
		"audit.advisory": {
			IsPrivate:        true,
			MinMondooVersion: "5.15.0",
			Fields: map[string]*docs.LrDocsField{
				"worstScore": {
					MinMondooVersion: "5.15.0",
				},
				"description": {
					MinMondooVersion: "5.15.0",
				},
				"id": {
					MinMondooVersion: "5.15.0",
				},
				"modified": {
					MinMondooVersion: "5.15.0",
				},
				"mrn": {
					MinMondooVersion: "5.15.0",
				},
				"published": {
					MinMondooVersion: "5.15.0",
				},
				"title": {
					MinMondooVersion: "5.15.0",
				},
			},
		},
		"packages": {
			IsPrivate:        false,
			MinMondooVersion: "5.15.0",
		},
		"regex": {
			IsPrivate:        false,
			MinMondooVersion: "5.15.0",
			Fields: map[string]*docs.LrDocsField{
				"uuid": {
					MinMondooVersion: "5.15.0",
				},
				"creditCard": {
					MinMondooVersion: "5.15.0",
				},
				"emoji": {
					MinMondooVersion: "5.15.0",
				},
				"ipv6": {
					MinMondooVersion: "5.15.0",
				},
				"semver": {
					MinMondooVersion: "5.15.0",
				},
				"url": {
					MinMondooVersion: "5.15.0",
				},
				"email": {
					MinMondooVersion: "5.15.0",
				},
				"ipv4": {
					MinMondooVersion: "5.15.0",
				},
				"mac": {
					MinMondooVersion: "5.15.0",
				},
			},
		},
		"socketstats": {
			IsPrivate:        false,
			MinMondooVersion: "5.15.0",
			Fields: map[string]*docs.LrDocsField{
				"openPorts": {
					MinMondooVersion: "5.15.0",
				},
			},
		},
		"dns": {
			IsPrivate:        false,
			MinMondooVersion: "5.15.0",
			Maturity:         "experimental",
			Fields: map[string]*docs.LrDocsField{
				"fqdn": {
					MinMondooVersion: "5.15.0",
				},
				"mx": {
					MinMondooVersion: "5.15.0",
				},
				"params": {
					MinMondooVersion: "5.15.0",
				},
				"records": {
					MinMondooVersion: "5.15.0",
				},
				"dkim": {
					MinMondooVersion: "5.15.0",
				},
			},
		},
		"dns.mxRecord": {
			IsPrivate:        false,
			MinMondooVersion: "5.15.0",
			Maturity:         "experimental",
			Fields: map[string]*docs.LrDocsField{
				"domainName": {
					MinMondooVersion: "5.15.0",
				},
				"name": {
					MinMondooVersion: "5.15.0",
				},
				"preference": {
					MinMondooVersion: "5.15.0",
				},
			},
		},
		"parse.yaml": {
			IsPrivate:        false,
			MinMondooVersion: "5.15.0",
			Fields: map[string]*docs.LrDocsField{
				"file": {
					MinMondooVersion: "5.15.0",
				},
				"params": {
					MinMondooVersion: "5.15.0",
				},
				"content": {
					MinMondooVersion: "5.15.0",
				},
			},
		},
		"yaml.path": {
			IsPrivate:        false,
			MinMondooVersion: "5.15.0",
			Fields: map[string]*docs.LrDocsField{
				"jsonpath": {
					MinMondooVersion: "5.15.0",
				},
				"result": {
					MinMondooVersion: "5.15.0",
				},
				"filepath": {
					MinMondooVersion: "5.15.0",
				},
			},
		},
		"parse.plist": {
			IsPrivate:        false,
			MinMondooVersion: "5.15.0",
			Fields: map[string]*docs.LrDocsField{
				"file": {
					MinMondooVersion: "5.15.0",
				},
				"params": {
					MinMondooVersion: "5.15.0",
				},
				"content": {
					MinMondooVersion: "5.15.0",
				},
			},
		},
		"pkix.name": {
			IsPrivate:        false,
			MinMondooVersion: "5.15.0",
			Fields: map[string]*docs.LrDocsField{
				"dn": {
					MinMondooVersion: "5.15.0",
				},
				"extraNames": {
					MinMondooVersion: "5.15.0",
				},
				"locality": {
					MinMondooVersion: "5.15.0",
				},
				"province": {
					MinMondooVersion: "5.15.0",
				},
				"streetAddress": {
					MinMondooVersion: "5.15.0",
				},
				"commonName": {
					MinMondooVersion: "5.15.0",
				},
				"country": {
					MinMondooVersion: "5.15.0",
				},
				"id": {
					MinMondooVersion: "5.15.0",
				},
				"names": {
					MinMondooVersion: "5.15.0",
				},
				"organization": {
					MinMondooVersion: "5.15.0",
				},
				"organizationalUnit": {
					MinMondooVersion: "5.15.0",
				},
				"postalCode": {
					MinMondooVersion: "5.15.0",
				},
				"serialNumber": {
					MinMondooVersion: "5.15.0",
				},
			},
		},
		"ports": {
			IsPrivate:        false,
			MinMondooVersion: "5.15.0",
			Fields: map[string]*docs.LrDocsField{
				"listening": {
					MinMondooVersion: "5.15.0",
				},
			},
		},
		"sshd": {
			IsPrivate:        false,
			MinMondooVersion: "5.15.0",
		},
		"sshd.config": {
			IsPrivate:        false,
			MinMondooVersion: "5.15.0",
			Fields: map[string]*docs.LrDocsField{
				"ciphers": {
					MinMondooVersion: "5.15.0",
				},
				"content": {
					MinMondooVersion: "5.15.0",
				},
				"file": {
					MinMondooVersion: "5.15.0",
				},
				"hostkeys": {
					MinMondooVersion: "5.15.0",
				},
				"kexs": {
					MinMondooVersion: "5.15.0",
				},
				"macs": {
					MinMondooVersion: "5.15.0",
				},
				"params": {
					MinMondooVersion: "5.15.0",
				},
			}, Snippets: []docs.LrDocsSnippet{
				{
					Title: "Check the ssh banner setting",
					Query: "sshd.config.params['Banner'] == '/etc/ssh/sshd-banner'",
				},
			},
		},
		"platform.advisories": {
			IsPrivate:        false,
			MinMondooVersion: "5.15.0",
			Fields: map[string]*docs.LrDocsField{
				"cvss": {
					MinMondooVersion: "5.15.0",
				},
				"stats": {
					MinMondooVersion: "5.15.0",
				},
			},
		},
		"processes": {
			IsPrivate:        false,
			MinMondooVersion: "5.15.0",
		},
		"dns.record": {
			IsPrivate:        false,
			MinMondooVersion: "5.15.0",
			Maturity:         "experimental",
			Fields: map[string]*docs.LrDocsField{
				"rdata": {
					MinMondooVersion: "5.15.0",
				},
				"ttl": {
					MinMondooVersion: "5.15.0",
				},
				"type": {
					MinMondooVersion: "5.15.0",
				},
				"class": {
					MinMondooVersion: "5.15.0",
				},
				"name": {
					MinMondooVersion: "5.15.0",
				},
			},
		},
		"time": {
			IsPrivate:        false,
			MinMondooVersion: "5.15.0",
			Fields: map[string]*docs.LrDocsField{
				"today": {
					MinMondooVersion: "5.15.0",
				},
				"tomorrow": {
					MinMondooVersion: "5.15.0",
				},
				"day": {
					MinMondooVersion: "5.15.0",
				},
				"hour": {
					MinMondooVersion: "5.15.0",
				},
				"minute": {
					MinMondooVersion: "5.15.0",
				},
				"now": {
					MinMondooVersion: "5.15.0",
				},
				"second": {
					MinMondooVersion: "5.15.0",
				},
			},
		},
		"platform": {
			IsPrivate:        false,
			MinMondooVersion: "5.15.0",
			Docs: &docs.LrDocsDocumentation{
				Description: "The `platform.runtimeEnv` fields is deprecated. Please use `platform.runtime` instead.\nThe `platform.release` field is deprecated. Please use `platform.version` instead.\n",
			}, Fields: map[string]*docs.LrDocsField{
				"fqdn": {
					MinMondooVersion: "5.15.0",
				},
				"runtime": {
					MinMondooVersion: "6.9.0",
				},
				"version": {
					MinMondooVersion: "6.9.0",
				},
				"vulnerabilityReport": {
					MinMondooVersion: "5.15.0",
				},
				"build": {
					MinMondooVersion: "5.15.0",
				},
				"family": {
					MinMondooVersion: "5.15.0",
				},
				"labels": {
					MinMondooVersion: "5.37.0",
				},
				"name": {
					MinMondooVersion: "5.15.0",
				},
				"release": {
					MinMondooVersion: "5.15.0",
				},
				"runtimeEnv": {
					MinMondooVersion: "5.15.0",
				},
				"title": {
					MinMondooVersion: "5.15.0",
				},
				"arch": {
					MinMondooVersion: "5.15.0",
				},
				"kind": {
					MinMondooVersion: "5.15.0",
				},
			}, Snippets: []docs.LrDocsSnippet{
				{
					Title: "Platform Name and Release",
					Query: "platform { name release }",
				},
			},
		},
		"platform.eol": {
			IsPrivate:        false,
			MinMondooVersion: "5.15.0",
			Fields: map[string]*docs.LrDocsField{
				"productUrl": {
					MinMondooVersion: "5.15.0",
				},
				"date": {
					MinMondooVersion: "5.15.0",
				},
				"docsUrl": {
					MinMondooVersion: "5.15.0",
				},
			},
		},
		"privatekey": {
			IsPrivate:        false,
			MinMondooVersion: "5.15.0",
			Fields: map[string]*docs.LrDocsField{
				"pem": {
					MinMondooVersion: "5.15.0",
				},
				"encrypted": {
					MinMondooVersion: "5.15.0",
				},
				"path": {
					MinMondooVersion: "5.15.0",
				},
			},
		},
		"authorizedkeys": {
			IsPrivate:        false,
			MinMondooVersion: "5.15.0",
			Fields: map[string]*docs.LrDocsField{
				"content": {
					MinMondooVersion: "5.15.0",
				},
				"file": {
					MinMondooVersion: "5.15.0",
				},
				"path": {
					MinMondooVersion: "5.15.0",
				},
			},
		},
		"process": {
			IsPrivate:        false,
			MinMondooVersion: "5.15.0",
			Fields: map[string]*docs.LrDocsField{
				"flags": {
					MinMondooVersion: "5.15.0",
				},
				"pid": {
					MinMondooVersion: "5.15.0",
				},
				"state": {
					MinMondooVersion: "5.15.0",
				},
				"command": {
					MinMondooVersion: "5.15.0",
				},
				"executable": {
					MinMondooVersion: "5.15.0",
				},
			},
		},
		"audit.cve": {
			IsPrivate:        true,
			MinMondooVersion: "5.15.0",
			Fields: map[string]*docs.LrDocsField{
				"mrn": {
					MinMondooVersion: "5.15.0",
				},
				"published": {
					MinMondooVersion: "5.15.0",
				},
				"state": {
					MinMondooVersion: "5.15.0",
				},
				"summary": {
					MinMondooVersion: "5.15.0",
				},
				"unscored": {
					MinMondooVersion: "5.15.0",
				},
				"worstScore": {
					MinMondooVersion: "5.15.0",
				},
				"id": {
					MinMondooVersion: "5.15.0",
				},
				"modified": {
					MinMondooVersion: "5.15.0",
				},
			},
		},
		"authorizedkeys.entry": {
			IsPrivate:        false,
			MinMondooVersion: "5.15.0",
			Fields: map[string]*docs.LrDocsField{
				"options": {
					MinMondooVersion: "5.15.0",
				},
				"type": {
					MinMondooVersion: "5.15.0",
				},
				"file": {
					MinMondooVersion: "5.15.0",
				},
				"key": {
					MinMondooVersion: "5.15.0",
				},
				"label": {
					MinMondooVersion: "5.15.0",
				},
				"line": {
					MinMondooVersion: "5.15.0",
				},
			},
		},
		"certificate": {
			IsPrivate:        false,
			MinMondooVersion: "5.15.0",
			Fields: map[string]*docs.LrDocsField{
				"isCA": {
					MinMondooVersion: "5.15.0",
				},
				"isRevoked": {
					MinMondooVersion: "5.15.0",
				},
				"issuingCertificateUrl": {
					MinMondooVersion: "5.15.0",
				},
				"notAfter": {
					MinMondooVersion: "5.15.0",
				},
				"policyIdentifier": {
					MinMondooVersion: "5.15.0",
				},
				"extensions": {
					MinMondooVersion: "5.15.0",
				},
				"revokedAt": {
					MinMondooVersion: "5.15.0",
				},
				"signingAlgorithm": {
					MinMondooVersion: "5.15.0",
				},
				"subject": {
					MinMondooVersion: "5.15.0",
				},
				"ocspServer": {
					MinMondooVersion: "5.15.0",
				},
				"isVerified": {
					MinMondooVersion: "5.17.1",
				},
				"pem": {
					MinMondooVersion: "5.15.0",
				},
				"serial": {
					MinMondooVersion: "5.15.0",
				},
				"signature": {
					MinMondooVersion: "5.15.0",
				},
				"subjectKeyID": {
					MinMondooVersion: "5.15.0",
				},
				"expiresIn": {
					MinMondooVersion: "5.15.0",
				},
				"crlDistributionPoints": {
					MinMondooVersion: "5.15.0",
				},
				"extendedKeyUsage": {
					MinMondooVersion: "5.15.0",
				},
				"fingerprints": {
					MinMondooVersion: "5.15.0",
				},
				"issuer": {
					MinMondooVersion: "5.15.0",
				},
				"keyUsage": {
					MinMondooVersion: "5.15.0",
				},
				"notBefore": {
					MinMondooVersion: "5.15.0",
				},
				"version": {
					MinMondooVersion: "5.15.0",
				},
				"authorityKeyID": {
					MinMondooVersion: "5.15.0",
				},
			},
		},
		"kernel.module": {
			IsPrivate:        false,
			MinMondooVersion: "5.15.0",
			Fields: map[string]*docs.LrDocsField{
				"loaded": {
					MinMondooVersion: "5.15.0",
				},
				"name": {
					MinMondooVersion: "5.15.0",
				},
				"size": {
					MinMondooVersion: "5.15.0",
				},
			},
		},
		"package": {
			IsPrivate:        false,
			MinMondooVersion: "5.15.0",
			Fields: map[string]*docs.LrDocsField{
				"version": {
					MinMondooVersion: "5.15.0",
				},
				"available": {
					MinMondooVersion: "5.15.0",
				},
				"description": {
					MinMondooVersion: "5.15.0",
				},
				"format": {
					MinMondooVersion: "5.15.0",
				},
				"installed": {
					MinMondooVersion: "5.15.0",
				},
				"name": {
					MinMondooVersion: "5.15.0",
				},
				"origin": {
					MinMondooVersion: "5.15.0",
				},
				"outdated": {
					MinMondooVersion: "5.15.0",
				},
				"status": {
					MinMondooVersion: "5.15.0",
				},
				"arch": {
					MinMondooVersion: "5.15.0",
				},
				"epoch": {
					MinMondooVersion: "5.15.0",
				},
			}, Snippets: []docs.LrDocsSnippet{
				{
					Title: "Check if a package is installed",
					Query: "package('git').installed",
				},
			},
		},
		"os.rootCertificates": {
			IsPrivate:        false,
			MinMondooVersion: "5.15.0",
			Fields: map[string]*docs.LrDocsField{
				"content": {
					MinMondooVersion: "5.15.0",
				},
				"files": {
					MinMondooVersion: "5.15.0",
				},
			},
		},
		"platform.virtualization": {
			IsPrivate:        false,
			MinMondooVersion: "5.15.0",
			Docs: &docs.LrDocsDocumentation{
				Description: "The `platform.virtualization.isContainer`is deprecated. Please use `platform.kind` or `platform.runtime` instead.\n",
			}, Fields: map[string]*docs.LrDocsField{
				"isContainer": {
					MinMondooVersion: "5.15.0",
				},
			},
		},
		"uuid": {
			IsPrivate:        false,
			MinMondooVersion: "5.15.0",
			Fields: map[string]*docs.LrDocsField{
				"variant": {
					MinMondooVersion: "5.15.0",
				},
				"version": {
					MinMondooVersion: "5.15.0",
				},
				"urn": {
					MinMondooVersion: "5.15.0",
				},
				"value": {
					MinMondooVersion: "5.15.0",
				},
			},
		},
		"domainName": {
			IsPrivate:        false,
			MinMondooVersion: "5.15.0",
			Fields: map[string]*docs.LrDocsField{
				"effectiveTLDPlusOne": {
					MinMondooVersion: "5.15.0",
				},
				"fqdn": {
					MinMondooVersion: "5.15.0",
				},
				"labels": {
					MinMondooVersion: "5.15.0",
				},
				"tld": {
					MinMondooVersion: "5.15.0",
				},
				"tldIcannManaged": {
					MinMondooVersion: "5.15.0",
				},
			},
		},
		"file.permissions": {
			IsPrivate:        true,
			MinMondooVersion: "5.15.0",
			Fields: map[string]*docs.LrDocsField{
				"group_writeable": {
					MinMondooVersion: "5.15.0",
				},
				"isDirectory": {
					MinMondooVersion: "5.15.0",
				},
				"other_readable": {
					MinMondooVersion: "5.15.0",
				},
				"sgid": {
					MinMondooVersion: "5.15.0",
				},
				"sticky": {
					MinMondooVersion: "5.15.0",
				},
				"user_executable": {
					MinMondooVersion: "5.15.0",
				},
				"group_readable": {
					MinMondooVersion: "5.15.0",
				},
				"mode": {
					MinMondooVersion: "5.15.0",
				},
				"suid": {
					MinMondooVersion: "5.15.0",
				},
				"user_readable": {
					MinMondooVersion: "5.15.0",
				},
				"user_writeable": {
					MinMondooVersion: "5.15.0",
				},
				"group_executable": {
					MinMondooVersion: "5.15.0",
				},
				"isFile": {
					MinMondooVersion: "5.15.0",
				},
				"isSymlink": {
					MinMondooVersion: "5.15.0",
				},
				"other_executable": {
					MinMondooVersion: "5.15.0",
				},
				"other_writeable": {
					MinMondooVersion: "5.15.0",
				},
			},
		},
		"groups": {
			IsPrivate:        false,
			MinMondooVersion: "5.15.0",
			Snippets: []docs.LrDocsSnippet{
				{
					Title: "Ensure the user is not part of group",
					Query: "groups.where(name == 'wheel') { members.all( name != 'username') }",
				},
			},
		},
		"kernel": {
			IsPrivate:        false,
			MinMondooVersion: "5.15.0",
			Fields: map[string]*docs.LrDocsField{
				"info": {
					MinMondooVersion: "5.15.0",
				},
				"installed": {
					MinMondooVersion: "5.15.0",
				},
				"modules": {
					MinMondooVersion: "5.15.0",
				},
				"parameters": {
					MinMondooVersion: "5.15.0",
				},
			}, Snippets: []docs.LrDocsSnippet{
				{
					Title: "List all kernel modules",
					Query: "kernel.modules { name loaded size }",
				},
				{
					Title: "List all loaded kernel modules",
					Query: "kernel.modules.where( loaded == true ) { name }",
				},
				{
					Title: "List all information from running kernel",
					Query: "kernel { info }",
				},
				{
					Title: "List version from running kernel",
					Query: "kernel { info['version'] }",
				},
			},
		},
		"mondoo": {
			IsPrivate:        false,
			MinMondooVersion: "5.15.0",
			Fields: map[string]*docs.LrDocsField{
				"capabilities": {
					MinMondooVersion: "5.15.0",
				},
				"jobEnvironment": {
					MinMondooVersion: "5.15.0",
				},
				"nulllist": {
					MinMondooVersion: "5.15.0",
				},
				"resources": {
					MinMondooVersion: "5.15.0",
				},
				"version": {
					MinMondooVersion: "5.15.0",
				},
				"build": {
					MinMondooVersion: "5.15.0",
				},
			},
		},
	},
}
