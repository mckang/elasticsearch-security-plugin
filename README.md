# Elasticsearch Security Plugin for Token/JDBC based authentication
This plugin is based on the implementation of <a href="mailto:hendrikdev22@gmail.com">E-Mail hendrikdev22@gmail.com</a><p>, who has done a great job of connecting elasticsearch to Kerberos/SPNEGO for authentication. I wanted to integrate the implementation into my Web Application based authentication, which relies on a standard user/group/role implementation for authentication.

## Difference to Hendriks version
* No support for Kerberos/SPNEGO, due to the fact they are not needed and would overload the plugin
* No support for DSL specification for security definition
* No support for Kibana, as it won't be used

* Support for Token and JDBC based authentication
* Migration from Elastic search security storage to MapDB in future, due to performance impacts for large security definitions
* Added integration with elastic search test runner https://github.com/codelibs/elasticsearch-cluster-runner

<h3>Installation</h3> 
To install the plugin it must be build with maven. Read below, how to build the plugin.

Prerequisites:
* Open JDK 7 or Oracle 7 JRE
* Elasticsearch 0.90.10 or higher
* If Kerberos is used you need an KDC like  AD, MIT or Heimdal

Build yourself:
* Install maven
* execute ``mvn clean package -DskipTests=true`` 

Windows:
``plugin.bat --url http://... --install elasticsearch-security-jdbc-token-plugin-0.0.1.Beta2``

UNIX:
``plugin --url http://... --install elasticsearch-security-jdbc-token-plugin-0.0.2.Beta2``



<h3>Configuration</h3>

<h4>Configuration (elasticsearch.yml)</h4>
Enable the security plugin
* ``http.type: org.elasticsearch.plugins.security.http.tomcat.TomcatHttpServerTransportModule`` (for ES <= 1.3)
* ``http.type: org.elasticsearch.plugins.security.http.tomcat.TomcatHttpServerTransport`` (for ES >= 1.4)
* ``script.disable_dynamic: true`` Dynamic scripts are unsafe and can potentially tamper this plugin (not needed for ES 1.2 and above)
* ``http.port: 9200`` Define exactly one port, Port ranges are not permitted

Setup Token based Authentication
* ``security.authentication.mode: jdbc`` JDBC/Http Token based authentication

If you use spnegoad and not Active Directory you may want configure your LDAP layout
(look here for details: http://tomcat.apache.org/tomcat-7.0-doc/realm-howto.html#JNDIRealm)
* ``security.jdbc.url: ""`` (e.g. postgres:jdbc)
* ``security.jdbc.driver: ""`` (e.g. org.postgresql.Driver)
* ``security.jdbc.host: ""`` (e.g. 172.16.248.128)
* ``security.jdbc.port: ""`` (e.g. 5432)
* ``security.jdbc.username: ""`` (e.g. User12)
* ``security.jdbc.password: ""`` (e.g. Password132)
* ``security.jdbc.database: ""`` (e.g. myDb)
* ``security.jdbc.table: ""`` (e.g. user)
* ``security.jdbc.column.username: ""`` (e.g. email)
* ``security.jdbc.column.password: ""`` (e.g. password)
* 
Optionally enable SSL/TLS
* ``security.ssl.enabled: true`` Enable SSL
* ``security.ssl.keystorefile: /path/to/keystore`` Keystore for private and public server certificates
* ``security.ssl.keystorepass: changeit`` Password for the keystore
* ``security.ssl.keystoretype: JKS`` Keystoretype (either JKS or PKCS12)

If SSL is enabled you can use PKI/Client certificates for authentication
* ``security.ssl.clientauth.enabled: true`` Enable PKI/Client certificates for authentication
* ``security.ssl.clientauth.truststorefile: /path/to/truststore`` Keystore (truststore) for public client certificates which the server should trust
* ``security.ssl.clientauth.truststorepass: changeit`` Password for the truststore
* ``security.ssl.clientauth.truststoretype: JKS`` (either JKS or PKCS12)
* ``security.ssl.userattribute: CN`` Name of the attribute from the client certificate user name which denotes the username for further authentication/authorization

Optionally enable XFF 
* ``security.http.xforwardedfor.header: X-Forwarded-For`` Enable XFF
* ``security.http.xforwardedfor.trustedproxies: <List of proxy ip's>`` Example: "192.168.1.1,31.122.45.1,193.54.55.21"
* ``security.http.xforwardedfor.enforce: true`` Enforce XFF header, default: false

Enable at least one of the two security modules 
* ``security.module.actionpathfilter.enabled: true``
* ``security.module.dls.enabled: true`` Note: DLS is an early development stage and considered to be "alpha"

Enable strict mode if really needed (disabled by default, enable only if you know what you are doing)
* ``security.strict: true`` Strict mode currently deny facet and suggester responses and treat some command like _mapping or _analyze as sensitive write requests 


<h4>Configuration (security rules)</h4>
The security rules for each module are stored in an special index ``securityconfiguration``. For security reasons you can access this index only from localhost (127.0.0.1). For performance and security reasons this will be changed to MapDB in future releases. 

<b>Example: Configure 'Restrict actions against elasticsearch on IP-Address only basis (actionpathfilter)' module. This work's without Kerberos/NTLM but maybe require XFF to be configured properly.</b>
<pre><code>$ curl -XPUT 'http://localhost:9200/securityconfiguration/actionpathfilter/actionpathfilter' -d '
{
			 "rules": [
			 	{
				 	"permission" : "ALL"
			 	},
			 	
			 	{
				 	"hosts" : [ "google-public-dns-a.google.com" ],
				 	"indices" : [ "*"],
				 	"types" : [ "twitter","facebook" ],
				 	"permission" : "NONE"
			 	},
			 	
			 	{
				 	"hosts" : [ "8.8.8.8" ],
				 	"indices" : [ "testindex1","testindex2" ],
				 	"types" : [ "*" ],
				 	"permission" : "READWRITE"
			 	},
			 	
			 	{
				 	"hosts" : [ "81.*.8.*","2.44.12.14","*google.de","192.168.*.*" ],
				 	"indices" : [ "testindex1" ],
				 	"types" : [ "quotes" ],
				 	"permission" : "READONLY"
			 	}
			 ]		 		 
}'</code></pre>

<b>Example: Configure 'Restrict actions against elasticsearch on user/role and ip/hostname basis (actionpathfilter)' module. This needs Kerberos/NTLM.</b>
<pre><code>$ curl -XPUT 'http://localhost:9200/securityconfiguration/actionpathfilter/actionpathfilter' -d '
{
			 "rules": [
			 	{
			 		
				 	"users" : [ "*" ],
				 	"roles" : [ "*" ],
				 	"hosts" : [ "*" ],
				 	"indices" : [ "*" ],
				 	"types" : [ "*" ],
				 	"permission" : "ALL"
			 	},
			 	
			 	{
			 		"users" : [ "spock","kirk" ],
				 	"roles" : [ "admin" ],
				 	"hosts" : [ "*" ],
				 	"indices" : [ "*"],
				 	"types" : [ "twitter","facebook" ],
				 	"permission" : "NONE"
			 	},
			 	
			 	{
			 	
			 		"users" : [ "bowna" ],
				 	"roles" : [ "*" ],
				 	"hosts" : [ "*" ],
				 	"indices" : [ "testindex1","testindex2" ],
				 	"types" : [ "*" ],
				 	"permission" : "READWRITE"
			 	},
			 	
			 	{
			 		"users" : [ "smithf","salyh" ],
				 	"roles" : [ "users","guests" ],
				 	"hosts" : [ "81.*.8.*","2.44.12.14","*google.de","192.168.*.*" ],
				 	"indices" : [ "testindex1" ],
				 	"types" : [ "quotes" ],
				 	"permission" : "READONLY"
			 	}
			 ]		 		 
}'</code></pre>


Permissions:
* ALL: No restrictions
* READWRITE: No admin actions but read write operations allowed (for example _settings, _status, _cluster)
* READONLY: No admin and no write actions allowed (but read actions) (for example _update, _bulk, _mapping)
* NONE: No action allowed (also read actions will be denied) (even _search and _msearch are denied)

In a more formal way the configuration looks like:

* Format is JSON
* One top level array named "rules"
* The single wildchar character (\*) match any user, role, host, type or any index
* In hostnames or ip's you can use the wildcard character (\*) for specifying subnets
* The rules elemens look like:

<pre><code>


			 	{
			 		"users" : [ &lt;* or list of users/principals for which this rule apply&gt; ],
			 		"roles" : [ &lt;* or list of AD roles for which this rule apply&gt; ],
				 	"hosts" : [ &lt;* or list of hostnames/ip's for which this rule apply&gt; ],
				 	"types" :[ &lt;* or list of types for which this rule apply&gt; ],
				 	"indices" :[ &lt;* or list of indices for which this rule apply&gt; ],
				 	"permission" : "ALL"&#448;"READWRITE"&#448;"READONLY"&#448;"NONE";
			 	}
			 	
</code></pre>
 
* There must be exactly one default rule:

<pre><code>


			 	{
				 	
				 	"&lt;qualification name\>" : &lt;qualification string&gt;
			 	}
			 	
</code></pre>

* If more than one rule match then the first one (right down at the top of the security config) is used

Who i am:<br>
"users" : [...], if * or not present match always, if empty match always, OR<br>
"roles" : [...], if * or not present match always, if empty match always, OR<br>
"hosts" : [...], if * or not present match always, if empty match always, OR<br>
<br><br>
On what i am operating<br>
"indices" : [...], if * or not present match always, if empty match always, OR<br>
"types": [...], if * or not present match always, if empty match always, OR<br>
<br><br>
What i am allowed to do/see/whatever when above match, if so then stop here and do not evaluate other rules (first one wins)<br>
"permission" : "READWRITE"<br>

All present attributes (users, roles, hosts, indices, types) must match, if not this rule will not be applied and the next one is evaluated.
If no rule matches the default rule will be applied.<br><br>
"users" : [u1,u2]<br>
"roles" : [role1, role2]<br>
"hosts" : [host1, host2]<br>
<br><br>
"indices" : [i1,i2]<br>
"types": [t1, t2]<br>
<br><br>
This rule match if (the user is u1 or u2) and (has the role rol1 or role2) <br>
and (issues the request from host1 or host2) and (operates on i1 or i2 or both)<br>
and uses (documents of types t1 or t2 or both)<br>


<h3>License</h3>
Licensed under the "No License" license (github default): 
http://choosealicense.com/licenses/no-license/

