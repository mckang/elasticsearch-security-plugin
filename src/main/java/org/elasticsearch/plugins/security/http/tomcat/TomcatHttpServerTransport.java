package org.elasticsearch.plugins.security.http.tomcat;

import static org.elasticsearch.common.network.NetworkService.TcpSettings.TCP_BLOCKING;
import static org.elasticsearch.common.network.NetworkService.TcpSettings.TCP_BLOCKING_SERVER;
import static org.elasticsearch.common.network.NetworkService.TcpSettings.TCP_DEFAULT_RECEIVE_BUFFER_SIZE;
import static org.elasticsearch.common.network.NetworkService.TcpSettings.TCP_DEFAULT_SEND_BUFFER_SIZE;
import static org.elasticsearch.common.network.NetworkService.TcpSettings.TCP_KEEP_ALIVE;
import static org.elasticsearch.common.network.NetworkService.TcpSettings.TCP_NO_DELAY;
import static org.elasticsearch.common.network.NetworkService.TcpSettings.TCP_RECEIVE_BUFFER_SIZE;
import static org.elasticsearch.common.network.NetworkService.TcpSettings.TCP_REUSE_ADDRESS;
import static org.elasticsearch.common.network.NetworkService.TcpSettings.TCP_SEND_BUFFER_SIZE;

import java.io.File;
import java.net.InetSocketAddress;

import org.apache.catalina.Context;
import org.apache.catalina.LifecycleException;
import org.apache.catalina.authenticator.SSLAuthenticator;
import org.apache.catalina.connector.Connector;
import org.apache.catalina.deploy.FilterDef;
import org.apache.catalina.deploy.FilterMap;
import org.apache.catalina.deploy.LoginConfig;
import org.apache.catalina.deploy.SecurityCollection;
import org.apache.catalina.deploy.SecurityConstraint;
import org.apache.catalina.startup.Tomcat;
import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.client.Client;
import org.elasticsearch.cluster.ClusterName;
import org.elasticsearch.common.component.AbstractLifecycleComponent;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.network.NetworkService;
import org.elasticsearch.common.network.NetworkUtils;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.transport.BoundTransportAddress;
import org.elasticsearch.common.transport.InetSocketTransportAddress;
import org.elasticsearch.common.unit.ByteSizeUnit;
import org.elasticsearch.common.unit.ByteSizeValue;
import org.elasticsearch.env.Environment;
import org.elasticsearch.http.HttpInfo;
import org.elasticsearch.http.HttpServerAdapter;
import org.elasticsearch.http.HttpServerTransport;
import org.elasticsearch.http.HttpStats;
import org.elasticsearch.plugins.security.service.SecurityService;
import org.elasticsearch.transport.BindTransportException;

/**
 * 
 * @author Hendrik Saly
 * @author Johannes Hiemer
 *
 */
public class TomcatHttpServerTransport extends AbstractLifecycleComponent<HttpServerTransport> implements 
	HttpServerTransport {

	private volatile ExtendedTomcat tomcat;

	private volatile HttpServerAdapter httpServerAdapter;

	private volatile BoundTransportAddress boundAddress;

	private final NetworkService networkService;

	private final String publishHost;

	private final String port;

	private final String bindHost;

	final ByteSizeValue maxContentLength;

	final ByteSizeValue maxHeaderSize;
	final ByteSizeValue maxChunkSize;

	private final boolean blockingServer;

	final boolean compression;

	private final int compressionLevel;

	private final Boolean tcpNoDelay;

	private final Boolean tcpKeepAlive;

	private final Boolean reuseAddress;

	private final ByteSizeValue tcpSendBufferSize;
	private final ByteSizeValue tcpReceiveBufferSize;

	private final Settings settings;

	private final SecurityService securityService;

	private final String authenticationMode;

	private final Boolean useSSL;

	private final  Boolean useClientAuth;

	static {
		System.setProperty("org.apache.catalina.connector.RECYCLE_FACADES", "true");
		System.setProperty("org.apache.catalina.connector.CoyoteAdapter.ALLOW_BACKSLASH", "false");
		System.setProperty("org.apache.tomcat.util.buf.UDecoder.ALLOW_ENCODED_SLASH", "false");
		System.setProperty("org.apache.catalina.connector.Response.ENFORCE_ENCODING_IN_GET_WRITER", "true");
	}

	@Inject
	public TomcatHttpServerTransport(final Settings settings,
			final Environment environment, final NetworkService networkService,
			final ClusterName clusterName, final Client client,
			final SecurityService securityService) {
		super(settings);

		this.settings = settings;
		this.securityService = securityService;

		useSSL = componentSettings.getAsBoolean("ssl.enabled",
				settings.getAsBoolean("security.ssl.enabled", false));

		useClientAuth= componentSettings.getAsBoolean("ssl.clientauth.enabled",
				settings.getAsBoolean("security.ssl.clientauth.enabled", false));

		authenticationMode = componentSettings.get("authentication.mode",
				settings.get("security.authentication.mode", "none"));

		port = componentSettings.get("port",
				settings.get("http.port", "8080"));
		bindHost = componentSettings.get("bind_host",
				settings.get("http.bind_host", settings.get("http.host")));
		publishHost = componentSettings.get("publish_host",
				settings.get("http.publish_host", settings.get("http.host")));
		this.networkService = networkService;

		ByteSizeValue maxContentLength = componentSettings.getAsBytesSize(
				"max_content_length", settings.getAsBytesSize(
						"http.max_content_length", new ByteSizeValue(100,
								ByteSizeUnit.MB)));
		maxChunkSize = componentSettings.getAsBytesSize(
				"max_chunk_size", settings.getAsBytesSize(
						"http.max_chunk_size", new ByteSizeValue(8,
								ByteSizeUnit.KB)));
		maxHeaderSize = componentSettings.getAsBytesSize(
				"max_header_size", settings.getAsBytesSize(
						"http.max_header_size", new ByteSizeValue(8,
								ByteSizeUnit.KB)));

		blockingServer = settings.getAsBoolean(
				"http.blocking_server",
				settings.getAsBoolean(TCP_BLOCKING_SERVER,
						settings.getAsBoolean(TCP_BLOCKING, false)));

		tcpNoDelay = componentSettings.getAsBoolean("tcp_no_delay",
				settings.getAsBoolean(TCP_NO_DELAY, true));
		tcpKeepAlive = componentSettings.getAsBoolean(
				"tcp_keep_alive", settings.getAsBoolean(TCP_KEEP_ALIVE, true));
		reuseAddress = componentSettings.getAsBoolean(
				"reuse_address",
				settings.getAsBoolean(TCP_REUSE_ADDRESS,
						NetworkUtils.defaultReuseAddress()));
		tcpSendBufferSize = componentSettings.getAsBytesSize(
				"tcp_send_buffer_size", settings.getAsBytesSize(
						TCP_SEND_BUFFER_SIZE, TCP_DEFAULT_SEND_BUFFER_SIZE));
		tcpReceiveBufferSize = componentSettings.getAsBytesSize(
				"tcp_receive_buffer_size", settings.getAsBytesSize(
						TCP_RECEIVE_BUFFER_SIZE,
						TCP_DEFAULT_RECEIVE_BUFFER_SIZE));

		compression = settings.getAsBoolean("http.compression", false);
		compressionLevel = settings.getAsInt("http.compression_level", 6);

		if (maxContentLength.bytes() > Integer.MAX_VALUE) {
			logger.warn("maxContentLength[" + maxContentLength
					+ "] set to high value, resetting it to [100mb]");
			maxContentLength = new ByteSizeValue(100, ByteSizeUnit.MB);
		}
		this.maxContentLength = maxContentLength;

		logger.debug("port: " + port);
		logger.debug("bindHost: " + bindHost);
		logger.debug("publishHost: " + publishHost);

		logger.debug("componentsettings: "
				+ componentSettings.getAsMap());
		logger.debug("settings: " + settings.getAsMap());

	}

	public SecurityService getSecurityService() {
		return securityService;
	}

	public Settings getSettings() {
		return settings;
	}

	@Override
	public BoundTransportAddress boundAddress() {
		return boundAddress;
	}

	@Override
	public HttpInfo info() {
		return new HttpInfo(boundAddress(), 0);
	}

	@Override
	public HttpStats stats() {
		return new HttpStats(0, 0);
	}

	@Override
	public void httpServerAdapter(final HttpServerAdapter httpServerAdapter) {
		this.httpServerAdapter = httpServerAdapter;
	}

	@Override
	protected void doStart() throws ElasticsearchException {
		try {
			final String currentDir = new File(".").getCanonicalPath();
			final String tomcatDir = currentDir + File.separatorChar + "tomcat";

			logger.debug("cur dir " + currentDir);

			if (tomcat != null) {
				try {
					tomcat.stop();
					tomcat.destroy();
				} catch (final Exception e) {

				}
			}

			tomcat = new ExtendedTomcat();
			tomcat.enableNaming();
			tomcat.getServer().setPort(-1);
			tomcat.getServer().setAddress("localhost");

			final String httpProtocolImpl = blockingServer ? "org.apache.coyote.http11.Http11Protocol"
					: "org.apache.coyote.http11.Http11NioProtocol";

			final Connector httpConnector = new Connector(httpProtocolImpl);
			tomcat.setConnector(httpConnector);
			tomcat.getService().addConnector(httpConnector);

			if (maxContentLength != null) {
				httpConnector
				.setMaxPostSize(maxContentLength.bytesAsInt());
			}

			if (maxHeaderSize != null) {
				httpConnector.setAttribute("maxHttpHeaderSize",
						maxHeaderSize.bytesAsInt());
			}

			if (tcpNoDelay != null) {
				httpConnector.setAttribute("tcpNoDelay",
						tcpNoDelay.booleanValue());
			}

			if (reuseAddress != null) {
				httpConnector.setAttribute("socket.soReuseAddress",
						reuseAddress.booleanValue());
			}

			if (tcpKeepAlive != null) {
				httpConnector.setAttribute("socket.soKeepAlive",
						tcpKeepAlive.booleanValue());
				httpConnector.setAttribute("maxKeepAliveRequests",
						tcpKeepAlive.booleanValue() ? "100" : "1");
			}

			if (tcpReceiveBufferSize != null) {
				httpConnector.setAttribute("socket.rxBufSize",
						tcpReceiveBufferSize.bytesAsInt());
			}

			if (tcpSendBufferSize != null) {
				httpConnector.setAttribute("socket.txBufSize",
						tcpSendBufferSize.bytesAsInt());
			}

			httpConnector.setAttribute("compression",
					compression ? String.valueOf(compressionLevel)
							: "off");

			if (maxChunkSize != null) {
				httpConnector.setAttribute("maxExtensionSize",
						maxChunkSize.bytesAsInt());
			}

			httpConnector.setPort(Integer.parseInt(port));

			tomcat.setBaseDir(tomcatDir);

			final TomcatHttpTransportHandlerServlet servlet = new TomcatHttpTransportHandlerServlet();
			servlet.setTransport(this);

			final Context ctx = tomcat.addContext("", currentDir);

			logger.debug("currentDir " + currentDir);

			Tomcat.addServlet(ctx, "ES Servlet", servlet);

			ctx.addServletMapping("/*", "ES Servlet");

			if(useSSL) {
				logger.info("Using SSL");

				httpConnector.setAttribute("SSLEnabled", "true");
				httpConnector.setSecure(true);
				httpConnector.setScheme("https");

				httpConnector.setAttribute("sslProtocol", "TLS");

				httpConnector.setAttribute("keystoreFile", settings.get(
						"security.ssl.keystorefile", "keystore"));
				httpConnector.setAttribute("keystorePass", settings.get(
						"security.ssl.keystorepass", "changeit"));
				httpConnector.setAttribute("keystoreType", settings.get(
						"security.ssl.keystoretype", "JKS"));

				final String keyalias = settings.get("security.ssl.keyalias", null);

				if(keyalias != null) {
					httpConnector.setAttribute("keyAlias", keyalias);
				}

				if(useClientAuth) {

					logger.info("Using SSL Client Auth (PKI), so user/roles will be retrieved from client certificate.");

					httpConnector.setAttribute("clientAuth", "true");

					httpConnector.setAttribute("truststoreFile", settings.get(
							"security.ssl.clientauth.truststorefile", "truststore"));
					httpConnector.setAttribute("truststorePass", settings.get(
							"security.ssl.clientauth.truststorepass", "changeit"));
					httpConnector.setAttribute("truststoreType", settings.get(
							"security.ssl.clientauth.truststoretype", "JKS"));

					final SecurityConstraint constraint = new SecurityConstraint();
					constraint.addAuthRole("*");
					constraint.setAuthConstraint(true);
					constraint.setUserConstraint("CONFIDENTIAL");

					final SecurityCollection col = new SecurityCollection();
					col.addPattern("/*");

					constraint.addCollection(col);
					ctx.addConstraint(constraint);

					final LoginConfig lc = new LoginConfig();
					lc.setAuthMethod("CLIENT-CERT");
					lc.setRealmName("clientcretificate");
					ctx.setLoginConfig(lc);

					ctx.getPipeline().addValve(new SSLAuthenticator());
					logger.info("Auth Method is CLIENT-CERT");

				}
			} else {
				if(useClientAuth) {
					logger.error("Client Auth only available with SSL");
					throw new RuntimeException("Client Auth only available with SSL");
				}
			}


			if(!useClientAuth) {
				if ("waffle".equalsIgnoreCase(authenticationMode)) {

				} else if ("spnegoad".equalsIgnoreCase(authenticationMode)) {
					
				} else if ("none".equalsIgnoreCase(authenticationMode)) {

					logger.warn("Kerberos is not configured so user/roles are unavailable. "
							+ "Host based security, in contrast, is woking. ");

				} else if ("jdbc".equalsIgnoreCase(authenticationMode)) {

					final FilterDef filterDef = new FilterDef();
					filterDef.setFilterClass("org.elasticsearch.plugins.security.filter.authentication.TokenFilter");
					filterDef.setFilterName("TokenFilter");
					
					String url = settings.get("security.jdbc.url");
					String driver = settings.get("security.jdbc.driver");
	            	String host = settings.get("security.jdbc.host");
	            	String port = settings.get("security.jdbc.port");
	            	String username = settings.get("security.jdbc.username");
	            	String password = settings.get("security.jdbc.password");
	            	String database = settings.get("security.jdbc.database");
	            	String table = settings.get("security.jdbc.table");
	            	String usernameColumn = settings.get("security.jdbc.column.username");
	            	String passwordColumn = settings.get("security.jdbc.column.password");
	            	
	            	filterDef.addInitParameter("security.jdbc.url", url);
	            	filterDef.addInitParameter("security.jdbc.driver", driver);
	            	filterDef.addInitParameter("security.jdbc.host", host);
	            	filterDef.addInitParameter("security.jdbc.port", port);
	            	filterDef.addInitParameter("security.jdbc.username", username);
	            	filterDef.addInitParameter("security.jdbc.password", password);
	            	filterDef.addInitParameter("security.jdbc.database", database);
	            	filterDef.addInitParameter("security.jdbc.table", table);
	            	filterDef.addInitParameter("security.jdbc.column.username", usernameColumn);
	            	filterDef.addInitParameter("security.jdbc.column.password", passwordColumn);
					
					ctx.addFilterDef(filterDef);
					final FilterMap filterMap = new FilterMap();
					filterMap.setFilterName("TokenFilter");
					filterMap.addURLPattern("/*");
					ctx.addFilterMap(filterMap);

				} else {
					logger
					.error("No Kerberos implementaion '" + authenticationMode + "' found. Kerberos is therefore not configured "
							+ "so user/roles are unavailable. Host based security, in contrast, is working.");
				}
			}

			tomcat.start();
			logger.info("Tomcat started");

			InetSocketAddress bindAddress;
			try {
				bindAddress = new InetSocketAddress(
						networkService
						.resolveBindHostAddress(bindHost),
						tomcat.getConnector().getLocalPort());
			} catch (final Exception e) {
				throw new BindTransportException(
						"Failed to resolve bind address", e);
			}

			InetSocketAddress publishAddress;
			try {
				publishAddress = new InetSocketAddress(
						networkService
						.resolvePublishHostAddress(publishHost),
						bindAddress.getPort());
			} catch (final Exception e) {
				throw new BindTransportException(
						"Failed to resolve publish address", e);
			}

			logger.debug("bindAddress " + bindAddress);
			logger.debug("publishAddress " + publishAddress);

			boundAddress = new BoundTransportAddress(
					new InetSocketTransportAddress(bindAddress),
					new InetSocketTransportAddress(publishAddress));

		} catch (final Exception e) {
			throw new ElasticsearchException("Unable to start Tomcat", e);
		}

	}

	@Override
	protected void doStop() throws ElasticsearchException {
		try {
			if (tomcat != null) {
				tomcat.stop();
			}
		} catch (final Exception e) {
			throw new ElasticsearchException("Unable to stop Tomcat", e);
		}

	}

	public HttpServerAdapter httpServerAdapter() {
		return httpServerAdapter;
	}

	@Override
	protected void doClose() throws ElasticsearchException {
		try {
			tomcat.destroy();
			tomcat = null;
		} catch (final LifecycleException e) {
			throw new ElasticsearchException("Unable to destroy Tomcat", e);
		}
	}

}
