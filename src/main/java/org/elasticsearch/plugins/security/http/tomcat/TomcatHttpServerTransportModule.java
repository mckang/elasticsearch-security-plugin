package org.elasticsearch.plugins.security.http.tomcat;

import org.elasticsearch.common.inject.AbstractModule;
import org.elasticsearch.http.HttpServerTransport;

/**
 * 
 * @author Hendrik Saly
 *
 */
public class TomcatHttpServerTransportModule extends AbstractModule {
	@Override
	protected void configure() {
		this.bind(HttpServerTransport.class)
		.to(TomcatHttpServerTransport.class).asEagerSingleton();
	}

}
