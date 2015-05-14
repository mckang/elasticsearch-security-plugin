package org.elasticsearch.plugins.security.http.tomcat;

import org.apache.catalina.startup.Tomcat;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;

/**
 * 
 * @author Hendrik Saly
 *
 */
public class ExtendedTomcat extends Tomcat {

	protected static final ESLogger log = Loggers
			.getLogger(ExtendedTomcat.class);

	public ExtendedTomcat() {
	}

}
