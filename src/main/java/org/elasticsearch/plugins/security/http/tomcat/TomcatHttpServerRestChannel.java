package org.elasticsearch.plugins.security.http.tomcat;

import java.util.concurrent.CountDownLatch;

import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletResponse;

import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.common.xcontent.XContentType;
import org.elasticsearch.http.HttpChannel;
import org.elasticsearch.plugins.security.service.SecurityService;
import org.elasticsearch.rest.RestResponse;

/**
 * 
 * @author Hendrik Saly
 * @author Johannes Hiemer
 *
 */
public class TomcatHttpServerRestChannel extends HttpChannel {

	protected final ESLogger log = Loggers.getLogger(this.getClass());

	private final HttpServletResponse resp;

	private Exception sendFailure;

	private final CountDownLatch latch;

	public TomcatHttpServerRestChannel(
			final TomcatHttpServerRestRequest restRequest,
			final HttpServletResponse resp,
			final SecurityService securityService) {
		super(restRequest, true);
		this.resp = resp;
		latch = new CountDownLatch(1);
	}

	public void await() throws InterruptedException {
		latch.await();
	}

	public Exception sendFailure() {
		return sendFailure;
	}

	@Override
	public void sendResponse(final RestResponse response) {
		
		resp.setContentType(response.contentType());
		resp.addHeader("Access-Control-Allow-Origin", "*"); 
		resp.addHeader("Access-Control-Allow-Methods", "OPTIONS, HEAD, GET, POST, PUT, DELETE");
		resp.addHeader("Access-Control-Allow-Headers", "X-Requested-With, Content-Type, Content-Length, X-HTTP-Method-Override, Origin, Accept, Authorization");
		resp.addHeader("Access-Control-Allow-Credentials", "true");
		resp.addHeader("Cache-Control", "max-age=0");
		
		if (response.status() != null) {
			resp.setStatus(response.status().getStatus());
		} else {
			resp.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
		}

		try {
			log.debug("Rest response contentype: "+response.contentType()+"/xcontent response contentype: "+ XContentType.fromRestContentType(response.contentType()));
			int contentLength = response.content().length();
			resp.setContentLength(contentLength);
	        ServletOutputStream out = resp.getOutputStream();
	        response.content().writeTo(out);
	        out.close();
		} catch (final Exception e) {
			log.error(e.toString(), e);
			sendFailure = e;
		} finally {
			latch.countDown();
		}
	}

	
}
