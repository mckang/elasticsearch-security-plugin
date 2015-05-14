package org.elasticsearch.plugins.security.http.tomcat;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.lang3.StringUtils;
import org.elasticsearch.plugins.security.filter.authentication.util.TokenUtil;
import org.elasticsearch.plugins.security.service.permission.UserRoleCallback;

/**
 * 
 * @author Hendrik Saly
 * @author Johannes Hiemer
 *
 */
public class TomcatUserRoleCallback implements UserRoleCallback {

	private final HttpServletRequest request;
	private final String sslUserAttribute;
	private final TokenUtil tokenUtil;

	public TomcatUserRoleCallback(final HttpServletRequest request,
			String sslUserAttribute, TokenUtil tokenUtil) {
		this.request = request;
		this.sslUserAttribute = sslUserAttribute;
		this.tokenUtil = tokenUtil;
		this.tokenUtil.init();
	}

	@Override
	public String getRemoteuser() {
		String remoteUser = tokenUtil.getUserName(request);

		if (remoteUser != null && !remoteUser.isEmpty()) {
			if (sslUserAttribute != null
					&& remoteUser.contains(sslUserAttribute)) {
				remoteUser = StringUtils.substringBetween(
						remoteUser.toLowerCase(),
						(sslUserAttribute + "=").toLowerCase(), ",");
			}
		}
		return remoteUser;
	}

	@Override
	public boolean isRemoteUserInRole(final String role) {
		return request.isUserInRole(role);
	}

}
