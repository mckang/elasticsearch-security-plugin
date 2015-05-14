package org.elasticsearch.plugins.security.service.permission;

/**
 * 
 * @author Hendrik Saly
 *
 */
public interface UserRoleCallback {

	public String getRemoteuser();

	public boolean isRemoteUserInRole(String role);

}
