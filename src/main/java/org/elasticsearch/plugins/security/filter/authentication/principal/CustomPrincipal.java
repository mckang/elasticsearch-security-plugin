/**
 * 
 */
package org.elasticsearch.plugins.security.filter.authentication.principal;

import java.security.Principal;
import java.util.ArrayList;
import java.util.List;

/**
 * @author Johannes Hiemer.
 *
 */
public class CustomPrincipal implements Principal {
	
	private String username;
	
	private String token;
	
	private String password;
	
	private List<String> roles = new ArrayList<String>();
	
	public CustomPrincipal() {
		super();
	}
	
	public CustomPrincipal(String username, String password) {
		super();
		this.username = username;
		this.password = password;
	}
	
	public CustomPrincipal(String username, String password, String token) {
		super();
		this.username = username;
		this.password = password;
		this.token = token;
	}
	
	public CustomPrincipal(String username, String password, String token,
			List<String> roles) {
		super();
		this.username = username;
		this.token = token;
		this.password = password;
		this.roles = roles;
	}

	@Override
	public String getName() {
		// TODO Auto-generated method stub
		return null;
	}

	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public List<String> getRoles() {
		return roles;
	}

	public void setRoles(List<String> roles) {
		this.roles = roles;
	}

	public String getToken() {
		return token;
	}

}
