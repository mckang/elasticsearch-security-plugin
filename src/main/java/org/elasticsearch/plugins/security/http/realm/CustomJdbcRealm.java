/**
 * 
 */
package org.elasticsearch.plugins.security.http.realm;

import java.security.Principal;

import org.apache.catalina.Realm;
import org.apache.catalina.realm.JDBCRealm;

/**
 * @author Johannes Hiemer.
 *
 */
public class CustomJdbcRealm extends JDBCRealm implements Realm {

	@Override
	public synchronized Principal authenticate(String username, String credentials) {
		// Here we do the authentication stuff.
		return null;
	}
	
	@Override
	protected synchronized Principal getPrincipal(String username) {
		// Here we load the principal.
		return super.getPrincipal(username);
	}
}
