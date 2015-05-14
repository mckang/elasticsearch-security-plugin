/**
 * 
 */
package org.elasticsearch.plugins.security.filter.authentication;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Principal;
import java.sql.Connection;
import java.sql.Driver;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Properties;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.tomcat.util.ExceptionUtils;
import org.elasticsearch.common.netty.handler.codec.http.HttpMethod;
import org.elasticsearch.plugins.security.filter.authentication.principal.CustomPrincipal;
import org.elasticsearch.plugins.security.filter.authentication.util.TokenUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author Johannes Hiemer.
 *
 */
public class TokenFilter implements Filter {
	
	private Logger log = LoggerFactory
			.getLogger(TokenFilter.class);
	
	private String tokenName = "X-Auth-Token";
	
	private String connectionName = null;

	private String connectionPassword = null;

	private String connectionURL = null;

	private Connection dbConnection = null;

	private Driver driver = null;

	private String driverName = null;

	private PreparedStatement preparedCredentials = null;

	private PreparedStatement preparedRoles = null;

    private String userCredCol = null;

    private String userNameCol = null;

    protected String userTable = null;
    
    private TokenUtil tokenUtil = null;

    public String getConnectionName() {
        return connectionName;
    }

    public void setConnectionName(String connectionName) {
        this.connectionName = connectionName;
    }

    public String getConnectionPassword() {
        return connectionPassword;
    }

    public void setConnectionPassword(String connectionPassword) {
        this.connectionPassword = connectionPassword;
    }

    public String getConnectionURL() {
        return connectionURL;
    }

    public void setConnectionURL( String connectionURL ) {
      this.connectionURL = connectionURL;
    }

    public String getDriverName() {
        return driverName;
    }

    public void setDriverName( String driverName ) {
      this.driverName = driverName;
    }

    public String getUserCredCol() {
        return userCredCol;
    }

    public void setUserCredCol( String userCredCol ) {
       this.userCredCol = userCredCol;
    }

    public String getUserNameCol() {
        return userNameCol;
    }

    public void setUserNameCol( String userNameCol ) {
       this.userNameCol = userNameCol;
    }

    public String getUserTable() {
        return userTable;
    }

    public void setUserTable( String userTable ) {
      this.userTable = userTable;
    }

	/* (non-Javadoc)
	 * @see javax.servlet.Filter#init(javax.servlet.FilterConfig)
	 */
	@Override
	public void init(FilterConfig filterConfig) throws ServletException {
		log.info("Initializing Token based authentication filter");
		
		if (filterConfig != null) {
			this.connectionURL =  filterConfig.getInitParameter("security.jdbc.url")
					+ "://" + filterConfig.getInitParameter("security.jdbc.host")
					+ ":" + filterConfig.getInitParameter("security.jdbc.port")
					+ "/" + filterConfig.getInitParameter("security.jdbc.database"); 
			this.driverName = filterConfig.getInitParameter("security.jdbc.driver");
        	this.userTable = filterConfig.getInitParameter("security.jdbc.table");
        	this.userNameCol = filterConfig.getInitParameter("security.jdbc.column.username");
        	this.userCredCol = filterConfig.getInitParameter("security.jdbc.column.password"); 
        	
        	this.connectionName = filterConfig.getInitParameter("security.jdbc.username");
        	this.connectionPassword = filterConfig.getInitParameter("security.jdbc.password");
        	
        	try {
				this.open();
			} catch (SQLException e) {
				throw new ServletException(e);
			} finally {
				this.tokenUtil = new TokenUtil();
				this.tokenUtil.init();
			}
		}
	}

	/* (non-Javadoc)
	 * @see javax.servlet.Filter#doFilter(javax.servlet.ServletRequest, javax.servlet.ServletResponse, javax.servlet.FilterChain)
	 */
	@Override
	public void doFilter(final ServletRequest sreq, final ServletResponse sres,
			final FilterChain chain) throws IOException, ServletException {

		final HttpServletRequest request = (HttpServletRequest) sreq;
		final HttpServletResponse response = (HttpServletResponse) sres;

		if (!request.getMethod().equals(HttpMethod.OPTIONS.toString())) {
			CustomPrincipal principal = (CustomPrincipal) this.getPrincipal(request);
			if ((principal.getUsername() != null && !principal.getUsername().isEmpty()) && 
					(principal.getPassword() != null  && !principal.getPassword().isEmpty())) {
				try {
					response.addHeader(tokenName,
							getTokenRenewal(principal.getUsername()));
				} catch (GeneralSecurityException e) {
					throw new ServletException(e);
				} finally {
					chain.doFilter(request, response);
				}
				return;
			}
		}

		sendUnauthorized(response, false);
	}

	private Principal getPrincipal(HttpServletRequest request) {
		tokenUtil.init();
		String userName = tokenUtil.getUserName(request);
		Principal principal = new CustomPrincipal(userName, getPassword(userName));
		
		return principal;
	}
	
	private String getTokenRenewal(String username) throws IOException, GeneralSecurityException {
		 return tokenUtil.createAuthToken(username);
	}

	/* (non-Javadoc)
	 * @see javax.servlet.Filter#destroy()
	 */
	@Override
	public void destroy() {
		log.info("Shutting down Token based authentication filter");
	}
	
	protected synchronized String getPassword(String username) {
		String dbCredentials = null;
		PreparedStatement preparedStatement = null;
		ResultSet resultSet = null;

		int numberOfTries = 2;
		while (numberOfTries > 0) {
			try {
				open();

				preparedStatement = credentials(dbConnection, username);
				resultSet = preparedStatement.executeQuery();
				if (resultSet.next()) {
					dbCredentials = resultSet.getString(1);
				}

				dbConnection.commit();

				if (dbCredentials != null) {
					dbCredentials = dbCredentials.trim();
				}

				return dbCredentials;
			} catch (SQLException e) {
				log.error("SQL Exception while retrieving User/Password", e);
			} finally {
				if (resultSet != null) {
					try {
						resultSet.close();
					} catch (SQLException e) {
						log.error("Abnormal SQL Exception while retrieving User/Password", e);
					}
				}
			}

			if (dbConnection != null) {
				close(dbConnection);
			}
			numberOfTries--;
		}

		return (null);
	}
	
	protected Connection open() throws SQLException {
        if (dbConnection != null)
            return (dbConnection);

        if (driver == null) {
            try {
                Class<?> clazz = Class.forName(driverName);
                driver = (Driver) clazz.newInstance();
            } catch (Throwable e) {
                ExceptionUtils.handleThrowable(e);
                throw new SQLException(e.getMessage(), e);
            }
        }

        Properties props = new Properties();
        if (connectionName != null)
            props.put("user", connectionName);
        if (connectionPassword != null)
            props.put("password", connectionPassword);
        dbConnection = driver.connect(connectionURL, props);
        if (dbConnection == null) {
            throw new SQLException(driverName, connectionURL);
        }
        dbConnection.setAutoCommit(false);
        return (dbConnection);
    }
	
	protected void close(Connection dbConnection) {
        if (dbConnection == null)
            return;

        try {
            preparedCredentials.close();
        } catch (Throwable f) {
            ExceptionUtils.handleThrowable(f);
        }
        this.preparedCredentials = null;

        try {
            preparedRoles.close();
        } catch (Throwable f) {
            ExceptionUtils.handleThrowable(f);
        }
        this.preparedRoles = null;

        try {
            dbConnection.close();
        } catch (SQLException e) {
            log.warn("Error closing connection", e);
        } finally {
           this.dbConnection = null;
        }

    }
	
	protected PreparedStatement credentials(Connection dbConnection,
            String username)
		throws SQLException {
		
		if (preparedCredentials == null) {
			StringBuilder sb = new StringBuilder("SELECT ");
			sb.append("\"" + userTable + "\"." + userCredCol);
			sb.append(" FROM ");
			sb.append("\"public\"." + userTable);
			sb.append(" WHERE ");
			sb.append("\"" + userTable + "\"." + userNameCol);
			sb.append(" = ?");
			
			log.info(sb.toString());
			
			preparedCredentials = dbConnection.prepareStatement(sb.toString());
		}
		
		if (username == null) {
			preparedCredentials.setNull(1,java.sql.Types.VARCHAR);
		} else {
			preparedCredentials.setString(1, username);
		}
		
		return (preparedCredentials);
	}
		
    private void sendUnauthorized(final HttpServletResponse response, final boolean close) {
        try {
            if (close) {
                response.setHeader("Connection", "close");
            } else {
                response.setHeader("Connection", "keep-alive");
            }
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
            response.flushBuffer();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

}
