/**
 * 
 */
package org.elasticsearch.plugins;

import static org.codelibs.elasticsearch.runner.ElasticsearchClusterRunner.newConfigs;
import junit.framework.TestCase;

import org.codelibs.elasticsearch.runner.ElasticsearchClusterRunner;
import org.elasticsearch.common.settings.ImmutableSettings.Builder;

/**
 * @author Johannes Hiemer.
 *
 */
public class PluginRunner extends TestCase {

    private ElasticsearchClusterRunner runner;

    @Override
    protected void setUp() throws Exception {
        runner = new ElasticsearchClusterRunner();

        runner.onBuild(new ElasticsearchClusterRunner.Builder() {
            @Override
            public void build(final int number, final Builder settingsBuilder) {
            	settingsBuilder.put("http.type", "org.elasticsearch.plugins.security.http.tomcat.TomcatHttpServerTransport");
            	settingsBuilder.put("script.disable_dynamic", true);
            	settingsBuilder.put("http.port", 9200);
            	settingsBuilder.put("security.strict", true);
            	
            	settingsBuilder.put("security.authentication.mode", "jdbc");
            	settingsBuilder.put("security.jdbc.url", "jdbc:postgresql");
            	settingsBuilder.put("security.jdbc.driver", "org.postgresql.Driver");
            	settingsBuilder.put("security.jdbc.host", "172.16.248.128");
            	settingsBuilder.put("security.jdbc.port", "5432");
            	settingsBuilder.put("security.jdbc.username", "postgres");
            	settingsBuilder.put("security.jdbc.password", "postgres");
            	settingsBuilder.put("security.jdbc.database", "cloudscale");
            	settingsBuilder.put("security.jdbc.table", "user");
            	settingsBuilder.put("security.jdbc.column.username", "email");
            	settingsBuilder.put("security.jdbc.column.password", "password");
            }
        }).build(newConfigs().ramIndexStore().numOfNode(1));

        runner.ensureYellow();
    }

    @Override
    protected void tearDown() throws Exception {
        runner.close();
        runner.clean();
    }
    
    public void test_runEs() throws Exception {
    	Thread.sleep(1000000);
    }
}
