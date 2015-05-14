package org.elasticsearch.plugins.security.filter;

import org.elasticsearch.plugins.security.service.permission.PermEvaluator;

/**
 * 
 * @author Hendrik Saly
 *
 */
public class PermLevelEvaluator extends PermEvaluator<PermLevel> {

	protected PermLevelEvaluator(final String xSecurityConfiguration) {
		super(xSecurityConfiguration);
	}

	@Override
	protected PermLevel createFromString(final String s) {
		return PermLevel.valueOf(s);
	}

	@Override
	protected String getPermissionFieldName() {
		return "permission";
	}

	@Override
    protected PermLevel getDefaultPermLevelForEvaluator() {
        return PermLevel.NONE;
    }
	
}
