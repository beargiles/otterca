package com.otterca.certificateAuthority;

import java.util.List;

/**
 * Policy Service
 * 
 * @author Bear Giles <bgiles@coyotesong.com>
 */
public interface PolicyService {
	public List<String> listPolicyIds();
	
	public String getPolicy(String policyId);
	
	public void setPolicy(String policyId, String policy);
	
	public String createPolicy(String policy);
	
	public String deletePolicy(String policyId);
}
