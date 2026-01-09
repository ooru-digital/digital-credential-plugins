package io.mosip.certify.digitaliddataprovider.integration.repository;

import org.json.JSONObject;

import io.mosip.certify.api.exception.DataProviderExchangeException;

import java.util.Map;

public interface DataProviderPlugin {
    JSONObject fetchData(Map<String, Object> identityDetails, String credentialType)throws DataProviderExchangeException;
}
