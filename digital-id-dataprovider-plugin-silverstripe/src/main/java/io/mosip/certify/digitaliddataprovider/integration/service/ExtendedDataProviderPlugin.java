package io.mosip.certify.digitaliddataprovider.integration.service;

import io.mosip.certify.api.spi.DataProviderPlugin;
import org.json.JSONObject;

public interface ExtendedDataProviderPlugin extends DataProviderPlugin {
    void pushCredential(JSONObject signedCredentialJson);
}
