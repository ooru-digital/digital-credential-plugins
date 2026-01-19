package io.mosip.certify.digitaliddataprovider.integration.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.certify.api.exception.DataProviderExchangeException;
import io.mosip.certify.api.spi.DataProviderPlugin;
import io.mosip.certify.digitaliddataprovider.integration.repository.DataProviderRepository;
import java.util.Map;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

@ConditionalOnProperty(value={"mosip.certify.integration.data-provider-plugin"}, havingValue="DigitalIdProviderPlugin")
@Component
public class DigitalIdDataProviderPlugin
implements DataProviderPlugin {
    private static final Logger log = LoggerFactory.getLogger(DigitalIdDataProviderPlugin.class);
    @Autowired
    private DataProviderRepository dataProviderRepository;
    @Autowired
    private ObjectMapper objectMapper;
    @Value(value="${mosip.data-provider.url}")
    private String dataProviderUrl;
    @Autowired
    private RestTemplate restTemplate;

    public JSONObject fetchData(Map<String, Object> identityDetails) throws DataProviderExchangeException {
        try {
            String individualId = (String)identityDetails.get("sub");
            System.out.println("individualId>>>>>" + individualId);
            ResponseEntity responseEntity = this.restTemplate.exchange(this.dataProviderUrl + individualId, HttpMethod.GET, null, (ParameterizedTypeReference)new ParameterizedTypeReference<Map<String, Object>>(this){}, new Object[0]);
            if (responseEntity.getStatusCode().is2xxSuccessful() && responseEntity.getBody() != null) {
                Map responseMap = (Map)responseEntity.getBody();
                Object data = responseMap.get("data");
                System.out.println("data>>>>>" + String.valueOf(data));
                if (data == null) {
                    log.warn("Data field is null in the response from Welerantt data provider");
                    throw new DataProviderExchangeException("No Data Found");
                }
                if (data instanceof Map) {
                    return new JSONObject((Map)data);
                }
                log.error("Unexpected data type in 'Data' field: {}", (Object)data.getClass().getName());
                throw new DataProviderExchangeException("Invalid data format received from data provider");
            }
            log.warn("Non-2xx response or null body from data provider: status={}, body={}", (Object)responseEntity.getStatusCode(), responseEntity.getBody());
        }
        catch (Exception e) {
            log.error("Failed to fetch json data from Welerantt data provider plugin", e);
            throw new DataProviderExchangeException("ERROR_FETCHING_IDENTITY_DATA");
        }
        throw new DataProviderExchangeException("No Data Found");
    }
}

